"""MCP server driver, tool definitions, server lifecycle, and smoke tests.

Extracted from scripts/collect_agent_traces.py — pure structural refactoring.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from mcphunt import workspace
from mcphunt.config import MCP_READ_TIMEOUT_S, PROCESS_STOP_TIMEOUT_S, HTTP_SERVER_START_DELAY_S
from mcphunt.log import get_logger
from mcphunt.workspace import _sanitized_env
from mcphunt.taxonomy import ABLATION_PROFILES

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# MCP server driver (JSON-RPC over stdio)
# ---------------------------------------------------------------------------

class MCPServerDriver:
    def __init__(self, name: str, command: List[str], env: Optional[Dict[str, str]] = None,
                 cwd: Optional[str] = None, read_timeout: float = MCP_READ_TIMEOUT_S):
        self.name = name
        self.command = command
        self.env = env or {}
        self.cwd = cwd
        self.read_timeout = read_timeout
        self.proc: Optional[subprocess.Popen] = None
        self._request_id = 0
        self._initialized = False

    async def start(self) -> None:
        merged_env = {**_sanitized_env(), **self.env}
        popen_kwargs: dict = dict(
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=merged_env, cwd=self.cwd,
        )
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            popen_kwargs["shell"] = True
        else:
            popen_kwargs["start_new_session"] = True
        self.proc = subprocess.Popen(self.command, **popen_kwargs)
        await self._initialize()

    async def _initialize(self) -> None:
        resp = await self._send_request("initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "mcphunt-agent-collector", "version": "3.0.0"},
        })
        if resp and not resp.get("error"):
            await self._send_notification("notifications/initialized", {})
            self._initialized = True

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        t0 = time.time()
        resp = await self._send_request("tools/call", {"name": tool_name, "arguments": arguments})
        latency = (time.time() - t0) * 1000
        if resp and "result" in resp:
            result_obj = resp["result"]
            content = result_obj.get("content", [])
            text_parts = [c.get("text", "") for c in content if c.get("type") == "text"]
            result_text = "\n".join(text_parts)
            is_error = result_obj.get("isError", False)
            if not is_error and result_text.startswith("exit_code: "):
                first_line = result_text.split("\n", 1)[0]
                code_str = first_line.split("exit_code: ", 1)[1].strip()
                if code_str.isdigit() and int(code_str) != 0:
                    is_error = True
            return {"success": not is_error, "result": result_text, "latency_ms": latency}
        error = resp.get("error", {}).get("message", str(resp)) if resp else "no response"
        return {"success": False, "error": error, "latency_ms": latency}

    async def list_tools(self) -> List[Dict[str, Any]]:
        resp = await self._send_request("tools/list", {})
        if resp and "result" in resp:
            return resp["result"].get("tools", [])
        return []

    async def _send_request(self, method: str, params: Dict[str, Any]) -> Optional[Dict]:
        if not self.proc or not self.proc.stdin or not self.proc.stdout:
            return None
        self._request_id += 1
        payload = json.dumps({"jsonrpc": "2.0", "id": self._request_id, "method": method, "params": params}) + "\n"
        try:
            self.proc.stdin.write(payload.encode())
            self.proc.stdin.flush()
            return await self._read_response()
        except (BrokenPipeError, OSError) as e:
            return {"error": {"message": str(e)}}

    async def _send_notification(self, method: str, params: Dict[str, Any]) -> None:
        if not self.proc or not self.proc.stdin:
            return
        payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params}) + "\n"
        try:
            self.proc.stdin.write(payload.encode())
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass

    async def _read_response(self) -> Optional[Dict]:
        """Read the next JSON-RPC response, skipping any interleaved notifications.

        MCP servers may emit notifications (no ``id`` field) or log messages
        between request and response.  Consuming them here prevents the
        actual response from being silently dropped.
        """
        if not self.proc or not self.proc.stdout:
            return None
        loop = asyncio.get_event_loop()
        deadline = asyncio.get_event_loop().time() + self.read_timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                return {"error": {"message": "timeout"}}
            try:
                line = await asyncio.wait_for(
                    loop.run_in_executor(None, self.proc.stdout.readline),
                    timeout=remaining,
                )
                if not line:
                    return None
                msg = json.loads(line.decode().strip())
                if "id" in msg:
                    return msg
                # No id → notification/log; skip and read next line
            except asyncio.TimeoutError:
                return {"error": {"message": "timeout"}}
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
                return {"error": {"message": str(e)}}

    async def stop(self) -> None:
        if self.proc:
            if sys.platform == "win32":
                self.proc.terminate()
            else:
                try:
                    pgid = os.getpgid(self.proc.pid)
                    os.killpg(pgid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError, OSError):
                    self.proc.terminate()
            try:
                self.proc.wait(timeout=PROCESS_STOP_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                if sys.platform == "win32":
                    self.proc.kill()
                else:
                    try:
                        pgid = os.getpgid(self.proc.pid)
                        os.killpg(pgid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError, OSError):
                        self.proc.kill()


# ---------------------------------------------------------------------------
# Local HTTP server for browser tasks
# ---------------------------------------------------------------------------

_http_server_proc: Optional[subprocess.Popen] = None


def _kill_processes_on_port(port: int) -> None:
    """Kill any process occupying the given port (cross-platform)."""
    pids: list[str] = []
    try:
        if sys.platform == "win32":
            result = subprocess.run(
                ["netstat", "-ano", "-p", "TCP"],
                capture_output=True, text=True, timeout=PROCESS_STOP_TIMEOUT_S,
            )
            for line in result.stdout.splitlines():
                if f":{port} " in line or f":{port}\t" in line:
                    parts = line.split()
                    if parts and parts[-1].isdigit():
                        pids.append(parts[-1])
        else:
            result = subprocess.run(
                ["lsof", "-ti", f":{port}"],
                capture_output=True, text=True, timeout=PROCESS_STOP_TIMEOUT_S,
            )
            pids = [p for p in result.stdout.strip().split() if p.isdigit()]
    except (OSError, subprocess.SubprocessError):
        return
    for pid in set(pids):
        try:
            if sys.platform == "win32":
                subprocess.run(
                    ["taskkill", "/F", "/PID", pid],
                    capture_output=True, timeout=PROCESS_STOP_TIMEOUT_S,
                )
            else:
                os.kill(int(pid), 9)
            log.info("Killed stale process %s on port %s", pid, port)
        except (OSError, subprocess.SubprocessError):
            pass
    if pids:
        time.sleep(HTTP_SERVER_START_DELAY_S)


def _start_local_http_server() -> None:
    """Start HTTP server for browser tasks on the per-model port.

    Web files are stored OUTSIDE the workspace (in WEB_DIR) so the
    filesystem MCP server cannot read them directly.  Agents must use
    browser or fetch tools to access web content, preventing fallback
    to filesystem.read_file that would confound the browser_to_local
    mechanism measurement.
    """
    global _http_server_proc
    _stop_local_http_server()
    port = workspace.ws.local_http_port
    web_dir = workspace.ws.web_dir
    _kill_processes_on_port(port)
    web_dir.mkdir(parents=True, exist_ok=True)
    _http_server_proc = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port), "--directory", str(web_dir)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    import urllib.request
    for _attempt in range(10):
        time.sleep(HTTP_SERVER_START_DELAY_S)
        try:
            urllib.request.urlopen(f"http://localhost:{port}/", timeout=2)
            break
        except Exception:
            pass
    else:
        log.warning("HTTP server on port %d did not respond after retries", port)


def _stop_local_http_server() -> None:
    global _http_server_proc
    if _http_server_proc:
        _http_server_proc.terminate()
        try:
            _http_server_proc.wait(timeout=PROCESS_STOP_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            _http_server_proc.kill()
        _http_server_proc = None


# ---------------------------------------------------------------------------
# _ws helper
# ---------------------------------------------------------------------------

def _ws(path: str) -> str:
    return str(workspace.ws.workspace / path)


# ---------------------------------------------------------------------------
# Tool definitions for the LLM
# ---------------------------------------------------------------------------

TOOL_DEFS = [
    {"type": "function", "function": {
        "name": "filesystem__read_file",
        "description": "Read the complete contents of a file from the workspace.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "Absolute path to the file"}
        }, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "filesystem__write_file",
        "description": "Write content to a file (creates or overwrites).",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "Absolute path"},
            "content": {"type": "string", "description": "Content to write"}
        }, "required": ["path", "content"]}}},
    {"type": "function", "function": {
        "name": "filesystem__list_directory",
        "description": "List files and directories at the given path.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "Directory path"}
        }, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "filesystem__search_files",
        "description": "Search for files matching a pattern in a directory.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "Directory to search"},
            "pattern": {"type": "string", "description": "Search pattern (glob)"}
        }, "required": ["path", "pattern"]}}},
    {"type": "function", "function": {
        "name": "filesystem__get_file_info",
        "description": "Get metadata about a file (size, timestamps).",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "File path"}
        }, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "filesystem__create_directory",
        "description": "Create a new directory.",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string", "description": "Directory path to create"}
        }, "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "filesystem__move_file",
        "description": "Move or rename a file.",
        "parameters": {"type": "object", "properties": {
            "source": {"type": "string", "description": "Source path"},
            "destination": {"type": "string", "description": "Destination path"}
        }, "required": ["source", "destination"]}}},
    {"type": "function", "function": {
        "name": "memory__create_entities",
        "description": "Create new entities in the knowledge graph.",
        "parameters": {"type": "object", "properties": {
            "entities": {"type": "array", "items": {"type": "object", "properties": {
                "name": {"type": "string"}, "entityType": {"type": "string"},
                "observations": {"type": "array", "items": {"type": "string"}}
            }}}
        }, "required": ["entities"]}}},
    {"type": "function", "function": {
        "name": "memory__read_graph",
        "description": "Read the entire knowledge graph with all entities and relations.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "memory__search_nodes",
        "description": "Search for entities by name or content.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string", "description": "Search query"}
        }, "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "memory__add_observations",
        "description": "Add observations to existing entities.",
        "parameters": {"type": "object", "properties": {
            "observations": {"type": "array", "items": {"type": "object", "properties": {
                "entityName": {"type": "string"},
                "contents": {"type": "array", "items": {"type": "string"}}
            }}}
        }, "required": ["observations"]}}},
    {"type": "function", "function": {
        "name": "memory__delete_entities",
        "description": "Delete entities from the knowledge graph.",
        "parameters": {"type": "object", "properties": {
            "entityNames": {"type": "array", "items": {"type": "string"}}
        }, "required": ["entityNames"]}}},
    {"type": "function", "function": {
        "name": "sqlite__read_query",
        "description": "Execute a SELECT query on the SQLite database.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string", "description": "SQL SELECT query"}
        }, "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "sqlite__write_query",
        "description": "Execute an INSERT/UPDATE/DELETE query on the SQLite database.",
        "parameters": {"type": "object", "properties": {
            "query": {"type": "string", "description": "SQL write query"}
        }, "required": ["query"]}}},
    {"type": "function", "function": {
        "name": "sqlite__list_tables",
        "description": "List all tables in the database.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "sqlite__describe_table",
        "description": "Get the schema of a table.",
        "parameters": {"type": "object", "properties": {
            "table_name": {"type": "string", "description": "Table name"}
        }, "required": ["table_name"]}}},
    {"type": "function", "function": {
        "name": "fetch__fetch",
        "description": "Fetch content from a URL (HTTP GET).",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string", "description": "URL to fetch"}
        }, "required": ["url"]}}},
    {"type": "function", "function": {
        "name": "git__git_status",
        "description": "Show the working tree status of the git repository.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "git__git_log",
        "description": "Show recent commit history.",
        "parameters": {"type": "object", "properties": {
            "max_count": {"type": "integer", "description": "Max commits to show", "default": 10}
        }}}},
    {"type": "function", "function": {
        "name": "git__git_diff_unstaged",
        "description": "Show unstaged changes in the working tree.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "git__git_show",
        "description": "Show details of a specific commit.",
        "parameters": {"type": "object", "properties": {
            "revision": {"type": "string", "description": "Commit hash or reference"}
        }, "required": ["revision"]}}},
    {"type": "function", "function": {
        "name": "time__get_current_time",
        "description": "Get the current time in a specific timezone.",
        "parameters": {"type": "object", "properties": {
            "timezone": {"type": "string", "description": "IANA timezone (e.g. America/New_York)"}
        }, "required": ["timezone"]}}},
    {"type": "function", "function": {
        "name": "shell__execute_command",
        "description": "Execute a shell command and return its output. Available commands include: ls, cat, head, tail, wc, grep, find, echo, printf, env, curl, wget, base64, sort, uniq, tr, cut, awk, sed, diff, file, stat, date, whoami, pwd, hostname.",
        "parameters": {"type": "object", "properties": {
            "command": {"type": "string", "description": "The shell command to execute"}
        }, "required": ["command"]}}},
]

BROWSER_TOOL_DEFS = [
    {"type": "function", "function": {
        "name": "browser__browser_navigate",
        "description": "Navigate the browser to a URL.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string", "description": "URL to navigate to"}
        }, "required": ["url"]}}},
    {"type": "function", "function": {
        "name": "browser__browser_snapshot",
        "description": "Get the accessibility tree of the current page (text content, links, forms, buttons).",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "browser__browser_click",
        "description": "Click an element on the page.",
        "parameters": {"type": "object", "properties": {
            "element": {"type": "string", "description": "Element description or accessible name"},
            "ref": {"type": "string", "description": "Element reference from snapshot"}
        }, "required": ["element"]}}},
    {"type": "function", "function": {
        "name": "browser__browser_type",
        "description": "Type text into a focused input field on the page.",
        "parameters": {"type": "object", "properties": {
            "text": {"type": "string", "description": "Text to type"},
            "submit": {"type": "boolean", "description": "Whether to press Enter after typing"}
        }, "required": ["text"]}}},
    {"type": "function", "function": {
        "name": "browser__browser_fill_form",
        "description": "Fill multiple form fields at once.",
        "parameters": {"type": "object", "properties": {
            "values": {"type": "array", "items": {"type": "object", "properties": {
                "ref": {"type": "string"}, "value": {"type": "string"}
            }}, "description": "Form field values to fill"}
        }, "required": ["values"]}}},
]

TOOL_SERVER_MAP = {}
for td in TOOL_DEFS + BROWSER_TOOL_DEFS:
    fname = td["function"]["name"]
    server, tool = fname.split("__", 1)
    TOOL_SERVER_MAP[fname] = (server, tool)


# ---------------------------------------------------------------------------
# Server management
# ---------------------------------------------------------------------------

SHELL_ALLOWED_COMMANDS = ",".join([
    "ls", "cat", "head", "tail", "wc", "grep", "find",
    "echo", "printf", "env", "printenv",
    "date", "whoami", "pwd", "hostname",
    "cd", "cp", "mv", "mkdir", "touch", "chmod", "rm",
    "sort", "uniq", "tr", "cut", "awk", "sed",
    "curl", "wget",
    "base64", "md5sum", "sha256sum",
    "diff", "file", "stat",
])

def _load_mcp_versions() -> Dict[str, Dict[str, str]]:
    ver_path = workspace.REPO_ROOT / "configs" / "mcp_server_versions.json"
    if ver_path.exists():
        return json.loads(ver_path.read_text(encoding="utf-8"))
    return {}

_MCP_VERSIONS = _load_mcp_versions()

def _pinned_uvx(pkg: str) -> str:
    ver = _MCP_VERSIONS.get("uvx", {}).get(pkg, "")
    return f"{pkg}=={ver}" if ver else pkg

def _pinned_npx(pkg: str) -> str:
    ver = _MCP_VERSIONS.get("npx", {}).get(pkg, "")
    return f"{pkg}@{ver}" if ver else pkg

def _server_commands() -> Dict[str, list]:
    return {
        "filesystem": ["npx", "--yes", _pinned_npx("@modelcontextprotocol/server-filesystem"), str(workspace.ws.workspace), str(workspace.ws.workspace_prompt)],
        "memory": ["npx", "--yes", _pinned_npx("@modelcontextprotocol/server-memory")],
        "git": ["uvx", _pinned_uvx("mcp-server-git"), "--repository", str(workspace.ws.workspace)],
        "sqlite": ["uvx", _pinned_uvx("mcp-server-sqlite"), "--db-path", workspace.ws.sqlite_db],
        "fetch": ["uvx", _pinned_uvx("mcp-server-fetch")],
        "time": ["uvx", _pinned_uvx("mcp-server-time")],
        "browser": ["npx", _pinned_npx("@playwright/mcp"), "--headless"],
        "shell": ["npx", "-y", _pinned_npx("shell-command-mcp")],
    }

def _server_envs() -> Dict[str, Dict[str, str]]:
    memory_dir = Path(tempfile.gettempdir()) / f"mcphunt_memory_{workspace.ws.workspace.name}"
    memory_dir.mkdir(parents=True, exist_ok=True)
    memory_file = str(memory_dir / "memory_kg.jsonl")
    return {
        "shell": {"ALLOWED_COMMANDS": SHELL_ALLOWED_COMMANDS, "SHELL_CWD": str(workspace.ws.workspace)},
        "memory": {"MEMORY_FILE_PATH": memory_file},
    }


def _filter_tool_defs(tool_defs: List[Dict], active_servers: set) -> List[Dict]:
    """Return only tool definitions whose server prefix is in active_servers."""
    out = []
    for td in tool_defs:
        server = td["function"]["name"].split("__", 1)[0]
        if server in active_servers:
            out.append(td)
    return out


async def start_servers(include_browser: bool = False,
                        allowed: Optional[set] = None) -> Dict[str, MCPServerDriver]:
    if allowed is None:
        allowed = ABLATION_PROFILES["full"]
    if include_browser:
        allowed = allowed | {"browser"}

    started = {}
    for name in allowed:
        cmd = _server_commands().get(name)
        if not cmd:
            continue
        cwd = str(workspace.ws.workspace) if name == "shell" else None
        read_timeout = 90 if name == "browser" else 30
        driver = MCPServerDriver(name, cmd, env=_server_envs().get(name), cwd=cwd, read_timeout=read_timeout)
        try:
            await driver.start()
            if driver._initialized:
                started[name] = driver
                log.info("%s: started", name)
            else:
                log.warning("%s: failed to initialize", name)
        except Exception as e:
            log.error("%s: error - %s", name, e)

    return started


async def stop_servers(servers: Dict[str, MCPServerDriver]) -> None:
    for name, driver in servers.items():
        await driver.stop()


# ---------------------------------------------------------------------------
# Smoke test: verify every MCP server tool actually works before bulk run
# ---------------------------------------------------------------------------

_ERROR_PATTERNS = ["validation error", "required property", "invalid", "error:"]

_GIT_NONEMPTY_TOOLS = {"git_status", "git_log", "git_show"}

_GIT_EXPECTED_PARAMS = {
    "git_status": {"repo_path"},
    "git_log": {"repo_path"},
    "git_diff_unstaged": {"repo_path"},
    "git_show": {"repo_path", "revision"},
}


def _build_smoke_calls() -> Dict[str, Tuple[str, Dict[str, Any]]]:
    """Build smoke test calls using current WORKSPACE (not module-load-time value)."""
    ws = str(workspace.ws.workspace)
    return {
        "filesystem": ("list_directory", {"path": ws}),
        "git": ("git_status", {"repo_path": ws}),
        "sqlite": ("list_tables", {}),
        "memory": ("read_graph", {}),
        "shell": ("execute_command", {"command": "echo ok"}),
        "fetch": ("fetch", {"url": "http://localhost:1/nonexistent"}),
        "time": ("get_current_time", {"timezone": "UTC"}),
    }


def _build_git_deep_smoke() -> List[Tuple[str, Dict[str, Any], str]]:
    """Build git deep smoke tests using current WORKSPACE."""
    ws = str(workspace.ws.workspace)
    return [
        ("git_log", {"repo_path": ws, "max_count": 5}, "commit"),
        ("git_diff_unstaged", {"repo_path": ws}, ""),
        ("git_show", {"repo_path": ws, "revision": "HEAD"}, ""),
    ]


async def _validate_server_schema(name: str, driver: MCPServerDriver, prefix: str) -> bool:
    """Query a server's actual tool schema and verify TOOL_DEFS parameter names match.

    Catches parameter name mismatches (e.g. 'path' vs 'file_path') that would
    cause silent validation errors at runtime.
    """
    try:
        tools = await driver.list_tools()
    except Exception as e:
        log.error("%s schema: failed to list tools: %s", name, e)
        return False
    if not tools:
        log.error("%s schema: server returned no tools", name)
        return False

    server_tools = {t["name"]: t for t in tools}
    hardcoded_tools = {
        td["function"]["name"].split("__", 1)[1]: td["function"]
        for td in TOOL_DEFS + BROWSER_TOOL_DEFS
        if td["function"]["name"].startswith(f"{prefix}__")
    }

    all_ok = True
    for tool_name, td_func in hardcoded_tools.items():
        if tool_name not in server_tools:
            continue
        our_params = set(td_func.get("parameters", {}).get("properties", {}).keys())
        our_required = set(td_func.get("parameters", {}).get("required", []))
        srv_schema = server_tools[tool_name].get("inputSchema", {})
        srv_required = set(srv_schema.get("required", []))
        missing_required = srv_required - our_params
        if missing_required:
            log.error("%s schema: %s — server requires %s but TOOL_DEFS omits them", name, tool_name, missing_required)
            all_ok = False

    if all_ok:
        log.info("%s schema: %d tools validated against server", name, len(hardcoded_tools))
    return all_ok


async def _validate_git_schema(driver: MCPServerDriver) -> bool:
    """Query git server's actual tool schema and validate against expectations.

    Catches parameter name changes across mcp-server-git versions before they
    cause silent failures at runtime.
    """
    log.info("Validating git server tool schema...")
    try:
        tools = await driver.list_tools()
    except Exception as e:
        log.error("git schema: failed to list tools: %s", e)
        return False

    if not tools:
        log.error("git schema: server returned no tools")
        return False

    server_tools = {t["name"]: t for t in tools}
    all_ok = True

    for tool_name, expected_params in _GIT_EXPECTED_PARAMS.items():
        if tool_name not in server_tools:
            log.error("git schema: expected tool '%s' not found in server", tool_name)
            all_ok = False
            continue
        schema = server_tools[tool_name].get("inputSchema", {})
        actual_props = set(schema.get("properties", {}).keys())
        actual_required = set(schema.get("required", []))
        missing = expected_params - actual_props
        if missing:
            log.error("git schema: %s missing expected params %s (actual: %s)", tool_name, missing, actual_props)
            all_ok = False
        if "repo_path" in expected_params and "repo_path" not in actual_required:
            log.warning("git schema: %s has repo_path but it's not required (required: %s)", tool_name, actual_required)

    hardcoded_git_tools = {
        td["function"]["name"].split("__", 1)[1]
        for td in TOOL_DEFS
        if td["function"]["name"].startswith("git__")
    }
    server_tool_names = set(server_tools.keys())
    in_code_not_server = hardcoded_git_tools - server_tool_names
    in_server_not_code = {t for t in server_tool_names if t.startswith("git_")} - hardcoded_git_tools
    if in_code_not_server:
        log.error("git schema: TOOL_DEFS reference tools not in server: %s", in_code_not_server)
        all_ok = False
    if in_server_not_code:
        log.info("git schema: server has extra tools not in TOOL_DEFS: %s", in_server_not_code)

    if all_ok:
        log.info("git schema: %d tools validated, params match", len(server_tools))
    return all_ok


async def smoke_test_servers(servers: Dict[str, MCPServerDriver]) -> bool:
    """Call each server once and verify the result is successful and non-empty.

    Three-layer validation:
    1. Schema check: query git server's actual tool schema, compare against TOOL_DEFS
    2. Basic smoke: one call per server, check success flag AND error patterns
    3. Git deep smoke: test all 4 git tools with runtime-identical args
    """
    log.info("Running pre-flight checks on all MCP servers...")
    all_ok = True

    for srv_name, srv_prefix in [("git", "git"), ("filesystem", "filesystem"),
                                    ("shell", "shell"), ("sqlite", "sqlite")]:
        if srv_name in servers:
            if srv_name == "git":
                if not await _validate_git_schema(servers["git"]):
                    all_ok = False
            else:
                if not await _validate_server_schema(srv_name, servers[srv_name], srv_prefix):
                    all_ok = False

    smoke_calls = _build_smoke_calls()
    for name, driver in servers.items():
        entry = smoke_calls.get(name)
        if not entry:
            continue
        tool, args = entry
        try:
            result = await driver.call_tool(tool, args)
            is_success = result.get("success", True)
            result_str = result.get("error") or result.get("result", "")
            result_lower = result_str.lower()

            if not is_success:
                if name == "fetch":
                    continue
                log.error("%s.%s: success=False: %s", name, tool, result_str[:150])
                all_ok = False
            elif any(p in result_lower for p in _ERROR_PATTERNS):
                if name == "fetch":
                    continue
                log.error("%s.%s: error text in result: %s", name, tool, result_str[:120])
                all_ok = False
            elif name == "git" and not result_str.strip():
                log.error("%s.%s: returned EMPTY result (silent failure)", name, tool)
                all_ok = False
            else:
                log.info("%s.%s: OK (%d chars)", name, tool, len(result_str))
        except Exception as e:
            log.error("%s.%s: exception: %s", name, tool, e)
            all_ok = False

    if "git" in servers and all_ok:
        git_driver = servers["git"]
        for tool, args, must_contain in _build_git_deep_smoke():
            try:
                result = await git_driver.call_tool(tool, args)
                is_success = result.get("success", True)
                result_str = result.get("error") or result.get("result", "")
                if not is_success:
                    log.error("git.%s: success=False: %s", tool, result_str[:150])
                    all_ok = False
                elif tool in _GIT_NONEMPTY_TOOLS and not result_str.strip():
                    log.error("git.%s: EMPTY result — git history not accessible", tool)
                    all_ok = False
                elif must_contain and must_contain not in result_str.lower():
                    log.error("git.%s: result missing expected content '%s'", tool, must_contain)
                    all_ok = False
                else:
                    log.info("git.%s: OK (%d chars)", tool, len(result_str))
            except Exception as e:
                log.error("git.%s: exception: %s", tool, e)
                all_ok = False

    if not all_ok:
        log.error("SMOKE TEST FAILED — aborting to prevent bad data collection")
    else:
        log.info("All servers passed pre-flight checks")
    return all_ok
