"""Tests for the private inference-gateway sanitization rules.

The judge / collection calls were routed through a private paid gateway whose
host must never reach a public release AND must never be stored in this (public)
source. The sanitizer reads the host at runtime from the environment variable
MCPHUNT_PRIVATE_GATEWAY_HOST; these tests inject a PLACEHOLDER host so no real
host literal appears anywhere in tracked code or tests.

They lock the behaviour of the gateway rules in scripts/sanitize_traces.py:
  - always-on keyed forms (host-agnostic): ANTHROPIC_BASE_URL=<url>,
    "judge_api_base": "<url>"
  - host-conditional forms (only when the host is configured): api_base /
    base_url value match, bare-host fallback, residual red line
  - no collateral damage to legitimate content (e.g. api.anthropic.com)
  - idempotence, and that validate_sanitization flags residuals only when a
    host is configured.
"""

import importlib.util
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "sanitize_traces", REPO / "scripts" / "sanitize_traces.py"
)
sanitize_traces = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sanitize_traces)

sanitize_text = sanitize_traces.sanitize_text
validate_sanitization = sanitize_traces.validate_sanitization
ENV_VAR = sanitize_traces._PRIVATE_GATEWAY_HOST_ENV

# Placeholder host used purely for tests - NOT the real private gateway.
FAKE_HOST = "private-gw.example"


@pytest.fixture
def with_host(monkeypatch):
    """Configure the placeholder private host via the env injection point."""
    monkeypatch.setenv(ENV_VAR, FAKE_HOST)
    return FAKE_HOST


@pytest.fixture
def without_host(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)


# -- Always-on keyed rules (host-agnostic) ----------------------------

def test_env_dump_form_neutralised_without_host(without_host):
    raw = r"n\n  ANTHROPIC_BASE_URL=https://private-gw.example/v1\n\n  APPDATA=C"
    out = sanitize_text(raw)
    assert "private-gw.example" not in out
    assert "ANTHROPIC_BASE_URL=<internal-gateway>" in out
    # Key preserved, surrounding content preserved.
    assert "APPDATA=C" in out


def test_judge_api_base_form_neutralised_without_host(without_host):
    raw = '{"judge_api_base": "https://private-gw.example/v1", "seed": 20260729}'
    out = sanitize_text(raw)
    assert "private-gw.example" not in out
    assert '"judge_api_base": "<internal-gateway>"' in out
    # Neighbouring fields untouched.
    assert '"seed": 20260729' in out


def test_judge_prefixed_field_not_touched(without_host):
    # Only the exact key judge_api_base is cleaned, not any field containing
    # "judge" - a URL under a different judge-* key must survive.
    raw = '{"judge_model_url": "https://private-gw.example/v1"}'
    out = sanitize_text(raw)
    assert '"judge_model_url": "https://private-gw.example/v1"' in out


# -- Host-conditional rules -------------------------------------------

def test_api_base_and_base_url_cleaned_when_host_matches(with_host):
    for key in ("api_base", "base_url"):
        raw = '{"%s": "https://private-gw.example/v1"}' % key
        out = sanitize_text(raw)
        assert "private-gw.example" not in out
        assert '"%s": "<internal-gateway>"' % key in out


def test_api_base_not_touched_without_host(without_host):
    # With no host configured, generic api_base/base_url values are left alone.
    raw = '{"api_base": "https://private-gw.example/v1"}'
    out = sanitize_text(raw)
    assert '"api_base": "https://private-gw.example/v1"' in out


def test_bare_host_fallback_when_host_configured(with_host):
    raw = "see private-gw.example for details"
    out = sanitize_text(raw)
    assert "private-gw.example" not in out
    assert "internal-gateway" in out


def test_bare_host_not_touched_without_host(without_host):
    raw = "see private-gw.example for details"
    out = sanitize_text(raw)
    # No host configured: bare host is not a known private host, left as-is.
    assert "private-gw.example" in out


# -- No collateral damage (Medium-finding regression lock) ------------

def test_anthropic_api_base_not_rewritten_with_host(with_host):
    # A different, non-private endpoint under api_base/base_url must survive
    # even when a private host IS configured - only the configured host matches.
    raw = '{"base_url": "https://api.anthropic.com/v1"}'
    out = sanitize_text(raw)
    assert '"base_url": "https://api.anthropic.com/v1"' in out


def test_no_collateral_on_legitimate_content(with_host):
    # Sanitised behaviour paths and standard install paths must survive.
    raw = (
        r"USERPROFILE=C:\\Users\\user  "
        r"reading /home/user/AppData/Local/Temp/mcphunt_sqlite.db  "
        r"EXEPATH=C:\\Program Files\\Git\\bin  "
        "public api https://api.anthropic.com/v1"
    )
    out = sanitize_text(raw)
    assert "/home/user/AppData/Local/Temp/mcphunt_sqlite.db" in out
    assert r"EXEPATH=C:\\Program Files\\Git\\bin" in out
    assert "https://api.anthropic.com/v1" in out


# -- Idempotence ------------------------------------------------------

def test_idempotent_without_host(without_host):
    raw = r"ANTHROPIC_BASE_URL=https://private-gw.example/v1"
    once = sanitize_text(raw)
    twice = sanitize_text(once)
    assert once == twice


def test_idempotent_with_host(with_host):
    raw = '{"api_base": "https://private-gw.example/v1"} and private-gw.example'
    once = sanitize_text(raw)
    twice = sanitize_text(once)
    assert once == twice
    assert "private-gw.example" not in once


# -- validate_sanitization red line -----------------------------------

def test_validate_flags_host_residual_when_configured(with_host):
    errs = validate_sanitization(
        '{"a": 1}',
        '{"api_base": "https://private-gw.example/v1"}',
        "fake.json",
    )
    assert any("private gateway host" in e for e in errs)


def test_validate_no_host_red_line_without_host(without_host):
    # With no host configured there is no host red line - a residual host
    # string is not flagged (nothing to compare against).
    errs = validate_sanitization(
        '{"a": 1}',
        '{"api_base": "https://private-gw.example/v1"}',
        "fake.json",
    )
    assert not any("private gateway host" in e for e in errs)


def test_validate_passes_when_neutralised(without_host):
    clean = '{"judge_api_base": "<internal-gateway>", "seed": 20260729}'
    errs = validate_sanitization('{"seed": 20260729}', clean, "fake.json")
    assert errs == []


# -- Counter / applier agreement ---------------------------------------
# The reported match count and the set of rules that actually rewrite a file
# must come from ONE list. When they were maintained separately, every
# Windows/VSCode rule applied in sanitize_text() but was invisible to the
# counter, so a file whose only leak was e.g. CLAUDE_CODE_EXECPATH counted 0
# replacements, was reported clean, and was never written out.

def test_counted_rules_are_derived_from_the_applied_rules():
    applied = [rgx for rgx, _ in sanitize_traces._HOST_INDEPENDENT_RULES]
    assert list(sanitize_traces._COUNTED_RULES) == applied


def test_every_applied_rule_is_counted(without_host):
    """No host-independent rule may fire without incrementing the count."""
    samples = {
        "CLAUDE_CODE_EXECPATH=/home/user/.vscode/extensions/x/bin",
        r"C:\\Users\\Administrator\\AppData",
        "USERNAME=Administrator",
        "Administrator   197121",
        "(197108/Administrator)",
        "COMPUTERNAME=DESKTOP-ABC1",
        r"LOGONSERVER=\\\\DESKTOP-ABC1",
        "DESKTOP-10UVREO",
        r"INIT_CWD=C:\\Project\\MCPHunt\\scripts",
        "C:UsersAdministrator",
        "/Users/someone/",
        "PyCharmProjects",
        "lihaonan",
        "ANTHROPIC_BASE_URL=https://private-gw.example/v1",
        '"judge_api_base": "https://private-gw.example/v1"',
    }
    for raw in samples:
        rewritten = sanitize_text(raw) != raw
        counted = sum(len(r.findall(raw))
                      for r in sanitize_traces._COUNTED_RULES) > 0
        assert rewritten == counted, (
            f"counter and applier disagree on {raw!r}: "
            f"rewritten={rewritten} counted={counted}")
