"""Shared text utilities used across labeling, agent loop, and taint tracker."""
from __future__ import annotations

import re

_MD_ESCAPE_RE = re.compile(r"\\([_*\[\]()~`>#+\-=|{}.!])")


def strip_md_escapes(text: str) -> str:
    """Remove Markdown backslash escapes (e.g. \\_  \\*) so canary matching works."""
    return _MD_ESCAPE_RE.sub(r"\1", text)
