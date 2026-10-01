"""OpenCode-inspired colour system.

The palette mirrors the default ``opencode`` theme (packages/tui/src/theme)
so the SplitAgent TUI feels native to the same visual language: a near-black
canvas, warm sand accent and a restrained, low-contrast grayscale.
"""

from __future__ import annotations

# Core steps
BG = "#0a0a0a"
PANEL = "#141414"
ELEMENT = "#1e1e1e"
STEP4 = "#282828"
STEP5 = "#323232"
BORDER_SUBTLE = "#3c3c3c"
BORDER = "#484848"
BORDER_ACTIVE = "#606060"
PRIMARY = "#fab283"
PRIMARY_SOFT = "#ffc09f"
MUTED = "#808080"
TEXT = "#eeeeee"

# Semantic
SECONDARY = "#5c9cf5"
ACCENT = "#9d7cd8"
RED = "#e06c75"
ORANGE = "#f5a742"
GREEN = "#7fd88f"
CYAN = "#56b6c2"
YELLOW = "#e5c07b"

SEVERITY_COLORS = {
    "critical": RED,
    "high": ORANGE,
    "medium": YELLOW,
    "low": GREEN,
    "info": CYAN,
}

AGENT_COLORS = {
    "red": RED,
    "blue": SECONDARY,
    "core": PRIMARY,
}

STATUS_COLORS = {
    "info": CYAN,
    "warning": ORANGE,
    "error": RED,
    "success": GREEN,
}

BANNER = r"""
  ___        _ _   _    _             _
 / __|_ __  (_) |_| |  | |__ _ _ _  __| |_
 \__ \ '_ \ | |  _| |__| / _` | ' \/ _`  _|
 |___/ .__/ |_|\__|____|_\__,_|_||_\__,_\__|
     |_|   autonomous dual-team security
"""


def severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity.lower(), MUTED)


def agent_color(agent: str) -> str:
    return AGENT_COLORS.get(agent, MUTED)


def status_color(level: str) -> str:
    return STATUS_COLORS.get(level, MUTED)
