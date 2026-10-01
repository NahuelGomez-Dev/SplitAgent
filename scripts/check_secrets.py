#!/usr/bin/env python
"""Refuse to commit a real credential.

Runs as a pre-commit hook over the staged files. It matches provider key
shapes only, so the documented placeholders (``sk-...``, ``oc_sk_...``) and the
``api_key: ""`` defaults pass through untouched.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Real-looking credentials. Deliberately specific so placeholders never match.
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Provider keys may contain underscores and dashes, so the character class
    # has to allow them - an alphanumeric-only pattern misses real keys.
    ("OpenCode", re.compile(r"oc_sk_[A-Za-z0-9_-]{16,}")),
    ("Anthropic", re.compile(r"sk-ant-[A-Za-z0-9_-]{24,}")),
    ("OpenAI", re.compile(r"\bsk-[A-Za-z0-9_-]{32,}\b")),
    ("OpenRouter", re.compile(r"\bsk-or-[A-Za-z0-9_-]{24,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]

# Files that legitimately contain key-shaped strings (docs, examples, this hook).
ALLOW_SUFFIXES = {".md", ".example", ".dist", ".lock"}


def main(argv: list[str]) -> int:
    findings: list[str] = []
    for raw in argv[1:]:
        path = Path(raw)
        if not path.is_file() or path.suffix in ALLOW_SUFFIXES:
            continue
        if path.name in {"check_secrets.py", "conftest.py"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for label, pattern in PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(f"{path}:{line}: possible {label} credential")

    if findings:
        print("Refusing to commit credentials:\n")
        for finding in findings:
            print(f"  {finding}")
        print(
            "\nIf this is a placeholder, extend ALLOW_SUFFIXES or the pattern in "
            "scripts/check_secrets.py."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
