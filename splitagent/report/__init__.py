"""Reporting: CVSS scoring and report rendering.

Keep this package initialiser light so ``splitagent.report.cvss`` can be
imported by tools without pulling in the whole rendering stack.
"""

from __future__ import annotations

__all__ = ["cvss"]
