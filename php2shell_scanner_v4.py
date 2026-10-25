#!/usr/bin/env python3
"""Entry point for the evidence-first php2shell scanner v4.

The original ``php2shell_scanner.py`` is intentionally left untouched.  This
tool implements the inventory / probe / prove / exploit / report / verify workflow
for CVE-2026-109618 and CVE-2026-109619.
"""

import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

if sys.stdout.encoding and sys.stdout.encoding.lower().replace("-", "") not in ("utf8", "utf16"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        os.environ.setdefault("PYTHONIOENCODING", "utf-8")

from p2s.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
