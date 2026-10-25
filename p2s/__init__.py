"""php2shell evidence-first scanner (v4).

Two independent CVE pipelines:
  * CVE-2026-109618 -- RCE via OOM corruption
  * CVE-2026-109619 -- RCE via stale global state

Design rule: no status is inferred from HTTP status codes, banners or
crashes alone.  Every elevated status names the evidence that supports it
and the evidence that is still missing.
"""

from .version import VERSION, TOOL_NAME

__all__ = ["VERSION", "TOOL_NAME"]
