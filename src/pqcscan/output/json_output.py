"""Plain JSON output: scan metadata plus a machine-readable findings array.

The document is deterministic for a given scan (stable finding sort, stable
key order from the dataclass fields) except for ``generated_at``, which tests
can pin via the ``generated_at`` parameter.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

from pqcscan import __version__
from pqcscan.scanner.engine import ScanResult


def findings_to_list(result: ScanResult) -> list[dict[str, Any]]:
    return [f.to_dict() for f in result.findings]


def to_json(result: ScanResult, *, indent: int = 2, generated_at: Optional[str] = None) -> str:
    """Findings plus scan metadata (tool version, timestamp, scanned paths)."""
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "tool": "pqc-scan",
        "version": __version__,
        "generated_at": generated_at,
        "paths": result.scanned_paths,
        "summary": {
            "total": result.total,
            "by_severity": result.counts_by_severity(),
            "files_scanned": result.files_scanned,
            "duration_seconds": round(result.duration_seconds, 4),
            "errors": result.errors,
        },
        "findings": findings_to_list(result),
    }
    return json.dumps(payload, indent=indent)


# Backwards-compatible alias: the metadata wrapper *is* the report now.
to_report = to_json
