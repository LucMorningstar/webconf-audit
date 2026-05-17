"""Stable finding fingerprints for CI, suppressions, and baselines."""

from __future__ import annotations

import hashlib
import json
import posixpath
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from webconf_audit.models import AnalysisResult, Finding, SourceLocation

_SCOPE_METADATA_KEYS = (
    "scope",
    "scope_id",
    "context",
    "host",
    "server_name",
    "location",
    "section",
)

# Host-like scope keys are case-insensitive (DNS), so lowercase their values to
# keep fingerprints stable across "Example.COM" / "example.com" variants — the
# same rule _normalize_target applies to URL netlocs.
_LOWERCASE_SCOPE_KEYS = frozenset({"host", "server_name"})


def finding_fingerprint(result: AnalysisResult, finding: Finding) -> str:
    """Return a stable SHA-256 fingerprint for a finding in result context."""
    payload = finding_fingerprint_components(result, finding)
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def finding_fingerprint_components(result: AnalysisResult, finding: Finding) -> dict[str, object]:
    """Return the canonical fields used to compute a finding fingerprint."""
    location = finding.location
    return {
        "rule_id": finding.rule_id,
        "server_type": result.server_type or "",
        "mode": result.mode,
        "source": _source_value(result, location),
        "line": location.line if location else None,
        "xml_path": _clean(location.xml_path) if location else None,
        "details": _details_value(location),
        "scope": _scope_value(finding.metadata),
    }


def _source_value(result: AnalysisResult, location: SourceLocation | None) -> str:
    if location is None:
        return _normalize_target(result.target)
    if location.file_path:
        return _normalize_path(location.file_path, result.target)
    if location.target:
        return _normalize_target(location.target)
    if location.xml_path:
        return _normalize_target(result.target)
    if location.details:
        return _clean(location.details) or ""
    return location.kind


def _details_value(location: SourceLocation | None) -> str | None:
    # Include details only when it acts as the primary locator (no target,
    # xml_path, or line) or when location.kind is one of the kinds where
    # details carry semantic meaning (header name, TLS parameter, check id).
    if location is None:
        return None
    if location.target is None and location.xml_path is None and location.line is None:
        return _clean(location.details)
    if location.kind in {"header", "tls", "check"}:
        return _clean(location.details)
    return None


def _scope_value(metadata: dict[str, Any]) -> str | None:
    for key in _SCOPE_METADATA_KEYS:
        value = metadata.get(key)
        normalized = _metadata_scalar(value)
        if normalized is not None:
            if key in _LOWERCASE_SCOPE_KEYS:
                return normalized.lower()
            return normalized
    return None


def _metadata_scalar(value: object) -> str | None:
    if isinstance(value, str):
        return _clean(value)
    if isinstance(value, bool | int | float):
        return str(value)
    return None


def _normalize_target(value: str) -> str:
    cleaned = _clean(value) or ""
    parsed = urlsplit(cleaned)
    if parsed.scheme and parsed.netloc:
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        return urlunsplit((scheme, netloc, path, parsed.query, ""))
    return _normalize_path(cleaned, "")


def _normalize_path(value: str, result_target: str) -> str:
    cleaned = (_clean(value) or "").replace("\\", "/")
    relative = _relative_to_known_root(cleaned, result_target)
    if relative is not None:
        cleaned = relative
    cleaned = _normalize_drive(cleaned)
    normalized = posixpath.normpath(cleaned)
    if normalized == ".":
        return ""
    if cleaned.endswith("/") and not normalized.endswith("/"):
        normalized += "/"
    return normalized


def _relative_to_known_root(value: str, result_target: str) -> str | None:
    try:
        path = Path(value)
    except (OSError, ValueError):
        return None
    if not path.is_absolute():
        return None

    # Roots are derived solely from result_target so fingerprints are stable
    # regardless of the current working directory (e.g. dev shell vs CI runner).
    roots: list[Path] = []
    try:
        target = Path(result_target)
    except (OSError, ValueError):
        target = None
    if target is not None and target.is_absolute():
        roots.append(target if target.is_dir() else target.parent)

    if not roots:
        return None

    for root in roots:
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            continue
    return None


def _normalize_drive(value: str) -> str:
    if len(value) >= 2 and value[1] == ":":
        return f"{value[0].lower()}:{value[2:]}"
    return value


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(value.strip().split())
    return cleaned or None


__all__ = [
    "finding_fingerprint",
    "finding_fingerprint_components",
]
