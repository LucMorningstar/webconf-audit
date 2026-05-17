"""Finding suppression file support for CI-oriented workflows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

import yaml

from webconf_audit.fingerprints import finding_fingerprint, finding_fingerprint_components
from webconf_audit.models import AnalysisIssue, AnalysisResult, Finding, SourceLocation

DEFAULT_SUPPRESSION_FILE = ".webconf-audit-ignore.yml"
SUPPRESSED_FINDINGS_METADATA_KEY = "suppressed_findings"

_CRITERIA_FIELDS = (
    "server_type",
    "mode",
    "source",
    "line",
    "xml_path",
    "details",
    "scope",
)
_HEX_DIGITS = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class Suppression:
    """A validated suppression entry from the YAML suppression file."""

    index: int
    rule_id: str
    reason: str
    expires: date
    fingerprint: str | None = None
    server_type: str | None = None
    mode: str | None = None
    source: str | None = None
    line: int | None = None
    xml_path: str | None = None
    details: str | None = None
    scope: str | None = None

    def matches(self, result: AnalysisResult, finding: Finding) -> tuple[bool, str | None]:
        components = finding_fingerprint_components(result, finding)
        if components["rule_id"] != self.rule_id:
            return False, None

        if self.fingerprint is not None:
            if finding_fingerprint(result, finding) != self.fingerprint:
                return False, None
            return True, "fingerprint"

        for field in _CRITERIA_FIELDS:
            expected = getattr(self, field)
            if expected is None:
                continue
            if components.get(field) != expected:
                return False, None
        return True, "locator"


@dataclass(frozen=True)
class SuppressionSet:
    """Validated suppressions plus loader issues."""

    entries: tuple[Suppression, ...] = ()
    issues: tuple[AnalysisIssue, ...] = ()
    source_path: str | None = None

    def match(self, result: AnalysisResult, finding: Finding) -> tuple[Suppression, str] | None:
        for entry in self.entries:
            matched, matched_by = entry.matches(result, finding)
            if matched and matched_by is not None:
                return entry, matched_by
        return None


def load_suppression_file(
    path: str | None = None,
    *,
    load_default: bool = False,
    today: date | None = None,
) -> SuppressionSet:
    """Load a YAML suppression file.

    ``path=None`` keeps interactive analysis unchanged by default. Callers that
    want CI-mode defaults pass ``load_default=True`` to read
    ``.webconf-audit-ignore.yml`` when it exists.
    """
    source_path = _suppression_path(path, load_default=load_default)
    if source_path is None:
        return SuppressionSet()

    issue_location = _issue_location(source_path)
    if not source_path.exists():
        return SuppressionSet(
            issues=(
                _issue(
                    "suppression_file_not_found",
                    "Suppression file not found.",
                    issue_location,
                    level="error",
                ),
            ),
            source_path=str(source_path),
        )

    try:
        data = yaml.safe_load(source_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return SuppressionSet(
            issues=(
                _issue(
                    "suppression_file_invalid",
                    "Suppression file is not valid YAML.",
                    issue_location,
                    details=str(exc),
                    level="error",
                ),
            ),
            source_path=str(source_path),
        )
    except OSError as exc:
        return SuppressionSet(
            issues=(
                _issue(
                    "suppression_file_unreadable",
                    "Suppression file could not be read.",
                    issue_location,
                    details=str(exc),
                    level="error",
                ),
            ),
            source_path=str(source_path),
        )

    return _parse_suppression_data(data, source_path, today=today or date.today())


def apply_suppressions(result: AnalysisResult, suppressions: SuppressionSet) -> AnalysisResult:
    """Remove suppressed findings from ``result`` and store them in metadata."""
    if not suppressions.entries or not result.findings:
        return result

    active_findings: list[Finding] = []
    suppressed_payloads: list[dict[str, object]] = []
    for finding in result.findings:
        match = suppressions.match(result, finding)
        if match is None:
            active_findings.append(finding)
            continue
        entry, matched_by = match
        suppressed_payloads.append(_suppressed_payload(result, finding, entry, matched_by))

    result.findings = active_findings
    if suppressed_payloads:
        existing = result.metadata.get(SUPPRESSED_FINDINGS_METADATA_KEY)
        if not isinstance(existing, list):
            existing = []
        existing.extend(suppressed_payloads)
        result.metadata[SUPPRESSED_FINDINGS_METADATA_KEY] = existing
    return result


def suppressed_findings(result: AnalysisResult) -> list[dict[str, object]]:
    """Return serialized suppressed findings stored on an analysis result."""
    entries = result.metadata.get(SUPPRESSED_FINDINGS_METADATA_KEY)
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


def _suppression_path(path: str | None, *, load_default: bool) -> Path | None:
    if path is not None:
        return Path(path)
    default_path = Path(DEFAULT_SUPPRESSION_FILE)
    if load_default and default_path.exists():
        return default_path
    return None


def _parse_suppression_data(
    data: object,
    source_path: Path,
    *,
    today: date,
) -> SuppressionSet:
    entries_data, top_level_issue = _suppression_entries(data, source_path)
    if top_level_issue is not None:
        return SuppressionSet(issues=(top_level_issue,), source_path=str(source_path))

    entries: list[Suppression] = []
    issues: list[AnalysisIssue] = []
    for index, raw_entry in enumerate(entries_data, start=1):
        entry, issue = _parse_entry(raw_entry, index, source_path, today=today)
        if issue is not None:
            issues.append(issue)
        if entry is not None:
            entries.append(entry)
    return SuppressionSet(
        entries=tuple(entries),
        issues=tuple(issues),
        source_path=str(source_path),
    )


def _suppression_entries(
    data: object,
    source_path: Path,
) -> tuple[list[object], AnalysisIssue | None]:
    if data is None:
        return [], None
    if isinstance(data, list):
        return data, None
    if isinstance(data, dict):
        raw_entries = data.get("suppressions")
        if raw_entries is None:
            return [], None
        if isinstance(raw_entries, list):
            return raw_entries, None
    return [], _issue(
        "suppression_file_invalid",
        "Suppression file must contain a top-level 'suppressions' list.",
        _issue_location(source_path),
        level="error",
    )


def _parse_entry(
    raw_entry: object,
    index: int,
    source_path: Path,
    *,
    today: date,
) -> tuple[Suppression | None, AnalysisIssue | None]:
    location = _issue_location(source_path)
    if not isinstance(raw_entry, dict):
        return None, _entry_issue(index, "Suppression entry must be a mapping.", location)

    rule_id = _required_string(raw_entry, "rule_id")
    reason = _required_string(raw_entry, "reason")
    expires, expiry_error = _expires_date(raw_entry)
    fingerprint = _optional_fingerprint(raw_entry)
    criteria = _normalized_criteria(raw_entry)

    errors: list[str] = []
    if rule_id is None:
        errors.append("'rule_id' is required")
    if reason is None:
        errors.append("'reason' is required")
    if expiry_error is not None:
        errors.append(expiry_error)
    if _has_invalid_fingerprint(raw_entry, fingerprint):
        errors.append("'fingerprint' must be a 64-character SHA-256 hex string")
    if fingerprint is None and not _has_locator(criteria):
        errors.append("either 'fingerprint' or locator fields are required")

    line = criteria.get("line")
    if line is not None:
        if not isinstance(line, int) or isinstance(line, bool):
            errors.append("'line' must be an integer")
        elif line < 1:
            errors.append("'line' must be greater than zero")

    if errors:
        return None, _entry_issue(index, "; ".join(errors), location)

    assert rule_id is not None
    assert reason is not None
    assert expires is not None

    if expires < today:
        return None, _entry_issue(
            index,
            f"Suppression expired on {expires.isoformat()}.",
            location,
            code="suppression_expired",
            level="warning",
        )

    return (
        Suppression(
            index=index,
            rule_id=rule_id,
            reason=reason,
            expires=expires,
            fingerprint=fingerprint,
            server_type=_optional_string(criteria, "server_type"),
            mode=_optional_string(criteria, "mode"),
            source=_optional_string(criteria, "source"),
            line=line,
            xml_path=_optional_string(criteria, "xml_path"),
            details=_optional_string(criteria, "details"),
            scope=_optional_string(criteria, "scope"),
        ),
        None,
    )


def _normalized_criteria(raw_entry: dict[object, object]) -> dict[str, object]:
    criteria: dict[str, object] = {}
    for field in _CRITERIA_FIELDS:
        if _has_raw_value(raw_entry, field):
            value = raw_entry[field]
            if field == "line":
                criteria[field] = value
                continue
            normalized = _optional_string_value(value)
            if normalized is not None:
                criteria[field] = normalized
    return criteria


def _has_locator(criteria: dict[str, object]) -> bool:
    return any(criteria.get(field) is not None for field in _CRITERIA_FIELDS)


def _required_string(raw_entry: dict[object, object], field: str) -> str | None:
    value = raw_entry.get(field)
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.strip().split())
    return cleaned or None


def _optional_string(raw_entry: dict[str, object], field: str) -> str | None:
    return _optional_string_value(raw_entry.get(field))


def _optional_string_value(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        return str(value)
    cleaned = " ".join(value.strip().split())
    return cleaned or None


def _optional_fingerprint(raw_entry: dict[object, object]) -> str | None:
    value = raw_entry.get("fingerprint")
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(char not in _HEX_DIGITS for char in normalized):
        return None
    return normalized


def _has_invalid_fingerprint(raw_entry: dict[object, object], fingerprint: str | None) -> bool:
    if "fingerprint" not in raw_entry or raw_entry["fingerprint"] is None:
        return False
    return fingerprint is None


def _expires_date(raw_entry: dict[object, object]) -> tuple[date | None, str | None]:
    raw_value = raw_entry.get("expires", raw_entry.get("expiry"))
    if raw_value is None:
        return None, "'expires' is required"
    if isinstance(raw_value, datetime):
        return raw_value.date(), None
    if isinstance(raw_value, date):
        return raw_value, None
    if isinstance(raw_value, str):
        try:
            return date.fromisoformat(raw_value.strip()), None
        except ValueError:
            return None, "'expires' must use YYYY-MM-DD format"
    return None, "'expires' must use YYYY-MM-DD format"


def _has_raw_value(raw_entry: dict[object, object], field: str) -> bool:
    return field in raw_entry and raw_entry[field] is not None


def _suppressed_payload(
    result: AnalysisResult,
    finding: Finding,
    suppression: Suppression,
    matched_by: str,
) -> dict[str, object]:
    payload = finding.model_dump()
    fingerprint = finding_fingerprint(result, finding)
    payload["fingerprint"] = fingerprint
    return {
        "fingerprint": fingerprint,
        "rule_id": finding.rule_id,
        "reason": suppression.reason,
        "expires": suppression.expires.isoformat(),
        "matched_by": matched_by,
        "suppression_index": suppression.index,
        "finding": payload,
    }


def _issue(
    code: str,
    message: str,
    location: SourceLocation,
    *,
    details: str | None = None,
    level: str = "error",
) -> AnalysisIssue:
    return AnalysisIssue(
        code=code,
        level=level,  # type: ignore[arg-type]
        message=message,
        details=details,
        location=location,
    )


def _entry_issue(
    index: int,
    message: str,
    location: SourceLocation,
    *,
    code: str = "suppression_file_invalid",
    level: str = "error",
) -> AnalysisIssue:
    return _issue(code, f"Suppression entry #{index}: {message}", location, level=level)


def _issue_location(path: Path) -> SourceLocation:
    return SourceLocation(mode="local", kind="file", file_path=str(path))


__all__ = [
    "DEFAULT_SUPPRESSION_FILE",
    "SUPPRESSED_FINDINGS_METADATA_KEY",
    "Suppression",
    "SuppressionSet",
    "apply_suppressions",
    "load_suppression_file",
    "suppressed_findings",
]
