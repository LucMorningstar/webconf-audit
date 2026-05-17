"""Baseline file support for diff-oriented CI reports."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from webconf_audit.models import AnalysisIssue, AnalysisResult, SourceLocation
from webconf_audit.report import (
    BaselineDiff,
    ReportData,
    deduplicated_finding_pairs,
    finding_payload,
    format_location,
)
from webconf_audit.suppressions import suppressed_findings

BASELINE_VERSION = 1
_HEX_DIGITS = frozenset("0123456789abcdef")


@dataclass(frozen=True)
class Baseline:
    """Loaded baseline entries keyed by stable finding fingerprints."""

    entries: tuple[dict[str, object], ...]
    source_path: str


@dataclass(frozen=True)
class BaselineLoadResult:
    """Baseline loader result plus user-facing issues."""

    baseline: Baseline | None = None
    issues: tuple[AnalysisIssue, ...] = ()

    @property
    def failed(self) -> bool:
        return any(issue.level == "error" for issue in self.issues)


def baseline_from_report(report: ReportData) -> dict[str, object]:
    """Create a compact baseline payload from a report."""
    return {
        "version": BASELINE_VERSION,
        "generated_at": report.generated_at,
        "findings": _current_finding_entries(report),
        "suppressed_findings": _current_suppressed_entries(report),
    }


def write_baseline_file(report: ReportData, path: str) -> AnalysisIssue | None:
    """Write a baseline file and return an issue when the write fails."""
    baseline_path = Path(path)
    try:
        if baseline_path.parent != Path("."):
            baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(
            json.dumps(baseline_from_report(report), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        return _issue(
            "baseline_file_unwritable",
            "Baseline file could not be written.",
            baseline_path,
            details=str(exc),
        )
    return None


def load_baseline_file(path: str) -> BaselineLoadResult:
    """Load a baseline file or a JSON report with top-level findings."""
    baseline_path = Path(path)
    if not baseline_path.exists():
        return BaselineLoadResult(
            issues=(
                _issue(
                    "baseline_file_not_found",
                    "Baseline file not found.",
                    baseline_path,
                ),
            )
        )

    try:
        data = json.loads(baseline_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return BaselineLoadResult(
            issues=(
                _issue(
                    "baseline_file_invalid",
                    "Baseline file is not valid JSON.",
                    baseline_path,
                    details=str(exc),
                ),
            )
        )
    except OSError as exc:
        return BaselineLoadResult(
            issues=(
                _issue(
                    "baseline_file_unreadable",
                    "Baseline file could not be read.",
                    baseline_path,
                    details=str(exc),
                ),
            )
        )

    entries, issues = _baseline_entries(data, baseline_path)
    baseline = None if any(issue.level == "error" for issue in issues) else Baseline(
        entries=tuple(entries),
        source_path=str(baseline_path),
    )
    return BaselineLoadResult(baseline=baseline, issues=tuple(issues))


def apply_baseline_diff(report: ReportData, baseline: Baseline) -> ReportData:
    """Attach baseline diff groups to a report."""
    current_entries = _current_finding_entries(report)
    suppressed_entries = _current_suppressed_entries(report)

    baseline_by_fingerprint = _entries_by_fingerprint(baseline.entries)
    current_by_fingerprint = _entries_by_fingerprint(current_entries)
    suppressed_by_fingerprint = _entries_by_fingerprint(suppressed_entries)

    new_findings = [
        entry
        for entry in current_entries
        if _fingerprint_key(entry) not in baseline_by_fingerprint
    ]
    unchanged_findings = [
        entry
        for entry in current_entries
        if _fingerprint_key(entry) in baseline_by_fingerprint
    ]
    resolved_findings = [
        entry
        for fingerprint, entry in baseline_by_fingerprint.items()
        if fingerprint not in current_by_fingerprint and fingerprint not in suppressed_by_fingerprint
    ]

    diff: BaselineDiff = {
        "baseline_path": baseline.source_path,
        "new_findings": new_findings,
        "unchanged_findings": unchanged_findings,
        "resolved_findings": resolved_findings,
        "suppressed_findings": suppressed_entries,
    }
    report.baseline_diff = diff
    return report


def _current_finding_entries(report: ReportData) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for result, finding in deduplicated_finding_pairs(report.results):
        payload = finding_payload(result, finding)
        entries.append(_display_entry(result, payload))
    return entries


def _current_suppressed_entries(report: ReportData) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for result in report.results:
        for raw_entry in suppressed_findings(result):
            fingerprint = _string_value(raw_entry.get("fingerprint"))
            if fingerprint is None:
                continue
            finding = raw_entry.get("finding")
            if isinstance(finding, dict):
                entry = _display_entry(result, finding)
            else:
                entry = {
                    "fingerprint": fingerprint,
                    "rule_id": _string_value(raw_entry.get("rule_id")) or "",
                    "target": result.target,
                    "server_type": result.server_type,
                    "mode": result.mode,
                }
            entry["fingerprint"] = fingerprint
            for field in ("reason", "expires", "matched_by", "suppression_index"):
                value = raw_entry.get(field)
                if value is not None:
                    entry[field] = value
            entries.append(entry)
    return entries


def _display_entry(
    result: AnalysisResult,
    payload: dict[str, Any],
) -> dict[str, object]:
    entry: dict[str, object] = {
        "fingerprint": _string_value(payload.get("fingerprint")) or "",
        "rule_id": _string_value(payload.get("rule_id")) or "",
        "severity": _string_value(payload.get("severity")) or "",
        "title": _string_value(payload.get("title")) or "",
        "target": result.target,
        "server_type": result.server_type,
        "mode": result.mode,
    }
    location_display = _location_display(payload.get("location"))
    if location_display is not None:
        entry["location_display"] = location_display
    return entry


def _baseline_entries(
    data: object,
    source_path: Path,
) -> tuple[list[dict[str, object]], tuple[AnalysisIssue, ...]]:
    if not isinstance(data, dict):
        return [], (
            _issue(
                "baseline_file_invalid",
                "Baseline file must be a JSON object.",
                source_path,
            ),
        )

    raw_version = data.get("version")
    if raw_version is not None and raw_version != BASELINE_VERSION:
        return [], (
            _issue(
                "baseline_file_invalid",
                f"Unsupported baseline version: {raw_version}. Expected: {BASELINE_VERSION}.",
                source_path,
            ),
        )

    raw_findings = data.get("findings")
    if not isinstance(raw_findings, list):
        return [], (
            _issue(
                "baseline_file_invalid",
                "Baseline file must contain a top-level 'findings' list.",
                source_path,
            ),
        )

    entries: list[dict[str, object]] = []
    issues: list[AnalysisIssue] = []
    for index, raw_entry in enumerate(raw_findings, start=1):
        entry, issue = _baseline_entry(raw_entry, index, source_path)
        if issue is not None:
            issues.append(issue)
        if entry is not None:
            entries.append(entry)
    return entries, tuple(issues)


def _baseline_entry(
    raw_entry: object,
    index: int,
    source_path: Path,
) -> tuple[dict[str, object] | None, AnalysisIssue | None]:
    if not isinstance(raw_entry, dict):
        return None, _entry_issue(index, "Finding entry must be a mapping.", source_path)

    fingerprint = _string_value(raw_entry.get("fingerprint"))
    if fingerprint is None or not _valid_fingerprint(fingerprint):
        return None, _entry_issue(
            index,
            "'fingerprint' must be a 64-character SHA-256 hex string.",
            source_path,
        )

    entry = _copy_display_fields(raw_entry)
    entry["fingerprint"] = fingerprint.lower()
    return entry, None


def _copy_display_fields(raw_entry: dict[object, object]) -> dict[str, object]:
    entry: dict[str, object] = {}
    for field in (
        "rule_id",
        "severity",
        "title",
        "target",
        "server_type",
        "mode",
        "location_display",
    ):
        value = raw_entry.get(field)
        if isinstance(value, str):
            entry[field] = value
        elif value is not None:
            entry[field] = str(value)
    return entry


def _entries_by_fingerprint(
    entries: tuple[dict[str, object], ...] | list[dict[str, object]],
) -> dict[str, dict[str, object]]:
    by_fingerprint: dict[str, dict[str, object]] = {}
    for entry in entries:
        fingerprint = _fingerprint_key(entry)
        if fingerprint is not None:
            by_fingerprint[fingerprint] = entry
    return by_fingerprint


def _fingerprint_key(entry: dict[str, object]) -> str | None:
    fingerprint = _string_value(entry.get("fingerprint"))
    if fingerprint is None:
        return None
    return fingerprint.lower()


def _location_display(value: object) -> str | None:
    if isinstance(value, SourceLocation):
        return format_location(value)
    if isinstance(value, dict):
        try:
            return format_location(SourceLocation.model_validate(value))
        except ValueError:
            return None
    return None


def _string_value(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned or None


def _valid_fingerprint(value: str) -> bool:
    normalized = value.lower()
    return len(normalized) == 64 and all(char in _HEX_DIGITS for char in normalized)


def _issue(
    code: str,
    message: str,
    path: Path,
    *,
    details: str | None = None,
) -> AnalysisIssue:
    return AnalysisIssue(
        code=code,
        level="error",
        message=message,
        details=details,
        location=SourceLocation(mode="local", kind="file", file_path=str(path)),
    )


def _entry_issue(index: int, message: str, path: Path) -> AnalysisIssue:
    return _issue(
        "baseline_file_invalid",
        f"Baseline finding entry #{index}: {message}",
        path,
    )


__all__ = [
    "BASELINE_VERSION",
    "Baseline",
    "BaselineLoadResult",
    "apply_baseline_diff",
    "baseline_from_report",
    "load_baseline_file",
    "write_baseline_file",
]
