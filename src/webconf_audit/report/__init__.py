"""Unified report module for webconf-audit.

Aggregates AnalysisResult(s) into a structured report with summary
statistics, severity-sorted findings, and multiple output formats.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pydantic import BaseModel, Field
from typing import Literal
from typing_extensions import TypedDict

from webconf_audit.fingerprints import finding_fingerprint
from webconf_audit.models import (
    AnalysisIssue,
    AnalysisResult,
    Finding,
    SourceLocation,
    Severity,
)
from webconf_audit.rule_registry import StandardReference, registry
from webconf_audit.suppressions import suppressed_findings as suppressed_finding_entries

# Severity ordering: most critical first.
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

_ISSUE_LEVEL_ORDER: dict[str, int] = {
    "error": 0,
    "warning": 1,
    "info": 2,
}

_ALL_SEVERITIES: list[Severity] = ["critical", "high", "medium", "low", "info"]
_STANDARD_ORDER = [
    "CWE",
    "OWASP Top 10",
    "OWASP ASVS",
    "CIS",
    "Vendor",
    "OWASP Cheat Sheet Series",
    "NIST SP 800-44 Rev. 2",
    "NIST SP 800-52 Rev. 2",
    "NIST SP 800-53 Rev. 5",
    "NIST SP 800-63B",
    "PCI DSS v4.0.1",
    "ISO/IEC 27002:2022",
    'ФСТЭК "Меры защиты информации в ГИС"',
    "Unmapped",
]
_SECONDARY_STANDARD_ORDER = [
    "MITRE ATT&CK Enterprise v15",
    "ФСТЭК БДУ",
]

ReportGroupBy = Literal["severity", "standard"]


class BaselineDiff(TypedDict, total=False):
    """Diff groups produced by comparing a report with a baseline."""

    baseline_path: str
    new_findings: list[dict[str, object]]
    unchanged_findings: list[dict[str, object]]
    resolved_findings: list[dict[str, object]]
    suppressed_findings: list[dict[str, object]]

# ---------------------------------------------------------------------------
# Deduplication: universal vs server-specific rule mapping
# ---------------------------------------------------------------------------

# When a server-specific rule fires for the same issue that a universal rule
# also covers, the universal finding is suppressed in the report to avoid
# duplicates.  The server-specific finding is always more precise.

UNIVERSAL_TO_SPECIFIC_MAP: dict[str, list[str]] = {
    "universal.directory_listing_enabled": [
        "nginx.autoindex_on",
        "apache.options_indexes",
        "lighttpd.dir_listing_enabled",
        "iis.directory_browse_enabled",
    ],
    "universal.server_identification_disclosed": [
        "nginx.server_tokens_on",
        "apache.server_tokens_not_prod",
        "apache.server_signature_not_off",
        "lighttpd.server_tag_not_blank",
        "iis.http_runtime_version_header_enabled",
    ],
    "universal.missing_hsts": [
        "nginx.missing_hsts_header",
        "lighttpd.missing_strict_transport_security",
        "iis.missing_hsts_header",
    ],
    "universal.missing_x_content_type_options": [
        "nginx.missing_x_content_type_options",
        "lighttpd.missing_x_content_type_options",
    ],
    "universal.missing_x_frame_options": [
        "nginx.missing_x_frame_options",
    ],
    "universal.missing_content_security_policy": [
        "nginx.missing_content_security_policy",
    ],
    "universal.missing_referrer_policy": [
        "nginx.missing_referrer_policy",
    ],
}


def deduplicate_findings(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Remove universal findings when a server-specific equivalent exists.

    Returns a tuple of (deduplicated findings, number of suppressed findings).
    The original list is not modified.
    """
    present_specific_locations = _collect_finding_locations(findings)
    suppress = _suppressed_universal_findings(
        findings, present_specific_locations,
    )

    if not suppress:
        return list(findings), 0

    deduplicated = [
        f
        for f in findings
        if (f.rule_id, _dedup_location_key(f)) not in suppress
    ]
    return deduplicated, len(findings) - len(deduplicated)


def _collect_finding_locations(
    findings: list[Finding],
) -> dict[str, set[tuple[object, ...]]]:
    present_locations: dict[str, set[tuple[object, ...]]] = {}
    for finding in findings:
        present_locations.setdefault(finding.rule_id, set()).add(
            _dedup_location_key(finding)
        )
    return present_locations


def _suppressed_universal_findings(
    findings: list[Finding],
    present_specific_locations: dict[str, set[tuple[object, ...]]],
) -> set[tuple[str, tuple[object, ...]]]:
    suppress: set[tuple[str, tuple[object, ...]]] = set()
    for universal_id, specific_ids in UNIVERSAL_TO_SPECIFIC_MAP.items():
        suppress.update(
            _suppressed_keys_for_universal_rule(
                findings,
                universal_id,
                specific_ids,
                present_specific_locations,
            )
        )
    return suppress


def _suppressed_keys_for_universal_rule(
    findings: list[Finding],
    universal_id: str,
    specific_ids: list[str],
    present_specific_locations: dict[str, set[tuple[object, ...]]],
) -> set[tuple[str, tuple[object, ...]]]:
    suppress: set[tuple[str, tuple[object, ...]]] = set()
    for finding in findings:
        if finding.rule_id != universal_id:
            continue
        universal_key = _dedup_location_key(finding)
        if _has_specific_location_match(
            universal_key, specific_ids, present_specific_locations,
        ):
            suppress.add((universal_id, universal_key))
    return suppress


def _has_specific_location_match(
    universal_key: tuple[object, ...],
    specific_ids: list[str],
    present_specific_locations: dict[str, set[tuple[object, ...]]],
) -> bool:
    return any(
        universal_key in present_specific_locations.get(specific_id, set())
        for specific_id in specific_ids
    )


def _dedup_location_key(finding: Finding) -> tuple[object, ...]:
    location = finding.location
    if location is None:
        return ("no-location",)
    return (
        location.mode,
        location.kind,
        location.file_path,
        location.line,
        location.xml_path,
        location.target,
        location.details
        if location.line is None and location.xml_path is None and location.target is None
        else None,
    )


def _deduplicated_findings_by_result(
    results: list[AnalysisResult],
) -> tuple[list[tuple[AnalysisResult, list[Finding]]], int]:
    """Deduplicate findings independently inside each analysis result."""
    deduplicated_results: list[tuple[AnalysisResult, list[Finding]]] = []
    suppressed_total = 0

    for result in results:
        deduplicated, suppressed = deduplicate_findings(result.findings)
        deduplicated.sort(key=_finding_sort_key)
        deduplicated_results.append((result, deduplicated))
        suppressed_total += suppressed

    return deduplicated_results, suppressed_total


def _finding_sort_key(f: Finding) -> tuple[int, str]:
    return (_SEVERITY_ORDER.get(f.severity, 99), f.rule_id)


def _issue_sort_key(i: AnalysisIssue) -> tuple[int, str]:
    return (_ISSUE_LEVEL_ORDER.get(i.level, 99), i.code)


class ReportSummary(BaseModel):
    """Aggregated statistics across all results."""

    total_findings: int = 0
    total_issues: int = 0
    suppressed_findings: int = 0
    suppressed_duplicates: int = 0
    by_severity: dict[str, int] = Field(default_factory=lambda: {s: 0 for s in _ALL_SEVERITIES})
    by_mode: dict[str, int] = Field(default_factory=dict)
    by_server_type: dict[str, int] = Field(default_factory=dict)
    targets_analyzed: list[str] = Field(default_factory=list)


class ReportData(BaseModel):
    """Unified report payload from one or more analysis runs."""

    results: list[AnalysisResult] = Field(default_factory=list)
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    baseline_diff: BaselineDiff | None = None

    @property
    def all_findings_raw(self) -> list[Finding]:
        """All findings across results (before deduplication), sorted."""
        findings: list[Finding] = []
        for r in self.results:
            findings.extend(r.findings)
        findings.sort(key=_finding_sort_key)
        return findings

    @property
    def all_findings(self) -> list[Finding]:
        """All findings across results, deduplicated and sorted."""
        deduplicated_results, _ = _deduplicated_findings_by_result(self.results)
        findings: list[Finding] = []
        for _result, deduplicated in deduplicated_results:
            findings.extend(deduplicated)
        findings.sort(key=_finding_sort_key)
        return findings

    @property
    def all_issues(self) -> list[AnalysisIssue]:
        """All issues across results, sorted by level then code."""
        issues: list[AnalysisIssue] = []
        for r in self.results:
            issues.extend(r.issues)
        issues.sort(key=_issue_sort_key)
        return issues

    def summary(self) -> ReportSummary:
        """Compute aggregated statistics (uses deduplicated findings)."""
        deduplicated_results, suppressed = _deduplicated_findings_by_result(self.results)

        by_severity: dict[str, int] = {s: 0 for s in _ALL_SEVERITIES}
        by_mode: dict[str, int] = {}
        by_server_type: dict[str, int] = {}
        targets: list[str] = []

        for result, deduplicated in deduplicated_results:
            targets.append(result.target)
            dedup_count = len(deduplicated)
            by_mode[result.mode] = by_mode.get(result.mode, 0) + dedup_count
            if result.server_type:
                by_server_type[result.server_type] = (
                    by_server_type.get(result.server_type, 0) + dedup_count
                )
            for finding in deduplicated:
                by_severity[finding.severity] = (
                    by_severity.get(finding.severity, 0) + 1
                )

        total_issues = sum(len(result.issues) for result in self.results)
        suppressed_total = sum(
            len(suppressed_finding_entries(result))
            for result in self.results
        )

        return ReportSummary(
            total_findings=sum(
                len(deduplicated)
                for _, deduplicated in deduplicated_results
            ),
            total_issues=total_issues,
            suppressed_findings=suppressed_total,
            suppressed_duplicates=suppressed,
            by_severity=by_severity,
            by_mode=by_mode,
            by_server_type=by_server_type,
            targets_analyzed=targets,
        )


# ---------------------------------------------------------------------------
# Location formatting (shared by formatters)
# ---------------------------------------------------------------------------

def format_location(location: SourceLocation | None) -> str | None:
    """Format a SourceLocation into a human-readable string."""
    if location is None:
        return None
    if location.file_path:
        if location.line is not None:
            return f"{location.file_path}:{location.line}"
        return location.file_path
    if location.target:
        return location.target
    if location.xml_path:
        return location.xml_path
    if location.details:
        return location.details
    return location.kind


# ---------------------------------------------------------------------------
# TextFormatter
# ---------------------------------------------------------------------------

class TextFormatter:
    """Render ReportData as human-readable terminal output."""

    def __init__(
        self,
        *,
        group_by: ReportGroupBy = "severity",
        group_repeated: bool = False,
        group_by_cause: bool = False,
    ) -> None:
        self.group_by = group_by
        self.group_repeated = group_repeated
        self.group_by_cause = group_by_cause

    def format(self, report: ReportData) -> str:
        summary = report.summary()
        deduplicated_results, _ = _deduplicated_findings_by_result(report.results)
        lines = _report_header_lines(report, summary)
        multi = len(report.results) > 1
        lines.extend(_baseline_diff_section_lines(report.baseline_diff))

        for result, result_findings in deduplicated_results:
            lines.extend(
                _result_section_lines(
                    result,
                    result_findings,
                    multi=multi,
                    group_by=self.group_by,
                    group_repeated=self.group_repeated,
                    group_by_cause=self.group_by_cause,
                )
            )

        total_line = (
            f"Total: {summary.total_findings} findings,"
            f" {summary.total_issues} issues"
        )
        if summary.suppressed_findings:
            total_line += f", {summary.suppressed_findings} suppressed"
        lines.append(total_line)
        return "\n".join(lines)


def _report_header_lines(
    report: ReportData,
    summary: ReportSummary,
) -> list[str]:
    lines = ["=" * 50, "  webconf-audit report"]
    lines.extend(_report_target_lines(report.results))
    lines.extend(_report_summary_lines(report.generated_at, summary))
    return lines


def _report_target_lines(results: list[AnalysisResult]) -> list[str]:
    lines: list[str] = []
    for result in results:
        parts = [f"Target: {result.target}", f"Mode: {result.mode}"]
        if result.server_type:
            parts.append(f"Server: {result.server_type}")
        lines.append(f"  {' | '.join(parts)}")
    return lines


def _report_summary_lines(
    generated_at: str,
    summary: ReportSummary,
) -> list[str]:
    sev = summary.by_severity
    lines = [
        f"  Generated: {generated_at}",
        "-" * 50,
        f"  Findings: {summary.total_findings}",
        (
            f"    Critical: {sev['critical']}  High: {sev['high']}"
            f"  Medium: {sev['medium']}  Low: {sev['low']}"
            f"  Info: {sev['info']}"
        ),
        f"  Analysis issues: {summary.total_issues}",
    ]
    if summary.suppressed_findings > 0:
        lines.append(f"  Suppressed findings: {summary.suppressed_findings}")
    if summary.suppressed_duplicates > 0:
        lines.append(
            f"  ({summary.suppressed_duplicates} universal finding(s)"
            " suppressed as duplicates of server-specific rules)"
        )
    lines.extend(["=" * 50, ""])
    return lines


def _baseline_diff_section_lines(baseline_diff: BaselineDiff | None) -> list[str]:
    if baseline_diff is None:
        return []

    lines = [
        "Baseline diff:",
        (
            "  "
            f"new {len(_diff_entries(baseline_diff, 'new_findings'))}, "
            f"unchanged {len(_diff_entries(baseline_diff, 'unchanged_findings'))}, "
            f"resolved {len(_diff_entries(baseline_diff, 'resolved_findings'))}, "
            f"suppressed {len(_diff_entries(baseline_diff, 'suppressed_findings'))}"
        ),
    ]
    lines.extend(_diff_entry_lines("New findings", _diff_entries(baseline_diff, "new_findings")))
    lines.extend(
        _diff_entry_lines("Resolved findings", _diff_entries(baseline_diff, "resolved_findings"))
    )
    lines.append("")
    return lines


def _diff_entries(baseline_diff: BaselineDiff, key: str) -> list[dict[str, object]]:
    entries = baseline_diff.get(key)
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, dict)]


def _diff_entry_lines(title: str, entries: list[dict[str, object]]) -> list[str]:
    if not entries:
        return []
    lines = [f"  {title}:"]
    for entry in entries:
        rule_id = _summary_string(entry.get("rule_id"), default="unknown")
        severity = _summary_string(entry.get("severity"), default="unknown")
        entry_title = _summary_string(entry.get("title"), default="Untitled finding")
        location = _summary_string(entry.get("location_display"))
        if location is None and isinstance(entry.get("location"), str):
            location = _summary_string(entry.get("location"))
        target = _summary_string(entry.get("target"))
        suffix = location or target
        line = f"    - [{rule_id}] {entry_title} ({severity})"
        if suffix:
            line += f" at {suffix}"
        lines.append(line)
    return lines


def _result_section_lines(
    result: AnalysisResult,
    result_findings: list[Finding],
    *,
    multi: bool,
    group_by: ReportGroupBy = "severity",
    group_repeated: bool = False,
    group_by_cause: bool = False,
) -> list[str]:
    lines: list[str] = []
    if multi:
        lines.extend(_multi_target_header_lines(result))
    lines.extend(_external_section_lines(result))
    if group_by_cause:
        lines.extend(_cause_section_lines(result_findings))
    elif group_by == "standard":
        lines.extend(
            _standard_section_lines(result_findings, group_repeated=group_repeated)
        )
    else:
        lines.extend(
            _severity_section_lines(result_findings, group_repeated=group_repeated)
        )
    lines.extend(_issue_section_lines(result.issues))
    lines.extend(_diagnostic_section_lines(result.diagnostics))
    return lines


def _multi_target_header_lines(result: AnalysisResult) -> list[str]:
    server_label = f" ({result.server_type})" if result.server_type else ""
    return [f"-- {result.target}{server_label} --", ""]


def _external_section_lines(result: AnalysisResult) -> list[str]:
    ext_lines = _external_summary_lines(result)
    if not ext_lines:
        return []
    return ["External Summary:", *[f"- {line}" for line in ext_lines], ""]


def _severity_section_lines(
    result_findings: list[Finding],
    *,
    group_repeated: bool = False,
) -> list[str]:
    lines: list[str] = []
    by_severity = _findings_by_severity(result_findings)
    for severity in _ALL_SEVERITIES:
        group = by_severity[severity]
        lines.append(f"=== {severity.upper()} ({len(group)}) ===")
        if group_repeated:
            lines.extend(_grouped_finding_lines(group))
        else:
            for finding in group:
                lines.extend(_finding_lines(finding))
        lines.append("")
    return lines


def _findings_by_severity(
    result_findings: list[Finding],
) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {severity: [] for severity in _ALL_SEVERITIES}
    for finding in result_findings:
        grouped[finding.severity].append(finding)
    return grouped


def _cause_section_lines(result_findings: list[Finding]) -> list[str]:
    lines: list[str] = []
    cause_groups = _findings_by_cause(result_findings)
    causal_group_count = len(cause_groups)
    uncausal_findings = [
        finding
        for finding in result_findings
        if finding.effective_cause_key is None
    ]

    lines.append(f"=== CAUSE GROUPS ({causal_group_count}) ===")
    if not cause_groups:
        lines.append("  none")
    for cause_key, findings in cause_groups:
        lines.append(f"  cause: {_cause_key_display(cause_key)}")
        scopes = _cause_group_scopes(findings)
        if scopes:
            lines.append(
                f"    affected scopes ({len(scopes)}): {', '.join(scopes)}"
            )
        lines.append(f"    findings ({len(findings)}):")
        for finding in findings:
            lines.extend(_indent_lines(_finding_lines(finding), "      "))
    lines.append("")

    lines.append(f"=== UNCAUSAL FINDINGS ({len(uncausal_findings)}) ===")
    if not uncausal_findings:
        lines.append("  none")
    else:
        for finding in uncausal_findings:
            lines.extend(_finding_lines(finding))
    lines.append("")
    return lines


def _finding_lines(finding: Finding) -> list[str]:
    lines = [f"  [{finding.rule_id}] {finding.title}"]
    location = format_location(finding.location)
    if location:
        lines.append(f"    location: {location}")
    note = _finding_note(finding)
    if note:
        lines.append(f"    note: {note}")
    lines.append(f"    description: {finding.description}")
    lines.append(f"    recommendation: {finding.recommendation}")
    return lines


def _grouped_finding_lines(findings: list[Finding]) -> list[str]:
    lines: list[str] = []
    for group in _finding_groups(findings):
        if len(group) == 1:
            lines.extend(_finding_lines(group[0]))
        else:
            lines.extend(_repeated_finding_group_lines(group))
    return lines


def _repeated_finding_group_lines(findings: list[Finding]) -> list[str]:
    first = findings[0]
    lines = [
        f"  [{first.rule_id}] {first.title}",
        f"    findings: {len(findings)} repeated",
    ]
    cause = _finding_group_cause(first)
    if cause:
        lines.append(f"    note: {cause}")
    locations = [_finding_location_display(finding) for finding in findings]
    lines.append(f"    locations ({len(locations)}):")
    lines.extend(f"      - {location}" for location in locations)
    lines.append(f"    description: {first.description}")
    lines.append(f"    recommendation: {first.recommendation}")
    return lines


def _finding_location_display(finding: Finding) -> str:
    return format_location(finding.location) or "no location"


def _findings_by_cause(
    findings: list[Finding],
) -> list[tuple[tuple[str, ...], list[Finding]]]:
    grouped: dict[tuple[str, ...], list[Finding]] = {}
    for finding in findings:
        cause_key = finding.effective_cause_key
        if cause_key is None:
            continue
        grouped.setdefault(cause_key, []).append(finding)
    return list(grouped.items())


def _cause_key_display(cause_key: tuple[str, ...]) -> str:
    if len(cause_key) == 2 and cause_key[1].isdigit():
        return f"{cause_key[0]}:{cause_key[1]}"
    return " | ".join(cause_key)


def _cause_group_scopes(findings: list[Finding]) -> list[str]:
    scopes: list[str] = []
    seen: set[str] = set()
    for finding in findings:
        for scope in _finding_affected_scopes(finding):
            if scope in seen:
                continue
            seen.add(scope)
            scopes.append(scope)
    return scopes


def _finding_affected_scopes(finding: Finding) -> list[str]:
    raw_affected_scopes = finding.metadata.get("affected_scopes")
    if isinstance(raw_affected_scopes, list):
        scopes = [
            scope
            for scope in raw_affected_scopes
            if isinstance(scope, str) and scope
        ]
        if scopes:
            return scopes
    scope_name = finding.metadata.get("scope_name")
    if isinstance(scope_name, str) and scope_name:
        return [scope_name]
    return []


def _indent_lines(lines: list[str], prefix: str) -> list[str]:
    return [f"{prefix}{line}" for line in lines]


def _finding_groups(findings: list[Finding]) -> list[list[Finding]]:
    grouped: dict[tuple[str, str, str, str, str, str], list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(_finding_group_key(finding), []).append(finding)
    return list(grouped.values())


def _finding_group_key(finding: Finding) -> tuple[str, str, str, str, str, str]:
    cause = _finding_group_cause(finding) or ""
    return (
        finding.rule_id,
        finding.severity,
        finding.title,
        finding.description,
        finding.recommendation,
        cause,
    )


def _finding_group_key_label(key: tuple[str, str, str, str, str, str]) -> str:
    return json.dumps(key, separators=(",", ":"), ensure_ascii=False)


def _finding_group_cause(finding: Finding) -> str | None:
    for key in ("report_group", "noise_group", "effective_cause", "note"):
        value = finding.metadata.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _finding_note(finding: Finding) -> str | None:
    note = finding.metadata.get("note")
    if isinstance(note, str) and note:
        return note
    return None


def _standard_section_lines(
    result_findings: list[Finding],
    *,
    group_repeated: bool = False,
) -> list[str]:
    lines: list[str] = []
    primary_groups = _findings_by_standard(result_findings, secondary=False)
    for standard in _ordered_standard_names(primary_groups):
        entries = primary_groups[standard]
        lines.append(f"=== STANDARD {standard.upper()} ({len(entries)}) ===")
        if group_repeated:
            lines.extend(_grouped_standard_finding_lines(entries))
        else:
            for finding, refs in entries:
                lines.extend(_standard_finding_lines(finding, refs))
        lines.append("")
    secondary_groups = _findings_by_standard(result_findings, secondary=True)
    if secondary_groups:
        total = sum(len(entries) for entries in secondary_groups.values())
        lines.append(f"=== SECONDARY TAGS ({total}) ===")
        for standard in _ordered_standard_names(secondary_groups, secondary=True):
            entries = secondary_groups[standard]
            lines.append(f"--- {standard} ({len(entries)}) ---")
            if group_repeated:
                lines.extend(_grouped_standard_finding_lines(entries))
            else:
                for finding, refs in entries:
                    lines.extend(_standard_finding_lines(finding, refs))
        lines.append("")
    return lines


def _findings_by_standard(
    result_findings: list[Finding],
    *,
    secondary: bool,
) -> dict[str, list[tuple[Finding, tuple[StandardReference, ...]]]]:
    groups: dict[str, list[tuple[Finding, tuple[StandardReference, ...]]]] = {}
    for finding in result_findings:
        refs = _standards_for_rule(finding.rule_id, secondary=secondary)
        if not refs:
            if not secondary:
                groups.setdefault("Unmapped", []).append((finding, ()))
            continue
        refs_by_standard: dict[str, list[StandardReference]] = {}
        for ref in refs:
            refs_by_standard.setdefault(ref.standard, []).append(ref)
        for standard, standard_refs in refs_by_standard.items():
            groups.setdefault(standard, []).append((finding, tuple(standard_refs)))
    return groups


def _ordered_standard_names(
    groups: dict[str, list[tuple[Finding, tuple[StandardReference, ...]]]],
    *,
    secondary: bool = False,
) -> list[str]:
    order = _SECONDARY_STANDARD_ORDER if secondary else _STANDARD_ORDER
    known = [name for name in order if name in groups]
    extra = sorted(name for name in groups if name not in order)
    return known + extra


def _grouped_standard_finding_lines(
    entries: list[tuple[Finding, tuple[StandardReference, ...]]],
) -> list[str]:
    lines: list[str] = []
    for group in _standard_finding_groups(entries):
        if len(group) == 1:
            finding, refs = group[0]
            lines.extend(_standard_finding_lines(finding, refs))
        else:
            lines.extend(_standard_repeated_finding_group_lines(group))
    return lines


def _standard_finding_groups(
    entries: list[tuple[Finding, tuple[StandardReference, ...]]],
) -> list[list[tuple[Finding, tuple[StandardReference, ...]]]]:
    grouped: dict[
        tuple[str, str, str, str, str, str],
        list[tuple[Finding, tuple[StandardReference, ...]]],
    ] = {}
    for finding, refs in entries:
        grouped.setdefault(_finding_group_key(finding), []).append((finding, refs))
    return list(grouped.values())


def _standard_repeated_finding_group_lines(
    entries: list[tuple[Finding, tuple[StandardReference, ...]]],
) -> list[str]:
    first, refs = entries[0]
    lines = [
        f"  [{first.rule_id}] {first.title} ({first.severity})",
    ]
    if refs:
        lines.append(f"    refs: {', '.join(_standard_ref_label(ref) for ref in refs)}")
    lines.append(f"    findings: {len(entries)} repeated")
    cause = _finding_group_cause(first)
    if cause:
        lines.append(f"    note: {cause}")
    locations = [_finding_location_display(finding) for finding, _refs in entries]
    lines.append(f"    locations ({len(locations)}):")
    lines.extend(f"      - {location}" for location in locations)
    lines.append(f"    description: {first.description}")
    lines.append(f"    recommendation: {first.recommendation}")
    return lines


def _standard_finding_lines(
    finding: Finding,
    refs: tuple[StandardReference, ...],
) -> list[str]:
    lines = [f"  [{finding.rule_id}] {finding.title} ({finding.severity})"]
    if refs:
        lines.append(f"    refs: {', '.join(_standard_ref_label(ref) for ref in refs)}")
    location = format_location(finding.location)
    if location:
        lines.append(f"    location: {location}")
    note = _finding_note(finding)
    if note:
        lines.append(f"    note: {note}")
    lines.append(f"    description: {finding.description}")
    lines.append(f"    recommendation: {finding.recommendation}")
    return lines


def _issue_section_lines(issues: list[AnalysisIssue]) -> list[str]:
    if not issues:
        return []
    lines = ["Issues:"]
    for issue in sorted(issues, key=_issue_sort_key):
        lines.extend(_issue_lines(issue))
    lines.append("")
    return lines


def _issue_lines(issue: AnalysisIssue) -> list[str]:
    lines = [f"  [{issue.level}] {issue.code}: {issue.message}"]
    location = format_location(issue.location)
    if location:
        lines.append(f"    location: {location}")
    return lines


def _diagnostic_section_lines(diagnostics: list[str]) -> list[str]:
    if not diagnostics:
        return []
    return ["Diagnostics:", *[f"  - {diagnostic}" for diagnostic in diagnostics], ""]


# ---------------------------------------------------------------------------
# JsonFormatter
# ---------------------------------------------------------------------------

class JsonFormatter:
    """Render ReportData as structured JSON."""

    def __init__(self, *, group_by_cause: bool = False) -> None:
        self.group_by_cause = group_by_cause

    def format(self, report: ReportData) -> str:
        summary = report.summary()
        top_level_findings = deduplicated_finding_pairs(report.results)
        baseline_diff = report.baseline_diff or {}
        suppressed_payloads = _suppressed_payloads_for_report(report, baseline_diff)
        payload = {
            "generated_at": report.generated_at,
            "summary": summary.model_dump(),
            "results": [
                _result_payload(result)
                for result in report.results
            ],
            "findings": [
                finding_payload(result, finding)
                for result, finding in top_level_findings
            ],
            "finding_groups": _repeated_finding_group_payloads(top_level_findings),
            "new_findings": _diff_entries(baseline_diff, "new_findings"),
            "resolved_findings": _diff_entries(baseline_diff, "resolved_findings"),
            "unchanged_findings": _diff_entries(baseline_diff, "unchanged_findings"),
            "suppressed_findings": suppressed_payloads,
            "standards": _standards_summary_payload(top_level_findings),
            "issues": [i.model_dump() for i in report.all_issues],
        }
        if self.group_by_cause:
            payload["cause_groups"] = _cause_group_payloads(top_level_findings)
        return json.dumps(payload, indent=2, ensure_ascii=False)


def _suppressed_payloads_for_report(
    report: ReportData,
    baseline_diff: BaselineDiff,
) -> list[dict[str, object]]:
    raw_payloads = _suppressed_finding_payloads(report.results)
    if report.baseline_diff is None:
        return raw_payloads
    diff_payloads = _diff_entries(baseline_diff, "suppressed_findings")
    return diff_payloads or raw_payloads


def deduplicated_finding_pairs(results: list[AnalysisResult]) -> list[tuple[AnalysisResult, Finding]]:
    deduplicated_results, _ = _deduplicated_findings_by_result(results)
    pairs = [
        (result, finding)
        for result, result_findings in deduplicated_results
        for finding in result_findings
    ]
    pairs.sort(
        key=lambda pair: (
            _finding_sort_key(pair[1]),
            finding_fingerprint(pair[0], pair[1]),
        )
    )
    return pairs


def _repeated_finding_group_payloads(
    finding_pairs: list[tuple[AnalysisResult, Finding]],
) -> list[dict[str, object]]:
    grouped: dict[
        tuple[str, str, str, str, str, str],
        list[tuple[AnalysisResult, Finding]],
    ] = {}
    for result, finding in finding_pairs:
        grouped.setdefault(_finding_group_key(finding), []).append((result, finding))

    return [
        _repeated_finding_group_payload(key, entries)
        for key, entries in grouped.items()
        if len(entries) > 1
    ]


def _repeated_finding_group_payload(
    key: tuple[str, str, str, str, str, str],
    entries: list[tuple[AnalysisResult, Finding]],
) -> dict[str, object]:
    _result, first = entries[0]
    cause = key[-1] or None
    return {
        "group_key": _finding_group_key_label(key),
        "rule_id": first.rule_id,
        "title": first.title,
        "severity": first.severity,
        "description": first.description,
        "recommendation": first.recommendation,
        "count": len(entries),
        "cause": cause,
        "locations": [
            _finding_group_location_payload(result, finding)
            for result, finding in entries
        ],
    }


def _finding_group_location_payload(
    result: AnalysisResult,
    finding: Finding,
) -> dict[str, object]:
    return {
        "target": result.target,
        "display": _finding_location_display(finding),
        "location": finding.location.model_dump() if finding.location else None,
        "fingerprint": finding_fingerprint(result, finding),
    }


def _cause_group_payloads(
    finding_pairs: list[tuple[AnalysisResult, Finding]],
) -> list[dict[str, object]]:
    grouped: dict[
        tuple[str, ...],
        list[tuple[AnalysisResult, Finding]],
    ] = {}
    for result, finding in finding_pairs:
        cause_key = finding.effective_cause_key
        if cause_key is None:
            continue
        grouped.setdefault(cause_key, []).append((result, finding))

    return [
        {
            "cause_key": list(cause_key),
            "findings": [
                {
                    "target": result.target,
                    **finding_payload(result, finding),
                }
                for result, finding in entries
            ],
        }
        for cause_key, entries in grouped.items()
    ]


def _result_payload(result: AnalysisResult) -> dict[str, object]:
    """Serialize a single analysis result with its raw, per-result findings.

    ``payload["findings"]`` mirrors ``result.findings`` and is intentionally not
    deduplicated, so it may include universal findings that are suppressed in
    the aggregated top-level ``"findings"`` array (built via
    ``deduplicated_finding_pairs``). Consumers that want a stable, dedup'd
    view of findings should read the top-level array; the per-result list is
    kept verbatim so callers retain the full detector output for each target.
    """
    payload = result.model_dump()
    payload["findings"] = [
        finding_payload(result, finding)
        for finding in result.findings
    ]
    return payload


def _suppressed_finding_payloads(results: list[AnalysisResult]) -> list[dict[str, object]]:
    payloads: list[dict[str, object]] = []
    for result in results:
        payloads.extend(suppressed_finding_entries(result))
    return payloads


def finding_payload(result: AnalysisResult, finding: Finding) -> dict[str, object]:
    payload = finding.model_dump()
    payload["fingerprint"] = finding_fingerprint(result, finding)
    payload["standards"] = _standard_ref_payloads(finding.rule_id)
    payload["standards_secondary"] = _standard_ref_payloads(
        finding.rule_id,
        secondary=True,
    )
    return payload


def _ensure_rule_metadata_loaded() -> None:
    registry.ensure_loaded("webconf_audit.local.rules.universal")
    registry.ensure_loaded("webconf_audit.local.nginx.rules")
    registry.ensure_loaded("webconf_audit.local.apache.rules")
    registry.ensure_loaded("webconf_audit.local.lighttpd.rules")
    registry.ensure_loaded("webconf_audit.local.iis.rules")
    registry.ensure_loaded("webconf_audit.external.rules")
    from webconf_audit.external.rules._runner import register_external_rule_metas

    register_external_rule_metas()


def _standards_for_rule(
    rule_id: str,
    *,
    secondary: bool = False,
) -> tuple[StandardReference, ...]:
    _ensure_rule_metadata_loaded()
    meta = registry.get_meta(rule_id)
    if meta is None:
        return ()
    return meta.standards_secondary if secondary else meta.standards


def _standard_ref_payloads(
    rule_id: str,
    *,
    secondary: bool = False,
) -> list[dict[str, object]]:
    return [
        _standard_ref_payload(ref)
        for ref in _standards_for_rule(rule_id, secondary=secondary)
    ]


def _standard_ref_payload(ref: StandardReference) -> dict[str, object]:
    payload: dict[str, object] = {
        "standard": ref.standard,
        "reference": ref.reference,
        "coverage": ref.coverage,
    }
    if ref.url is not None:
        payload["url"] = ref.url
    if ref.note is not None:
        payload["note"] = ref.note
    if ref.tier != "primary":
        payload["tier"] = ref.tier
    return payload


def _standards_summary_payload(
    finding_pairs: list[tuple[AnalysisResult, Finding]],
) -> list[dict[str, object]]:
    buckets: dict[
        tuple[str, str, str, str, str | None, str | None],
        dict[str, object],
    ] = {}
    for _result, finding in finding_pairs:
        for ref in (
            *_standards_for_rule(finding.rule_id),
            *_standards_for_rule(finding.rule_id, secondary=True),
        ):
            key = (
                ref.tier,
                ref.standard,
                ref.reference,
                ref.coverage,
                ref.url,
                ref.note,
            )
            bucket = buckets.setdefault(
                key,
                {
                    **_standard_ref_payload(ref),
                    "finding_count": 0,
                    "rule_ids": set(),
                },
            )
            bucket["finding_count"] = int(bucket["finding_count"]) + 1
            rule_ids = bucket["rule_ids"]
            if isinstance(rule_ids, set):
                rule_ids.add(finding.rule_id)

    payload: list[dict[str, object]] = []
    for bucket in buckets.values():
        rule_ids = bucket["rule_ids"]
        if isinstance(rule_ids, set):
            bucket["rule_ids"] = sorted(rule_ids)
        payload.append(bucket)
    payload.sort(key=_standard_summary_sort_key)
    return payload


def _standard_summary_sort_key(entry: dict[str, object]) -> tuple[int, int, str, str]:
    tier_order = 1 if entry.get("tier") == "secondary" else 0
    standard = str(entry.get("standard", ""))
    reference = str(entry.get("reference", ""))
    if entry.get("tier") == "secondary":
        order = (
            _SECONDARY_STANDARD_ORDER.index(standard)
            if standard in _SECONDARY_STANDARD_ORDER
            else 999
        )
    else:
        order = _STANDARD_ORDER.index(standard) if standard in _STANDARD_ORDER else 999
    return (tier_order, order, standard, reference)


def _standard_ref_label(ref: StandardReference) -> str:
    label = ref.reference
    if ref.coverage != "direct":
        label = f"{label} ({ref.coverage})"
    return label


# ---------------------------------------------------------------------------
# External summary helpers (moved from cli.py)
# ---------------------------------------------------------------------------

def _external_summary_lines(result: AnalysisResult) -> list[str]:
    if result.mode != "external":
        return []
    lines: list[str] = []
    lines.extend(_port_scan_summary_lines(result.metadata))
    identification_line = _identification_summary_line(result.metadata)
    if identification_line is not None:
        lines.append(identification_line)
    lines.extend(_tls_summary_lines(result.metadata))
    lines.extend(_extra_header_summary_lines(result.metadata))
    lines.extend(_redirect_chain_summary_lines(result.metadata))
    return lines


def _port_scan_summary_lines(metadata: dict[str, object]) -> list[str]:
    raw_scan_results = metadata.get("port_scan")
    if not isinstance(raw_scan_results, list) or not raw_scan_results:
        return []
    open_ports: list[str] = []
    errored_ports: list[str] = []
    for entry in raw_scan_results:
        if not isinstance(entry, dict):
            continue
        port = entry.get("port")
        if not isinstance(port, int):
            continue
        if entry.get("tcp_open") is True:
            open_ports.append(str(port))
        elif entry.get("error_message"):
            errored_ports.append(str(port))
    lines = [
        "port discovery: "
        f"{len(raw_scan_results)} scanned; open ports: "
        f"{', '.join(open_ports) if open_ports else 'none'}"
    ]
    if errored_ports:
        lines.append(f"port discovery errors: {', '.join(errored_ports)}")
    return lines


def _identification_summary_line(metadata: dict[str, object]) -> str | None:
    raw_identification = metadata.get("server_identification")
    if not isinstance(raw_identification, dict):
        return None
    confidence = _summary_string(raw_identification.get("confidence"), default="unknown")
    signal_suffix = _identification_signal_suffix(raw_identification)
    if raw_identification.get("ambiguous") is True:
        return _ambiguous_identification_line(raw_identification, confidence, signal_suffix)
    server_type = _summary_string(raw_identification.get("server_type"))
    if server_type:
        return (
            "server identification: "
            f"{server_type} ({confidence} confidence{signal_suffix})"
        )
    return f"server identification: unknown ({confidence} confidence{signal_suffix})"


def _identification_signal_suffix(raw_identification: dict[str, object]) -> str:
    signals = _identification_signals(raw_identification.get("evidence"))
    if not signals:
        return ""
    return f"; signals: {', '.join(signals)}"


def _identification_signals(raw_evidence: object) -> list[str]:
    if not isinstance(raw_evidence, list):
        return []
    seen: set[str] = set()
    for entry in raw_evidence:
        if not isinstance(entry, dict):
            continue
        signal = _summary_string(entry.get("signal"))
        if signal:
            seen.add(signal)
    return sorted(seen)


def _ambiguous_identification_line(
    raw_identification: dict[str, object],
    confidence: str,
    signal_suffix: str,
) -> str:
    candidates = raw_identification.get("candidate_server_types")
    if isinstance(candidates, list) and candidates:
        return (
            "server identification: ambiguous "
            f"({confidence} confidence; candidates: {', '.join(candidates)}"
            f"{signal_suffix})"
        )
    return f"server identification: ambiguous ({confidence} confidence{signal_suffix})"


def _tls_summary_lines(metadata: dict[str, object]) -> list[str]:
    raw_attempts = metadata.get("probe_attempts")
    if not isinstance(raw_attempts, list):
        return []
    lines: list[str] = []
    for attempt in raw_attempts:
        line = _tls_summary_line(attempt)
        if line is not None:
            lines.append(line)
    return lines


def _tls_summary_line(attempt: object) -> str | None:
    if not isinstance(attempt, dict) or attempt.get("scheme") != "https":
        return None
    tls_info = attempt.get("tls_info")
    url = _summary_string(attempt.get("url"))
    if not isinstance(tls_info, dict) or not url:
        return None
    parts = _tls_summary_parts(tls_info)
    if not parts:
        return None
    return f"tls: {url}: {'; '.join(parts)}"


def _tls_summary_parts(tls_info: dict[str, object]) -> list[str]:
    parts = _tls_protocol_parts(tls_info)
    cipher_text = _tls_cipher_text(tls_info)
    if cipher_text:
        parts.append(cipher_text)
    parts.extend(_tls_chain_parts(tls_info))
    return parts


def _tls_protocol_parts(tls_info: dict[str, object]) -> list[str]:
    parts: list[str] = []
    protocol_version = _summary_string(tls_info.get("protocol_version"))
    if protocol_version:
        parts.append(protocol_version)
    supported = _summary_string_list(tls_info.get("supported_protocols"))
    if supported:
        parts.append(f"supports {', '.join(supported)}")
    return parts


def _tls_cipher_text(tls_info: dict[str, object]) -> str | None:
    cipher_name = _summary_string(tls_info.get("cipher_name"))
    if not cipher_name:
        return None
    cipher_text = f"cipher {cipher_name}"
    cipher_bits = tls_info.get("cipher_bits")
    if isinstance(cipher_bits, int):
        cipher_text += f" ({cipher_bits} bits)"
    return cipher_text


def _tls_chain_parts(tls_info: dict[str, object]) -> list[str]:
    parts: list[str] = []
    chain_complete = tls_info.get("cert_chain_complete")
    if chain_complete is True:
        parts.append("chain complete")
    elif chain_complete is False:
        parts.append("chain incomplete")
    chain_error = _summary_string(tls_info.get("cert_chain_error"))
    if chain_error:
        parts.append(f"chain error: {chain_error}")
    return parts


def _extra_header_summary_lines(metadata: dict[str, object]) -> list[str]:
    raw_attempts = metadata.get("probe_attempts")
    if not isinstance(raw_attempts, list):
        return []
    lines: list[str] = []
    for attempt in raw_attempts:
        if not isinstance(attempt, dict):
            continue
        url = attempt.get("url")
        if not isinstance(url, str):
            continue
        header_parts: list[str] = []
        for field, label in (
            ("cache_control_header", "Cache-Control"),
            ("x_dns_prefetch_control_header", "X-DNS-Prefetch-Control"),
            ("cross_origin_embedder_policy_header", "COEP"),
            ("cross_origin_opener_policy_header", "COOP"),
            ("cross_origin_resource_policy_header", "CORP"),
        ):
            value = attempt.get(field)
            if isinstance(value, str) and value:
                header_parts.append(f"{label}={value}")
        if header_parts:
            lines.append(f"extra headers: {url}: {'; '.join(header_parts)}")
    return lines


def _redirect_chain_summary_lines(metadata: dict[str, object]) -> list[str]:
    raw_chains = metadata.get("redirect_chains")
    if not isinstance(raw_chains, list):
        return []
    lines: list[str] = []
    for chain in raw_chains:
        line = _redirect_chain_line(chain)
        if line is not None:
            lines.append(line)
    return lines


def _redirect_chain_line(chain: object) -> str | None:
    if not isinstance(chain, dict):
        return None
    path_parts = _redirect_path_parts(chain)
    if not path_parts:
        return None
    flags = _redirect_flags(chain)
    suffix = f" ({', '.join(flags)})" if flags else ""
    return f"redirect chain: {' -> '.join(path_parts)}{suffix}"


def _redirect_path_parts(chain: dict[str, object]) -> list[str]:
    hops = chain.get("hops")
    if not isinstance(hops, list) or not hops:
        return []
    path_parts: list[str] = []
    for hop in hops:
        if not isinstance(hop, dict):
            continue
        url = _summary_string(hop.get("url"))
        if url:
            path_parts.append(url)
    final_url = _summary_string(chain.get("final_url"))
    if final_url and (not path_parts or final_url != path_parts[-1]):
        path_parts.append(final_url)
    return path_parts


def _redirect_flags(chain: dict[str, object]) -> list[str]:
    flags: list[str] = []
    for field, label in (
        ("loop_detected", "loop"),
        ("mixed_scheme_redirect", "mixed-scheme"),
        ("cross_domain_redirect", "cross-domain"),
        ("truncated", "truncated"),
    ):
        if chain.get(field) is True:
            flags.append(label)
    error_message = _summary_string(chain.get("error_message"))
    if error_message:
        flags.append(f"error: {error_message}")
    return flags


def _summary_string(value: object, *, default: str | None = None) -> str | None:
    if isinstance(value, str) and value:
        return value
    return default


def _summary_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


__all__ = [
    "JsonFormatter",
    "BaselineDiff",
    "ReportData",
    "ReportGroupBy",
    "ReportSummary",
    "TextFormatter",
    "UNIVERSAL_TO_SPECIFIC_MAP",
    "deduplicated_finding_pairs",
    "deduplicate_findings",
    "finding_payload",
    "format_location",
]
