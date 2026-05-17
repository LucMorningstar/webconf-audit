from __future__ import annotations

import json

from webconf_audit.baselines import (
    Baseline,
    apply_baseline_diff,
    baseline_from_report,
    load_baseline_file,
)
from webconf_audit.models import AnalysisResult, Finding, SourceLocation
from webconf_audit.report import JsonFormatter, ReportData
from webconf_audit.suppressions import SUPPRESSED_FINDINGS_METADATA_KEY


def _finding(
    rule_id: str,
    *,
    severity: str = "medium",
    line: int = 1,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"{rule_id} title",
        severity=severity,  # type: ignore[arg-type]
        description="desc",
        recommendation="rec",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path="nginx.conf",
            line=line,
        ),
    )


def _result(findings: list[Finding]) -> AnalysisResult:
    return AnalysisResult(
        mode="local",
        target="nginx.conf",
        server_type="nginx",
        findings=findings,
    )


def test_baseline_from_report_stores_fingerprint_and_display_metadata() -> None:
    report = ReportData(results=[_result([_finding("nginx.server_tokens_on", line=12)])])

    baseline = baseline_from_report(report)

    assert baseline["version"] == 1
    entries = baseline["findings"]
    assert isinstance(entries, list)
    assert entries[0]["rule_id"] == "nginx.server_tokens_on"
    assert entries[0]["target"] == "nginx.conf"
    assert entries[0]["location_display"] == "nginx.conf:12"
    assert len(entries[0]["fingerprint"]) == 64


def test_apply_baseline_diff_groups_new_unchanged_and_resolved_findings() -> None:
    unchanged = _finding("nginx.server_tokens_on", line=10)
    resolved = _finding("nginx.autoindex_on", line=20)
    baseline_payload = baseline_from_report(ReportData(results=[_result([unchanged, resolved])]))
    baseline = Baseline(
        entries=tuple(baseline_payload["findings"]),  # type: ignore[arg-type]
        source_path="baseline.json",
    )

    current_report = ReportData(
        results=[_result([unchanged, _finding("nginx.missing_access_log", line=30)])]
    )
    apply_baseline_diff(current_report, baseline)

    assert current_report.baseline_diff is not None
    assert [entry["rule_id"] for entry in current_report.baseline_diff["new_findings"]] == [
        "nginx.missing_access_log"
    ]
    assert [entry["rule_id"] for entry in current_report.baseline_diff["unchanged_findings"]] == [
        "nginx.server_tokens_on"
    ]
    assert [entry["rule_id"] for entry in current_report.baseline_diff["resolved_findings"]] == [
        "nginx.autoindex_on"
    ]


def test_apply_baseline_diff_compares_fingerprints_case_insensitively() -> None:
    finding = _finding("nginx.server_tokens_on", line=10)
    baseline_payload = baseline_from_report(ReportData(results=[_result([finding])]))
    baseline_entry = dict(baseline_payload["findings"][0])  # type: ignore[index]
    baseline_entry["fingerprint"] = str(baseline_entry["fingerprint"]).upper()
    baseline = Baseline(entries=(baseline_entry,), source_path="baseline.json")
    current_report = ReportData(results=[_result([finding])])

    apply_baseline_diff(current_report, baseline)

    assert current_report.baseline_diff is not None
    assert current_report.baseline_diff["new_findings"] == []
    assert [entry["rule_id"] for entry in current_report.baseline_diff["unchanged_findings"]] == [
        "nginx.server_tokens_on"
    ]


def test_apply_baseline_diff_keeps_currently_suppressed_findings_out_of_resolved() -> None:
    baseline_payload = baseline_from_report(
        ReportData(results=[_result([_finding("nginx.server_tokens_on", line=12)])])
    )
    baseline_entry = baseline_payload["findings"][0]  # type: ignore[index]
    baseline = Baseline(entries=(baseline_entry,), source_path="baseline.json")
    result = _result([])
    result.metadata[SUPPRESSED_FINDINGS_METADATA_KEY] = [
        {
            "fingerprint": baseline_entry["fingerprint"],
            "rule_id": "nginx.server_tokens_on",
            "reason": "accepted",
            "expires": "2099-01-01",
            "finding": {
                "rule_id": "nginx.server_tokens_on",
                "title": "Server tokens",
                "severity": "low",
                "location": {
                    "mode": "local",
                    "kind": "file",
                    "file_path": "nginx.conf",
                    "line": 12,
                },
            },
        }
    ]
    report = ReportData(results=[result])

    apply_baseline_diff(report, baseline)

    assert report.baseline_diff is not None
    assert report.baseline_diff["resolved_findings"] == []
    assert len(report.baseline_diff["suppressed_findings"]) == 1


def test_apply_baseline_diff_compares_suppressed_fingerprints_case_insensitively() -> None:
    baseline_payload = baseline_from_report(
        ReportData(results=[_result([_finding("nginx.server_tokens_on", line=12)])])
    )
    baseline_entry = baseline_payload["findings"][0]  # type: ignore[index]
    baseline = Baseline(entries=(baseline_entry,), source_path="baseline.json")
    result = _result([])
    result.metadata[SUPPRESSED_FINDINGS_METADATA_KEY] = [
        {
            "fingerprint": str(baseline_entry["fingerprint"]).upper(),
            "rule_id": "nginx.server_tokens_on",
            "reason": "accepted",
            "expires": "2099-01-01",
        }
    ]
    report = ReportData(results=[result])

    apply_baseline_diff(report, baseline)

    assert report.baseline_diff is not None
    assert report.baseline_diff["resolved_findings"] == []
    assert len(report.baseline_diff["suppressed_findings"]) == 1


def test_load_baseline_file_accepts_json_report_findings(tmp_path) -> None:
    report_payload = JsonFormatter().format(
        ReportData(results=[_result([_finding("x.rule")])])
    )
    report_path = tmp_path / "report.json"
    report_path.write_text(report_payload, encoding="utf-8")

    loaded = load_baseline_file(str(report_path))

    assert loaded.baseline is not None
    assert loaded.issues == ()
    assert len(loaded.baseline.entries) == 1


def test_load_baseline_file_rejects_unsupported_version(tmp_path) -> None:
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps({"version": 999, "findings": []}),
        encoding="utf-8",
    )

    loaded = load_baseline_file(str(baseline_path))

    assert loaded.baseline is None
    assert loaded.failed is True
    assert loaded.issues[0].code == "baseline_file_invalid"
    assert "Unsupported baseline version" in loaded.issues[0].message


def test_load_baseline_file_reports_invalid_fingerprint(tmp_path) -> None:
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps({"findings": [{"fingerprint": "not-a-fingerprint"}]}),
        encoding="utf-8",
    )

    loaded = load_baseline_file(str(baseline_path))

    assert loaded.baseline is None
    assert loaded.failed is True
    assert loaded.issues[0].code == "baseline_file_invalid"
