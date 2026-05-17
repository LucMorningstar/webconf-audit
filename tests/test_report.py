"""Tests for the report module."""

from __future__ import annotations

import json

import pytest

from webconf_audit.models import (
    AnalysisIssue,
    AnalysisResult,
    Finding,
    SourceLocation,
)
import webconf_audit.report as report_module
from webconf_audit.report import JsonFormatter, ReportData, TextFormatter
from webconf_audit.rule_registry import StandardReference, registry
from webconf_audit.suppressions import SUPPRESSED_FINDINGS_METADATA_KEY


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(
    rule_id: str = "test.rule",
    severity: str = "medium",
    title: str = "Test finding",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,  # type: ignore[arg-type]
        description="desc",
        recommendation="rec",
    )


def _issue(code: str = "W001", level: str = "warning", message: str = "warn") -> AnalysisIssue:
    return AnalysisIssue(code=code, level=level, message=message)  # type: ignore[arg-type]


def _result(
    mode: str = "local",
    target: str = "/etc/nginx/nginx.conf",
    server_type: str | None = "nginx",
    findings: list[Finding] | None = None,
    issues: list[AnalysisIssue] | None = None,
) -> AnalysisResult:
    return AnalysisResult(
        mode=mode,  # type: ignore[arg-type]
        target=target,
        server_type=server_type,
        findings=findings or [],
        issues=issues or [],
    )


# ---------------------------------------------------------------------------
# 7.1.1  ReportData + ReportSummary
# ---------------------------------------------------------------------------

class TestReportDataBasic:
    def test_single_result_counts(self) -> None:
        r = _result(findings=[_finding(), _finding(severity="high")])
        report = ReportData(results=[r])
        s = report.summary()
        assert s.total_findings == 2
        assert s.total_issues == 0

    def test_multiple_results_aggregation(self) -> None:
        r1 = _result(
            target="/a",
            server_type="nginx",
            findings=[_finding(severity="high")],
        )
        r2 = _result(
            target="/b",
            server_type="apache",
            findings=[_finding(severity="low"), _finding(severity="low")],
        )
        report = ReportData(results=[r1, r2])
        s = report.summary()
        assert s.total_findings == 3
        assert s.by_server_type == {"nginx": 1, "apache": 2}
        assert s.targets_analyzed == ["/a", "/b"]

    def test_all_findings_sorted_by_severity(self) -> None:
        r = _result(findings=[
            _finding(rule_id="z", severity="low"),
            _finding(rule_id="a", severity="critical"),
            _finding(rule_id="m", severity="high"),
        ])
        report = ReportData(results=[r])
        ids = [f.rule_id for f in report.all_findings]
        assert ids == ["a", "m", "z"]

    def test_all_findings_sorted_by_rule_id_within_severity(self) -> None:
        r = _result(findings=[
            _finding(rule_id="b.rule", severity="medium"),
            _finding(rule_id="a.rule", severity="medium"),
        ])
        report = ReportData(results=[r])
        ids = [f.rule_id for f in report.all_findings]
        assert ids == ["a.rule", "b.rule"]

    def test_summary_by_severity_full_keys(self) -> None:
        """by_severity always contains all 5 keys, even if zero."""
        r = _result(findings=[_finding(severity="high")])
        report = ReportData(results=[r])
        s = report.summary()
        assert set(s.by_severity.keys()) == {"critical", "high", "medium", "low", "info"}
        assert s.by_severity["high"] == 1
        assert s.by_severity["critical"] == 0

    def test_summary_by_mode(self) -> None:
        r1 = _result(mode="local", findings=[_finding()])
        r2 = _result(mode="external", target="example.com", findings=[_finding(), _finding()])
        report = ReportData(results=[r1, r2])
        s = report.summary()
        assert s.by_mode == {"local": 1, "external": 2}

    def test_empty_report(self) -> None:
        report = ReportData(results=[])
        s = report.summary()
        assert s.total_findings == 0
        assert s.total_issues == 0
        assert s.targets_analyzed == []

    def test_issues_sorted_error_before_warning(self) -> None:
        r = _result(issues=[
            _issue(code="W001", level="warning"),
            _issue(code="E001", level="error"),
        ])
        report = ReportData(results=[r])
        codes = [i.code for i in report.all_issues]
        assert codes == ["E001", "W001"]

    def test_generated_at_is_utc_iso(self) -> None:
        report = ReportData(results=[])
        # UTC ISO format ends with +00:00
        assert "+00:00" in report.generated_at or "Z" in report.generated_at

    def test_issues_counted_in_summary(self) -> None:
        r = _result(issues=[_issue(), _issue(code="E002", level="error")])
        report = ReportData(results=[r])
        s = report.summary()
        assert s.total_issues == 2

    def test_suppressed_findings_counted_separately(self) -> None:
        r = _result(
            findings=[],
            issues=[],
        )
        r.metadata[SUPPRESSED_FINDINGS_METADATA_KEY] = [
            {"rule_id": "nginx.weak_ssl_protocols", "fingerprint": "abc"}
        ]
        report = ReportData(results=[r])
        s = report.summary()
        assert s.total_findings == 0
        assert s.suppressed_findings == 1


# ---------------------------------------------------------------------------
# 7.1.2  TextFormatter
# ---------------------------------------------------------------------------

class TestTextFormatter:
    def test_contains_summary_header(self) -> None:
        r = _result(findings=[_finding(severity="high")])
        out = TextFormatter().format(ReportData(results=[r]))
        assert "webconf-audit report" in out
        assert "Findings: 1" in out

    def test_severity_group_headers(self) -> None:
        r = _result(findings=[_finding(severity="high")])
        out = TextFormatter().format(ReportData(results=[r]))
        assert "=== HIGH (1) ===" in out
        assert "=== MEDIUM (0) ===" in out

    def test_findings_grouped_critical_before_low(self) -> None:
        r = _result(findings=[
            _finding(rule_id="low.rule", severity="low"),
            _finding(rule_id="crit.rule", severity="critical"),
        ])
        out = TextFormatter().format(ReportData(results=[r]))
        crit_pos = out.index("crit.rule")
        low_pos = out.index("low.rule")
        assert crit_pos < low_pos

    def test_location_in_output(self) -> None:
        f = _finding()
        f.location = SourceLocation(mode="local", kind="file", file_path="/a.conf", line=10)
        r = _result(findings=[f])
        out = TextFormatter().format(ReportData(results=[r]))
        assert "/a.conf:10" in out

    def test_repeated_findings_can_be_grouped_without_losing_locations(self) -> None:
        f1 = _finding(
            rule_id="nginx.missing_hsts_header",
            severity="medium",
            title="Missing HSTS header",
        )
        f1.location = SourceLocation(mode="local", kind="file", file_path="/sites/app.conf", line=3)
        f2 = _finding(
            rule_id="nginx.missing_hsts_header",
            severity="medium",
            title="Missing HSTS header",
        )
        f2.location = SourceLocation(mode="local", kind="file", file_path="/sites/app.conf", line=27)
        r = _result(findings=[f1, f2])

        out = TextFormatter(group_repeated=True).format(ReportData(results=[r]))

        assert out.count("[nginx.missing_hsts_header] Missing HSTS header") == 1
        assert "findings: 2 repeated" in out
        assert "locations (2):" in out
        assert "      - /sites/app.conf:3" in out
        assert "      - /sites/app.conf:27" in out
        assert out.count("description: desc") == 1
        assert out.count("recommendation: rec") == 1

    def test_repeated_grouping_keeps_different_recommendations_separate(self) -> None:
        f1 = _finding(rule_id="nginx.missing_limit_req", severity="low")
        f1.recommendation = "Configure limit_req."
        f2 = _finding(rule_id="nginx.missing_limit_req", severity="low")
        f2.recommendation = "Configure limit_conn."
        r = _result(findings=[f1, f2])

        out = TextFormatter(group_repeated=True).format(ReportData(results=[r]))

        assert out.count("[nginx.missing_limit_req] Test finding") == 2
        assert "findings: 2 repeated" not in out

    def test_issues_in_output(self) -> None:
        r = _result(issues=[_issue(code="E001", level="error", message="bad")])
        out = TextFormatter().format(ReportData(results=[r]))
        assert "[error] E001: bad" in out

    def test_footer_totals(self) -> None:
        r = _result(findings=[_finding()], issues=[_issue()])
        out = TextFormatter().format(ReportData(results=[r]))
        assert "Total: 1 findings, 1 issues" in out

    def test_multi_target_headers(self) -> None:
        r1 = _result(target="/a", server_type="nginx")
        r2 = _result(target="/b", server_type="apache")
        out = TextFormatter().format(ReportData(results=[r1, r2]))
        assert "-- /a (nginx) --" in out
        assert "-- /b (apache) --" in out

    def test_empty_report(self) -> None:
        out = TextFormatter().format(ReportData(results=[]))
        assert "Findings: 0" in out
        assert "Total: 0 findings, 0 issues" in out

    def test_suppressed_count_in_output(self) -> None:
        r = _result()
        r.metadata[SUPPRESSED_FINDINGS_METADATA_KEY] = [
            {"rule_id": "nginx.weak_ssl_protocols", "fingerprint": "abc"}
        ]

        out = TextFormatter().format(ReportData(results=[r]))

        assert "Suppressed findings: 1" in out
        assert "Total: 0 findings, 0 issues, 1 suppressed" in out

    def test_baseline_diff_summary_is_rendered(self) -> None:
        report = ReportData(
            results=[_result()],
            baseline_diff={
                "new_findings": [
                    {
                        "rule_id": "x.new",
                        "title": "New finding",
                        "severity": "medium",
                        "target": "nginx.conf",
                    }
                ],
                "unchanged_findings": [{"rule_id": "x.old"}],
                "resolved_findings": [
                    {
                        "rule_id": "x.fixed",
                        "title": "Fixed finding",
                        "severity": "low",
                        "target": "nginx.conf",
                    }
                ],
                "suppressed_findings": [],
            },
        )

        out = TextFormatter().format(report)

        assert "Baseline diff:" in out
        assert "new 1, unchanged 1, resolved 1, suppressed 0" in out
        assert "[x.new] New finding (medium)" in out
        assert "[x.fixed] Fixed finding (low)" in out

    def test_external_summary_renders_port_tls_headers_and_redirects(self) -> None:
        result = AnalysisResult(
            mode="external",
            target="example.com",
            server_type="nginx",
            metadata={
                "port_scan": [
                    {"port": 443, "tcp_open": True},
                    {"port": 8443, "tcp_open": False, "error_message": "timeout"},
                ],
                "server_identification": {
                    "server_type": "nginx",
                    "confidence": "high",
                    "evidence": [
                        {"signal": "server_header"},
                        {"signal": "error_page_body"},
                    ],
                },
                "probe_attempts": [
                    {
                        "scheme": "https",
                        "url": "https://example.com/",
                        "tls_info": {
                            "protocol_version": "TLSv1.3",
                            "supported_protocols": ["TLSv1.2", "TLSv1.3"],
                            "cipher_name": "TLS_AES_256_GCM_SHA384",
                            "cipher_bits": 256,
                            "cert_chain_complete": False,
                            "cert_chain_error": "certificate verify failed",
                        },
                        "cache_control_header": "no-store",
                        "cross_origin_embedder_policy_header": "require-corp",
                    }
                ],
                "redirect_chains": [
                    {
                        "hops": [{"url": "http://example.com/"}],
                        "final_url": "https://example.com/login",
                        "mixed_scheme_redirect": True,
                        "truncated": True,
                    }
                ],
            },
        )

        out = TextFormatter().format(ReportData(results=[result]))

        assert "External Summary:" in out
        assert "port discovery: 2 scanned; open ports: 443" in out
        assert "port discovery errors: 8443" in out
        assert "server identification: nginx" in out
        assert "high confidence" in out
        assert "signals: error_page_body, server_header" in out
        assert "tls: https://example.com/:" in out
        assert "TLSv1.3" in out
        assert "supports TLSv1.2, TLSv1.3" in out
        assert "cipher TLS_AES_256_GCM_SHA384 (256 bits)" in out
        assert "chain incomplete" in out
        assert "chain error: certificate verify failed" in out
        assert "extra headers: https://example.com/:" in out
        assert "Cache-Control=no-store" in out
        assert "COEP=require-corp" in out
        assert "redirect chain: http://example.com/ -> https://example.com/login" in out
        assert "mixed-scheme" in out
        assert "truncated" in out

    def test_external_summary_renders_ambiguous_identification(self) -> None:
        result = AnalysisResult(
            mode="external",
            target="example.com",
            metadata={
                "server_identification": {
                    "ambiguous": True,
                    "confidence": "medium",
                    "candidate_server_types": ["apache", "nginx"],
                    "evidence": [
                        {"signal": "server_header"},
                        {"signal": "malformed_response_body"},
                    ],
                }
            },
        )

        out = TextFormatter().format(ReportData(results=[result]))

        assert "server identification: ambiguous" in out
        assert "medium confidence" in out
        assert "candidates: apache, nginx" in out
        assert "malformed_response_body" in out
        assert "server_header" in out

    def test_can_group_findings_by_standard(self) -> None:
        r = _result(
            findings=[
                _finding(
                    rule_id="universal.weak_tls_protocol",
                    severity="medium",
                    title="Weak TLS/SSL protocols enabled",
                )
            ]
        )

        out = TextFormatter(group_by="standard").format(ReportData(results=[r]))

        assert "=== STANDARD CWE (1) ===" in out
        assert "refs: CWE-327" in out
        assert "=== STANDARD OWASP TOP 10 (1) ===" in out

    def test_standard_grouping_can_group_repeated_findings(self) -> None:
        f1 = _finding(
            rule_id="universal.weak_tls_protocol",
            severity="medium",
            title="Weak TLS/SSL protocols enabled",
        )
        f1.location = SourceLocation(mode="local", kind="file", file_path="/sites/app.conf", line=3)
        f2 = _finding(
            rule_id="universal.weak_tls_protocol",
            severity="medium",
            title="Weak TLS/SSL protocols enabled",
        )
        f2.location = SourceLocation(mode="local", kind="file", file_path="/sites/app.conf", line=27)
        r = _result(findings=[f1, f2])

        out = TextFormatter(group_by="standard", group_repeated=True).format(
            ReportData(results=[r])
        )

        meta = registry.get_meta("universal.weak_tls_protocol")
        assert meta is not None
        standards_count = len({ref.standard for ref in meta.standards}) + len(
            {ref.standard for ref in meta.standards_secondary}
        )

        assert out.count("[universal.weak_tls_protocol] Weak TLS/SSL protocols enabled") == standards_count
        assert out.count("findings: 2 repeated") == standards_count
        assert "=== STANDARD CWE (2) ===" in out
        assert "refs: CWE-327" in out
        assert "=== STANDARD OWASP TOP 10 (2) ===" in out
        assert "refs: A02:2021" in out
        assert "=== STANDARD OWASP ASVS (2) ===" in out
        assert "refs: v5.0.0-12.1.1" in out
        assert "=== SECONDARY TAGS" in out
        assert "      - /sites/app.conf:3" in out
        assert "      - /sites/app.conf:27" in out


# ---------------------------------------------------------------------------
# 7.1.2  JsonFormatter
# ---------------------------------------------------------------------------

class TestJsonFormatter:
    def test_valid_json(self) -> None:
        r = _result(findings=[_finding()])
        out = JsonFormatter().format(ReportData(results=[r]))
        parsed = json.loads(out)
        assert isinstance(parsed, dict)

    def test_json_has_summary(self) -> None:
        r = _result(findings=[_finding(severity="high")])
        out = JsonFormatter().format(ReportData(results=[r]))
        parsed = json.loads(out)
        assert "summary" in parsed
        assert parsed["summary"]["total_findings"] == 1
        assert parsed["summary"]["by_severity"]["high"] == 1

    def test_json_has_results(self) -> None:
        r = _result(findings=[_finding()])
        out = JsonFormatter().format(ReportData(results=[r]))
        parsed = json.loads(out)
        assert len(parsed["results"]) == 1
        assert parsed["results"][0]["target"] == "/etc/nginx/nginx.conf"

    def test_json_has_generated_at(self) -> None:
        out = JsonFormatter().format(ReportData(results=[]))
        parsed = json.loads(out)
        assert "generated_at" in parsed

    def test_json_findings_present(self) -> None:
        r = _result(findings=[_finding(rule_id="x.rule")])
        out = JsonFormatter().format(ReportData(results=[r]))
        parsed = json.loads(out)
        findings = parsed["results"][0]["findings"]
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "x.rule"
        assert len(findings[0]["fingerprint"]) == 64
        assert findings[0]["standards"] == []
        assert findings[0]["standards_secondary"] == []
        assert parsed["findings"][0]["fingerprint"] == findings[0]["fingerprint"]
        assert parsed["findings"][0]["standards"] == []
        assert parsed["findings"][0]["standards_secondary"] == []

    def test_json_includes_repeated_finding_groups_with_locations(self) -> None:
        f1 = _finding(
            rule_id="nginx.missing_hsts_header",
            severity="medium",
            title="Missing HSTS header",
        )
        f1.location = SourceLocation(mode="local", kind="file", file_path="/sites/app.conf", line=3)
        f2 = _finding(
            rule_id="nginx.missing_hsts_header",
            severity="medium",
            title="Missing HSTS header",
        )
        f2.location = SourceLocation(mode="local", kind="file", file_path="/sites/app.conf", line=27)
        r = _result(findings=[f1, f2])

        parsed = json.loads(JsonFormatter().format(ReportData(results=[r])))

        assert len(parsed["findings"]) == 2
        assert parsed["finding_groups"] == [
            {
                "group_key": (
                    '["nginx.missing_hsts_header","medium","Missing HSTS header","desc","rec",""]'
                ),
                "rule_id": "nginx.missing_hsts_header",
                "title": "Missing HSTS header",
                "severity": "medium",
                "description": "desc",
                "recommendation": "rec",
                "count": 2,
                "cause": None,
                "locations": [
                    {
                        "target": "/etc/nginx/nginx.conf",
                        "display": "/sites/app.conf:3",
                        "location": f1.location.model_dump(),
                        "fingerprint": parsed["findings"][0]["fingerprint"],
                    },
                    {
                        "target": "/etc/nginx/nginx.conf",
                        "display": "/sites/app.conf:27",
                        "location": f2.location.model_dump(),
                        "fingerprint": parsed["findings"][1]["fingerprint"],
                    },
                ],
            }
        ]

    def test_json_repeated_group_keys_do_not_collide_on_pipe_characters(self) -> None:
        first_pair = [
            _finding(rule_id="test.rule", severity="medium", title="a|b"),
            _finding(rule_id="test.rule", severity="medium", title="a|b"),
        ]
        for finding in first_pair:
            finding.description = "c"
        second_pair = [
            _finding(rule_id="test.rule", severity="medium", title="a"),
            _finding(rule_id="test.rule", severity="medium", title="a"),
        ]
        for finding in second_pair:
            finding.description = "b|c"
        r = _result(findings=[*first_pair, *second_pair])

        parsed = json.loads(JsonFormatter().format(ReportData(results=[r])))
        group_keys = [group["group_key"] for group in parsed["finding_groups"]]

        assert len(group_keys) == 2
        assert len(set(group_keys)) == 2

    def test_json_empty_report(self) -> None:
        out = JsonFormatter().format(ReportData(results=[]))
        parsed = json.loads(out)
        assert parsed["summary"]["total_findings"] == 0
        assert parsed["results"] == []

    def test_json_severity_full_keys(self) -> None:
        out = JsonFormatter().format(ReportData(results=[]))
        parsed = json.loads(out)
        keys = set(parsed["summary"]["by_severity"].keys())
        assert keys == {"critical", "high", "medium", "low", "info"}

    def test_json_top_level_findings_sorted(self) -> None:
        """Top-level findings array is severity-sorted (critical before low)."""
        r = _result(findings=[
            _finding(rule_id="low.rule", severity="low"),
            _finding(rule_id="high.rule", severity="high"),
            _finding(rule_id="crit.rule", severity="critical"),
        ])
        out = JsonFormatter().format(ReportData(results=[r]))
        parsed = json.loads(out)
        top_ids = [f["rule_id"] for f in parsed["findings"]]
        assert top_ids == ["crit.rule", "high.rule", "low.rule"]

    def test_json_top_level_issues_sorted(self) -> None:
        """Top-level issues array is level-sorted (error before warning)."""
        r = _result(issues=[
            _issue(code="W001", level="warning"),
            _issue(code="E001", level="error"),
        ])
        out = JsonFormatter().format(ReportData(results=[r]))
        parsed = json.loads(out)
        top_codes = [i["code"] for i in parsed["issues"]]
        assert top_codes == ["E001", "W001"]

    def test_json_top_level_findings_aggregated_across_results(self) -> None:
        """Top-level findings aggregates from multiple results."""
        r1 = _result(target="/a", findings=[_finding(rule_id="a.rule", severity="high")])
        r2 = _result(target="/b", findings=[_finding(rule_id="b.rule", severity="medium")])
        out = JsonFormatter().format(ReportData(results=[r1, r2]))
        parsed = json.loads(out)
        assert len(parsed["findings"]) == 2
        assert parsed["findings"][0]["rule_id"] == "a.rule"
        assert parsed["findings"][1]["rule_id"] == "b.rule"

    def test_json_top_level_findings_stable_for_equal_sort_keys(self) -> None:
        r1 = _result(target="/a", findings=[_finding(rule_id="same.rule", severity="medium")])
        r2 = _result(target="/b", findings=[_finding(rule_id="same.rule", severity="medium")])

        first = json.loads(JsonFormatter().format(ReportData(results=[r1, r2])))
        second = json.loads(JsonFormatter().format(ReportData(results=[r2, r1])))

        first_fingerprints = [entry["fingerprint"] for entry in first["findings"]]
        second_fingerprints = [entry["fingerprint"] for entry in second["findings"]]
        assert len(first_fingerprints) == len(second_fingerprints) == 2
        assert first_fingerprints == second_fingerprints

    def test_json_empty_report_has_empty_top_level_arrays(self) -> None:
        out = JsonFormatter().format(ReportData(results=[]))
        parsed = json.loads(out)
        assert parsed["findings"] == []
        assert parsed["issues"] == []

    def test_json_includes_suppressed_findings(self) -> None:
        r = _result()
        r.metadata[SUPPRESSED_FINDINGS_METADATA_KEY] = [
            {"rule_id": "nginx.weak_ssl_protocols", "fingerprint": "abc"}
        ]

        out = JsonFormatter().format(ReportData(results=[r]))
        parsed = json.loads(out)

        assert parsed["summary"]["suppressed_findings"] == 1
        assert parsed["suppressed_findings"] == [
            {"rule_id": "nginx.weak_ssl_protocols", "fingerprint": "abc"}
        ]

    def test_json_includes_baseline_diff_arrays(self) -> None:
        report = ReportData(
            results=[_result()],
            baseline_diff={
                "new_findings": [{"rule_id": "x.new", "fingerprint": "1" * 64}],
                "unchanged_findings": [{"rule_id": "x.same", "fingerprint": "2" * 64}],
                "resolved_findings": [{"rule_id": "x.fixed", "fingerprint": "3" * 64}],
                "suppressed_findings": [],
            },
        )

        parsed = json.loads(JsonFormatter().format(report))

        assert parsed["new_findings"] == [{"rule_id": "x.new", "fingerprint": "1" * 64}]
        assert parsed["unchanged_findings"] == [
            {"rule_id": "x.same", "fingerprint": "2" * 64}
        ]
        assert parsed["resolved_findings"] == [
            {"rule_id": "x.fixed", "fingerprint": "3" * 64}
        ]

    def test_json_findings_include_standards_metadata(self) -> None:
        r = _result(
            findings=[
                _finding(
                    rule_id="universal.weak_tls_protocol",
                    severity="medium",
                    title="Weak TLS/SSL protocols enabled",
                )
            ]
        )

        parsed = json.loads(JsonFormatter().format(ReportData(results=[r])))

        finding = parsed["findings"][0]
        assert {
            "standard": "CWE",
            "reference": "CWE-327",
            "url": "https://cwe.mitre.org/data/definitions/327.html",
            "coverage": "direct",
        } in finding["standards"]
        assert {
            "standard": "CWE",
            "reference": "CWE-327",
            "url": "https://cwe.mitre.org/data/definitions/327.html",
            "coverage": "direct",
            "finding_count": 1,
            "rule_ids": ["universal.weak_tls_protocol"],
        } in parsed["standards"]

    def test_json_findings_include_secondary_standards_metadata(self) -> None:
        r = _result(
            findings=[
                _finding(
                    rule_id="external.https_not_available",
                    severity="high",
                    title="HTTPS unavailable",
                )
            ]
        )

        parsed = json.loads(JsonFormatter().format(ReportData(results=[r])))

        finding = parsed["findings"][0]
        assert {
            "standard": "MITRE ATT&CK Enterprise v15",
            "reference": "T1040",
            "url": "https://attack.mitre.org/techniques/T1040/",
            "coverage": "direct",
            "tier": "secondary",
        } in finding["standards_secondary"]
        assert {
            "standard": "MITRE ATT&CK Enterprise v15",
            "reference": "T1040",
            "url": "https://attack.mitre.org/techniques/T1040/",
            "coverage": "direct",
            "tier": "secondary",
            "finding_count": 1,
            "rule_ids": ["external.https_not_available"],
        } in parsed["standards"]

    def test_json_summary_keeps_primary_and_secondary_buckets_separate(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        shared_primary = StandardReference(
            standard="Shared Standard",
            reference="CTRL-1",
            url="https://example.test/ctrl-1",
        )
        shared_secondary = StandardReference(
            standard="Shared Standard",
            reference="CTRL-1",
            url="https://example.test/ctrl-1",
            tier="secondary",
        )

        def fake_standards_for_rule(
            rule_id: str,
            *,
            secondary: bool = False,
        ) -> tuple[StandardReference, ...]:
            if rule_id != "test.rule":
                return ()
            return (shared_secondary,) if secondary else (shared_primary,)

        monkeypatch.setattr(report_module, "_standards_for_rule", fake_standards_for_rule)

        parsed = json.loads(
            JsonFormatter().format(ReportData(results=[_result(findings=[_finding()])]))
        )

        assert {
            "standard": "Shared Standard",
            "reference": "CTRL-1",
            "url": "https://example.test/ctrl-1",
            "coverage": "direct",
            "finding_count": 1,
            "rule_ids": ["test.rule"],
        } in parsed["standards"]
        assert {
            "standard": "Shared Standard",
            "reference": "CTRL-1",
            "url": "https://example.test/ctrl-1",
            "coverage": "direct",
            "tier": "secondary",
            "finding_count": 1,
            "rule_ids": ["test.rule"],
        } in parsed["standards"]

    def test_json_summary_keeps_distinct_standard_metadata_in_separate_buckets(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        direct_ref = StandardReference(
            standard="Shared Standard",
            reference="CTRL-1",
            url="https://example.test/ctrl-1",
        )
        partial_ref = StandardReference(
            standard="Shared Standard",
            reference="CTRL-1",
            url="https://example.test/ctrl-1",
            coverage="partial",
            note="TLS-only signal.",
        )

        def fake_standards_for_rule(
            rule_id: str,
            *,
            secondary: bool = False,
        ) -> tuple[StandardReference, ...]:
            if secondary or rule_id not in {"test.rule", "other.rule"}:
                return ()
            return (direct_ref,) if rule_id == "test.rule" else (partial_ref,)

        monkeypatch.setattr(report_module, "_standards_for_rule", fake_standards_for_rule)

        parsed = json.loads(
            JsonFormatter().format(
                ReportData(
                    results=[
                        _result(findings=[_finding(rule_id="test.rule")]),
                        _result(target="/other", findings=[_finding(rule_id="other.rule")]),
                    ]
                )
            )
        )

        assert {
            "standard": "Shared Standard",
            "reference": "CTRL-1",
            "url": "https://example.test/ctrl-1",
            "coverage": "direct",
            "finding_count": 1,
            "rule_ids": ["test.rule"],
        } in parsed["standards"]
        assert {
            "standard": "Shared Standard",
            "reference": "CTRL-1",
            "url": "https://example.test/ctrl-1",
            "coverage": "partial",
            "note": "TLS-only signal.",
            "finding_count": 1,
            "rule_ids": ["other.rule"],
        } in parsed["standards"]

    def test_json_formatter_reloads_external_metadata_after_registry_clear(self) -> None:
        catalog = dict(registry._catalog)
        executable = dict(registry._executable)
        loaded_packages = set(registry._loaded_packages)
        try:
            registry.clear()
            assert registry.get_meta("external.https_not_available") is None

            JsonFormatter().format(
                ReportData(
                    results=[_result(findings=[_finding(rule_id="external.https_not_available")])]
                )
            )

            assert registry.get_meta("external.https_not_available") is not None
        finally:
            registry._catalog = catalog
            registry._executable = executable
            registry._loaded_packages = loaded_packages

    def test_json_uses_baseline_diff_suppressed_findings_when_available(self) -> None:
        r = _result()
        r.metadata[SUPPRESSED_FINDINGS_METADATA_KEY] = [
            {
                "rule_id": "raw.suppressed",
                "fingerprint": "a" * 64,
                "finding": {"rule_id": "raw.suppressed"},
            }
        ]
        report = ReportData(
            results=[r],
            baseline_diff={
                "new_findings": [],
                "unchanged_findings": [],
                "resolved_findings": [],
                "suppressed_findings": [
                    {
                        "rule_id": "diff.suppressed",
                        "fingerprint": "b" * 64,
                        "target": "nginx.conf",
                    }
                ],
            },
        )

        parsed = json.loads(JsonFormatter().format(report))

        assert parsed["suppressed_findings"] == [
            {
                "rule_id": "diff.suppressed",
                "fingerprint": "b" * 64,
                "target": "nginx.conf",
            }
        ]

    def test_json_falls_back_to_raw_suppressed_when_baseline_diff_is_incomplete(self) -> None:
        r = _result()
        r.metadata[SUPPRESSED_FINDINGS_METADATA_KEY] = [
            {"rule_id": "raw.suppressed", "fingerprint": "a" * 64}
        ]
        report = ReportData(
            results=[r],
            baseline_diff={
                "new_findings": [],
                "unchanged_findings": [],
                "resolved_findings": [],
            },
        )

        parsed = json.loads(JsonFormatter().format(report))

        assert parsed["suppressed_findings"] == [
            {"rule_id": "raw.suppressed", "fingerprint": "a" * 64}
        ]
