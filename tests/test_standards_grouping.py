"""Regression tests for primary and secondary standards grouping."""

from __future__ import annotations

import json

from webconf_audit.models import AnalysisResult, Finding
from webconf_audit.report import JsonFormatter, ReportData, TextFormatter


def _finding(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity="high",
        title="title",
        description="desc",
        recommendation="rec",
        location=None,
    )


def _result(rule_id: str) -> AnalysisResult:
    return AnalysisResult(
        target="https://example.test",
        mode="external",
        server_type="nginx",
        findings=[_finding(rule_id)],
        issues=[],
        diagnostics=[],
        metadata={},
    )


def test_text_group_by_standard_surfaces_secondary_tags() -> None:
    text = TextFormatter(group_by="standard").format(
        ReportData(results=[_result("external.https_not_available")])
    )

    assert "STANDARD PCI DSS V4.0.1" in text
    assert "SECONDARY TAGS" in text
    assert "MITRE ATT&CK Enterprise v15" in text
    assert "ФСТЭК БДУ" in text


def test_json_findings_include_standards_secondary_array() -> None:
    parsed = json.loads(
        JsonFormatter().format(ReportData(results=[_result("external.https_not_available")]))
    )

    finding = parsed["findings"][0]
    assert finding["standards_secondary"]
    assert {
        "standard": "ФСТЭК БДУ",
        "reference": "УБИ.044",
        "url": "https://bdu.fstec.ru/threat/ubi.044",
        "coverage": "direct",
        "tier": "secondary",
    } in finding["standards_secondary"]
