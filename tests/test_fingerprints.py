from __future__ import annotations

from webconf_audit.fingerprints import (
    finding_fingerprint,
    finding_fingerprint_components,
)
from webconf_audit.models import AnalysisResult, Finding, SourceLocation


def _result(server_type: str | None = "nginx") -> AnalysisResult:
    return AnalysisResult(
        mode="local",
        target="C:/repo/nginx/nginx.conf",
        server_type=server_type,
    )


def _finding(
    *,
    rule_id: str = "nginx.autoindex_on",
    severity: str = "medium",
    file_path: str = "C:/repo/nginx/conf.d/site.conf",
    line: int | None = 12,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Directory listing enabled",
        severity=severity,  # type: ignore[arg-type]
        description="desc",
        recommendation="rec",
        location=SourceLocation(
            mode="local",
            kind="file",
            file_path=file_path,
            line=line,
        ),
    )


def test_fingerprint_is_stable_for_display_text_changes() -> None:
    finding = _finding()
    same_locator = finding.model_copy(
        update={
            "title": "Different title",
            "severity": "critical",
            "description": "Different description",
            "recommendation": "Different recommendation",
        }
    )

    assert finding_fingerprint(_result(), finding) == finding_fingerprint(_result(), same_locator)


def test_fingerprint_changes_for_rule_server_and_location_changes() -> None:
    baseline = finding_fingerprint(_result(), _finding())

    assert finding_fingerprint(_result(), _finding(rule_id="nginx.server_tokens_on")) != baseline
    assert finding_fingerprint(_result(server_type="apache"), _finding()) != baseline
    assert finding_fingerprint(_result(), _finding(line=13)) != baseline


def test_fingerprint_normalizes_paths_and_scope_metadata() -> None:
    finding = _finding(file_path=r"conf.d\.\site.conf")
    finding.metadata["host"] = "  EXAMPLE.com  "

    components = finding_fingerprint_components(_result(), finding)

    assert components["source"] == "conf.d/site.conf"
    assert components["scope"] == "example.com"


def test_fingerprint_normalizes_url_targets_without_fragment() -> None:
    result = AnalysisResult(mode="external", target="HTTPS://Example.COM/#frag")
    finding = Finding(
        rule_id="external.hsts_header_missing",
        title="HSTS missing",
        severity="low",
        description="desc",
        recommendation="rec",
        location=SourceLocation(
            mode="external",
            kind="header",
            target="HTTPS://Example.COM/#frag",
            details="Strict-Transport-Security",
        ),
    )

    components = finding_fingerprint_components(result, finding)

    assert components["source"] == "https://example.com/"
    assert components["details"] == "Strict-Transport-Security"
