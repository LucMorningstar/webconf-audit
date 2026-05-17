"""Focused regression tests for rule-standards mapping helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

import webconf_audit.rule_standards as rule_standards


def test_known_rule_ids_logs_when_rule_coverage_doc_is_missing(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
) -> None:
    fake_module = tmp_path / "src" / "webconf_audit" / "rule_standards.py"
    fake_source_rule = tmp_path / "src" / "webconf_audit" / "local" / "rules" / "sample.py"
    fake_module.parent.mkdir(parents=True)
    fake_source_rule.parent.mkdir(parents=True)
    fake_module.write_text("# stub\n", encoding="utf-8")
    fake_source_rule.write_text(
        "RULE_ID = 'nginx.sample_rule'\n"
        "@rule(rule_id=RULE_ID)\n"
        "Finding(rule_id='external.sample_rule')\n",
        encoding="utf-8",
    )

    rule_standards._known_rule_ids.cache_clear()
    monkeypatch.setattr(rule_standards, "__file__", str(fake_module))
    try:
        with caplog.at_level("DEBUG"):
            assert rule_standards._known_rule_ids() == frozenset(
                {"nginx.sample_rule", "external.sample_rule"}
            )

        assert "falling back to source-derived rule IDs" in caplog.text
    finally:
        rule_standards._known_rule_ids.cache_clear()


def test_direct_iso_references_do_not_apply_catch_all_to_unknown_rule() -> None:
    refs = rule_standards._iso_references("test.rule")

    assert all(ref.reference != "8.27" for ref in refs)


def test_direct_fstec_references_do_not_apply_catch_all_to_unknown_rule() -> None:
    refs = rule_standards._fstec_references("test.rule")

    assert all(not ref.reference.endswith(".32") for ref in refs)


def test_direct_catch_all_references_apply_to_migrated_rule_ids() -> None:
    iso_refs = rule_standards._iso_references("nginx.autoindex_on")
    fstec_refs = rule_standards._fstec_references("nginx.autoindex_on")

    assert any(ref.reference == "8.27" for ref in iso_refs)
    assert any(ref.reference.endswith(".32") for ref in fstec_refs)


def test_direct_catch_all_references_do_not_apply_to_future_known_rule_ids() -> None:
    iso_refs = rule_standards._iso_references("nginx.future_rule")
    fstec_refs = rule_standards._fstec_references("nginx.future_rule")

    assert all(ref.reference != "8.27" for ref in iso_refs)
    assert all(not ref.reference.endswith(".32") for ref in fstec_refs)
