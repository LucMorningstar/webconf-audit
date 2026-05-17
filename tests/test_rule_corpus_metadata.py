from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest


_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE_ROOT = (_ROOT / "tests" / "fixtures" / "rule-corpus").resolve()
_MANIFEST_PATH = _FIXTURE_ROOT / "manifest.json"
_LOCAL_SERVER_TYPES = frozenset({"nginx", "apache", "lighttpd", "iis"})


def _load_manifest() -> dict[str, Any]:
    payload = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    assert payload["schema_version"] == 1
    assert isinstance(payload.get("cases"), list)
    return payload


_MANIFEST = _load_manifest()
_CASES: list[dict[str, Any]] = _MANIFEST["cases"]


def _case_id(case: dict[str, Any]) -> str:
    return str(case["id"])


def _fixture_path(value: str, *, field_name: str) -> Path:
    candidate = (_FIXTURE_ROOT / value).resolve()
    try:
        candidate.relative_to(_FIXTURE_ROOT)
    except ValueError as exc:
        raise AssertionError(
            f"rule corpus {field_name} escapes fixture root: {value!r}"
        ) from exc
    return candidate


def test_rule_corpus_metadata_shape() -> None:
    assert _MANIFEST["scope"] == ["local", "universal"]
    assert _MANIFEST["excluded_scope"] == ["external"]

    profile_counts = Counter(case["profile"] for case in _CASES)
    server_counts = Counter(case["server_type"] for case in _CASES)

    assert profile_counts["hybrid-vulnerable"] >= 4
    assert profile_counts["targeted-vulnerable"] >= 12
    assert set(server_counts) == _LOCAL_SERVER_TYPES


@pytest.mark.parametrize("case", _CASES, ids=_case_id)
def test_rule_corpus_metadata_entries_are_complete(case: dict[str, Any]) -> None:
    for key in (
        "id",
        "server_type",
        "profile",
        "description",
        "entrypoint",
        "provenance",
        "references",
        "expected_findings",
    ):
        assert key in case, f"{case.get('id', '<unknown>')} missing {key}"

    assert case["server_type"] in _LOCAL_SERVER_TYPES
    assert case["profile"] in {"hybrid-vulnerable", "targeted-vulnerable"}
    assert case["provenance"] in {"synthetic-derived", "synthetic-targeted"}
    assert isinstance(case["references"], list)
    assert isinstance(case["expected_findings"], list)
    assert _fixture_path(str(case["entrypoint"]), field_name="entrypoint").is_file()

    options = case.get("analyzer_options", {})
    if "tls_registry_path" in options:
        assert _fixture_path(
            str(options["tls_registry_path"]),
            field_name="tls_registry_path",
        ).is_file()
