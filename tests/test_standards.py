"""Tests for legacy standards metadata helpers."""

from __future__ import annotations

import pytest

from webconf_audit.standards import (
    asvs_5,
    bsi_app_3_2,
    cwe,
    fstec_gis,
    nist_sp_800_53_rev5,
    owasp_top10_2021,
    pci_dss_4,
    rfc,
)


def test_cwe_uses_canonical_reference_and_url() -> None:
    ref = cwe(79)

    assert ref.standard == "CWE"
    assert ref.reference == "CWE-79"
    assert ref.url == "https://cwe.mitre.org/data/definitions/79.html"


def test_cwe_propagates_coverage_and_note() -> None:
    ref = cwe(327, coverage="partial", note="TLS-only signal.")

    assert ref.coverage == "partial"
    assert ref.note == "TLS-only signal."


@pytest.mark.parametrize("cwe_id", [0, -1, True])
def test_cwe_rejects_invalid_ids(cwe_id: int) -> None:
    with pytest.raises(ValueError, match="Unsupported CWE id"):
        cwe(cwe_id)


def test_owasp_top10_2021_uses_known_category_url() -> None:
    ref = owasp_top10_2021("A10:2021")

    assert ref.standard == "OWASP Top 10"
    assert ref.reference == "A10:2021"
    assert ref.url == "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"


def test_asvs_5_uses_canonical_reference_and_url() -> None:
    ref = asvs_5("1.1.1")

    assert ref.standard == "OWASP ASVS"
    assert ref.reference == "v5.0.0-1.1.1"
    assert ref.url == "https://owasp.org/www-project-application-security-verification-standard/"


def test_rfc_accepts_section_and_propagates_metadata() -> None:
    ref = rfc(
        8996,
        section="1",
        coverage="partial",
        note="TLS 1.0 and 1.1 are deprecated.",
    )

    assert ref.reference == "RFC 8996 \N{SECTION SIGN}1"
    assert ref.url == "https://datatracker.ietf.org/doc/html/rfc8996#section-1"
    assert ref.coverage == "partial"
    assert ref.note == "TLS 1.0 and 1.1 are deprecated."


def test_nist_sp_800_53_rev5_uses_canonical_reference_and_url() -> None:
    ref = nist_sp_800_53_rev5("IA-2")

    assert ref.standard == "NIST SP 800-53 Rev. 5"
    assert ref.reference == "IA-2"
    assert ref.url == "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"


def test_pci_dss_4_accepts_requirement_with_prefix() -> None:
    ref = pci_dss_4("Req. 4.2.1")

    assert ref.reference == "Req. 4.2.1"


def test_bsi_app_3_2_uses_canonical_reference_and_url() -> None:
    ref = bsi_app_3_2("A5")

    assert ref.standard == "BSI IT-Grundschutz"
    assert ref.reference == "APP.3.2.A5"


def test_fstec_gis_uses_canonical_reference_and_url() -> None:
    ref = fstec_gis("ИАФ.1")

    assert ref.standard == 'ФСТЭК "Меры защиты информации в ГИС"'
    assert ref.reference == "ИАФ.1"
    assert (
        ref.url
        == "https://fstec.ru/dokumenty/vse-dokumenty/prikazy/prikaz-fstek-rossii-ot-11-fevralya-2013-g-n-17"
    )
