"""Tests for typed standards helper functions."""

from __future__ import annotations

import json

import pytest

from webconf_audit.standards import (
    cis_iis_10_v1_2_1,
    cis_nginx_v3_0_0,
    fstec_bdu,
    fstec_mera,
    iso_27002_2022,
    mitre_attack,
    nist_csf_2,
    nist_sp,
    owasp_api_top10_2023,
    pci_dss_4,
)


def test_nist_sp_uses_known_publication_url() -> None:
    ref = nist_sp("800-52 Rev. 2", "3.3.1")

    assert ref.standard == "NIST SP 800-52 Rev. 2"
    assert ref.reference == "3.3.1"
    assert ref.url == "https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final"


def test_nist_sp_round_trips_through_json() -> None:
    ref = nist_sp("800-52 Rev. 2", "3.3.1")

    payload = json.loads(json.dumps(ref.__dict__, ensure_ascii=False))

    assert payload["standard"] == "NIST SP 800-52 Rev. 2"
    assert payload["reference"] == "3.3.1"
    assert payload["url"] == "https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final"


@pytest.mark.parametrize(
    ("publication", "url"),
    [
        ("800-53 Rev. 5", "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"),
        ("800-63B", "https://pages.nist.gov/800-63-3/sp800-63b.html"),
        ("800-44 Rev. 2", "https://csrc.nist.gov/publications/detail/sp/800-44/ver-2/final"),
    ],
)
def test_nist_sp_accepts_supported_publications(publication: str, url: str) -> None:
    ref = nist_sp(publication, "x")

    assert ref.standard == f"NIST SP {publication}"
    assert ref.url == url


def test_pci_dss_4_uses_canonical_reference_and_url() -> None:
    ref = pci_dss_4("4.2.1")

    assert ref.standard == "PCI DSS v4.0.1"
    assert ref.reference == "Req. 4.2.1"
    assert (
        ref.url
        == "https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf"
    )


def test_pci_dss_4_canonicalizes_req_prefix() -> None:
    ref = pci_dss_4("req. 4.2.1")

    assert ref.reference == "Req. 4.2.1"


def test_pci_dss_4_rejects_empty_requirement_after_prefix() -> None:
    with pytest.raises(ValueError, match="requirement number"):
        pci_dss_4("Req.")


def test_cis_nginx_v3_0_0_uses_canonical_reference_and_url() -> None:
    ref = cis_nginx_v3_0_0("2.4.2")

    assert ref.standard == "CIS"
    assert ref.reference == "NGINX v3.0.0 §2.4.2"
    assert ref.url == "https://www.cisecurity.org/benchmark/nginx"


def test_cis_nginx_v3_0_0_rejects_empty_section_after_sign() -> None:
    with pytest.raises(ValueError, match="section"):
        cis_nginx_v3_0_0("§")


def test_cis_iis_10_v1_2_1_uses_canonical_reference_and_url() -> None:
    ref = cis_iis_10_v1_2_1("3.11")

    assert ref.standard == "CIS"
    assert ref.reference == "Microsoft IIS 10 v1.2.1 §3.11"
    assert ref.url == "https://www.cisecurity.org/benchmark/microsoft_iis"


def test_cis_iis_10_v1_2_1_strips_leading_section_sign() -> None:
    ref = cis_iis_10_v1_2_1("§3.11")

    assert ref.standard == "CIS"
    assert ref.reference == "Microsoft IIS 10 v1.2.1 §3.11"
    assert ref.url == "https://www.cisecurity.org/benchmark/microsoft_iis"


def test_cis_iis_10_v1_2_1_rejects_empty_section_after_sign() -> None:
    with pytest.raises(ValueError, match="section"):
        cis_iis_10_v1_2_1("§")


def test_iso_27002_2022_uses_canonical_url() -> None:
    ref = iso_27002_2022("8.24")

    assert ref.standard == "ISO/IEC 27002:2022"
    assert ref.reference == "8.24"
    assert ref.url == "https://www.iso.org/standard/75652.html"


def test_fstec_mera_uses_canonical_url() -> None:
    ref = fstec_mera("ИАФ.1")

    assert ref.standard == 'ФСТЭК "Меры защиты информации в ГИС"'
    assert ref.reference == "ИАФ.1"
    assert (
        ref.url
        == "https://fstec.ru/dokumenty/vse-dokumenty/prikazy/prikaz-fstek-rossii-ot-11-fevralya-2013-g-n-17"
    )


def test_mitre_attack_marks_reference_as_secondary() -> None:
    ref = mitre_attack("T1592.002")

    assert ref.standard == "MITRE ATT&CK Enterprise v15"
    assert ref.reference == "T1592.002"
    assert ref.url == "https://attack.mitre.org/techniques/T1592/002/"
    assert ref.tier == "secondary"


@pytest.mark.parametrize("technique_id", ["TA0001", "T15", "foo"])
def test_mitre_attack_rejects_invalid_technique_ids(technique_id: str) -> None:
    with pytest.raises(ValueError, match="T1190 or T1592.002"):
        mitre_attack(technique_id)


def test_fstec_bdu_marks_reference_as_secondary() -> None:
    ref = fstec_bdu("УБИ.044")

    assert ref.standard == "ФСТЭК БДУ"
    assert ref.reference == "УБИ.044"
    assert ref.url == "https://bdu.fstec.ru/threat/ubi.044"
    assert ref.tier == "secondary"


def test_fstec_bdu_canonicalizes_reference_without_prefix() -> None:
    ref = fstec_bdu("044")

    assert ref.reference == "\u0423\u0411\u0418.044"
    assert ref.url == "https://bdu.fstec.ru/threat/ubi.044"


def test_fstec_bdu_rejects_prefix_without_number() -> None:
    with pytest.raises(ValueError, match="non-empty number"):
        fstec_bdu("UBI.")


def test_nist_csf_2_marks_reference_as_secondary() -> None:
    ref = nist_csf_2("PR.DS-01")

    assert ref.standard == "NIST CSF"
    assert ref.reference == "CSF v2.0 PR.DS-01"
    assert ref.url == "https://www.nist.gov/cyberframework"
    assert ref.tier == "secondary"


def test_nist_csf_2_normalizes_lowercase_input() -> None:
    ref = nist_csf_2("pr.ds-02")

    assert ref.reference == "CSF v2.0 PR.DS-02"


def test_nist_csf_2_accepts_optional_note() -> None:
    ref = nist_csf_2("GV.OC-03", note="Govern function alignment")

    assert ref.note == "Govern function alignment"


@pytest.mark.parametrize(
    "subcategory",
    [
        "XX.YY-01",
        "PR.DS-1",
        "PR.DS-123",
        "PR-DS-01",
        "PR.D-01",
        "PR.DSDS-01",
    ],
)
def test_nist_csf_2_rejects_invalid_subcategory(subcategory: str) -> None:
    with pytest.raises(ValueError, match="PR.DS-01 or GV.OC-03"):
        nist_csf_2(subcategory)


def test_owasp_api_top10_2023_marks_reference_as_secondary() -> None:
    ref = owasp_api_top10_2023("API7:2023")

    assert ref.standard == "OWASP API Security Top 10"
    assert ref.reference == "API7:2023"
    assert ref.url == (
        "https://owasp.org/API-Security/editions/2023/en/"
        "0xa7-server-side-request-forgery/"
    )
    assert ref.tier == "secondary"


def test_owasp_api_top10_2023_accepts_each_canonical_category() -> None:
    for index in range(1, 11):
        ref = owasp_api_top10_2023(f"API{index}:2023")
        assert ref.reference == f"API{index}:2023"


def test_owasp_api_top10_2023_rejects_unknown_categories() -> None:
    with pytest.raises(ValueError, match="API1:2023"):
        owasp_api_top10_2023("API11:2023")


def test_owasp_api_top10_2023_rejects_year_drift() -> None:
    with pytest.raises(ValueError, match="API1:2023"):
        owasp_api_top10_2023("API7:2019")
