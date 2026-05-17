"""Helpers for attaching standards references to rule metadata."""

from __future__ import annotations

import re

from webconf_audit.rule_registry import StandardCoverage, StandardReference

_OWASP_TOP10_2021_URLS = {
    "A01:2021": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "A02:2021": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "A03:2021": "https://owasp.org/Top10/A03_2021-Injection/",
    "A04:2021": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    "A05:2021": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "A06:2021": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    "A07:2021": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "A08:2021": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    "A09:2021": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    "A10:2021": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
}

_NIST_SP_URLS = {
    "800-44 Rev. 2": "https://csrc.nist.gov/publications/detail/sp/800-44/ver-2/final",
    "800-52 Rev. 2": "https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final",
    "800-53 Rev. 5": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    "800-63B": "https://pages.nist.gov/800-63-3/sp800-63b.html",
}

_ISO_27002_2022_URL = "https://www.iso.org/standard/75652.html"
_FSTEC_MERA_URL = (
    "https://fstec.ru/dokumenty/vse-dokumenty/prikazy/"
    "prikaz-fstek-rossii-ot-11-fevralya-2013-g-n-17"
)
_PCI_DSS_4_URL = (
    "https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0_1.pdf"
)
_CIS_NGINX_V3_0_0_URL = "https://www.cisecurity.org/benchmark/nginx"
_CIS_IIS_10_V1_2_1_URL = "https://www.cisecurity.org/benchmark/microsoft_iis"
_MITRE_ATTACK_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

_NIST_CSF_FUNCTIONS = frozenset({"GV", "ID", "PR", "DE", "RS", "RC"})
_NIST_CSF_2_URL = "https://www.nist.gov/cyberframework"
_NIST_CSF_2_SUBCATEGORY_RE = re.compile(
    r"^(?P<function>GV|ID|PR|DE|RS|RC)\.[A-Z]{2,3}-\d{2}$",
)

_OWASP_API_TOP10_2023_URLS = {
    "API1:2023": (
        "https://owasp.org/API-Security/editions/2023/en/"
        "0xa1-broken-object-level-authorization/"
    ),
    "API2:2023": (
        "https://owasp.org/API-Security/editions/2023/en/"
        "0xa2-broken-authentication/"
    ),
    "API3:2023": (
        "https://owasp.org/API-Security/editions/2023/en/"
        "0xa3-broken-object-property-level-authorization/"
    ),
    "API4:2023": (
        "https://owasp.org/API-Security/editions/2023/en/"
        "0xa4-unrestricted-resource-consumption/"
    ),
    "API5:2023": (
        "https://owasp.org/API-Security/editions/2023/en/"
        "0xa5-broken-function-level-authorization/"
    ),
    "API6:2023": (
        "https://owasp.org/API-Security/editions/2023/en/"
        "0xa6-unrestricted-access-to-sensitive-business-flows/"
    ),
    "API7:2023": (
        "https://owasp.org/API-Security/editions/2023/en/"
        "0xa7-server-side-request-forgery/"
    ),
    "API8:2023": (
        "https://owasp.org/API-Security/editions/2023/en/"
        "0xa8-security-misconfiguration/"
    ),
    "API9:2023": (
        "https://owasp.org/API-Security/editions/2023/en/"
        "0xa9-improper-inventory-management/"
    ),
    "API10:2023": (
        "https://owasp.org/API-Security/editions/2023/en/"
        "0xaa-unsafe-consumption-of-apis/"
    ),
}


def cwe(
    cwe_id: int,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    if isinstance(cwe_id, bool) or not isinstance(cwe_id, int) or cwe_id < 1:
        raise ValueError(f"Unsupported CWE id: {cwe_id}. Expected a positive integer.")
    return StandardReference(
        standard="CWE",
        reference=f"CWE-{cwe_id}",
        url=f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
        coverage=coverage,
        note=note,
    )


def owasp_top10_2021(
    category: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    if category not in _OWASP_TOP10_2021_URLS:
        valid_categories = ", ".join(sorted(_OWASP_TOP10_2021_URLS))
        raise ValueError(
            f"Unsupported OWASP Top 10 2021 category: {category}. "
            f"Expected one of: {valid_categories}."
        )
    return StandardReference(
        standard="OWASP Top 10",
        reference=category,
        url=_OWASP_TOP10_2021_URLS[category],
        coverage=coverage,
        note=note,
    )


def asvs_5(
    requirement: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    normalized_requirement = requirement.strip()
    if not normalized_requirement:
        raise ValueError("asvs_5: requirement must be a non-empty string.")
    return StandardReference(
        standard="OWASP ASVS",
        reference=f"v5.0.0-{normalized_requirement}",
        url="https://owasp.org/www-project-application-security-verification-standard/",
        coverage=coverage,
        note=note,
    )


def cis_nginx_v3_0_0(
    section: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    normalized_section = _normalize_non_empty_text(
        section,
        fn_name="cis_nginx_v3_0_0",
        field_name="section",
    )
    if normalized_section.startswith("\N{SECTION SIGN}"):
        normalized_section = normalized_section[1:].strip()
    if not normalized_section:
        raise ValueError(
            "cis_nginx_v3_0_0: section must include a section number after §."
        )
    return StandardReference(
        standard="CIS",
        reference=f"NGINX v3.0.0 \N{SECTION SIGN}{normalized_section}",
        url=_CIS_NGINX_V3_0_0_URL,
        coverage=coverage,
        note=note,
    )


def cis_iis_10_v1_2_1(
    section: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    normalized_section = _normalize_non_empty_text(
        section,
        fn_name="cis_iis_10_v1_2_1",
        field_name="section",
    )
    if normalized_section.startswith("\N{SECTION SIGN}"):
        normalized_section = normalized_section[1:].strip()
    if not normalized_section:
        raise ValueError(
            "cis_iis_10_v1_2_1: section must include a section number after §."
        )
    return StandardReference(
        standard="CIS",
        reference=f"Microsoft IIS 10 v1.2.1 \N{SECTION SIGN}{normalized_section}",
        url=_CIS_IIS_10_V1_2_1_URL,
        coverage=coverage,
        note=note,
    )


def _normalize_non_empty_text(value: str, *, fn_name: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{fn_name}: {field_name} must be a non-empty string.")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{fn_name}: {field_name} must be a non-empty string.")
    return normalized


def nist_sp_800_53_rev5(
    control: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    return nist_sp("800-53 Rev. 5", control, coverage=coverage, note=note)


def nist_sp(
    publication: str,
    section: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    normalized_publication = _normalize_non_empty_text(
        publication,
        fn_name="nist_sp",
        field_name="publication",
    )
    if normalized_publication not in _NIST_SP_URLS:
        valid_publications = ", ".join(sorted(_NIST_SP_URLS))
        raise ValueError(
            f"Unsupported NIST SP publication: {publication}. "
            f"Expected one of: {valid_publications}."
        )
    normalized_section = _normalize_non_empty_text(
        section,
        fn_name="nist_sp",
        field_name="section",
    ).upper()
    return StandardReference(
        standard=f"NIST SP {normalized_publication}",
        reference=normalized_section,
        url=_NIST_SP_URLS[normalized_publication],
        coverage=coverage,
        note=note,
    )


def pci_dss_4(
    requirement: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    normalized_requirement = _normalize_non_empty_text(
        requirement,
        fn_name="pci_dss_4",
        field_name="requirement",
    )
    if normalized_requirement.lower().startswith("req."):
        normalized_requirement = normalized_requirement[4:].strip()
    if not normalized_requirement:
        raise ValueError("pci_dss_4: requirement must include a requirement number.")
    normalized_requirement = f"Req. {normalized_requirement}"
    return StandardReference(
        standard="PCI DSS v4.0.1",
        reference=normalized_requirement,
        url=_PCI_DSS_4_URL,
        coverage=coverage,
        note=note,
    )


def bsi_app_3_2(
    requirement: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    normalized_requirement = _normalize_non_empty_text(
        requirement,
        fn_name="bsi_app_3_2",
        field_name="requirement",
    ).upper()
    if not normalized_requirement.startswith("APP.3.2."):
        normalized_requirement = f"APP.3.2.{normalized_requirement}"
    return StandardReference(
        standard="BSI IT-Grundschutz",
        reference=normalized_requirement,
        url=(
            "https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/"
            "Standards-und-Zertifizierung/IT-Grundschutz/"
            "IT-Grundschutz-Kompendium/it-grundschutz-kompendium_node.html"
        ),
        coverage=coverage,
        note=note,
    )


def fstec_gis(
    measure: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    return fstec_mera(measure, coverage=coverage, note=note)


def iso_27002_2022(
    control: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    normalized_control = _normalize_non_empty_text(
        control,
        fn_name="iso_27002_2022",
        field_name="control",
    )
    return StandardReference(
        standard="ISO/IEC 27002:2022",
        reference=normalized_control,
        url=_ISO_27002_2022_URL,
        coverage=coverage,
        note=note,
    )


def fstec_mera(
    measure_id: str,
    *,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    normalized_measure = _normalize_non_empty_text(
        measure_id,
        fn_name="fstec_mera",
        field_name="measure_id",
    ).upper()
    return StandardReference(
        standard='ФСТЭК "Меры защиты информации в ГИС"',
        reference=normalized_measure,
        url=_FSTEC_MERA_URL,
        coverage=coverage,
        note=note,
    )


def mitre_attack(
    technique_id: str,
    *,
    version: str = "v15",
    note: str | None = None,
) -> StandardReference:
    normalized_technique_id = _normalize_non_empty_text(
        technique_id,
        fn_name="mitre_attack",
        field_name="technique_id",
    ).upper()
    if not _MITRE_ATTACK_TECHNIQUE_ID_RE.fullmatch(normalized_technique_id):
        raise ValueError("mitre_attack: technique_id must look like T1190 or T1592.002.")
    normalized_version = _normalize_non_empty_text(
        version,
        fn_name="mitre_attack",
        field_name="version",
    ).lower()
    technique_url = normalized_technique_id.replace(".", "/")
    return StandardReference(
        standard=f"MITRE ATT&CK Enterprise {normalized_version}",
        reference=normalized_technique_id,
        url=f"https://attack.mitre.org/techniques/{technique_url}/",
        note=note,
        tier="secondary",
    )


def fstec_bdu(
    threat_id: str,
    *,
    note: str | None = None,
) -> StandardReference:
    normalized_threat_id = _normalize_non_empty_text(
        threat_id,
        fn_name="fstec_bdu",
        field_name="threat_id",
    ).upper()
    threat_number = normalized_threat_id
    for prefix in ("УБИ.", "UBI."):
        if threat_number.startswith(prefix):
            threat_number = threat_number[len(prefix):]
            break
    if not threat_number:
        raise ValueError("fstec_bdu: threat_id must include a non-empty number.")
    canonical_reference = "\u0423\u0411\u0418." + threat_number
    return StandardReference(
        standard="ФСТЭК БДУ",
        reference=canonical_reference,
        url=f"https://bdu.fstec.ru/threat/ubi.{threat_number.lower()}",
        note=note,
        tier="secondary",
    )


def nist_csf_2(
    subcategory: str,
    *,
    note: str | None = None,
) -> StandardReference:
    """Return a NIST Cybersecurity Framework 2.0 secondary reference.

    ``subcategory`` must follow the canonical NIST CSF 2.0 form
    ``<FUNCTION>.<CATEGORY>-<NN>``, for example ``PR.DS-01`` or
    ``GV.OC-03``. The six valid function prefixes are GV (Govern),
    ID (Identify), PR (Protect), DE (Detect), RS (Respond), RC (Recover).

    CSF references are alignment-level mappings: a single CSF subcategory
    typically covers many concrete rules. They are stored with
    ``tier="secondary"`` so they do not displace primary CWE / OWASP /
    ASVS / CIS / vendor mappings.
    """
    normalized_subcategory = _normalize_non_empty_text(
        subcategory,
        fn_name="nist_csf_2",
        field_name="subcategory",
    ).upper()
    match = _NIST_CSF_2_SUBCATEGORY_RE.fullmatch(normalized_subcategory)
    if match is None:
        raise ValueError(
            "nist_csf_2: subcategory must look like PR.DS-01 or GV.OC-03 "
            "(function in {GV, ID, PR, DE, RS, RC}, 2-3 letter category, "
            "two-digit subcategory)."
        )
    return StandardReference(
        standard="NIST CSF",
        reference=f"CSF v2.0 {normalized_subcategory}",
        url=_NIST_CSF_2_URL,
        note=note,
        tier="secondary",
    )


def owasp_api_top10_2023(
    category: str,
    *,
    note: str | None = None,
) -> StandardReference:
    """Return an OWASP API Security Top 10 (2023) secondary reference.

    ``category`` must be the canonical short identifier such as
    ``"API7:2023"``. Only the ten canonical 2023-edition identifiers are
    accepted; arbitrary strings are rejected to keep mappings honest.

    Stored with ``tier="secondary"`` because the OWASP API Top 10 is
    application-layer alignment, while webconf-audit's primary mappings
    are at the web-server configuration layer.
    """
    normalized_category = _normalize_non_empty_text(
        category,
        fn_name="owasp_api_top10_2023",
        field_name="category",
    ).upper()
    if normalized_category not in _OWASP_API_TOP10_2023_URLS:
        raise ValueError(
            "owasp_api_top10_2023: category must be one of "
            f"{sorted(_OWASP_API_TOP10_2023_URLS.keys())}, got "
            f"{normalized_category!r}."
        )
    return StandardReference(
        standard="OWASP API Security Top 10",
        reference=normalized_category,
        url=_OWASP_API_TOP10_2023_URLS[normalized_category],
        note=note,
        tier="secondary",
    )


def rfc(
    number: int,
    *,
    section: str | None = None,
    coverage: StandardCoverage = "direct",
    note: str | None = None,
) -> StandardReference:
    if isinstance(number, bool) or not isinstance(number, int) or number < 1:
        raise ValueError(f"Unsupported RFC number: {number}. Expected a positive integer.")

    if section is not None and not isinstance(section, str):
        raise ValueError("rfc: section must be a non-empty string when provided.")
    normalized_section = section.strip() if section is not None else None
    if normalized_section == "":
        raise ValueError("rfc: section must be a non-empty string when provided.")

    reference = f"RFC {number}"
    url = f"https://datatracker.ietf.org/doc/html/rfc{number}"
    if normalized_section is not None:
        reference = f"{reference} \N{SECTION SIGN}{normalized_section}"
        url = f"{url}#section-{normalized_section}"

    return StandardReference(
        standard="IETF RFC",
        reference=reference,
        url=url,
        coverage=coverage,
        note=note,
    )


__all__ = [
    "asvs_5",
    "bsi_app_3_2",
    "cis_iis_10_v1_2_1",
    "cis_nginx_v3_0_0",
    "cwe",
    "fstec_bdu",
    "fstec_mera",
    "fstec_gis",
    "iso_27002_2022",
    "mitre_attack",
    "nist_csf_2",
    "nist_sp",
    "nist_sp_800_53_rev5",
    "owasp_api_top10_2023",
    "owasp_top10_2021",
    "pci_dss_4",
    "rfc",
]
