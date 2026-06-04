"""CPE 매핑 (§10.1 D4) — 정규화 파서 + 3-tier 사전.

STD: NVD CPE 직접 / MANUAL: 비표준 표기 매핑 / NO_CPE: 국산·NVD 미커버(cpe_unmapped).
미지(UNKNOWN)도 unmapped 처리해 silent 누락 방지.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# canonical token → (cpe_vendor, cpe_product)
_CPE_STD: dict[str, tuple[str, str]] = {
    "tomcat": ("apache", "tomcat"),
    "apache_http": ("apache", "http_server"),
    "nginx": ("f5", "nginx"),
    "websphere": ("ibm", "websphere_application_server"),
    "iis": ("microsoft", "internet_information_services"),
    "oracle_db": ("oracle", "database_server"),
    "sql_server": ("microsoft", "sql_server"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "db2": ("ibm", "db2"),
    "redis": ("redis", "redis"),
    "valkey": ("linuxfoundation", "valkey"),
    "opensearch": ("opensearch", "opensearch"),
    "mongodb": ("mongodb", "mongodb"),
    "rhel": ("redhat", "enterprise_linux"),
    "aix": ("ibm", "aix"),
    "windows": ("microsoft", "windows"),
    "rocky": ("rocky", "rocky_linux"),
    "ubuntu": ("canonical", "ubuntu_linux"),
    "centos": ("centos", "centos"),
    "oracle_linux": ("oracle", "linux"),
    "esxi": ("vmware", "esxi"),
    "hpux": ("hp", "hp-ux"),
    "cisco_ios": ("cisco", "ios"),
    "cisco_iosxe": ("cisco", "ios_xe"),
    "cisco_nxos": ("cisco", "nx-os"),
    "junos": ("juniper", "junos"),
    "fortios": ("fortinet", "fortios"),
    "panos": ("paloaltonetworks", "pan-os"),
    "screenos": ("juniper", "screenos"),
    "arubaos": ("arubanetworks", "arubaos"),
}
# CPE 존재하나 표기 비표준 → 매핑테이블
_CPE_MANUAL: dict[str, tuple[str, str]] = {
    "edb": ("enterprisedb", "edb_postgres_advanced_server"),
    "smartzone": ("ruckuswireless", "smartzone"),
    "fastiron": ("ruckuswireless", "fastiron"),
    "ironware": ("brocade", "ironware"),
    "nios": ("infoblox", "nios"),
    "netscaler": ("citrix", "netscaler_application_delivery_controller"),
    "bigip": ("f5", "big-ip"),
}
# 국산·NVD 미커버 → cpe_unmapped + KISA/수동 경로
_NO_CPE: set[str] = {"lena", "secureos", "secui", "tos", "selfsecure"}

# OS류 토큰 (CPE part 'o'), 나머지는 'a'
_OS_TOKENS = {
    "rhel", "aix", "windows", "rocky", "ubuntu", "centos", "oracle_linux",
    "esxi", "hpux", "cisco_ios", "cisco_iosxe", "cisco_nxos", "junos",
    "fortios", "panos", "screenos", "arubaos",
}

# (substring 매칭, canonical token) — 구체적인 것 먼저
_ALIASES: list[tuple[str, str]] = [
    ("apache tomcat", "tomcat"), ("tomcat", "tomcat"),
    ("httpd", "apache_http"), ("apache", "apache_http"),
    ("nginx", "nginx"), ("websphere", "websphere"), ("iis", "iis"),
    ("lena", "lena"),
    ("oracle linux", "oracle_linux"), ("oracle", "oracle_db"),
    ("ppas", "edb"), ("edb", "edb"), ("enterprisedb", "edb"),
    ("mssql", "sql_server"), ("sql server", "sql_server"),
    ("aurora-postgresql", "postgresql"), ("aurora-mysql", "mysql"),
    ("mariadb", "mariadb"), ("mysql", "mysql"),
    ("postgres", "postgresql"), ("postgresql", "postgresql"),
    ("db2", "db2"), ("valkey", "valkey"), ("redis", "redis"),
    ("opensearch", "opensearch"), ("docdb", "mongodb"),
    ("rhel", "rhel"), ("red hat", "rhel"), ("redhat", "rhel"),
    ("aix", "aix"), ("rocky", "rocky"), ("ubuntu", "ubuntu"),
    ("centos", "centos"), ("windows", "windows"),
    ("esxi", "esxi"), ("hp-ux", "hpux"), ("hpux", "hpux"),
    ("iosxe", "cisco_iosxe"), ("ios xe", "cisco_iosxe"), ("ios-xe", "cisco_iosxe"),
    ("nx-os", "cisco_nxos"), ("nxos", "cisco_nxos"), ("ios", "cisco_ios"),
    ("junos", "junos"), ("fortios", "fortios"), ("pan-os", "panos"),
    ("screenos", "screenos"), ("arubaos", "arubaos"), ("aruba", "arubaos"),
    ("smartzone", "smartzone"), ("fastiron", "fastiron"), ("ironware", "ironware"),
    ("nios", "nios"), ("netscaler", "netscaler"), ("big-ip", "bigip"), ("bigip", "bigip"),
    ("secui", "secui"), ("secureos", "secureos"), ("자체", "selfsecure"),
]

_VER_RE = re.compile(r"(\d+(?:\.\d+)+)")
_VER_FALLBACK = re.compile(r"(\d+)")


@dataclass(frozen=True)
class CpeResult:
    cpe_uri: str | None
    vendor: str | None
    product: str | None
    version: str | None
    tier: str  # STD / MANUAL / NO_CPE / UNKNOWN
    unmapped: bool


def _canon(raw: str) -> str | None:
    t = raw.lower().strip()
    if not t:
        return None
    for sub, token in _ALIASES:
        if sub in t:
            return token
    return None


def extract_version(*texts: str) -> str | None:
    for text in texts:
        if not text:
            continue
        m = _VER_RE.search(text) or _VER_FALLBACK.search(text)
        if m:
            return m.group(1)
    return None


def cpe_for(product_raw: str, version_raw: str = "") -> CpeResult:
    """제품/버전 원문 → CPE 결과. 미매핑은 unmapped=True (cpe_* None)."""
    token = _canon(product_raw or "")
    if token is None:
        return CpeResult(None, None, None, None, "UNKNOWN", True)
    if token in _NO_CPE:
        return CpeResult(None, None, None, None, "NO_CPE", True)

    if token in _CPE_STD:
        vendor, product = _CPE_STD[token]
        tier = "STD"
    elif token in _CPE_MANUAL:
        vendor, product = _CPE_MANUAL[token]
        tier = "MANUAL"
    else:  # alias가 가리키는 토큰이 사전에 없음 — 미매핑 처리(KeyError 방지)
        return CpeResult(None, None, None, None, "UNKNOWN", True)

    version = extract_version(version_raw, product_raw)
    part = "o" if token in _OS_TOKENS else "a"
    cpe_uri = f"cpe:2.3:{part}:{vendor}:{product}:{version or '*'}:*:*:*:*:*:*:*"
    return CpeResult(cpe_uri, vendor, product, version, tier, False)
