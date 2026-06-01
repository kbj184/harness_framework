"""네트워크 장비 PSIRT 통합 수집기.

4 벤더 (Cisco / F5 / Palo Alto / Fortinet) — Trivy 가 다루지 않는 영역.
같은 tb_vendor_advisory 테이블에 vendor_source 컬럼으로 구분 적재.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any
from xml.etree import ElementTree as ET

import httpx

logger = logging.getLogger("collect_cmdb")

# 외부 endpoint (기본값 — 운영 시 환경변수로 override 가능)
CISCO_OPENVULN_URL = (
    "https://apix.cisco.com/security/advisories/v2/all"  # OAuth 필요
)
# F5 은 myF5 로그인 페이지 (인증 필요) — placeholder.
F5_PSIRT_RSS_URL = "https://support.f5.com/csp/security-advisories.rss"        # placeholder (HTML 응답)
PALOALTO_RSS_URL = "https://security.paloaltonetworks.com/rss.xml"             # 정상 동작 RSS
# Fortinet 은 fortiguard.com/psirt HTML 스크래핑 (User-Agent 필수, 봇 차단 우회)
FORTINET_PSIRT_URL = "https://www.fortiguard.com/psirt"
FORTINET_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)
# 구 변수 — handler 호환
FORTINET_RSS_URL = FORTINET_PSIRT_URL

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# affected_version 후보 — "17.9 이하", "9.18.x", "v6.4" 등
VERSION_PATTERN = re.compile(r"\b\d+(?:\.\d+){1,3}(?:\.x)?\b")


# Cisco productNames → 표준 cpe_product 정규화 (LIKE 매칭 호환)
CISCO_PRODUCT_NORMALIZE: list[tuple[re.Pattern, str]] = [
    (re.compile(r"ios\s*xe",          re.IGNORECASE), "ios_xe"),
    (re.compile(r"nx-?os",            re.IGNORECASE), "nx-os"),
    (re.compile(r"asa\b",             re.IGNORECASE), "asa"),
    (re.compile(r"firepower",         re.IGNORECASE), "firepower"),
    (re.compile(r"meraki",            re.IGNORECASE), "meraki"),
    (re.compile(r"webex",             re.IGNORECASE), "webex"),
    (re.compile(r"catalyst",          re.IGNORECASE), "ios"),
    (re.compile(r"\bios\b",           re.IGNORECASE), "ios"),
]


def normalize_cisco_products(product_names: list[str]) -> str | None:
    """Cisco productNames 리스트 → cpe_product LIKE 매칭 가능한 정규화 문자열.

    예: ["Cisco IOS XE Software", "Catalyst 9200"] → "ios_xe, ios"
    """
    normalized: list[str] = []
    for name in product_names:
        for pattern, product in CISCO_PRODUCT_NORMALIZE:
            if pattern.search(name):
                if product not in normalized:
                    normalized.append(product)
                break
    return ", ".join(normalized) if normalized else None


@dataclass
class PsirtAdvisory:
    advisory_id: str
    vendor_source: str                                 # PSIRT_CISCO / PSIRT_F5 / ...
    title: str
    description: str
    cve_ids: list[str] = field(default_factory=list)
    severity: str | None = None
    affected_model: str | None = None
    affected_version: str | None = None
    source_url: str = ""
    published_at: date | None = None


# ───────────────────── helpers ─────────────────────

def _extract_cves(text: str | None) -> list[str]:
    if not text:
        return []
    seen: dict[str, None] = {}
    for m in CVE_PATTERN.finditer(text):
        seen[m.group(0).upper()] = None
    return list(seen.keys())


def extract_affected_versions(text: str | None) -> str:
    """문자열에서 버전 패턴(예: 17.9, 9.18.x) 추출 후 콤마 join."""
    if not text:
        return ""
    matches = VERSION_PATTERN.findall(text)
    return ", ".join(dict.fromkeys(matches))   # dedupe, 순서 보존


def _parse_iso_date(s: str | None) -> date | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _parse_rfc822_date(s: str | None) -> date | None:
    if not s:
        return None
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S"):
        try:
            return datetime.strptime(s.strip(), fmt).date()
        except ValueError:
            continue
    return None


# ───────────────────── Cisco openVuln ─────────────────────

def fetch_cisco_advisories(
    token: str | None = None, timeout: int = 60
) -> dict[str, Any]:
    """Cisco openVuln REST API 호출 (OAuth Bearer).

    token 미지정 시 환경변수 CISCO_PSIRT_TOKEN 사용. 인증 실패 시 RuntimeError.
    """
    token = token or os.environ.get("CISCO_PSIRT_TOKEN")
    if not token:
        raise RuntimeError("CISCO_PSIRT_TOKEN 미설정 — Cisco openVuln API 호출 불가")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    with httpx.Client(timeout=timeout) as client:
        resp = client.get(CISCO_OPENVULN_URL, headers=headers)
        resp.raise_for_status()
        return resp.json()


def parse_cisco_advisories(data: dict[str, Any]) -> list[PsirtAdvisory]:
    """Cisco openVuln JSON → PsirtAdvisory 리스트."""
    items: list[PsirtAdvisory] = []
    for adv in data.get("advisories", []):
        advisory_id = adv.get("advisoryId") or adv.get("id")
        if not advisory_id:
            continue
        title = adv.get("advisoryTitle") or adv.get("title", "")
        summary = adv.get("summary") or ""
        cve_ids = adv.get("cves") or _extract_cves(title + " " + summary)
        sir = (adv.get("sir") or "").strip().lower() or None   # Critical/High/Medium/Low
        product_names = adv.get("productNames") or []
        # cpe_product (ios_xe, ios, asa 등) 와 LIKE 매칭되도록 정규화 — 원본은 raw 도 보존
        affected_model = (
            normalize_cisco_products(product_names) or
            (", ".join(product_names) if product_names else None)
        )
        affected_version = extract_affected_versions(summary) or None

        items.append(PsirtAdvisory(
            advisory_id=advisory_id,
            vendor_source="PSIRT_CISCO",
            title=title,
            description=summary,
            cve_ids=cve_ids,
            severity=sir,
            affected_model=affected_model,
            affected_version=affected_version,
            source_url=adv.get("publicationUrl", ""),
            published_at=_parse_iso_date(adv.get("firstPublished")),
        ))
    logger.info("Cisco openVuln advisory %d건 파싱 완료", len(items))
    return items


# ───────────────────── RSS (F5 / Palo Alto / Fortinet) ─────────────────────

def fetch_psirt_rss(url: str, timeout: int = 60) -> str:
    logger.info("PSIRT RSS 다운로드: %s", url)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.text


def parse_psirt_rss(
    rss_text: str, vendor_source: str, id_prefix: str
) -> list[PsirtAdvisory]:
    """범용 RSS → PsirtAdvisory.

    id_prefix 로 시작하는 영숫자 패턴(K12345, FG-IR-22-XXX, PAN-12345 등)을
    title 에서 추출해 advisory_id 로 사용.
    """
    id_pattern = re.compile(rf"\b{re.escape(id_prefix)}[\w-]+", re.IGNORECASE)

    root = ET.fromstring(rss_text)
    channel = root.find("channel")
    if channel is None:
        logger.warning("RSS channel 없음: %s", vendor_source)
        return []

    items: list[PsirtAdvisory] = []
    for item in channel.findall("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        description = (item.findtext("description") or "").strip()
        pub_raw = item.findtext("pubDate")

        # advisory_id: 제목에서 prefix 패턴 추출 — 없으면 link 사용
        m = id_pattern.search(title)
        if m:
            advisory_id = m.group(0).upper() if id_prefix.isalpha() else m.group(0)
        else:
            advisory_id = link[-50:]   # fallback

        cve_ids = _extract_cves(title + " " + description)
        affected_version = extract_affected_versions(title + " " + description) or None

        # vendor_source 별 기본 affected_model — 자산 cpe_product LIKE 매칭 호환
        # 제목에 명시된 제품 우선, 없으면 vendor 기본값
        combined = (title + " " + description).lower()
        if vendor_source == "PSIRT_F5":
            if "big-ip" in combined or "bigip" in combined:
                affected_model = "big-ip"
            elif "nginx" in combined:
                affected_model = "nginx"
            else:
                affected_model = "big-ip"
        elif vendor_source == "PSIRT_PA":
            if "pan-os" in combined:
                affected_model = "pan-os"
            elif "prisma" in combined:
                affected_model = "prisma"
            elif "globalprotect" in combined:
                affected_model = "globalprotect"
            else:
                affected_model = "pan-os"
        else:
            affected_model = None

        items.append(PsirtAdvisory(
            advisory_id=advisory_id,
            vendor_source=vendor_source,
            title=title,
            description=description,
            cve_ids=cve_ids,
            severity=None,                        # RSS 에 severity 없음 — 본문 파싱 추후
            affected_model=affected_model,        # cpe_product LIKE 매칭 호환
            affected_version=affected_version,
            source_url=link,
            published_at=_parse_rfc822_date(pub_raw),
        ))
    logger.info("%s RSS advisory %d건 파싱 완료", vendor_source, len(items))
    return items


# ───────────────────── Fortinet HTML (fortiguard.com/psirt) ─────────────────────

def fetch_fortinet_html(url: str = FORTINET_PSIRT_URL, timeout: int = 60) -> str:
    """Fortinet PSIRT 목록 페이지 HTML 다운로드.

    봇 차단 우회 위해 브라우저 User-Agent 필수. RSS feed 는 미제공.
    """
    headers = {
        "User-Agent": FORTINET_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
    }
    logger.info("Fortinet PSIRT HTML 다운로드: %s", url)
    with httpx.Client(timeout=timeout, follow_redirects=True, headers=headers) as c:
        resp = c.get(url)
        resp.raise_for_status()
        return resp.text


# Fortinet 목록 행 패턴 — onclick='/psirt/FG-IR-XX-XXX' 이후 행 내용
FORTINET_ROW_RE = re.compile(
    r"location\.href\s*=\s*'(/psirt/FG-IR-[0-9]+-[0-9]+)'.*?"
    r"<b>(FG-IR-[0-9]+-[0-9]+)\s+(.*?)</b>"
    r"(?:.*?<b\s+class=\"cve\">(CVE-[0-9]+-[0-9]+)</b>)?"
    r".*?<b>\s*(Critical|High|Medium|Low)\s*</b>",
    re.DOTALL | re.IGNORECASE,
)


def parse_fortinet_html(html_text: str) -> list[PsirtAdvisory]:
    """Fortinet PSIRT 목록 페이지 HTML → PsirtAdvisory 리스트.

    각 행 구조 (요약):
      <div class="row" onclick="location.href = '/psirt/FG-IR-XX-XXX'">
        <div><b>FG-IR-XX-XXX Title</b><br><b class="cve">CVE-YYYY-NNNN</b></div>
        ... <b>Severity</b> ...
    """
    items: list[PsirtAdvisory] = []
    seen: set[str] = set()
    for m in FORTINET_ROW_RE.finditer(html_text):
        href, advisory_id, title, cve, severity = m.groups()
        if advisory_id in seen:
            continue
        seen.add(advisory_id)
        # 제목에서 FortiOS/FortiManager/FortiAnalyzer 등 세분화 — 없으면 기본 fortios
        title_low = title.lower()
        if "fortios" in title_low or "fortigate" in title_low:
            affected_model = "fortios"
        elif "fortimanager" in title_low:
            affected_model = "fortimanager"
        elif "fortianalyzer" in title_low:
            affected_model = "fortianalyzer"
        elif "fortiweb" in title_low:
            affected_model = "fortiweb"
        elif "fortinac" in title_low:
            affected_model = "fortinac"
        else:
            affected_model = "fortios"                      # 기본
        items.append(PsirtAdvisory(
            advisory_id=advisory_id,
            vendor_source="PSIRT_FORTI",
            title=title.strip(),
            description="",
            cve_ids=[cve.upper()] if cve else [],
            severity=severity.lower() if severity else None,
            affected_model=affected_model,                  # cpe_product LIKE 매칭 호환
            affected_version=None,
            source_url=f"https://www.fortiguard.com{href}",
            published_at=None,                              # 목록엔 날짜 미명시
        ))
    logger.info("Fortinet PSIRT advisory %d건 파싱 완료", len(items))
    return items


# ───────────────────── transform / upsert ─────────────────────

def transform_psirt(items: list[PsirtAdvisory]) -> list[dict[str, Any]]:
    return [
        {
            "advisory_id": a.advisory_id,
            "vendor_source": a.vendor_source,
            "severity": a.severity,
            "title": a.title,
            "overview": a.description,
            "affected_model": a.affected_model,
            "affected_version": a.affected_version,
            "fix_command": None,
            "cve_ids": a.cve_ids,
            "source_url": a.source_url,
            "published_at": a.published_at,
            "updated_at": a.published_at,
        }
        for a in items
    ]


# tb_vendor_advisory 는 kisa_collector 와 공용. UPSERT 는 같은 SQL.
# 에이전트 간 import 금지 (CLAUDE.md) — 동일 SQL 재선언.
UPSERT_SQL = """
INSERT INTO tb_vendor_advisory (
    advisory_id, vendor_source, severity, title, overview,
    affected_model, affected_version, fix_command,
    cve_ids, source_url, published_at, updated_at, fetched_at
) VALUES (
    %(advisory_id)s, %(vendor_source)s, %(severity)s, %(title)s, %(overview)s,
    %(affected_model)s, %(affected_version)s, %(fix_command)s,
    %(cve_ids)s, %(source_url)s, %(published_at)s, %(updated_at)s, NOW()
)
ON CONFLICT (advisory_id) DO UPDATE SET
    vendor_source    = EXCLUDED.vendor_source,
    severity         = COALESCE(EXCLUDED.severity, tb_vendor_advisory.severity),
    title            = EXCLUDED.title,
    overview         = EXCLUDED.overview,
    affected_model   = COALESCE(EXCLUDED.affected_model, tb_vendor_advisory.affected_model),
    affected_version = COALESCE(EXCLUDED.affected_version, tb_vendor_advisory.affected_version),
    cve_ids          = EXCLUDED.cve_ids,
    source_url       = EXCLUDED.source_url,
    updated_at       = EXCLUDED.updated_at,
    fetched_at       = NOW()
"""


def upsert_advisory_rows(conn, rows: list[dict[str, Any]]) -> int:
    count = 0
    with conn.cursor() as cur:
        for r in rows:
            cur.execute(UPSERT_SQL, r)
            count += 1
    return count
