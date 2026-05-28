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
# F5 / Fortinet 은 2026-05-28 확인: 공식 RSS feed 미제공 (로그인 페이지 또는 HTML 응답).
# 실제 운영 시 HTML 스크래퍼 또는 인증 API 별도 구축 필요.
# 현재 placeholder URL — Lambda 호출 시 fetch 실패 → skip 처리 (handler.py 의 try/except).
F5_PSIRT_RSS_URL = "https://support.f5.com/csp/security-advisories.rss"        # placeholder (HTML 응답)
PALOALTO_RSS_URL = "https://security.paloaltonetworks.com/rss.xml"             # 정상 동작
FORTINET_RSS_URL = "https://www.fortiguard.com/rss/psirt.xml"                  # placeholder (500 응답)

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# affected_version 후보 — "17.9 이하", "9.18.x", "v6.4" 등
VERSION_PATTERN = re.compile(r"\b\d+(?:\.\d+){1,3}(?:\.x)?\b")


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
        affected_model = ", ".join(product_names) if product_names else None
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

        items.append(PsirtAdvisory(
            advisory_id=advisory_id,
            vendor_source=vendor_source,
            title=title,
            description=description,
            cve_ids=cve_ids,
            severity=None,                        # RSS 에 severity 없음 — 본문 파싱 추후
            affected_model=None,                  # RSS 에서 모델 추출 어려움
            affected_version=affected_version,
            source_url=link,
            published_at=_parse_rfc822_date(pub_raw),
        ))
    logger.info("%s RSS advisory %d건 파싱 완료", vendor_source, len(items))
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
