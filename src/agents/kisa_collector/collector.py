"""KISA 보안공지 수집 (Trivy 미커버 — 한국 한정 advisory).

RSS feed 일 1회 폴링 → 각 공지에서 CVE 추출 → tb_vendor_advisory UPSERT.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any
from urllib.parse import parse_qs, urlparse
from xml.etree import ElementTree as ET

import httpx

logger = logging.getLogger("collect_cmdb")

# KISA 보안공지 — 2026-05-28 확인: 공식 RSS feed 미제공.
# 운영 환경 적용 전에 다음 중 하나 결정 필요:
#   (1) HTML 스크래핑 (parse_kisa_rss 대체) — https://www.boho.or.kr/kr/bbs/list.do?bbsId=B0000133
#   (2) KISA C-TAS 회원 가입 후 API token (별도)
#   (3) 제휴 RSS feed (벤더사 보안 권고 통합)
# 현재 placeholder URL 유지 — Lambda 호출 시 404 로 즉시 종료.
KISA_RSS_URL = "https://www.boho.or.kr/krcert/secNoticeListRss.do"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


@dataclass
class KisaAdvisory:
    """파싱된 KISA 공지 1건."""
    advisory_id: str                                  # KISA-12345
    title: str
    description: str
    cve_ids: list[str] = field(default_factory=list)
    source_url: str = ""
    published_at: date | None = None


def extract_advisory_id(link: str) -> str:
    """KISA link URL 에서 advisory_id 추출.

    Pattern 1: ?bulletin_writing_sequence=12345 → KISA-12345
    Pattern 2: seq 없으면 URL 해시 fallback
    """
    parsed = urlparse(link)
    qs = parse_qs(parsed.query)
    seq = qs.get("bulletin_writing_sequence", [None])[0]
    if seq:
        return f"KISA-{seq}"
    # fallback: URL 해시 (8자리)
    h = hashlib.md5(link.encode("utf-8")).hexdigest()[:8]
    return f"KISA-{h}"


def _parse_pubdate(s: str | None) -> date | None:
    """RSS pubDate (RFC 822) → date."""
    if not s:
        return None
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S"):
        try:
            return datetime.strptime(s.strip(), fmt).date()
        except ValueError:
            continue
    return None


def fetch_kisa_rss(url: str = KISA_RSS_URL, timeout: int = 60) -> str:
    """KISA 보안공지 RSS XML 다운로드."""
    logger.info("KISA RSS 다운로드: %s", url)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        text = resp.text
    logger.info("KISA RSS %d bytes 다운로드 완료", len(text))
    return text


def parse_kisa_rss(rss_text: str) -> list[KisaAdvisory]:
    """RSS XML → KisaAdvisory 리스트. title + description 에서 CVE 추출."""
    root = ET.fromstring(rss_text)
    channel = root.find("channel")
    if channel is None:
        logger.warning("RSS channel element 없음")
        return []

    items: list[KisaAdvisory] = []
    for item in channel.findall("item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        description = (item.findtext("description") or "").strip()
        pub_raw = item.findtext("pubDate")

        # CVE 는 title + description 양쪽에서 추출 후 dedupe (순서 보존)
        cve_set: dict[str, None] = {}
        for source in (title, description):
            for m in CVE_PATTERN.finditer(source):
                cve_set[m.group(0).upper()] = None

        items.append(KisaAdvisory(
            advisory_id=extract_advisory_id(link),
            title=title,
            description=description,
            cve_ids=list(cve_set.keys()),
            source_url=link,
            published_at=_parse_pubdate(pub_raw),
        ))

    logger.info("KISA 공지 %d건 파싱 완료", len(items))
    return items


def transform_kisa(items: list[KisaAdvisory]) -> list[dict[str, Any]]:
    """KisaAdvisory → DB upsert dict."""
    return [
        {
            "advisory_id": a.advisory_id,
            "vendor_source": "KISA",
            "severity": None,                       # KISA RSS 에 severity 없음 — 추후 본문 파싱
            "title": a.title,
            "overview": a.description,
            "affected_model": None,                 # KISA SW advisory (네트워크 X)
            "affected_version": None,
            "fix_command": None,
            "cve_ids": a.cve_ids,
            "source_url": a.source_url,
            "published_at": a.published_at,
            "updated_at": a.published_at,
        }
        for a in items
    ]


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
    title           = EXCLUDED.title,
    overview        = EXCLUDED.overview,
    severity        = COALESCE(EXCLUDED.severity, tb_vendor_advisory.severity),
    cve_ids         = EXCLUDED.cve_ids,
    source_url      = EXCLUDED.source_url,
    updated_at      = EXCLUDED.updated_at,
    fetched_at      = NOW()
"""


def upsert_advisory_rows(conn, rows: list[dict[str, Any]]) -> int:
    """tb_vendor_advisory UPSERT. 처리 행수 반환."""
    count = 0
    with conn.cursor() as cur:
        for r in rows:
            cur.execute(UPSERT_SQL, r)
            count += 1
    return count
