"""KISA 보안공지 수집 (Trivy 미커버 — 한국 한정 advisory).

KISA 공식 RSS feed 미제공 (2026-05-28 확인). 대신 보안공지 게시판 HTML
스크래핑으로 수집:
  - 목록 페이지: bbs/list.do?menuNo=205020&bbsId=B0000133
  - 게시물 행: <tr><td class="num">번호</td><td class="sbj tal"><a href="...">제목</a></td>
              <td>등록일</td>...
  - 게시물 URL: bbs/view.do?...&nttId=NNNNN

CVE 는 제목·본문에서 정규식 추출.
"""

from __future__ import annotations

import hashlib
import html
import logging
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx

logger = logging.getLogger("collect_cmdb")

KISA_LIST_URL = "https://www.boho.or.kr/kr/bbs/list.do?menuNo=205020&bbsId=B0000133"
KISA_VIEW_BASE = "https://www.boho.or.kr"

# RSS 호환 함수명 유지 — handler 가 import 함
KISA_RSS_URL = KISA_LIST_URL                              # 별칭

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# 게시물 행 매칭 — <tr> 안에 num/title/date 컬럼이 순서대로
ROW_RE = re.compile(
    r'<tr[^>]*>\s*'
    r'<td[^>]*class="num"[^>]*>(?P<num>[^<]*)</td>\s*'
    r'<td[^>]*class="sbj[^"]*"[^>]*>\s*'
    r'<a\s+href="(?P<href>[^"]+)"[^>]*>(?P<title>.*?)</a>',
    re.DOTALL | re.IGNORECASE,
)

# 등록일 컬럼 — 행 안 어딘가 yyyy-mm-dd 형태
DATE_RE = re.compile(r"\b(20\d{2})[-./](\d{1,2})[-./](\d{1,2})\b")


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

    Pattern 1: ?nttId=12345 → KISA-12345 (HTML 게시판)
    Pattern 2: ?bulletin_writing_sequence=12345 → KISA-12345 (legacy)
    Pattern 3: 둘 다 없으면 URL 해시 fallback
    """
    parsed = urlparse(link)
    qs = parse_qs(parsed.query)
    seq = qs.get("nttId", [None])[0] or qs.get("bulletin_writing_sequence", [None])[0]
    if seq:
        return f"KISA-{seq}"
    h = hashlib.md5(link.encode("utf-8")).hexdigest()[:8]
    return f"KISA-{h}"


def _parse_date(s: str | None) -> date | None:
    """yyyy-mm-dd 형태 추출."""
    if not s:
        return None
    m = DATE_RE.search(s)
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


# RSS 호환 — 동일 이름 유지 (handler 가 import)
_parse_pubdate = _parse_date


def fetch_kisa_rss(url: str = KISA_LIST_URL, timeout: int = 60) -> str:
    """KISA 보안공지 HTML 목록 페이지 다운로드 (RSS 호환 함수명).

    HTML 게시판으로 전환됨 (RSS 미제공).
    """
    logger.info("KISA 목록 페이지 다운로드: %s", url)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        text = resp.text
    logger.info("KISA HTML %d bytes 다운로드 완료", len(text))
    return text


def _strip_tags(s: str) -> str:
    """간단 HTML 태그 제거 + entity decode."""
    s = re.sub(r"<[^>]+>", "", s)
    return html.unescape(s).strip()


def parse_kisa_rss(html_text: str) -> list[KisaAdvisory]:
    """KISA 게시판 HTML → KisaAdvisory 리스트 (RSS 호환 함수명).

    행 단위로 <tr>...</tr> 매칭 후 num/sbj/제목/등록일 추출. CVE 는 제목에서
    정규식 추출 (본문은 별도 fetch 안 함 — 목록 페이지 수준).
    """
    items: list[KisaAdvisory] = []
    for tr_match in re.finditer(r"<tr[^>]*>(.*?)</tr>", html_text, re.DOTALL):
        tr = tr_match.group(0)
        row_m = ROW_RE.search(tr)
        if not row_m:
            continue

        href = html.unescape(row_m.group("href"))
        if not href.startswith("http"):
            href = KISA_VIEW_BASE + href

        title = _strip_tags(row_m.group("title"))
        if not title:
            continue

        # 등록일 — <tr> 안에 yyyy-mm-dd
        pub_date = _parse_date(tr)

        # CVE 는 제목에서만 추출 (본문 fetch 부담 회피)
        cve_set: dict[str, None] = {}
        for m in CVE_PATTERN.finditer(title):
            cve_set[m.group(0).upper()] = None

        items.append(KisaAdvisory(
            advisory_id=extract_advisory_id(href),
            title=title,
            description="",                     # 목록 페이지엔 본문 없음
            cve_ids=list(cve_set.keys()),
            source_url=href,
            published_at=pub_date,
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
