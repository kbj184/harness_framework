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

# 제목에서 제품 키워드 추출 — affected_model 채움 (매칭은 LIKE %cpe_product%)
# 우선순위 순 (긴 키워드 먼저)
PRODUCT_KEYWORDS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"한컴(?:오피스)?|hancom", re.IGNORECASE),     "hancom"),
    (re.compile(r"안랩|ahnlab",            re.IGNORECASE),     "ahnlab"),
    (re.compile(r"cisco\s*ios\s*xe",       re.IGNORECASE),     "ios_xe"),
    (re.compile(r"cisco\s*ios",            re.IGNORECASE),     "ios"),
    (re.compile(r"cisco\s*asa",            re.IGNORECASE),     "asa"),
    (re.compile(r"cisco",                  re.IGNORECASE),     "cisco"),
    (re.compile(r"vmware\s*vcenter",       re.IGNORECASE),     "vcenter"),
    (re.compile(r"vmware",                 re.IGNORECASE),     "vmware"),
    (re.compile(r"windows\s*server",       re.IGNORECASE),     "windows_server"),
    (re.compile(r"windows\s*1[01]",        re.IGNORECASE),     "windows"),
    (re.compile(r"windows|윈도우",          re.IGNORECASE),     "windows"),
    (re.compile(r"microsoft",              re.IGNORECASE),     "microsoft"),
    (re.compile(r"chrome",                 re.IGNORECASE),     "chrome"),
    (re.compile(r"firefox",                re.IGNORECASE),     "firefox"),
    (re.compile(r"apache",                 re.IGNORECASE),     "apache"),
    (re.compile(r"nginx",                  re.IGNORECASE),     "nginx"),
    (re.compile(r"mysql",                  re.IGNORECASE),     "mysql"),
    (re.compile(r"oracle",                 re.IGNORECASE),     "oracle"),
    (re.compile(r"openssl",                re.IGNORECASE),     "openssl"),
    (re.compile(r"openssh",                re.IGNORECASE),     "openssh"),
    (re.compile(r"java",                   re.IGNORECASE),     "java"),
    (re.compile(r"node\.?js",              re.IGNORECASE),     "node"),
    (re.compile(r"adobe",                  re.IGNORECASE),     "adobe"),
    (re.compile(r"fortinet|forti(?:os|gate)?", re.IGNORECASE), "fortinet"),
    (re.compile(r"palo\s*alto|pan-os",     re.IGNORECASE),     "paloaltonetworks"),
    (re.compile(r"f5\s+big-?ip|big-?ip",   re.IGNORECASE),     "big-ip"),
    (re.compile(r"f5",                     re.IGNORECASE),     "f5"),
    (re.compile(r"juniper",                re.IGNORECASE),     "juniper"),
    (re.compile(r"sonicwall",              re.IGNORECASE),     "sonicwall"),
    (re.compile(r"리눅스|linux",           re.IGNORECASE),     "linux"),
    (re.compile(r"우분투|ubuntu",          re.IGNORECASE),     "ubuntu"),
    (re.compile(r"centos|레드햇|redhat",   re.IGNORECASE),     "redhat"),
    (re.compile(r"맥(?:os|북)|macos",      re.IGNORECASE),     "macos"),
    (re.compile(r"안드로이드|android",     re.IGNORECASE),     "android"),
    (re.compile(r"ios(?!\s*xe|s)",         re.IGNORECASE),     "iphone_os"),
]


def extract_product_keyword(title: str) -> str | None:
    """제목에서 첫 번째 매칭되는 제품 키워드 반환 (없으면 None)."""
    for pattern, product in PRODUCT_KEYWORDS:
        if pattern.search(title):
            return product
    return None

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


def fetch_kisa_detail(view_url: str, timeout: int = 30) -> str:
    """KISA 보안공지 상세 페이지 다운로드 (CVE/영향제품 추출용)."""
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(view_url)
        resp.raise_for_status()
        return resp.text


# 본문에서 영향제품/영향버전/심각도 추출용 정규식
SEVERITY_RE = re.compile(
    r"(긴급|높음|중요|중간|낮음|critical|high|medium|moderate|low)",
    re.IGNORECASE,
)
# "영향받는 제품"/"영향제품"/"영향버전" 키워드 인근의 텍스트 추출
AFFECTED_BLOCK_RE = re.compile(
    r"영향(?:\s*받는)?\s*(?:제품|버전|소프트웨어|시스템)[\s\S]{0,500}",
)
# 버전 패턴 (3.14.2, 17.9, v1.2.3, 3.x 등)
VERSION_PATTERN = re.compile(r"\b\d+(?:\.\d+){1,3}(?:\.x)?\b")

SEVERITY_NORMALIZE = {
    "긴급":      "critical",
    "critical":  "critical",
    "높음":      "high",
    "high":      "high",
    "중요":      "high",
    "중간":      "medium",
    "medium":    "medium",
    "moderate":  "medium",
    "낮음":      "low",
    "low":       "low",
}


def parse_kisa_detail(detail_html: str) -> dict[str, Any]:
    """KISA 본문 HTML → cve_ids + affected_model + affected_version + severity 추출.

    반환: {cve_ids: [...], affected_model: str|None, affected_version: str|None, severity: str|None}
    """
    text = _strip_tags(detail_html)   # HTML 태그 제거 + entity decode

    # CVE 추출 (중복 제거)
    cve_set: dict[str, None] = {}
    for m in CVE_PATTERN.finditer(detail_html):
        cve_set[m.group(0).upper()] = None
    cve_ids = list(cve_set.keys())

    # 영향제품/버전 블록 추출
    affected_block = ""
    block_m = AFFECTED_BLOCK_RE.search(text)
    if block_m:
        affected_block = block_m.group(0)

    # 영향제품 — 제품 키워드 추출 (블록 우선, 없으면 전체 텍스트)
    affected_model = extract_product_keyword(affected_block) or extract_product_keyword(text)

    # 영향버전 — 영향 블록에서 버전 패턴 추출
    versions: list[str] = []
    if affected_block:
        for m in VERSION_PATTERN.finditer(affected_block):
            v = m.group(0)
            if v not in versions:
                versions.append(v)
            if len(versions) >= 5:        # 최대 5개
                break
    affected_version = ", ".join(versions) if versions else None

    # 심각도
    severity = None
    sev_m = SEVERITY_RE.search(text)
    if sev_m:
        key = sev_m.group(1).lower()
        severity = SEVERITY_NORMALIZE.get(key)

    return {
        "cve_ids": cve_ids,
        "affected_model": affected_model,
        "affected_version": affected_version,
        "severity": severity,
    }


def enrich_with_detail(
    items: list[KisaAdvisory], *, max_items: int = 50, timeout: int = 30
) -> list[KisaAdvisory]:
    """각 KisaAdvisory 의 source_url 본문을 fetch 해서 cve_ids 등 보강.

    이미 cve_ids 가 있는 항목은 fetch 후 합산(append). 최대 max_items 까지 처리.
    """
    enriched: list[KisaAdvisory] = []
    for idx, item in enumerate(items[:max_items]):
        try:
            html_text = fetch_kisa_detail(item.source_url, timeout=timeout)
            detail = parse_kisa_detail(html_text)

            # cve_ids 합산 (제목 + 본문 dedupe)
            merged = list(dict.fromkeys((item.cve_ids or []) + detail["cve_ids"]))
            # affected_model — title 추출이 우선, 없으면 detail
            new_desc = item.description or detail["affected_model"] or ""

            enriched.append(KisaAdvisory(
                advisory_id=item.advisory_id,
                title=item.title,
                description=new_desc,
                cve_ids=merged,
                source_url=item.source_url,
                published_at=item.published_at,
            ))
            logger.debug(
                "KISA detail %s — cve=%d, model=%s, ver=%s, sev=%s",
                item.advisory_id, len(merged),
                detail["affected_model"], detail["affected_version"], detail["severity"],
            )
        except Exception:
            logger.exception("KISA detail fetch 실패 — skip: %s", item.advisory_id)
            enriched.append(item)
    if len(items) > max_items:
        enriched.extend(items[max_items:])
    logger.info("KISA detail enrich %d/%d 완료", min(len(items), max_items), len(items))
    return enriched


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
            description=extract_product_keyword(title) or "",   # affected_model 추론용
            cve_ids=list(cve_set.keys()),
            source_url=href,
            published_at=pub_date,
        ))

    logger.info("KISA 공지 %d건 파싱 완료", len(items))
    return items


def transform_kisa(items: list[KisaAdvisory]) -> list[dict[str, Any]]:
    """KisaAdvisory → DB upsert dict.

    description 필드에 extract_product_keyword 결과를 저장했음. 이것을 affected_model 로
    노출 → KISA cross-ref 매칭 SQL 에서 LIKE '%' || cpe_product || '%' 매칭 가능.
    """
    return [
        {
            "advisory_id": a.advisory_id,
            "vendor_source": "KISA",
            "severity": None,                       # KISA 본문 파싱 — 추후
            "title": a.title,
            "overview": a.title,                    # 목록 페이지엔 본문 없음 → 제목 재사용
            "affected_model": a.description or None,    # 제품 키워드 (hancom/windows/cisco 등)
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
    title            = EXCLUDED.title,
    overview         = EXCLUDED.overview,
    severity         = COALESCE(EXCLUDED.severity, tb_vendor_advisory.severity),
    affected_model   = COALESCE(EXCLUDED.affected_model, tb_vendor_advisory.affected_model),
    affected_version = COALESCE(EXCLUDED.affected_version, tb_vendor_advisory.affected_version),
    cve_ids          = EXCLUDED.cve_ids,
    source_url       = EXCLUDED.source_url,
    updated_at       = EXCLUDED.updated_at,
    fetched_at       = NOW()
"""


def upsert_advisory_rows(conn, rows: list[dict[str, Any]]) -> int:
    """tb_vendor_advisory UPSERT. 처리 행수 반환."""
    count = 0
    with conn.cursor() as cur:
        for r in rows:
            cur.execute(UPSERT_SQL, r)
            count += 1
    return count
