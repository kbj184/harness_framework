"""KISA Collector 단위 테스트 (TDD).

KISA 보안공지 HTML 게시판 스크래핑 + tb_vendor_advisory UPSERT.
(공식 RSS 미제공 — 2026-05-28 확인 후 HTML scrape 로 전환)
"""

from __future__ import annotations

from datetime import date
from unittest.mock import MagicMock

from src.agents.kisa_collector.collector import (
    extract_advisory_id,
    parse_kisa_rss,                                   # HTML 입력으로 변경됨
    transform_kisa,
    upsert_advisory_rows,
)


# ───────────────────── KISA HTML 게시판 샘플 ─────────────────────
# 실제 구조: <tr><td class="num">번호</td><td class="sbj tal"><a href="...nttId=...">제목</a></td><td>등록일</td>
KISA_HTML = """
<html><body>
<table class="board_list">
  <tbody>
    <tr>
      <td class="num">2442</td>
      <td class="sbj tal">
        <a href="/kr/bbs/view.do?menuNo=205020&amp;bbsId=B0000133&amp;nttId=72071">
          7-Zip 제품 보안 업데이트 권고 (CVE-2026-1234)
        </a>
      </td>
      <td class="writer">KISA</td>
      <td class="date">2026-05-15</td>
    </tr>
    <tr>
      <td class="num">2441</td>
      <td class="sbj tal">
        <a href="/kr/bbs/view.do?menuNo=205020&amp;bbsId=B0000133&amp;nttId=72069">
          한컴오피스 다중 취약점 (CVE-2026-9999, CVE-2026-9998)
        </a>
      </td>
      <td class="writer">KISA</td>
      <td class="date">2026-05-10</td>
    </tr>
    <tr>
      <td class="num">2440</td>
      <td class="sbj tal">
        <a href="/kr/bbs/view.do?menuNo=205020&amp;bbsId=B0000133&amp;nttId=72068">
          NVIDIA 제품 보안 권고
        </a>
      </td>
      <td class="writer">KISA</td>
      <td class="date">2026-05-05</td>
    </tr>
  </tbody>
</table>
</body></html>
"""


class TestExtractAdvisoryId:
    def test_from_nttid(self):
        link = "https://www.boho.or.kr/kr/bbs/view.do?menuNo=205020&bbsId=B0000133&nttId=72071"
        assert extract_advisory_id(link) == "KISA-72071"

    def test_legacy_bulletin_seq(self):
        link = "https://www.boho.or.kr/krcert/secNoticeView.do?bulletin_writing_sequence=12345"
        assert extract_advisory_id(link) == "KISA-12345"

    def test_no_id_param(self):
        """nttId / bulletin seq 둘 다 없으면 URL 해시 fallback."""
        link = "https://www.boho.or.kr/krcert/foo.do?x=y"
        result = extract_advisory_id(link)
        assert result.startswith("KISA-") and len(result) > 5


class TestParseKisaHtml:
    def test_extracts_all_items(self):
        items = parse_kisa_rss(KISA_HTML)
        assert len(items) == 3

    def test_advisory_id(self):
        items = parse_kisa_rss(KISA_HTML)
        ids = sorted(i.advisory_id for i in items)
        assert ids == ["KISA-72068", "KISA-72069", "KISA-72071"]

    def test_title_clean(self):
        items = parse_kisa_rss(KISA_HTML)
        first = next(i for i in items if i.advisory_id == "KISA-72071")
        assert "7-Zip" in first.title
        assert "<" not in first.title and "&amp;" not in first.title

    def test_cve_extraction(self):
        items = parse_kisa_rss(KISA_HTML)
        zip7 = next(i for i in items if i.advisory_id == "KISA-72071")
        assert zip7.cve_ids == ["CVE-2026-1234"]

        hancom = next(i for i in items if i.advisory_id == "KISA-72069")
        assert "CVE-2026-9999" in hancom.cve_ids
        assert "CVE-2026-9998" in hancom.cve_ids

    def test_no_cve_item(self):
        """제목에 CVE 없으면 cve_ids 빈 배열."""
        items = parse_kisa_rss(KISA_HTML)
        nvidia = next(i for i in items if i.advisory_id == "KISA-72068")
        assert nvidia.cve_ids == []

    def test_source_url_absolute(self):
        """상대 경로 → 절대 URL 변환."""
        items = parse_kisa_rss(KISA_HTML)
        first = next(i for i in items if i.advisory_id == "KISA-72071")
        assert first.source_url.startswith("https://www.boho.or.kr/")
        assert "nttId=72071" in first.source_url

    def test_published_at(self):
        items = parse_kisa_rss(KISA_HTML)
        first = next(i for i in items if i.advisory_id == "KISA-72071")
        assert first.published_at == date(2026, 5, 15)


class TestTransformKisa:
    def test_to_db_rows(self):
        items = parse_kisa_rss(KISA_HTML)
        rows = transform_kisa(items)
        assert len(rows) == 3
        first = next(r for r in rows if r["advisory_id"] == "KISA-72071")
        assert first["vendor_source"] == "KISA"
        assert first["cve_ids"] == ["CVE-2026-1234"]
        assert first["source_url"]


class TestUpsertAdvisoryRows:
    def test_batch_calls(self):
        cursor = MagicMock()
        cursor.__enter__ = MagicMock(return_value=cursor)
        cursor.__exit__ = MagicMock(return_value=None)
        conn = MagicMock()
        conn.cursor = MagicMock(return_value=cursor)

        items = parse_kisa_rss(KISA_HTML)
        rows = transform_kisa(items)
        count = upsert_advisory_rows(conn, rows)
        assert count == 3
        assert cursor.execute.call_count == 3
