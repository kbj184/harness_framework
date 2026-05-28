"""KISA Collector 단위 테스트 (TDD).

KISA(한국인터넷진흥원) 보안공지 RSS 파싱 + tb_vendor_advisory UPSERT.
"""

from __future__ import annotations

from datetime import date
from unittest.mock import MagicMock

from src.agents.kisa_collector.collector import (
    extract_advisory_id,
    parse_kisa_rss,
    transform_kisa,
    upsert_advisory_rows,
)


# ───────────────────── KISA RSS 샘플 (실제 구조 모사) ─────────────────────
# KISA 보안공지 RSS — 일반적 RSS 2.0 + KISA 특유 link query string
KISA_RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>KISA 보안공지</title>
    <link>https://www.boho.or.kr/krcert/secNoticeList.do</link>
    <description>KISA 보안공지 RSS</description>
    <item>
      <title>[보안권고] OpenSSL 보안 취약점 (CVE-2024-1234)</title>
      <link>https://www.boho.or.kr/krcert/secNoticeView.do?bulletin_writing_sequence=12345</link>
      <description>OpenSSL 3.5.5 이하 버전에 영향. 즉시 업데이트 권고.</description>
      <pubDate>Fri, 15 Mar 2024 09:00:00 +0900</pubDate>
    </item>
    <item>
      <title>[보안공지] 한컴오피스 다중 취약점 (CVE-2024-9999, CVE-2024-9998)</title>
      <link>https://www.boho.or.kr/krcert/secNoticeView.do?bulletin_writing_sequence=12346</link>
      <description>한컴오피스 2022 이전 버전 영향. 패치 적용 권고.</description>
      <pubDate>Mon, 01 Apr 2024 10:00:00 +0900</pubDate>
    </item>
    <item>
      <title>[일반공지] 보안 인식 캠페인 안내</title>
      <link>https://www.boho.or.kr/krcert/secNoticeView.do?bulletin_writing_sequence=12347</link>
      <description>4월 보안 인식 캠페인 안내. CVE 정보 없음.</description>
      <pubDate>Tue, 02 Apr 2024 11:00:00 +0900</pubDate>
    </item>
  </channel>
</rss>
"""


class TestExtractAdvisoryId:
    def test_from_kisa_link(self):
        link = "https://www.boho.or.kr/krcert/secNoticeView.do?bulletin_writing_sequence=12345"
        assert extract_advisory_id(link) == "KISA-12345"

    def test_extra_params(self):
        link = "https://www.boho.or.kr/krcert/secNoticeView.do?foo=bar&bulletin_writing_sequence=99&baz=qux"
        assert extract_advisory_id(link) == "KISA-99"

    def test_no_seq_param(self):
        """seq 없는 경우 URL hash 기반 fallback."""
        link = "https://www.boho.or.kr/krcert/foo.do?x=y"
        result = extract_advisory_id(link)
        assert result.startswith("KISA-") and len(result) > 5


class TestParseKisaRss:
    def test_extracts_all_items(self):
        items = parse_kisa_rss(KISA_RSS)
        assert len(items) == 3

    def test_fields_populated(self):
        items = parse_kisa_rss(KISA_RSS)
        first = items[0]
        assert first.advisory_id == "KISA-12345"
        assert "OpenSSL" in first.title
        assert first.published_at == date(2024, 3, 15)

    def test_cve_extraction(self):
        items = parse_kisa_rss(KISA_RSS)
        openssl = items[0]
        assert openssl.cve_ids == ["CVE-2024-1234"]

        hancom = items[1]
        assert "CVE-2024-9999" in hancom.cve_ids
        assert "CVE-2024-9998" in hancom.cve_ids

    def test_no_cve_item(self):
        """일반공지(CVE 없음)도 포함하되 cve_ids 는 빈 배열."""
        items = parse_kisa_rss(KISA_RSS)
        general = items[2]
        assert general.cve_ids == []
        assert general.advisory_id == "KISA-12347"

    def test_source_url_preserved(self):
        items = parse_kisa_rss(KISA_RSS)
        assert "12345" in items[0].source_url


class TestTransformKisa:
    def test_to_db_rows(self):
        items = parse_kisa_rss(KISA_RSS)
        rows = transform_kisa(items)
        assert len(rows) == 3
        first = rows[0]
        assert first["advisory_id"] == "KISA-12345"
        assert first["vendor_source"] == "KISA"
        assert first["cve_ids"] == ["CVE-2024-1234"]
        assert first["source_url"]


class TestUpsertAdvisoryRows:
    def test_batch_calls(self):
        cursor = MagicMock()
        cursor.__enter__ = MagicMock(return_value=cursor)
        cursor.__exit__ = MagicMock(return_value=None)
        conn = MagicMock()
        conn.cursor = MagicMock(return_value=cursor)

        items = parse_kisa_rss(KISA_RSS)
        rows = transform_kisa(items)
        count = upsert_advisory_rows(conn, rows)
        assert count == 3
        assert cursor.execute.call_count == 3
