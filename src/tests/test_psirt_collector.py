"""PSIRT Collector 단위 테스트 (TDD).

4 벤더 PSIRT (Cisco / F5 / Palo Alto / Fortinet) 통합 수집.
"""

from __future__ import annotations

from datetime import date
from unittest.mock import MagicMock

from src.agents.psirt_collector.collector import (
    extract_affected_versions,
    parse_cisco_advisories,
    parse_fortinet_html,
    parse_psirt_rss,
    transform_psirt,
    upsert_advisory_rows,
)


# ───────────────────── Fortinet PSIRT HTML 샘플 (fortiguard.com/psirt 구조 모사) ─────────────────────

FORTINET_HTML = """
<html><body>
<section class="table-body">
  <div class="container-xxl">
    <div class="row" onclick="location.href = '/psirt/FG-IR-26-131'">
      <div class="col-md-3">
        <b>FG-IR-26-131 Command injection in CLI</b>
        <br>
        <b class="cve">CVE-2025-53680</b>
      </div>
      <div class="col-md-2">
        <p><b> Medium </b></p>
      </div>
    </div>
    <div class="row" onclick="location.href = '/psirt/FG-IR-26-137'">
      <div class="col-md-3">
        <b>FG-IR-26-137 DoS due to unsafe function</b>
        <br>
        <b class="cve">CVE-2025-67604</b>
      </div>
      <div class="col-md-2">
        <p><b> High </b></p>
      </div>
    </div>
    <div class="row" onclick="location.href = '/psirt/FG-IR-26-136'">
      <div class="col-md-3">
        <b>FG-IR-26-136 Incorrect authorization (CVE-less)</b>
      </div>
      <div class="col-md-2">
        <p><b> Critical </b></p>
      </div>
    </div>
  </div>
</section>
</body></html>
"""


class TestParseFortinetHtml:
    def test_extracts_items(self):
        items = parse_fortinet_html(FORTINET_HTML)
        assert len(items) == 3

    def test_advisory_ids(self):
        items = parse_fortinet_html(FORTINET_HTML)
        ids = sorted(i.advisory_id for i in items)
        assert ids == ["FG-IR-26-131", "FG-IR-26-136", "FG-IR-26-137"]

    def test_vendor_source(self):
        items = parse_fortinet_html(FORTINET_HTML)
        assert all(i.vendor_source == "PSIRT_FORTI" for i in items)

    def test_cve_extraction(self):
        items = parse_fortinet_html(FORTINET_HTML)
        first = next(i for i in items if i.advisory_id == "FG-IR-26-131")
        assert first.cve_ids == ["CVE-2025-53680"]

    def test_no_cve_item(self):
        items = parse_fortinet_html(FORTINET_HTML)
        no_cve = next(i for i in items if i.advisory_id == "FG-IR-26-136")
        assert no_cve.cve_ids == []

    def test_severity_lowercased(self):
        items = parse_fortinet_html(FORTINET_HTML)
        sev_map = {i.advisory_id: i.severity for i in items}
        assert sev_map["FG-IR-26-131"] == "medium"
        assert sev_map["FG-IR-26-137"] == "high"
        assert sev_map["FG-IR-26-136"] == "critical"

    def test_source_url_absolute(self):
        items = parse_fortinet_html(FORTINET_HTML)
        first = next(i for i in items if i.advisory_id == "FG-IR-26-131")
        assert first.source_url == "https://www.fortiguard.com/psirt/FG-IR-26-131"


# ───────────────────── Cisco openVuln API JSON 샘플 ─────────────────────

CISCO_JSON = {
    "advisories": [
        {
            "advisoryId": "cisco-sa-ios-xe-rce-2024-01",
            "advisoryTitle": "Cisco IOS XE Software Web UI RCE",
            "summary": "Cisco IOS XE 17.9 이하 Web UI 원격 코드 실행 취약점.",
            "sir": "Critical",
            "cves": ["CVE-2024-1234", "CVE-2024-1235"],
            "productNames": ["Cisco IOS XE Software"],
            "firstPublished": "2024-01-15T15:00:00Z",
            "lastUpdated": "2024-02-01T10:00:00Z",
            "publicationUrl": "https://sec.cloudapps.cisco.com/security/center/content/cisco-sa-ios-xe-rce-2024-01",
            "platforms": ["Catalyst 9200", "Catalyst 9300"],
        },
        {
            "advisoryId": "cisco-sa-asa-dos-2024-02",
            "advisoryTitle": "Cisco ASA DoS",
            "summary": "ASA 9.18 이하.",
            "sir": "High",
            "cves": ["CVE-2024-5678"],
            "productNames": ["Cisco ASA"],
            "firstPublished": "2024-02-20T15:00:00Z",
            "publicationUrl": "https://sec.cloudapps.cisco.com/security/center/content/cisco-sa-asa-dos-2024-02",
        },
    ]
}


class TestParseCiscoAdvisories:
    def test_extracts_all(self):
        items = parse_cisco_advisories(CISCO_JSON)
        assert len(items) == 2

    def test_advisory_id_and_source(self):
        items = parse_cisco_advisories(CISCO_JSON)
        first = items[0]
        assert first.advisory_id == "cisco-sa-ios-xe-rce-2024-01"
        assert first.vendor_source == "PSIRT_CISCO"

    def test_cve_ids(self):
        items = parse_cisco_advisories(CISCO_JSON)
        first = items[0]
        assert first.cve_ids == ["CVE-2024-1234", "CVE-2024-1235"]

    def test_severity_mapping(self):
        items = parse_cisco_advisories(CISCO_JSON)
        assert items[0].severity == "critical"
        assert items[1].severity == "high"

    def test_affected_model(self):
        items = parse_cisco_advisories(CISCO_JSON)
        first = items[0]
        assert "Cisco IOS XE Software" in first.affected_model

    def test_published_at_parsed(self):
        items = parse_cisco_advisories(CISCO_JSON)
        assert items[0].published_at == date(2024, 1, 15)


# ───────────────────── RSS 샘플 (F5/PA/Fortinet 공용 구조) ─────────────────────

F5_RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>F5 K-Articles Security Advisory</title>
    <item>
      <title>K12345: BIG-IP TMUI vulnerability (CVE-2024-9999)</title>
      <link>https://my.f5.com/manage/s/article/K12345</link>
      <description>BIG-IP 16.x TMUI auth bypass.</description>
      <pubDate>Mon, 15 Mar 2024 09:00:00 +0000</pubDate>
    </item>
    <item>
      <title>K12346: NGINX worker process RCE (CVE-2024-8888)</title>
      <link>https://my.f5.com/manage/s/article/K12346</link>
      <description>NGINX 1.20 이하.</description>
      <pubDate>Tue, 16 Mar 2024 10:00:00 +0000</pubDate>
    </item>
  </channel>
</rss>
"""


class TestParsePsirtRss:
    def test_extracts_items(self):
        items = parse_psirt_rss(F5_RSS, vendor_source="PSIRT_F5", id_prefix="K")
        assert len(items) == 2

    def test_vendor_source(self):
        items = parse_psirt_rss(F5_RSS, vendor_source="PSIRT_F5", id_prefix="K")
        assert all(i.vendor_source == "PSIRT_F5" for i in items)

    def test_advisory_id_from_title(self):
        """제목에서 id_prefix + 숫자 패턴(K12345) 추출."""
        items = parse_psirt_rss(F5_RSS, vendor_source="PSIRT_F5", id_prefix="K")
        ids = sorted(i.advisory_id for i in items)
        assert ids == ["K12345", "K12346"]

    def test_cve_extraction(self):
        items = parse_psirt_rss(F5_RSS, vendor_source="PSIRT_F5", id_prefix="K")
        first = next(i for i in items if i.advisory_id == "K12345")
        assert first.cve_ids == ["CVE-2024-9999"]

    def test_pubdate_parsed(self):
        items = parse_psirt_rss(F5_RSS, vendor_source="PSIRT_F5", id_prefix="K")
        first = next(i for i in items if i.advisory_id == "K12345")
        assert first.published_at == date(2024, 3, 15)


# ───────────────────── affected_versions 추출 ─────────────────────

class TestExtractAffectedVersions:
    def test_version_range(self):
        text = "Cisco IOS XE 17.9 이하"
        result = extract_affected_versions(text)
        assert "17.9" in result

    def test_no_version(self):
        text = "취약점 설명만 있음"
        result = extract_affected_versions(text)
        assert result == ""


# ───────────────────── transform / upsert ─────────────────────

class TestTransformPsirt:
    def test_combined_sources(self):
        cisco = parse_cisco_advisories(CISCO_JSON)
        f5 = parse_psirt_rss(F5_RSS, vendor_source="PSIRT_F5", id_prefix="K")
        rows = transform_psirt(cisco + f5)
        sources = {r["vendor_source"] for r in rows}
        assert sources == {"PSIRT_CISCO", "PSIRT_F5"}


class TestUpsertAdvisoryRows:
    def test_batch_calls(self):
        cursor = MagicMock()
        cursor.__enter__ = MagicMock(return_value=cursor)
        cursor.__exit__ = MagicMock(return_value=None)
        conn = MagicMock()
        conn.cursor = MagicMock(return_value=cursor)

        cisco = parse_cisco_advisories(CISCO_JSON)
        f5 = parse_psirt_rss(F5_RSS, vendor_source="PSIRT_F5", id_prefix="K")
        rows = transform_psirt(cisco + f5)

        count = upsert_advisory_rows(conn, rows)
        assert count == len(rows)
        assert cursor.execute.call_count == len(rows)
