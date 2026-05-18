"""KEV Collector 단위 테스트."""

from __future__ import annotations

from datetime import date
from unittest.mock import MagicMock

from src.agents.kev_collector.collector import (
    _parse_date,
    transform_kev,
    upsert_kev_rows,
)


SAMPLE_VULNS = [
    {
        "cveID": "CVE-2024-1234",
        "vendorProject": "Microsoft",
        "product": "Windows",
        "vulnerabilityName": "Windows Kernel Privilege Escalation",
        "dateAdded": "2024-03-15",
        "shortDescription": "Kernel elevation-of-privilege",
        "requiredAction": "Apply patch",
        "dueDate": "2024-04-05",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Exploited in the wild",
    },
    {
        "cveID": "CVE-2023-5678",
        "vendorProject": "Apache",
        "product": "Log4j",
        "dateAdded": "2023-12-01",
        "knownRansomwareCampaignUse": "Unknown",
    },
    {
        # cveID 없는 엔트리 — 스킵 대상
        "vendorProject": "x",
        "product": "y",
    },
]


class TestParseDate:
    def test_valid(self):
        assert _parse_date("2024-03-15") == date(2024, 3, 15)

    def test_empty(self):
        assert _parse_date(None) is None
        assert _parse_date("") is None

    def test_invalid_format(self):
        assert _parse_date("2024/03/15") is None


class TestTransformKev:
    def test_basic(self):
        rows = transform_kev(SAMPLE_VULNS)
        assert len(rows) == 2

    def test_fields_mapped(self):
        rows = transform_kev(SAMPLE_VULNS)
        first = rows[0]
        assert first["cve_id"] == "CVE-2024-1234"
        assert first["vendor_project"] == "Microsoft"
        assert first["product"] == "Windows"
        assert first["date_added"] == date(2024, 3, 15)
        assert first["due_date"] == date(2024, 4, 5)
        assert first["known_ransomware_campaign_use"] == "Y"

    def test_ransomware_unknown(self):
        rows = transform_kev(SAMPLE_VULNS)
        second = rows[1]
        assert second["known_ransomware_campaign_use"] == "N"

    def test_skip_missing_cve_id(self):
        rows = transform_kev(SAMPLE_VULNS)
        ids = [r["cve_id"] for r in rows]
        assert None not in ids


class TestUpsertKevRows:
    def test_batch_calls(self):
        cursor = MagicMock()
        cursor.__enter__ = MagicMock(return_value=cursor)
        cursor.__exit__ = MagicMock(return_value=None)
        conn = MagicMock()
        conn.cursor = MagicMock(return_value=cursor)

        rows = transform_kev(SAMPLE_VULNS)
        count = upsert_kev_rows(conn, rows)
        assert count == 2
        assert cursor.execute.call_count == 2
