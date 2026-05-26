"""crowdstrike_apps transformer 단위 테스트."""

from __future__ import annotations

import json
from datetime import datetime

from src.agents.crowdstrike_apps.transformer import transform

SAMPLE_RAW = {
    "id": "872c8eca9e81464baa63f7620b64f0d9_9d36ad11b421e26112ace01d29b498d96fdf5901065030a8a1afda8fc79c4b16",
    "cid": "872c8eca9e81464baa63f7620b64f0d9",
    "name": "Windows",
    "vendor": "Microsoft",
    "version": "10.0.17763.1697",
    "software_type": "application",
    "name_vendor": "Windows-Microsoft",
    "name_vendor_version": "Windows-Microsoft-10.0.17763.1697",
    "versioning_scheme": "unknown",
    "category": "System tools",
    "last_used_user_name": "EC2AMAZ-BCTCLIP$",
    "last_used_user_sid": "S-1-5-18",
    "last_used_file_name": "DismHost.exe",
    "last_used_file_hash": "2fb529de54d39308398e59cc7fa5caef1acf81a13bccdd645950e7f88d3842e1",
    "last_used_timestamp": "2026-05-21T10:00:00Z",
    "first_seen_timestamp": "2025-08-01T00:00:00Z",
    "is_suspicious": False,
    "is_normalized": True,
    "host": {
        "aid": "bf477d80c5ba4d079fcecb9fec81a234",
        "hostname": "EC2AMAZ-BCTCLIP",
        "platform_name": "Windows",
        "os_version": "Windows Server 2019",
    },
}


class TestTransformBasic:
    def test_single_row(self):
        rows = transform([SAMPLE_RAW])
        assert len(rows) == 1
        r = rows[0]
        assert r["cs_app_id"] == SAMPLE_RAW["id"]
        assert r["cs_agent_id"] == "bf477d80c5ba4d079fcecb9fec81a234"
        assert r["asset_id_hash"] is None  # backfill 단계에서 채움
        assert r["name"] == "Windows"
        assert r["vendor"] == "Microsoft"
        assert r["version"] == "10.0.17763.1697"
        assert r["name_vendor_version"] == "Windows-Microsoft-10.0.17763.1697"
        assert r["category"] == "System tools"
        assert r["host_hostname"] == "EC2AMAZ-BCTCLIP"
        assert r["is_normalized"] is True
        assert r["is_suspicious"] is False

    def test_timestamp_parsing(self):
        rows = transform([SAMPLE_RAW])
        r = rows[0]
        assert r["last_used_timestamp"] == datetime(2026, 5, 21, 10, 0, 0)
        assert r["first_seen_timestamp"] == datetime(2025, 8, 1, 0, 0, 0)

    def test_raw_data_preserved(self):
        rows = transform([SAMPLE_RAW])
        raw = json.loads(rows[0]["raw_data"])
        assert raw["id"] == SAMPLE_RAW["id"]
        assert raw["host"]["aid"] == "bf477d80c5ba4d079fcecb9fec81a234"


class TestTransformEdgeCases:
    def test_missing_host_skips(self):
        raw = {**SAMPLE_RAW, "host": None}
        rows = transform([raw])
        assert rows == []

    def test_missing_aid_skips(self):
        raw = {**SAMPLE_RAW, "host": {"hostname": "x"}}
        rows = transform([raw])
        assert rows == []

    def test_invalid_timestamp_becomes_none(self):
        raw = {**SAMPLE_RAW, "last_used_timestamp": "not-a-date"}
        rows = transform([raw])
        assert rows[0]["last_used_timestamp"] is None

    def test_long_name_truncated(self):
        raw = {**SAMPLE_RAW, "name": "x" * 600}
        rows = transform([raw])
        assert len(rows[0]["name"]) == 500

    def test_minimal_fields(self):
        raw = {
            "id": "min-app-001",
            "host": {"aid": "min-host-001"},
        }
        rows = transform([raw])
        assert len(rows) == 1
        r = rows[0]
        assert r["cs_app_id"] == "min-app-001"
        assert r["cs_agent_id"] == "min-host-001"
        assert r["name"] is None
        assert r["vendor"] is None

    def test_batch_partial_failure(self):
        rows = transform([SAMPLE_RAW, {"id": "no-host", "host": None}, SAMPLE_RAW])
        assert len(rows) == 2  # 가운데 항목 스킵


class TestUpsertSql:
    def test_sql_has_required_columns(self):
        from src.agents.crowdstrike_apps.collector import UPSERT_SQL
        for col in [
            "cs_app_id", "cs_agent_id", "asset_id_hash",
            "name", "vendor", "version",
            "name_vendor_version", "is_normalized",
            "raw_data", "fetched_at",
        ]:
            assert col in UPSERT_SQL

    def test_sql_has_on_conflict(self):
        from src.agents.crowdstrike_apps.collector import UPSERT_SQL
        assert "ON CONFLICT (cs_app_id)" in UPSERT_SQL
