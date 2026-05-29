"""EOS Collector 단위 테스트 (TDD)."""

from __future__ import annotations

from datetime import date
from unittest.mock import MagicMock, patch

from src.agents.eos_collector.collector import (
    PRODUCTS,
    transform,
    upsert_rows,
)


# endoflife.date 응답 샘플 (실제 amazon-linux 응답 축약)
SAMPLE_AMAZON_LINUX = [
    {
        "cycle": "2023",
        "releaseDate": "2023-03-15",
        "eol": "2028-03-15",
        "support": "2025-06-30",
        "latest": "2023.6.20250218",
        "lts": True,
        "link": "https://endoflife.date/amazon-linux",
    },
    {
        "cycle": "2",
        "releaseDate": "2017-09-13",
        "eol": "2026-06-30",
        "support": "2024-06-30",
        "latest": "2.0.20250214",
        "lts": False,
        "link": "https://endoflife.date/amazon-linux",
    },
]

# extendedSupport 포함 케이스 (RHEL 패턴)
SAMPLE_RHEL = [
    {
        "cycle": "9",
        "releaseDate": "2022-05-17",
        "support": "2027-05-31",
        "eol": "2032-05-31",
        "extendedSupport": "2035-05-31",
        "latest": "9.5",
        "lts": False,
        "link": "https://endoflife.date/rhel",
    },
]


class TestTransform:
    def test_amazon_linux_rows(self):
        rows = transform("amazon-linux", SAMPLE_AMAZON_LINUX)
        assert len(rows) == 2
        amzn2023 = next(r for r in rows if r["cycle"] == "2023")
        assert amzn2023["product"] == "amazon-linux"
        assert amzn2023["eol_date"] == date(2028, 3, 15)
        assert amzn2023["support_date"] == date(2025, 6, 30)
        assert amzn2023["lts"] is True
        assert amzn2023["latest"] == "2023.6.20250218"

    def test_extended_support_mapped(self):
        rows = transform("rhel", SAMPLE_RHEL)
        rhel9 = rows[0]
        assert rhel9["extended_date"] == date(2035, 5, 31)
        assert rhel9["eol_date"] == date(2032, 5, 31)

    def test_missing_cycle_skipped(self):
        items = [{"eol": "2030-01-01"}]  # cycle 없음
        rows = transform("ubuntu", items)
        assert rows == []

    def test_eol_boolean_handled(self):
        # endoflife.date 가 가끔 eol: true (수명 끝) 또는 false (현재 지원) 반환
        items = [{"cycle": "20.04", "eol": True}]
        rows = transform("ubuntu", items)
        assert rows[0]["eol_date"] is None  # bool 은 NULL 로


class TestUpsertRows:
    def test_calls_upsert_per_row(self):
        conn = MagicMock()
        cur = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cur

        rows = transform("amazon-linux", SAMPLE_AMAZON_LINUX)
        count = upsert_rows(conn, rows)

        assert count == 2
        assert cur.execute.call_count == 2


class TestHandler:
    def test_handler_success_path(self):
        with patch("src.agents.eos_collector.handler.dbm") as mock_db, \
             patch("src.agents.eos_collector.handler.collect_all", return_value=(2, 2)) as mock_collect:
            mock_db.load_db_config.return_value = MagicMock()
            mock_db.connect.return_value.__enter__.return_value = MagicMock()
            mock_db.log_collection_start.return_value = 1

            from src.agents.eos_collector.handler import lambda_handler

            result = lambda_handler({}, None)

            assert result["status"] == "SUCCESS"
            assert result["upserted_count"] == 2
            mock_collect.assert_called_once()
            mock_db.log_collection_end.assert_called_once()

    def test_handler_custom_products(self):
        with patch("src.agents.eos_collector.handler.dbm") as mock_db, \
             patch("src.agents.eos_collector.handler.collect_all", return_value=(1, 1)) as mock_collect:
            mock_db.load_db_config.return_value = MagicMock()
            mock_db.connect.return_value.__enter__.return_value = MagicMock()
            mock_db.log_collection_start.return_value = 1

            from src.agents.eos_collector.handler import lambda_handler

            result = lambda_handler({"products": ["ubuntu"]}, None)

            assert result["status"] == "SUCCESS"
            assert result["products"] == ["ubuntu"]
            mock_collect.assert_called_once()
            _, kwargs = mock_collect.call_args
            assert kwargs["products"] == ["ubuntu"]

    def test_handler_failure_logs_and_returns(self):
        with patch("src.agents.eos_collector.handler.dbm") as mock_db, \
             patch("src.agents.eos_collector.handler.collect_all", side_effect=RuntimeError("boom")):
            mock_db.load_db_config.return_value = MagicMock()
            mock_db.connect.return_value.__enter__.return_value = MagicMock()
            mock_db.log_collection_start.return_value = 1

            from src.agents.eos_collector.handler import lambda_handler

            result = lambda_handler({}, None)

            assert result["status"] == "FAILED"
            assert "boom" in result["error"]


class TestProducts:
    def test_default_products_present(self):
        assert "amazon-linux" in PRODUCTS
        assert "rhel" in PRODUCTS
        assert "ubuntu" in PRODUCTS
