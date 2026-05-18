"""EPSS Collector 단위 테스트."""

from __future__ import annotations

import gzip
import io
from datetime import date
from unittest.mock import MagicMock, patch

from src.agents.epss_collector.collector import fetch_epss_csv, upsert_epss_rows


def _mock_csv_gz(csv_text: str) -> bytes:
    return gzip.compress(csv_text.encode("utf-8"))


SAMPLE_WITH_META = (
    "#model_version:v2023.03.01,score_date:2024-03-15T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2024-0001,0.12345,0.96789\n"
    "CVE-2024-0002,0.00100,0.10000\n"
    "CVE-2024-0003,0.99000,0.99999\n"
)

SAMPLE_NO_META = (
    "cve,epss,percentile\n"
    "CVE-2024-5555,0.50000,0.75000\n"
)


class TestFetchEpssCsv:
    @patch("src.agents.epss_collector.collector.httpx.Client")
    def test_with_meta_header(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.content = _mock_csv_gz(SAMPLE_WITH_META)
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client.get = MagicMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        score_date, rows = fetch_epss_csv("http://example/fake.gz")
        assert score_date == date(2024, 3, 15)
        assert len(rows) == 3
        assert rows[0]["cve_id"] == "CVE-2024-0001"
        assert rows[0]["epss"] == 0.12345
        assert rows[0]["percentile"] == 0.96789

    @patch("src.agents.epss_collector.collector.httpx.Client")
    def test_without_meta(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.content = _mock_csv_gz(SAMPLE_NO_META)
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client.get = MagicMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        score_date, rows = fetch_epss_csv("http://example/fake.gz")
        assert score_date is None
        assert len(rows) == 1
        assert rows[0]["cve_id"] == "CVE-2024-5555"

    @patch("src.agents.epss_collector.collector.httpx.Client")
    def test_plain_text_fallback(self, mock_client_cls):
        # gzip이 아닌 plain text로 응답하는 경우
        mock_resp = MagicMock()
        mock_resp.content = SAMPLE_NO_META.encode("utf-8")
        mock_resp.raise_for_status = MagicMock()
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=None)
        mock_client.get = MagicMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_client

        score_date, rows = fetch_epss_csv("http://example/fake.gz")
        assert len(rows) == 1


class TestUpsertEpssRows:
    def test_executes_batch(self):
        cursor = MagicMock()
        cursor.__enter__ = MagicMock(return_value=cursor)
        cursor.__exit__ = MagicMock(return_value=None)
        conn = MagicMock()
        conn.cursor = MagicMock(return_value=cursor)

        rows = [
            {"cve_id": "CVE-1", "epss": 0.1, "percentile": 0.5, "score_date": None},
            {"cve_id": "CVE-2", "epss": 0.2, "percentile": 0.6, "score_date": None},
        ]
        count = upsert_epss_rows(conn, rows, batch_size=10)
        assert count == 2
        assert cursor.executemany.call_count == 1
