"""asset_parser loader/handler 단위 테스트."""

from __future__ import annotations

import gzip
import io
import json
from unittest.mock import MagicMock, patch

from src.agents.asset_parser import loader
from src.agents.asset_parser.handler import lambda_handler


def _common_asset_json(source_id: str) -> dict:
    return {
        "source": "AWS_EC2",
        "source_id": source_id,
        "hostname": f"host-{source_id}",
        "ip_addresses": ["10.0.0.1"],
        "mac_addresses": [],
        "tags": {"Name": source_id},
        "raw_data": {"InstanceId": source_id},
        "collected_at": "2026-06-04T12:00:00Z",
    }


# ── loader.to_row ──
def test_to_row_serializes_collections():
    row = loader.to_row(_common_asset_json("i-1"))
    assert row["source"] == "AWS_EC2"
    assert row["source_id"] == "i-1"
    assert json.loads(row["ip_addresses"]) == ["10.0.0.1"]
    assert json.loads(row["mac_addresses"]) == []
    assert json.loads(row["tags"]) == {"Name": "i-1"}
    assert json.loads(row["raw_data"]) == {"InstanceId": "i-1"}


def test_to_row_null_raw_data():
    a = _common_asset_json("i-1")
    a["raw_data"] = None
    assert loader.to_row(a)["raw_data"] is None


def test_upsert_assets_executes_per_row():
    conn = MagicMock()
    cur = MagicMock()
    conn.cursor.return_value.__enter__.return_value = cur
    n = loader.upsert_assets(conn, [_common_asset_json("i-1"), _common_asset_json("i-2")])
    assert n == 2
    assert cur.execute.call_count == 2


# ── handler ──
def _s3_event(bucket: str, key: str) -> dict:
    return {"Records": [{"s3": {"bucket": {"name": bucket}, "object": {"key": key}}}]}


def _gz_body(*source_ids: str) -> dict:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        for sid in source_ids:
            gz.write((json.dumps(_common_asset_json(sid)) + "\n").encode())
    return {"Body": io.BytesIO(buf.getvalue())}


@patch("src.agents.asset_parser.handler.boto3")
@patch("src.agents.asset_parser.handler.dbm")
@patch("src.agents.asset_parser.handler.loader")
def test_handler_success(mock_loader, mock_dbm, mock_boto3):
    s3 = MagicMock()
    s3.get_object.return_value = _gz_body("i-1", "i-2")
    mock_boto3.client.return_value = s3
    mock_dbm.connect.return_value.__enter__.return_value = MagicMock()
    mock_loader.log_start.return_value = 7
    mock_loader.upsert_assets.return_value = 2

    result = lambda_handler(_s3_event("b", "AWS_EC2/20260604/run.jsonl.gz"), MagicMock())

    assert result["status"] == "SUCCESS"
    assert result["files_processed"] == 1
    assert result["rows_upserted"] == 2
    # source 는 key prefix 에서 추출
    assert mock_loader.log_start.call_args.args[1] == "AWS_EC2"
    s3.copy_object.assert_not_called()


@patch("src.agents.asset_parser.handler.boto3")
@patch("src.agents.asset_parser.handler.dbm")
@patch("src.agents.asset_parser.handler.loader")
def test_handler_quarantine_on_failure(mock_loader, mock_dbm, mock_boto3):
    s3 = MagicMock()
    s3.get_object.side_effect = RuntimeError("boom")
    mock_boto3.client.return_value = s3

    result = lambda_handler(_s3_event("b", "AWS_EC2/20260604/run.jsonl.gz"), MagicMock())

    assert result["status"] == "PARTIAL"
    assert result["failures"][0]["key"] == "AWS_EC2/20260604/run.jsonl.gz"
    # 실패 객체는 failed/ 로 격리
    s3.copy_object.assert_called_once()
    assert s3.copy_object.call_args.kwargs["Key"] == "failed/AWS_EC2/20260604/run.jsonl.gz"


@patch("src.agents.asset_parser.handler.boto3")
@patch("src.agents.asset_parser.handler.dbm")
def test_handler_skips_non_jsonl(mock_dbm, mock_boto3):
    s3 = MagicMock()
    mock_boto3.client.return_value = s3
    result = lambda_handler(_s3_event("b", "AWS_EC2/20260604/run.json"), MagicMock())
    assert result["files_processed"] == 0
    s3.get_object.assert_not_called()


def test_handler_no_records():
    assert lambda_handler({}, MagicMock())["status"] == "NO_RECORDS"
