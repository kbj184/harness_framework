"""shared/s3_client 단위 테스트."""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from src.shared.models import AssetSource, CommonAsset
from src.shared.s3_client import put_assets


def _asset(source_id: str) -> CommonAsset:
    return CommonAsset(
        source=AssetSource.AWS_EC2,
        source_id=source_id,
        hostname=f"host-{source_id}",
        ip_addresses=["10.0.0.1"],
        collected_at=datetime(2026, 6, 4, 12, 0, 0, tzinfo=UTC),
    )


def test_put_assets_key_and_payload(monkeypatch):
    monkeypatch.setenv("ASSET_RAW_BUCKET", "test-bucket")
    s3 = MagicMock()
    collected_at = datetime(2026, 6, 4, 12, 0, 0, tzinfo=UTC)

    key = put_assets([_asset("i-1"), _asset("i-2")], "AWS_EC2", collected_at, s3_client=s3)

    assert key.startswith("AWS_EC2/20260604/")
    assert key.endswith(".jsonl.gz")
    s3.put_object.assert_called_once()
    kwargs = s3.put_object.call_args.kwargs
    assert kwargs["Bucket"] == "test-bucket"
    assert kwargs["Key"] == key
    # gzip JSONL 검증 — 2줄, 각 줄이 CommonAsset
    lines = gzip.decompress(kwargs["Body"]).decode("utf-8").splitlines()
    assert len(lines) == 2
    assert {json.loads(lines[0])["source_id"], json.loads(lines[1])["source_id"]} == {"i-1", "i-2"}
    assert json.loads(lines[0])["source"] == "AWS_EC2"


def test_put_assets_empty_raises(monkeypatch):
    monkeypatch.setenv("ASSET_RAW_BUCKET", "test-bucket")
    with pytest.raises(ValueError):
        put_assets([], "AWS_EC2", datetime(2026, 6, 4, tzinfo=UTC), s3_client=MagicMock())


def test_put_assets_missing_bucket_raises(monkeypatch):
    monkeypatch.delenv("ASSET_RAW_BUCKET", raising=False)
    with pytest.raises(RuntimeError):
        put_assets([_asset("i-1")], "AWS_EC2", datetime(2026, 6, 4, tzinfo=UTC), s3_client=MagicMock())
