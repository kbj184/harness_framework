"""shared/models.py 단위 테스트."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from src.shared.models import AssetSource, BulkAssetPayload, BulkAssetResponse, CommonAsset


class TestAssetSource:
    def test_crowdstrike_value(self):
        assert AssetSource.CROWDSTRIKE == "CROWDSTRIKE"

    def test_all_sources_defined(self):
        assert set(AssetSource) == {
            AssetSource.CROWDSTRIKE,
            AssetSource.ACTIVE_DIRECTORY,
            AssetSource.SCCM,
            AssetSource.AWS,
            AssetSource.AWS_EC2,
        }


class TestCommonAsset:
    @pytest.fixture
    def valid_asset_data(self):
        return {
            "source": AssetSource.CROWDSTRIKE,
            "source_id": "abc123",
            "hostname": "server-01",
            "os_name": "Windows",
            "os_version": "10.0.19045",
            "ip_addresses": ["192.168.1.10"],
            "mac_addresses": ["AA:BB:CC:DD:EE:FF"],
            "collected_at": datetime.now(UTC),
        }

    def test_valid_asset(self, valid_asset_data):
        asset = CommonAsset(**valid_asset_data)
        assert asset.source == AssetSource.CROWDSTRIKE
        assert asset.source_id == "abc123"
        assert asset.hostname == "server-01"

    def test_minimal_asset(self):
        asset = CommonAsset(
            source=AssetSource.CROWDSTRIKE,
            source_id="min-001",
            collected_at=datetime.now(UTC),
        )
        assert asset.hostname is None
        assert asset.ip_addresses == []
        assert asset.tags == {}
        assert asset.raw_data is None

    def test_empty_source_id_fails(self):
        with pytest.raises(ValidationError):
            CommonAsset(
                source=AssetSource.CROWDSTRIKE,
                source_id="",
                collected_at=datetime.now(UTC),
            )

    def test_missing_source_fails(self):
        with pytest.raises(ValidationError):
            CommonAsset(source_id="abc", collected_at=datetime.now(UTC))  # type: ignore

    def test_missing_collected_at_fails(self):
        with pytest.raises(ValidationError):
            CommonAsset(source=AssetSource.CROWDSTRIKE, source_id="abc")  # type: ignore

    def test_tags_and_raw_data(self, valid_asset_data):
        valid_asset_data["tags"] = {"env": "prod", "team": "infra"}
        valid_asset_data["raw_data"] = {"original_field": "value"}
        asset = CommonAsset(**valid_asset_data)
        assert asset.tags["env"] == "prod"
        assert asset.raw_data["original_field"] == "value"

    def test_serialization_roundtrip(self, valid_asset_data):
        asset = CommonAsset(**valid_asset_data)
        json_str = asset.model_dump_json()
        restored = CommonAsset.model_validate_json(json_str)
        assert restored.source_id == asset.source_id
        assert restored.source == asset.source


class TestBulkAssetPayload:
    def test_valid_payload(self):
        now = datetime.now(UTC)
        assets = [CommonAsset(source=AssetSource.CROWDSTRIKE, source_id=f"dev-{i}", collected_at=now) for i in range(3)]
        payload = BulkAssetPayload(source=AssetSource.CROWDSTRIKE, collected_at=now, assets=assets)
        assert len(payload.assets) == 3
        assert payload.source == AssetSource.CROWDSTRIKE

    def test_empty_assets(self):
        payload = BulkAssetPayload(
            source=AssetSource.CROWDSTRIKE,
            collected_at=datetime.now(UTC),
            assets=[],
        )
        assert payload.assets == []


class TestBulkAssetResponse:
    def test_success_response(self):
        resp = BulkAssetResponse(success=True, total_count=100, created_count=80, updated_count=20)
        assert resp.success is True
        assert resp.error_message is None

    def test_error_response(self):
        resp = BulkAssetResponse(success=False, error_message="DB connection failed")
        assert resp.success is False
        assert resp.total_count == 0
