"""CrowdStrike transformer 단위 테스트."""

from datetime import UTC, datetime

from src.agents.crowdstrike.models import CrowdStrikeDevice
from src.agents.crowdstrike.transformer import transform_device, transform_devices
from src.shared.models import AssetSource

COLLECTED_AT = datetime(2026, 4, 16, 10, 0, 0, tzinfo=UTC)

SAMPLE_RAW = {
    "device_id": "abc123",
    "hostname": "server-01",
    "local_ip": "192.168.1.10",
    "external_ip": "203.0.113.1",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "os_version": "Windows 10",
    "os_build": "19045",
    "platform_name": "Windows",
    "system_manufacturer": "Dell Inc.",
    "system_product_name": "OptiPlex 7080",
    "serial_number": "SN12345",
    "agent_version": "7.10.16303.0",
    "last_seen": "2026-04-16T01:00:00Z",
    "first_seen": "2025-01-15T08:00:00Z",
    "machine_domain": "corp.example.com",
    "tags": ["SensorGroupingTags/env:prod", "FalconGroupingTags/team:infra"],
    "product_type_desc": "Workstation",
    "status": "normal",
    "service_provider": None,
}


class TestTransformDevice:
    def test_basic_fields(self):
        device = CrowdStrikeDevice(**SAMPLE_RAW)
        asset = transform_device(device, COLLECTED_AT)

        assert asset.source == AssetSource.CROWDSTRIKE
        assert asset.source_id == "abc123"
        assert asset.hostname == "server-01"
        assert asset.os_name == "Windows"
        assert asset.os_version == "Windows 10"
        assert asset.os_build == "19045"
        assert asset.serial_number == "SN12345"
        assert asset.manufacturer == "Dell Inc."
        assert asset.model == "OptiPlex 7080"
        assert asset.agent_version == "7.10.16303.0"
        assert asset.domain == "corp.example.com"
        assert asset.collected_at == COLLECTED_AT

    def test_ip_addresses(self):
        device = CrowdStrikeDevice(**SAMPLE_RAW)
        asset = transform_device(device, COLLECTED_AT)

        assert "192.168.1.10" in asset.ip_addresses
        assert "203.0.113.1" in asset.ip_addresses
        assert len(asset.ip_addresses) == 2

    def test_ip_dedup_when_same(self):
        data = {**SAMPLE_RAW, "external_ip": "192.168.1.10"}
        device = CrowdStrikeDevice(**data)
        asset = transform_device(device, COLLECTED_AT)

        assert asset.ip_addresses == ["192.168.1.10"]

    def test_mac_addresses(self):
        device = CrowdStrikeDevice(**SAMPLE_RAW)
        asset = transform_device(device, COLLECTED_AT)

        assert asset.mac_addresses == ["AA:BB:CC:DD:EE:FF"]

    def test_datetime_parsing(self):
        device = CrowdStrikeDevice(**SAMPLE_RAW)
        asset = transform_device(device, COLLECTED_AT)

        assert asset.last_seen == datetime(2026, 4, 16, 1, 0, 0, tzinfo=UTC)
        assert asset.first_seen == datetime(2025, 1, 15, 8, 0, 0, tzinfo=UTC)

    def test_tags_parsing(self):
        device = CrowdStrikeDevice(**SAMPLE_RAW)
        asset = transform_device(device, COLLECTED_AT)

        assert asset.tags["SensorGroupingTags"] == "env:prod"
        assert asset.tags["FalconGroupingTags"] == "team:infra"
        assert asset.tags["product_type"] == "Workstation"
        assert asset.tags["status"] == "normal"

    def test_raw_data_preserved(self):
        device = CrowdStrikeDevice(**SAMPLE_RAW)
        asset = transform_device(device, COLLECTED_AT)

        assert asset.raw_data is not None
        assert asset.raw_data["device_id"] == "abc123"

    def test_minimal_device(self):
        device = CrowdStrikeDevice(device_id="min-001")
        asset = transform_device(device, COLLECTED_AT)

        assert asset.source_id == "min-001"
        assert asset.hostname is None
        assert asset.ip_addresses == []
        assert asset.mac_addresses == []
        assert asset.last_seen is None

    def test_invalid_datetime_handled(self):
        data = {**SAMPLE_RAW, "last_seen": "not-a-date"}
        device = CrowdStrikeDevice(**data)
        asset = transform_device(device, COLLECTED_AT)

        assert asset.last_seen is None


class TestTransformDevices:
    def test_batch_transform(self):
        devices = [CrowdStrikeDevice(device_id=f"dev-{i}", hostname=f"host-{i}") for i in range(5)]
        assets = transform_devices(devices, COLLECTED_AT)

        assert len(assets) == 5
        assert all(a.source == AssetSource.CROWDSTRIKE for a in assets)

    def test_default_collected_at(self):
        devices = [CrowdStrikeDevice(device_id="dev-0")]
        assets = transform_devices(devices)

        assert len(assets) == 1
        assert assets[0].collected_at is not None

    def test_empty_list(self):
        assert transform_devices([]) == []
