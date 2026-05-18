"""CrowdStrike 디바이스 → CommonAsset 변환기."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from src.agents.crowdstrike.models import CrowdStrikeDevice
from src.shared.models import AssetSource, CommonAsset

logger = logging.getLogger("collect_cmdb")


def _parse_iso_datetime(value: str | None) -> datetime | None:
    """ISO 8601 문자열을 datetime으로 변환한다."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        logger.warning("날짜 파싱 실패: %s", value)
        return None


def _parse_os_fields(device: CrowdStrikeDevice) -> tuple[str | None, str | None]:
    """platform_name과 os_version에서 os_name, os_version을 추출한다."""
    os_name = device.platform_name  # Windows, Mac, Linux
    os_version = device.os_version
    return os_name, os_version


def _collect_ip_addresses(device: CrowdStrikeDevice) -> list[str]:
    """local_ip와 external_ip를 리스트로 합친다."""
    ips: list[str] = []
    if device.local_ip:
        ips.append(device.local_ip)
    if device.external_ip and device.external_ip != device.local_ip:
        ips.append(device.external_ip)
    return ips


def _collect_mac_addresses(device: CrowdStrikeDevice) -> list[str]:
    """MAC 주소를 리스트로 반환한다."""
    if device.mac_address:
        return [device.mac_address]
    return []


def _build_tags(device: CrowdStrikeDevice) -> dict[str, str]:
    """CrowdStrike tags(리스트)를 dict로 변환한다."""
    tags: dict[str, str] = {}
    if device.tags:
        for i, tag in enumerate(device.tags):
            if "/" in tag:
                key, _, value = tag.partition("/")
                tags[key] = value
            else:
                tags[f"tag_{i}"] = tag
    if device.product_type_desc:
        tags["product_type"] = device.product_type_desc
    if device.status:
        tags["status"] = device.status
    if device.service_provider:
        tags["cloud_provider"] = device.service_provider
    return tags


def transform_device(device: CrowdStrikeDevice, collected_at: datetime) -> CommonAsset:
    """CrowdStrikeDevice를 CommonAsset으로 변환한다."""
    os_name, os_version = _parse_os_fields(device)

    return CommonAsset(
        source=AssetSource.CROWDSTRIKE,
        source_id=device.device_id,
        hostname=device.hostname,
        os_name=os_name,
        os_version=os_version,
        os_build=device.os_build,
        ip_addresses=_collect_ip_addresses(device),
        mac_addresses=_collect_mac_addresses(device),
        serial_number=device.serial_number,
        manufacturer=device.system_manufacturer,
        model=device.system_product_name,
        agent_version=device.agent_version,
        last_seen=_parse_iso_datetime(device.last_seen),
        first_seen=_parse_iso_datetime(device.first_seen),
        domain=device.machine_domain,
        tags=_build_tags(device),
        raw_data=device.model_dump(),
        collected_at=collected_at,
    )


def transform_devices(devices: list[CrowdStrikeDevice], collected_at: datetime | None = None) -> list[CommonAsset]:
    """CrowdStrikeDevice 리스트를 CommonAsset 리스트로 변환한다."""
    ts = collected_at or datetime.now(UTC)
    results: list[CommonAsset] = []

    for device in devices:
        try:
            results.append(transform_device(device, ts))
        except Exception:
            logger.exception("디바이스 변환 실패: %s", device.device_id)

    return results
