"""CrowdStrike 전용 데이터 모델."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class CrowdStrikeDevice(BaseModel):
    """CrowdStrike Hosts API에서 반환하는 디바이스 상세 정보."""

    model_config = ConfigDict(extra="allow")

    device_id: str
    hostname: str | None = None
    local_ip: str | None = None
    external_ip: str | None = None
    mac_address: str | None = None
    os_version: str | None = None
    os_build: str | None = None
    platform_name: str | None = None  # Windows, Mac, Linux
    system_manufacturer: str | None = None
    system_product_name: str | None = None
    serial_number: str | None = None
    agent_version: str | None = None
    last_seen: str | None = None  # ISO 8601
    first_seen: str | None = None  # ISO 8601
    machine_domain: str | None = None
    ou: str | None = None
    tags: list[str] | None = None
    service_provider: str | None = None  # 클라우드 프로바이더
    bios_version: str | None = None
    kernel_version: str | None = None
    product_type_desc: str | None = None  # Server, Workstation, Domain Controller
    status: str | None = None  # normal, containment 등
