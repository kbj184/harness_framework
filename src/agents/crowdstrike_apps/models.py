"""CrowdStrike Falcon Discover Application 데이터 모델."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class DiscoverApplicationHost(BaseModel):
    """Application 응답에 포함된 host 객체 (자산 매칭 키)."""

    model_config = ConfigDict(extra="allow")

    id: str | None = None
    aid: str | None = None  # = CrowdStrike device_id
    hostname: str | None = None
    platform_name: str | None = None
    os_version: str | None = None
    product_type_desc: str | None = None
    system_manufacturer: str | None = None
    agent_version: str | None = None
    external_ip: str | None = None


class DiscoverApplication(BaseModel):
    """CrowdStrike Discover Applications API 의 단일 application."""

    model_config = ConfigDict(extra="allow")

    id: str
    cid: str | None = None
    name: str | None = None
    vendor: str | None = None
    version: str | None = None
    software_type: str | None = None  # application/system/driver
    name_vendor: str | None = None
    name_vendor_version: str | None = None
    versioning_scheme: str | None = None
    category: str | None = None

    installation_timestamp: str | None = None
    last_used_user_name: str | None = None
    last_used_user_sid: str | None = None
    last_used_file_name: str | None = None
    last_used_file_hash: str | None = None
    last_used_timestamp: str | None = None
    first_seen_timestamp: str | None = None

    is_suspicious: bool | None = None
    is_normalized: bool | None = None

    host: DiscoverApplicationHost | None = None
