"""공통 자산 수집 데이터 모델."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class AssetSource(StrEnum):
    """자산 수집 소스."""

    CROWDSTRIKE = "CROWDSTRIKE"
    ACTIVE_DIRECTORY = "AD"
    SCCM = "SCCM"
    AWS = "AWS"
    AWS_EC2 = "AWS_EC2"


class CommonAsset(BaseModel):
    """모든 수집 에이전트가 공유하는 정규화된 자산 스키마."""

    source: AssetSource
    source_id: str = Field(min_length=1, description="소스 시스템 내 고유 ID")
    hostname: str | None = None
    fqdn: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    os_build: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    mac_addresses: list[str] = Field(default_factory=list)
    serial_number: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    agent_version: str | None = None
    last_seen: datetime | None = None
    first_seen: datetime | None = None
    domain: str | None = None
    ou: str | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    raw_data: dict | None = None
    collected_at: datetime


class BulkAssetPayload(BaseModel):
    """Spring Boot bulk API 요청 페이로드."""

    source: AssetSource
    collected_at: datetime
    assets: list[CommonAsset]


class BulkAssetResponse(BaseModel):
    """Spring Boot bulk API 응답."""

    success: bool
    total_count: int = 0
    created_count: int = 0
    updated_count: int = 0
    error_message: str | None = None
