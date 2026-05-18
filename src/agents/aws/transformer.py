"""AWS EC2 인스턴스 → CommonAsset 변환기."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from src.agents.aws.models import AwsEc2Instance
from src.shared.models import AssetSource, CommonAsset

logger = logging.getLogger("collect_cmdb")


def _resolve_hostname(inst: AwsEc2Instance) -> str | None:
    """hostname 결정 — Name 태그 우선, 없으면 PrivateDnsName."""
    name_tag = inst.tags_dict.get("Name")
    if name_tag:
        return name_tag
    if inst.PrivateDnsName:
        return inst.PrivateDnsName
    return None


def _resolve_os_name(inst: AwsEc2Instance) -> str | None:
    """OS 이름 추정 — Platform이 있으면 그것(대부분 windows), 없으면 Linux로 간주.

    상세 OS 정보(Ubuntu/Amazon Linux 등)는 AMI 메타데이터 조회가 필요하므로
    이번 단계에서는 거시적 분류만 수행하고, 구체 OS는 CrowdStrike가 덮어쓴다.
    """
    if inst.Platform:
        return inst.Platform.capitalize()  # windows -> Windows
    if inst.PlatformDetails:
        # "Linux/UNIX", "Red Hat Enterprise Linux" 등
        detail = inst.PlatformDetails.lower()
        if "windows" in detail:
            return "Windows"
        return "Linux"
    return "Linux"  # 기본값 — AWS EC2에서 Platform 필드 비어있으면 linux


def _collect_ip_addresses(inst: AwsEc2Instance) -> list[str]:
    """Private + Public IP를 리스트로."""
    ips: list[str] = []
    if inst.PrivateIpAddress:
        ips.append(inst.PrivateIpAddress)
    if inst.PublicIpAddress and inst.PublicIpAddress != inst.PrivateIpAddress:
        ips.append(inst.PublicIpAddress)
    return ips


def _collect_mac_addresses(inst: AwsEc2Instance) -> list[str]:
    """NetworkInterfaces에서 MAC 추출."""
    macs: list[str] = []
    for nic in inst.NetworkInterfaces or []:
        mac = nic.get("MacAddress") if isinstance(nic, dict) else None
        if mac and mac not in macs:
            macs.append(mac)
    return macs


def _build_tags(inst: AwsEc2Instance) -> dict[str, str]:
    """CommonAsset.tags — 사용자 Tag + AWS 메타데이터 합침."""
    tags = dict(inst.tags_dict)  # 사용자 태그 (Name, Service 등) 복사

    # AWS 메타데이터 추가 (태그 충돌 없도록 PascalCase 유지)
    if inst.InstanceType:
        tags["InstanceType"] = inst.InstanceType
    if inst.VpcId:
        tags["VpcId"] = inst.VpcId
    if inst.SubnetId:
        tags["SubnetId"] = inst.SubnetId
    if inst.AvailabilityZone:
        tags["AvailabilityZone"] = inst.AvailabilityZone
    if inst.Architecture:
        tags["Architecture"] = inst.Architecture
    if inst.ImageId:
        tags["ImageId"] = inst.ImageId
    if inst.state_name:
        tags["State"] = inst.state_name
    if inst.PlatformDetails:
        tags["PlatformDetails"] = inst.PlatformDetails
    return tags


def transform_instance(inst: AwsEc2Instance, collected_at: datetime) -> CommonAsset:
    """단일 EC2 인스턴스를 CommonAsset으로 변환."""
    return CommonAsset(
        source=AssetSource.AWS_EC2,
        source_id=inst.InstanceId,
        hostname=_resolve_hostname(inst),
        os_name=_resolve_os_name(inst),
        os_version=None,  # AWS API로는 상세 OS 버전 미제공
        ip_addresses=_collect_ip_addresses(inst),
        mac_addresses=_collect_mac_addresses(inst),
        serial_number=inst.InstanceId,  # ★ CrowdStrike 매칭 키
        manufacturer="Amazon",
        model=inst.InstanceType,
        first_seen=inst.LaunchTime,
        last_seen=collected_at,
        tags=_build_tags(inst),
        raw_data=inst.model_dump(mode="json"),
        collected_at=collected_at,
    )


def transform_instances(
    instances: list[AwsEc2Instance],
    collected_at: datetime | None = None,
) -> list[CommonAsset]:
    """EC2 인스턴스 리스트를 CommonAsset 리스트로 변환. 실패 건은 로그만 남기고 계속."""
    ts = collected_at or datetime.now(UTC)
    results: list[CommonAsset] = []

    for inst in instances:
        try:
            results.append(transform_instance(inst, ts))
        except Exception:
            logger.exception("EC2 인스턴스 변환 실패: %s", inst.InstanceId)

    return results
