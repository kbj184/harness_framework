"""자산 Perception 행을 자연어 문장으로 변환 (L1+L2 공통 + 관점별 L3)."""

from __future__ import annotations

from typing import Any

# 관점별 한글명 + visible_to_roles 매핑
PERSPECTIVE_LABEL = {
    "SECURITY": "보안 관점",
    "FINANCE": "재무 관점",
    "OPERATIONS": "운영 관점",
    "COMPLIANCE": "준법 관점",
    "BUSINESS": "비즈니스 관점",
}

VISIBLE_ROLES = {
    "SECURITY": ["보안팀", "C-Level"],
    "FINANCE": ["재무팀", "C-Level"],
    "OPERATIONS": ["운영팀", "SRE", "C-Level"],
    "COMPLIANCE": ["준법팀", "감사팀", "C-Level"],
    "BUSINESS": ["비즈니스팀", "C-Level"],
}


def build_head(asset: dict[str, Any]) -> str:
    """L1 Ontology + L2 Context 공통 머리 (5관점 행 모두 공유)."""
    parts: list[str] = []

    hostname = asset.get("hostname") or "미상"
    category = asset.get("category_cd") or "미분류"
    os_name = asset.get("os_name") or "미상"
    parts.append(f"{hostname} 자산은 {category} 유형이며 {os_name} 운영체제를 사용한다.")

    primary_ip = asset.get("primary_ip")
    env_type = asset.get("env_type")
    location = asset.get("location")
    if primary_ip or env_type:
        bits = []
        if primary_ip:
            bits.append(f"IP {primary_ip}")
        if env_type:
            bits.append(f"환경 {env_type}")
        if location:
            bits.append(f"위치 {location}")
        parts.append("네트워크/환경: " + ", ".join(bits) + ".")

    service = asset.get("service_name")
    if service:
        parts.append(f"서비스: {service}.")

    attrs = asset.get("attributes") or {}
    # AWS_EC2 tags 에서 Tag 값 추출
    aws_attrs = (attrs.get("AWS_EC2") or {}).get("tags") or {}
    if aws_attrs:
        inst = aws_attrs.get("InstanceType")
        vpc = aws_attrs.get("VpcId")
        state = aws_attrs.get("State")
        az = aws_attrs.get("AvailabilityZone")
        extras = []
        if inst:
            extras.append(f"인스턴스 {inst}")
        if vpc:
            extras.append(f"VPC {vpc}")
        if state:
            extras.append(f"상태 {state}")
        if az:
            extras.append(f"AZ {az}")
        if extras:
            parts.append("AWS 메타: " + ", ".join(extras) + ".")

    sc = asset.get("source_count") or 0
    conf = asset.get("confidence_score") or 0
    parts.append(f"수집원 수 {sc}, 신뢰도 {conf}.")

    return " ".join(parts)


def build_tail(perception: dict[str, Any]) -> str:
    """관점별 L3 뒷부분."""
    p = perception.get("perspective") or ""
    label = PERSPECTIVE_LABEL.get(p, p)
    priority = perception.get("perceived_priority") or "-"
    role = perception.get("perceived_role") or ""
    reason = perception.get("reasoning") or ""
    bits = [f"{label} 우선순위 {priority}"]
    if role:
        bits.append(f"역할 '{role}'")
    if reason:
        bits.append(f"판정 사유: {reason}")
    return ". ".join(bits) + "."


def textify(asset: dict[str, Any], perception: dict[str, Any]) -> str:
    head = build_head(asset)
    tail = build_tail(perception)
    return f"{head} {tail}"


def visible_roles_for(perspective: str) -> list[str]:
    return VISIBLE_ROLES.get(perspective, ["C-Level"])
