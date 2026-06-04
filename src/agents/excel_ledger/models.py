"""ISMS 대장 정규화 자산 레코드 모델 (§9 적재 스키마)."""

from __future__ import annotations

from pydantic import BaseModel, Field


class LedgerAsset(BaseModel):
    """엑셀 한 행 → 정규화 자산 1건. tb_asset_source + master 매핑 (§9.2/9.3).

    serial_number는 엑셀에 없으므로 항상 None (수집채널 보류, §8.7).
    """

    # --- 출처 (tb_asset_source) ---
    source_type: str = "EXCEL"
    source_id: str = Field(description="시트코드+NO 예: S12-1638")
    sheet: str

    # --- 식별 (§8) ---
    category_cd: str
    asset_id_hash: str
    hostname: str | None = None
    primary_ip: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)

    # --- 기술 속성 (§9.2 정형) ---
    os_name: str | None = None
    os_version: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    serial_number: None = None  # 엑셀 부재 — 항상 NULL

    # --- CPE (§10.1 D4, CVE 매칭용) ---
    cpe_uri: str | None = None
    cpe_vendor: str | None = None
    cpe_product: str | None = None
    cpe_version: str | None = None
    cpe_tier: str | None = None  # STD/MANUAL/NO_CPE/UNKNOWN

    # --- ISMS 분류 (§9.2 정형) ---
    isms_yn: str | None = None  # 'Y'/'N'
    confidentiality: int | None = None
    integrity: int | None = None
    availability: int | None = None
    criticality_score: int | None = None  # C+I+A (3~9)
    criticality_grade: str | None = None  # 상/중/하
    env_type: str | None = None  # IDC/CLOUD/STORE/OA
    owner_user_nm: str | None = None
    owner_dept: str | None = None
    lifecycle_state: str = "ACTIVE"  # 모호행은 CANDIDATE

    # --- 관측 (키 아님, §9.2) ---
    mac_addresses: list[str] = Field(default_factory=list)

    # --- 무손실 (§9.3) ---
    attributes: dict = Field(default_factory=dict)
    raw_data: dict = Field(default_factory=dict)

    # --- 파싱 플래그 (3차 수동 큐) ---
    # SUSPECTED_SAME_DEVICE / SUSPECTED_DUPLICATE_INSTANCE / TBD_IP / DUP_ROW / DUP_HOSTNAME_SAMEIP 등
    review_flag: str | None = None


class SheetStat(BaseModel):
    """시트별 파싱 통계 (dry-run 검증용)."""

    sheet: str
    category_cd: str
    rows: int
    unique_hash: int
    auto: int          # review_flag 없는 결정론 확정
    review_queue: int  # 3차 수동 큐 (review_flag 부여)
    review_breakdown: dict[str, int] = Field(default_factory=dict)
