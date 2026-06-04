"""시트별 적재 스펙 — §8 식별 + §9 컬럼맵의 코드 SSOT.

컬럼은 1-based 인덱스로 바인딩하고 expected 헤더로 assert (off-by-one 방지, §9 결정).
natural_key = §8 카테고리별 정본키 구성 필드(NO 제외). 시트내 충돌 시 NO 덧붙여 유니크화.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SheetSpec:
    sheet_name: str             # 공백 무시 매칭
    category_cd: str
    header_row: int
    fields: dict[str, int]      # 논리필드 → 1-based 컬럼
    asserts: dict[int, str]     # 컬럼 → 기대 헤더 substring (식별 핵심만)
    natural_key: tuple[str, ...]  # §8 정본키 필드 (NO 제외)
    collision_flag: str         # natural_key 충돌 모호행 review_flag
    env_default: str            # env_type 기본값
    review_on_dup_hostname: bool = False  # 동명 호스트 의미검토 플래그(서버 등)


# 공통 필드 위치는 시트마다 달라 각 스펙에 명시.
SHEET_SPECS: list[SheetSpec] = [
    SheetSpec(
        "2. 서버", "HW_SVR", 6,
        {"no": 2, "isms": 3, "use": 7, "hostname": 6, "primary_ip": 8,
         "manufacturer": 9, "model": 10, "os_name": 11, "os_version": 12,
         "eos": 13, "location": 14, "owner": 18, "dept": 20,
         "c": 21, "i": 22, "a": 23, "grade": 25},
        {6: "자산명", 8: "IP", 10: "모델", 11: "OS"},
        ("hostname", "primary_ip", "model"), "DUP_REVIEW", "IDC",
        review_on_dup_hostname=True,
    ),
    SheetSpec(
        "3. WEBWAS", "SW_WAS", 6,
        {"no": 2, "isms": 3, "hostname": 5, "app": 6, "use": 7, "primary_ip": 8,
         "sw": 9, "sw_version": 10, "os_name": 11, "os_version": 12,
         "location": 13, "owner": 17, "dept": 19, "c": 20, "i": 21, "a": 22, "grade": 24},
        {5: "자산명", 6: "APP", 9: "S/W"},
        ("hostname", "app", "use", "primary_ip", "sw", "sw_version"),
        "SUSPECTED_DUPLICATE_INSTANCE", "IDC",
    ),
    SheetSpec(
        "4. DB", "SW_DB", 6,
        {"no": 2, "isms": 3, "hostname": 5, "inst": 6, "use": 7, "primary_ip": 8,
         "port": 9, "sw": 10, "sw_version": 11, "eos": 12, "os_name": 13, "os_version": 14,
         "location": 15, "owner": 19, "dept": 21, "c": 22, "i": 23, "a": 24, "grade": 26},
        {5: "호스트명", 6: "인스턴스", 9: "포트", 10: "S/W"},
        ("hostname", "inst", "port"), "SUSPECTED_HA_PAIR", "IDC",
    ),
    SheetSpec(
        "5. 네트워크 장비", "HW_NET", 6,
        {"no": 2, "isms": 3, "subtype": 5, "hostname": 6, "use": 7, "primary_ip": 8,
         "manufacturer": 9, "model": 10, "os_name": 11, "os_version": 12,
         "location": 13, "owner": 17, "dept": 19, "c": 20, "i": 21, "a": 22, "grade": 24},
        {6: "자산명", 8: "IP", 10: "모델"},
        ("hostname", "primary_ip"), "DUP_REVIEW", "IDC",
    ),
    SheetSpec(
        "6. 보안장비", "HW_SEC", 6,
        {"no": 2, "isms": 3, "subtype": 5, "hostname": 6, "use": 7, "primary_ip": 8,
         "manufacturer": 9, "model": 10, "os_name": 11, "os_version": 12,
         "location": 13, "owner": 17, "dept": 19, "c": 20, "i": 21, "a": 22, "grade": 24},
        {6: "자산명", 8: "IP"},
        ("hostname", "primary_ip"), "DUP_REVIEW", "IDC",
        review_on_dup_hostname=True,
    ),
    SheetSpec(
        "7. 클라우드 서버", "CLD_SVR", 6,
        {"no": 2, "isms": 3, "account_raw": 8, "name": 10, "instance_id": 11, "use": 12,
         "primary_ip": 13, "pub_ip": 14, "model": 15, "os_name": 16, "os_version": 17,
         "eos": 18, "location": 19, "owner": 23, "dept": 25, "c": 26, "i": 27, "a": 28, "grade": 30},
        {8: "계정", 11: "instance-id", 13: "Private"},
        ("instance_id",), "COLLISION_REVIEW", "CLOUD",
    ),
    SheetSpec(
        "8. 클라우드 DB", "CLD_DB", 6,
        {"no": 2, "isms": 3, "account_raw": 7, "tag": 9, "use": 10, "endpoint": 11,
         "model": 12, "sw": 13, "sw_version": 14, "eos": 15, "location": 16,
         "owner": 20, "dept": 22, "c": 23, "i": 24, "a": 25, "grade": 27},
        {7: "계정", 9: "자산명", 11: "Endpoint"},
        ("account_key", "tag"), "SUSPECTED_HA_PAIR", "CLOUD",
    ),
    SheetSpec(
        "9. 클라우드 보안서비스", "CLD_SEC", 6,
        {"no": 2, "isms": 3, "svc": 6, "acctname": 7, "account_raw": 8, "use": 9,
         "location": 10, "owner": 14, "dept": 16, "c": 17, "i": 18, "a": 19, "grade": 21},
        {6: "유형", 8: "UsageAccountid"},
        ("account_key", "svc"), "COLLISION_REVIEW", "CLOUD",
    ),
    SheetSpec(
        "10. 클라우드 스토리지", "CLD_STG", 6,
        {"no": 2, "isms": 3, "acctname": 6, "bucket": 8, "use": 9, "location": 10,
         "owner": 14, "dept": 16, "c": 17, "i": 18, "a": 19, "grade": 21},
        {6: "계정", 8: "자산명"},
        ("bucket",), "COLLISION_REVIEW", "CLOUD",
    ),
    SheetSpec(
        "11. 어플리케이션", "SW_APP", 6,
        {"no": 2, "isms": 3, "gubun": 5, "subtype": 6, "svcname": 7, "sysname": 8,
         "use": 9, "url": 10, "external": 11, "owner": 12, "dept": 14,
         "c": 15, "i": 16, "a": 17, "grade": 19},
        {7: "서비스명", 8: "시스템명", 10: "URL"},
        ("sysname",), "COLLISION_REVIEW", "OA",
    ),
    SheetSpec(
        "12. PC", "HW_PC", 6,
        {"no": 2, "isms": 3, "subtype": 4, "uid": 5, "agent_ip": 6, "cn": 7, "dom": 8,
         "mac": 9, "os_name": 11, "os_version": 12, "mangbun": 13,
         "owner": 18, "dept": 19, "c": 20, "i": 21, "a": 22, "grade": 24},
        {5: "사용자", 7: "컴퓨터", 9: "MAC"},
        ("cn", "uid", "dom"), "SUSPECTED_SAME_DEVICE", "OA",
    ),
    SheetSpec(
        "13. 저장장치", "HW_STG", 6,
        {"no": 2, "isms": 4, "name": 6, "use": 7, "location": 8, "owner": 12, "dept": 14,
         "c": 15, "i": 16, "a": 17, "grade": 19},
        {6: "자산명"},
        ("name", "location"), "DUP_ROW", "IDC",
    ),
    SheetSpec(
        "14. 소프트웨어", "SW_PKG", 6,
        {"no": 2, "isms": 4, "name": 5, "use": 6, "location": 7, "owner": 11, "dept": 13,
         "c": 14, "i": 15, "a": 16, "grade": 18},
        {5: "자산명"},
        ("name",), "COLLISION_REVIEW", "OA",
    ),
    SheetSpec(
        "1. 문서", "INFO_DOC", 6,
        {"no": 2, "isms": 4, "subtype": 5, "name": 6, "use": 7, "owner": 8, "dept": 10,
         "c": 11, "i": 12, "a": 13, "grade": 15},
        {6: "자산명"},
        ("name",), "COLLISION_REVIEW", "OA",
    ),
]

# 시트 인덱스 → 짧은 코드 (source_id 접두)
SHEET_CODE = {
    "1. 문서": "S01", "2. 서버": "S02", "3. WEBWAS": "S03", "4. DB": "S04",
    "5. 네트워크 장비": "S05", "6. 보안장비": "S06", "7. 클라우드 서버": "S07",
    "8. 클라우드 DB": "S08", "9. 클라우드 보안서비스": "S09", "10. 클라우드 스토리지": "S10",
    "11. 어플리케이션": "S11", "12. PC": "S12", "13. 저장장치": "S13", "14. 소프트웨어": "S14",
}

# CPE 매핑 원천 (§10.1 D4) — category → (product_field, version_field). 없으면 CPE 미생성.
CPE_SOURCE: dict[str, tuple[str, str | None]] = {
    "HW_SVR": ("os_name", "os_version"),
    "HW_NET": ("os_name", "os_version"),
    "HW_SEC": ("os_name", "os_version"),
    "CLD_SVR": ("os_name", "os_version"),
    "HW_PC": ("os_name", "os_version"),
    "SW_WAS": ("sw", "sw_version"),
    "SW_DB": ("sw", "sw_version"),
    "CLD_DB": ("sw", "sw_version"),
    "SW_PKG": ("name", None),
}

# dry-run 검증용 기대 데이터 행수 (실측 2026-06-04)
EXPECTED_ROWS = {
    "HW_SVR": 596, "SW_WAS": 156, "SW_DB": 110, "HW_NET": 521, "HW_SEC": 116,
    "CLD_SVR": 1373, "CLD_DB": 472, "CLD_SEC": 263, "CLD_STG": 994,
    "SW_APP": 151, "HW_PC": 9050, "HW_STG": 53, "SW_PKG": 12, "INFO_DOC": 18,
}
