"""ISMS 대장(xlsx) → tb_asset_master 직접 적재 (1회성 시드 로더).

★ 일반 수집기(수집→S3→파서→DB)와 다른 단일소스 1회 적재 경로.
  - tb_asset_source/수집기 머지(mergeGoldenRecord)를 우회한다(그 머지는 tb_asset 기반·해시 재계산·EXCEL 분기/cpe_vendor 미지원).
  - excel_ledger 자체 결정론 해시(asset_id_hash)를 PK로 그대로 적재 → prod→dev 스냅샷 재현과 동일 키.
  - ON CONFLICT(asset_id_hash) UPSERT → 재실행 idempotent.

주의(충돌):
  수집기(CrowdStrike/AWS)는 md5(IP/serial) 해시로 적재하므로 본 로더의 excel 해시와 키가 달라
  같은 물리장비라도 별도 master 행으로 공존한다. PC/CLD_SVR 등 수집기와 겹치는 카테고리는
  중복 가능 — dedup 전략은 별도 결정(현재는 ISMS 대장을 신뢰 원천으로 그대로 적재).

대외비: hostname/IP/소유자 등 PII는 DB에만 적재하고 콘솔/로그/파일로 출력하지 않는다(집계만).

사용:
  python -m src.agents.excel_ledger.load_master [xlsx경로] [--dry-run] [--category HW_NET,HW_SEC]
  - 기본: 전체 시트 적재(commit).
  - --dry-run: 적재 트랜잭션을 ROLLBACK (매핑·연결 검증만, 영속화 X).
  - --category: 지정 카테고리만 적재(쉼표 구분).
환경: DB_HOST/.. 또는 Secrets Manager(DB_SECRET_NAME, 기본 cmdb/db-writer). VPC 접근 필요.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import UTC, datetime

import psycopg2.extras

from src.agents.excel_ledger.models import LedgerAsset
from src.agents.excel_ledger.parser import parse_workbook
from src.shared.db import connect, load_db_config

DEFAULT_PATH = (
    r"C:\itamcmdb\kbjdocs\origin"
    r"\(대외비)2026년 GS리테일 ISMS-P - 정보자산 목록 통합본_v1.0 1.xlsx"
)

# INSERT 컬럼 순서 (tb_asset_master + add_asset_cpe_columns 마이그 컬럼).
# service_name/location 은 대장에 없어 생략(NULL). reg/upd 메타는 템플릿 리터럴.
_COLS = (
    "asset_id_hash", "hostname", "primary_ip", "serial_number",
    "os_name", "os_version", "manufacturer", "model",
    "category_cd", "env_type", "lifecycle_state",
    "source_count", "confidence_score", "last_seen", "attributes",
    "cpe_vendor", "cpe_product", "cpe_version", "criticality_score", "isms_yn",
)

_TEMPLATE = (
    "(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
    "'Y',0,LOCALTIMESTAMP,0,LOCALTIMESTAMP)"
)

_INSERT = f"""
INSERT INTO tb_asset_master (
    {", ".join(_COLS)},
    use_yn, reg_no, reg_dt, upd_no, upd_dt
) VALUES %s
ON CONFLICT (asset_id_hash) DO UPDATE SET
    hostname          = EXCLUDED.hostname,
    primary_ip        = EXCLUDED.primary_ip,
    os_name           = EXCLUDED.os_name,
    os_version        = EXCLUDED.os_version,
    manufacturer      = EXCLUDED.manufacturer,
    model             = EXCLUDED.model,
    category_cd       = EXCLUDED.category_cd,
    env_type          = EXCLUDED.env_type,
    lifecycle_state   = EXCLUDED.lifecycle_state,
    source_count      = EXCLUDED.source_count,
    confidence_score  = EXCLUDED.confidence_score,
    last_seen         = EXCLUDED.last_seen,
    attributes        = EXCLUDED.attributes,
    cpe_vendor        = EXCLUDED.cpe_vendor,
    cpe_product       = EXCLUDED.cpe_product,
    cpe_version       = EXCLUDED.cpe_version,
    criticality_score = EXCLUDED.criticality_score,
    isms_yn           = EXCLUDED.isms_yn,
    use_yn            = 'Y',
    upd_dt            = LOCALTIMESTAMP
"""


def _attributes(a: LedgerAsset) -> dict:
    """대장 컬럼 중 master 전용컬럼에 없는 정보를 attributes.EXCEL 로 무손실 보존."""
    return {
        "EXCEL": {
            "source_id": a.source_id,
            "sheet": a.sheet,
            "confidentiality": a.confidentiality,
            "integrity": a.integrity,
            "availability": a.availability,
            "criticality_grade": a.criticality_grade,
            "owner_user_nm": a.owner_user_nm,
            "owner_dept": a.owner_dept,
            "cpe_uri": a.cpe_uri,
            "cpe_tier": a.cpe_tier,
            "ip_addresses": a.ip_addresses,
            "mac_addresses": a.mac_addresses,
            "review_flag": a.review_flag,
            "ledger_attributes": a.attributes,
        }
    }


def _row(a: LedgerAsset, collected_at: datetime) -> tuple:
    return (
        a.asset_id_hash, a.hostname, a.primary_ip, a.serial_number,
        a.os_name, a.os_version, a.manufacturer, a.model,
        a.category_cd, a.env_type, a.lifecycle_state,
        1,                       # source_count (단일 원천)
        100,                     # confidence_score (ISMS 대장 = 신뢰 원천)
        collected_at, psycopg2.extras.Json(_attributes(a)),
        a.cpe_vendor, a.cpe_product, a.cpe_version, a.criticality_score, a.isms_yn,
    )


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", default=DEFAULT_PATH)
    ap.add_argument("--dry-run", action="store_true", help="ROLLBACK — 매핑·연결만 검증")
    ap.add_argument("--category", help="적재 카테고리 필터 (쉼표 구분, 예: HW_NET,HW_SEC)")
    args = ap.parse_args(argv)

    assets, _ = parse_workbook(args.path)
    if args.category:
        wanted = {c.strip() for c in args.category.split(",")}
        assets = [a for a in assets if a.category_cd in wanted]

    by_cat = Counter(a.category_cd for a in assets)
    print(f"적재 대상: {len(assets)}건  /  카테고리 {len(by_cat)}종")
    for cat, n in by_cat.most_common():
        print(f"  {cat:<10}{n:>6}")
    if not assets:
        print("대상 0건 — 종료")
        return 1

    collected_at = datetime.now(UTC)
    rows = [_row(a, collected_at) for a in assets]

    cfg = load_db_config()
    with connect(cfg) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM tb_asset_master")
            before = cur.fetchone()[0]
            psycopg2.extras.execute_values(cur, _INSERT, rows, template=_TEMPLATE, page_size=500)
            cur.execute("SELECT COUNT(*) FROM tb_asset_master")
            after = cur.fetchone()[0]
        if args.dry_run:
            conn.rollback()
            print(f"\n[DRY-RUN] UPSERT {len(rows)}행 실행 후 ROLLBACK "
                  f"(master {before}→{after}, 영속화 안 함)")
            return 0
        # connect() 컨텍스트 종료 시 commit
        print(f"\n✅ 적재 완료 — UPSERT {len(rows)}행 "
              f"(master {before}→{after}, 신규 {after - before} / 갱신 {len(rows) - (after - before)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
