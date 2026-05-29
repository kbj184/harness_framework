"""신규 콜렉터 6종 DDL 적용 스크립트.

Secrets Manager에서 DB 자격증명을 받아 psycopg2로 5개 DDL 파일 순차 실행.
자격증명은 메모리에서만 사용되고 stdout/stderr에 노출되지 않는다.

사용:
    python scripts/apply_ddl.py [--check-only]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import boto3
import psycopg2

DDL_FILES = [
    "src/agents/mitre_cwe_collector/ddl.sql",
    "src/agents/exploit_signal_collector/ddl.sql",
    "src/agents/kisa_collector/ddl.sql",          # tb_vendor_advisory CREATE
    "src/agents/psirt_collector/ddl.sql",          # tb_vendor_advisory 인덱스 추가
    "src/agents/trivy_scan/ddl.sql",               # tb_asset_vulnerability
    "src/agents/vex_collector/ddl.sql",            # tb_vex
    "src/agents/eos_collector/ddl.sql",            # tb_eos_catalog (신규)
    "../backend/shcema/ddl/cmdb_tier3_embed.sql",  # Tier 3 임베딩 3종 (신규)
]

SECRET_ID = "cmdb/db-writer"
REGION = "ap-northeast-2"


def load_db_config() -> dict:
    """Secrets Manager 에서 DB 자격증명 로드 — 메모리 전용."""
    sm = boto3.client("secretsmanager", region_name=REGION)
    raw = sm.get_secret_value(SecretId=SECRET_ID)["SecretString"]
    return json.loads(raw)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--check-only", action="store_true",
        help="연결 테스트만 (DDL 미적용)",
    )
    args = ap.parse_args()

    cfg = load_db_config()

    # psycopg2 connect — credentials는 connect 인자로만 사용
    try:
        conn = psycopg2.connect(
            host=cfg.get("host") or cfg.get("DB_HOST"),
            port=int(cfg.get("port") or cfg.get("DB_PORT") or 5432),
            dbname=cfg.get("dbname") or cfg.get("database") or cfg.get("DB_NAME"),
            user=cfg.get("username") or cfg.get("user") or cfg.get("DB_USER"),
            password=cfg.get("password") or cfg.get("DB_PASSWORD"),
            connect_timeout=10,
        )
    except Exception as e:
        print(f"[FAIL] DB 연결 실패: {type(e).__name__}", file=sys.stderr)
        # error 메시지에 password 가 들어가지 않도록 클래스명만
        print(f"   사유: {str(e).split(chr(10))[0][:200]}", file=sys.stderr)
        return 1

    print("[OK] DB 연결 성공")
    if args.check_only:
        conn.close()
        return 0

    try:
        for ddl_path in DDL_FILES:
            p = Path(ddl_path)
            if not p.exists():
                print(f"[SKIP]  파일 없음 — 스킵: {ddl_path}")
                continue
            sql = p.read_text(encoding="utf-8")
            with conn.cursor() as cur:
                cur.execute(sql)
            conn.commit()
            print(f"[OK] 적용 완료: {ddl_path}")
    except Exception as e:
        conn.rollback()
        print(f"[FAIL] DDL 적용 실패: {type(e).__name__}", file=sys.stderr)
        print(f"   사유: {str(e).split(chr(10))[0][:200]}", file=sys.stderr)
        return 1
    finally:
        conn.close()

    # 적용된 테이블 확인
    print("\n── 적용 결과 검증 ──")
    conn = psycopg2.connect(
        host=cfg.get("host") or cfg.get("DB_HOST"),
        port=int(cfg.get("port") or cfg.get("DB_PORT") or 5432),
        dbname=cfg.get("dbname") or cfg.get("database") or cfg.get("DB_NAME"),
        user=cfg.get("username") or cfg.get("user") or cfg.get("DB_USER"),
        password=cfg.get("password") or cfg.get("DB_PASSWORD"),
        connect_timeout=10,
    )
    with conn.cursor() as cur:
        for table in [
            "tb_cwe_dictionary", "tb_exploit_signal",
            "tb_vendor_advisory", "tb_asset_vulnerability", "tb_vex",
            "tb_eos_catalog",                       # 신규
            "tb_rag_cve_desc", "tb_cve_match_pending", "tb_sw_cpe_mapping",  # Tier 3
        ]:
            cur.execute(
                "SELECT to_regclass(%s) IS NOT NULL", (f"public.{table}",)
            )
            exists = cur.fetchone()[0]
            print(f"  {'[OK]' if exists else '[FAIL]'} {table}")
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
