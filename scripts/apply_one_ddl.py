"""단일 DDL 파일 적용 — 메모리 전용 자격증명."""
from __future__ import annotations
import json
import sys
from pathlib import Path
import boto3
import psycopg2

REGION = "ap-northeast-2"
SECRET_ID = "cmdb/db-writer"

def main():
    if len(sys.argv) < 2:
        print("usage: python apply_one_ddl.py <ddl_file>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.exists():
        print(f"[FAIL] {path} not found", file=sys.stderr)
        return 1

    sm = boto3.client("secretsmanager", region_name=REGION)
    cfg = json.loads(sm.get_secret_value(SecretId=SECRET_ID)["SecretString"])

    conn = psycopg2.connect(
        host=cfg.get("host") or cfg.get("DB_HOST"),
        port=int(cfg.get("port") or cfg.get("DB_PORT") or 5432),
        dbname=cfg.get("dbname") or cfg.get("database") or cfg.get("DB_NAME"),
        user=cfg.get("username") or cfg.get("user") or cfg.get("DB_USER"),
        password=cfg.get("password") or cfg.get("DB_PASSWORD"),
        connect_timeout=10,
    )
    print("[OK] DB connected")
    try:
        sql = path.read_text(encoding="utf-8")
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
        print(f"[OK] applied: {path}")

        # 검증 — tb_asset_master 컬럼 확인
        with conn.cursor() as cur:
            cur.execute(
                """SELECT column_name FROM information_schema.columns
                   WHERE table_name='tb_asset_master'
                     AND column_name IN ('cpe_vendor','cpe_product','cpe_version','criticality_score','isms_yn')
                   ORDER BY column_name"""
            )
            for row in cur.fetchall():
                print(f"  [OK] tb_asset_master.{row[0]}")
    except Exception as e:
        conn.rollback()
        print(f"[FAIL] {type(e).__name__}: {str(e).split(chr(10))[0][:200]}", file=sys.stderr)
        return 1
    finally:
        conn.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
