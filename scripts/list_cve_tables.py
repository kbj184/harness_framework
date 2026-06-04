"""CVE 관련 실제 테이블·tb_epss_score 컬럼 전체 조사."""
from __future__ import annotations
import json
import sys
import boto3
import psycopg2

REGION = "ap-northeast-2"
SECRET_ID = "cmdb/db-writer"

def main():
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
    with conn.cursor() as cur:
        # 1) CVE/EPSS 관련 테이블 모두 나열
        cur.execute(
            """SELECT table_name FROM information_schema.tables
               WHERE table_schema='public'
                 AND (table_name LIKE '%cve%'
                   OR table_name LIKE '%epss%'
                   OR table_name LIKE '%nvd%'
                   OR table_name LIKE '%vuln%')
               ORDER BY table_name"""
        )
        print("=== CVE/EPSS/NVD/Vuln 관련 테이블 ===")
        for row in cur.fetchall():
            print(f"  {row[0]}")

        # 2) tb_epss_score 컬럼 전체
        print("\n=== tb_epss_score 컬럼 ===")
        cur.execute(
            """SELECT column_name, data_type FROM information_schema.columns
               WHERE table_name='tb_epss_score' ORDER BY ordinal_position"""
        )
        for row in cur.fetchall():
            print(f"  {row[0]:30s} {row[1]}")

        # 3) 행 카운트
        print("\n=== 핵심 테이블 행 카운트 ===")
        for tbl in ["tb_kev_catalog", "tb_epss_score", "tb_exploit_signal",
                    "tb_vendor_advisory", "tb_vex", "tb_asset_software",
                    "tb_asset_vulnerability", "tb_asset_master"]:
            try:
                cur.execute(f"SELECT COUNT(*) FROM {tbl}")
                print(f"  {tbl:30s} {cur.fetchone()[0]:>10,}")
            except Exception as e:
                print(f"  {tbl:30s} ERROR: {type(e).__name__}")
    conn.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
