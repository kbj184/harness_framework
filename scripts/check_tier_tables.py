"""tb_cve_cpe_match, tb_cve_meta 컬럼 확인."""
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
        for tbl in ["tb_cve_cpe_match", "tb_cve_meta", "tb_asset_software"]:
            print(f"\n=== {tbl} ===")
            cur.execute(
                """SELECT column_name, data_type FROM information_schema.columns
                   WHERE table_name=%s ORDER BY ordinal_position""", (tbl,)
            )
            for row in cur.fetchall():
                print(f"  {row[0]:30s} {row[1]}")
            cur.execute(f"SELECT COUNT(*) FROM {tbl}")
            print(f"  rows: {cur.fetchone()[0]:,}")
    conn.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
