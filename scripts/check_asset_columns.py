"""tb_asset_master 컬럼 확인 — 메모리 전용."""
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
        cur.execute(
            """SELECT column_name, data_type, is_nullable
               FROM information_schema.columns
               WHERE table_name='tb_asset_master'
               ORDER BY ordinal_position"""
        )
        for row in cur.fetchall():
            print(f"  {row[0]:30s} {row[1]:20s} nullable={row[2]}")
    conn.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
