"""tb_vex 현재 상태 + product_purl/product_cpe 채움 비율 확인."""
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
        cur.execute("SELECT COUNT(*) FROM tb_vex")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM tb_vex WHERE product_purl IS NOT NULL")
        with_purl = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM tb_vex WHERE product_cpe IS NOT NULL")
        with_cpe = cur.fetchone()[0]
        cur.execute("SELECT MAX(fetched_at) FROM tb_vex")
        last = cur.fetchone()[0]
        print(f"total          : {total:,}")
        print(f"with product_purl: {with_purl:,}")
        print(f"with product_cpe : {with_cpe:,}")
        print(f"last fetched_at : {last}")
    conn.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
