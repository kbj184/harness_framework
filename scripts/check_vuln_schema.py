"""tb_asset_vulnerability 기존 스키마 확인."""

import json
import boto3
import psycopg2

sm = boto3.client("secretsmanager", region_name="ap-northeast-2")
cfg = json.loads(sm.get_secret_value(SecretId="cmdb/db-writer")["SecretString"])

conn = psycopg2.connect(
    host=cfg.get("host"),
    port=int(cfg.get("port") or 5432),
    dbname=cfg.get("dbname") or cfg.get("database"),
    user=cfg.get("username") or cfg.get("user"),
    password=cfg.get("password"),
    connect_timeout=10,
)

with conn.cursor() as cur:
    cur.execute("""
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_name = 'tb_asset_vulnerability'
        ORDER BY ordinal_position
    """)
    rows = cur.fetchall()
    print(f"tb_asset_vulnerability: {len(rows)} columns")
    for name, dtype, nullable in rows:
        print(f"  {name:30s} {dtype:20s} {'NULL' if nullable=='YES' else 'NOT NULL'}")
conn.close()
