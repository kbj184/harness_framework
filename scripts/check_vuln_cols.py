"""tb_asset_vulnerability VARCHAR 컬럼 길이 확인."""
import json, sys, boto3, psycopg2

sm = boto3.client("secretsmanager", region_name="ap-northeast-2")
cfg = json.loads(sm.get_secret_value(SecretId="cmdb/db-writer")["SecretString"])
conn = psycopg2.connect(
    host=cfg.get("host") or cfg.get("DB_HOST"),
    port=int(cfg.get("port") or 5432),
    dbname=cfg.get("dbname") or cfg.get("DB_NAME"),
    user=cfg.get("username") or cfg.get("user") or cfg.get("DB_USER"),
    password=cfg.get("password") or cfg.get("DB_PASSWORD"),
    connect_timeout=10,
)
with conn.cursor() as cur:
    cur.execute(
        """SELECT column_name, data_type, character_maximum_length
           FROM information_schema.columns
           WHERE table_name='tb_asset_vulnerability'
             AND data_type IN ('character varying','character')
           ORDER BY character_maximum_length NULLS LAST"""
    )
    for r in cur.fetchall():
        print(f"  {r[0]:25s} {r[1]:20s} len={r[2]}")
conn.close()
