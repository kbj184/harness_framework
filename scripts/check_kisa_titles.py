"""KISA advisory title 샘플 확인 — 키워드 매칭 가능 여부 진단."""
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
    cur.execute("""SELECT advisory_id, title FROM tb_vendor_advisory
                   WHERE vendor_source='KISA' ORDER BY advisory_id DESC LIMIT 20""")
    for r in cur.fetchall():
        print(f"{r[0]}: {r[1]}")
conn.close()
