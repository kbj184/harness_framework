"""KISA cve_ids/affected_model 적재 확인."""
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
    cur.execute("""SELECT advisory_id, affected_model, affected_version, severity,
                          array_length(cve_ids, 1) AS cve_count,
                          CASE WHEN cve_ids IS NOT NULL AND array_length(cve_ids, 1) > 0
                               THEN cve_ids[1] ELSE NULL END AS first_cve
                   FROM tb_vendor_advisory
                   WHERE vendor_source='KISA' ORDER BY advisory_id DESC LIMIT 20""")
    print(f"{'advisory':12s} {'model':18s} {'version':15s} {'sev':10s} {'cves':5s} first")
    print("-" * 80)
    for r in cur.fetchall():
        print(f"{r[0]:12s} {(r[1] or '-'):18s} {(r[2] or '-'):15s} {(r[3] or '-'):10s} {r[4] or 0:>5} {r[5] or '-'}")
    cur.execute("""SELECT COUNT(*) FROM tb_vendor_advisory
                   WHERE vendor_source='KISA' AND array_length(cve_ids, 1) > 0""")
    print(f"\nKISA with CVEs: {cur.fetchone()[0]}/15")
conn.close()
