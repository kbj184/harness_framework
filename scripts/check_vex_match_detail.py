"""겹친 14 CVE 의 매칭 가능성 상세 분석."""
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
    # 겹친 not_affected CVE 14개 샘플
    print("=== 겹친 not_affected CVE 와 우리 자산의 matched_pkg + VEX product_cpe ===")
    cur.execute("""SELECT DISTINCT v.cve_id, v.matched_pkg, vex.product_cpe, vex.product_purl,
                          vex.justification
                   FROM tb_asset_vulnerability v
                   JOIN tb_vex vex ON vex.cve_id = v.cve_id AND vex.status='not_affected'
                   WHERE v.status='OPEN'
                   LIMIT 30""")
    for r in cur.fetchall():
        print(f"  cve={r[0]:18} pkg='{(r[1] or '-')[:30]:30}' cpe='{(r[2] or '-')[:60]:60}' just={r[4] or '-'}")

    # product_purl/cpe 둘 다 NULL 인 VEX 비율
    print("\n=== VEX product 정보 분포 ===")
    cur.execute("""SELECT
        SUM(CASE WHEN product_purl IS NULL AND product_cpe IS NULL THEN 1 ELSE 0 END) AS both_null,
        SUM(CASE WHEN product_cpe IS NOT NULL AND product_purl IS NULL THEN 1 ELSE 0 END) AS cpe_only,
        SUM(CASE WHEN product_purl IS NOT NULL AND product_cpe IS NULL THEN 1 ELSE 0 END) AS purl_only,
        SUM(CASE WHEN product_purl IS NOT NULL AND product_cpe IS NOT NULL THEN 1 ELSE 0 END) AS both_set,
        COUNT(*) AS total
        FROM tb_vex WHERE status='not_affected'""")
    r = cur.fetchone()
    print(f"  both_null:  {r[0]:>5}")
    print(f"  cpe_only:   {r[1]:>5}")
    print(f"  purl_only:  {r[2]:>5}")
    print(f"  both_set:   {r[3]:>5}")
    print(f"  total:      {r[4]:>5}")
conn.close()
