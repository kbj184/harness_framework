"""VEX dismiss 매칭 후보 실제 row 진단."""
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
    # 조건 3: cpe vendor 매칭 — 카운트 시뮬레이션
    print("=== Condition 3: cpe vendor LIKE asset.cpe_vendor ===")
    cur.execute("""SELECT COUNT(*) FROM tb_asset_vulnerability v
                   JOIN tb_vex vex ON vex.cve_id = v.cve_id AND vex.status='not_affected'
                   JOIN tb_asset_master m ON m.asset_id_hash = v.asset_id_hash
                   WHERE v.status = 'OPEN'
                     AND vex.product_cpe IS NOT NULL
                     AND m.cpe_vendor IS NOT NULL
                     AND LOWER(vex.product_cpe) LIKE '%' || LOWER(m.cpe_vendor) || '%'""")
    print(f"  매칭 행수: {cur.fetchone()[0]}")

    # 조건 4: both NULL
    print("\n=== Condition 4: VEX product_purl AND product_cpe 모두 NULL ===")
    cur.execute("""SELECT COUNT(*) FROM tb_asset_vulnerability v
                   JOIN tb_vex vex ON vex.cve_id = v.cve_id AND vex.status='not_affected'
                   WHERE v.status = 'OPEN'
                     AND vex.product_purl IS NULL
                     AND vex.product_cpe IS NULL""")
    print(f"  매칭 행수: {cur.fetchone()[0]}")

    # 자산 cpe_vendor 분포 (NULL 포함)
    print("\n=== 자산 cpe_vendor 분포 (OPEN vuln 보유 자산만) ===")
    cur.execute("""SELECT m.cpe_vendor, COUNT(DISTINCT v.vuln_no) AS rows
                   FROM tb_asset_vulnerability v
                   JOIN tb_asset_master m ON m.asset_id_hash = v.asset_id_hash
                   WHERE v.status='OPEN'
                   GROUP BY m.cpe_vendor ORDER BY 2 DESC""")
    for r in cur.fetchall():
        print(f"  {(r[0] or 'NULL'):20s} {r[1]:>5}")

    # redhat 자산의 CVE 가 VEX 에 있는지
    print("\n=== redhat 자산의 OPEN CVE 가 VEX 에 있는 행 ===")
    cur.execute("""SELECT v.vuln_no, v.cve_id, v.matched_pkg, vex.product_cpe
                   FROM tb_asset_vulnerability v
                   JOIN tb_asset_master m ON m.asset_id_hash = v.asset_id_hash
                   LEFT JOIN tb_vex vex ON vex.cve_id = v.cve_id AND vex.status='not_affected'
                   WHERE v.status='OPEN' AND m.cpe_vendor='redhat'
                   ORDER BY v.cve_id LIMIT 20""")
    for r in cur.fetchall():
        print(f"  vuln={r[0]:5} cve={r[1]:18} pkg={(r[2] or '-'):18} vex_cpe={(r[3] or 'NO MATCH')[:40]}")
conn.close()
