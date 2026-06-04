"""tb_asset_vulnerability 현재 SSVC 분포 + KEV 자산 criticality 확인."""
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
        print("=== tb_asset_vulnerability.ssvc_priority distribution ===")
        cur.execute("""SELECT ssvc_priority, COUNT(*) FROM tb_asset_vulnerability
                       WHERE status = 'OPEN'
                       GROUP BY ssvc_priority ORDER BY 2 DESC""")
        for row in cur.fetchall():
            print(f"  {row[0] or 'NULL':10s} {row[1]:>5}")

        print("\n=== match_type distribution ===")
        cur.execute("""SELECT match_type, COUNT(*) FROM tb_asset_vulnerability
                       GROUP BY match_type ORDER BY 2 DESC""")
        for row in cur.fetchall():
            print(f"  {row[0] or 'NULL':10s} {row[1]:>5}")

        print("\n=== KEV matched rows (is_kev=TRUE) — criticality 분포 ===")
        cur.execute("""SELECT v.is_kev, v.ssvc_priority, v.criticality_score, m.criticality_score AS m_crit, COUNT(*)
                       FROM tb_asset_vulnerability v
                       LEFT JOIN tb_asset_master m ON m.asset_id_hash = v.asset_id_hash
                       WHERE v.is_kev = TRUE
                       GROUP BY v.is_kev, v.ssvc_priority, v.criticality_score, m.criticality_score""")
        for row in cur.fetchall():
            print(f"  is_kev={row[0]}  ssvc={row[1] or 'NULL':6}  v.crit={row[2]}  m.crit={row[3]}  count={row[4]}")

        print("\n=== tb_vendor_advisory KISA + PSIRT 데이터 (vendor_source 분포) ===")
        cur.execute("""SELECT vendor_source, COUNT(*) FROM tb_vendor_advisory
                       GROUP BY vendor_source ORDER BY 2 DESC""")
        for row in cur.fetchall():
            print(f"  {row[0]:20s} {row[1]:>5}")

        print("\n=== KISA advisory sample (affected_model) ===")
        cur.execute("""SELECT advisory_id, affected_model, affected_version, array_length(cve_ids, 1) AS cve_count
                       FROM tb_vendor_advisory
                       WHERE vendor_source = 'KISA'
                       LIMIT 5""")
        for row in cur.fetchall():
            print(f"  {row[0]}: model='{row[1]}' ver='{row[2]}' cves={row[3]}")
    conn.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
