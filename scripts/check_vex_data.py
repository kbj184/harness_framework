"""VEX 데이터 vs Trivy 결과 비교 — 매칭 가능성 진단."""
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
        print("=== tb_vex columns ===")
        cur.execute("""SELECT column_name, data_type FROM information_schema.columns
                       WHERE table_name='tb_vex' ORDER BY ordinal_position""")
        for row in cur.fetchall():
            print(f"  {row[0]:30s} {row[1]}")

        print("\n=== tb_vex.status distribution ===")
        cur.execute("SELECT status, COUNT(*) FROM tb_vex GROUP BY status ORDER BY 2 DESC")
        for row in cur.fetchall():
            print(f"  {row[0]:30s} {row[1]:>5}")

        print("\n=== VEX not_affected 샘플 (product_purl/product_cpe) ===")
        cur.execute("""SELECT cve_id, product_purl, product_cpe, vex_source
                       FROM tb_vex WHERE status='not_affected' LIMIT 10""")
        for row in cur.fetchall():
            print(f"  cve={row[0]:18} purl='{(row[1] or '-')[:50]}' cpe='{(row[2] or '-')[:50]}' src={row[3]}")

        print("\n=== Trivy 매칭 결과 matched_pkg 형식 ===")
        cur.execute("""SELECT v.cve_id, v.matched_pkg FROM tb_asset_vulnerability v
                       WHERE v.match_type='TRIVY' LIMIT 10""")
        for row in cur.fetchall():
            print(f"  cve={row[0]:18} matched_pkg='{(row[1] or '-')[:80]}'")

        print("\n=== (cve_id 겹침) Trivy CVE ∩ VEX CVE ===")
        cur.execute("""SELECT COUNT(DISTINCT v.cve_id) FROM tb_asset_vulnerability v
                       JOIN tb_vex x ON x.cve_id = v.cve_id AND x.status='not_affected'""")
        print(f"  겹치는 CVE 수 (cve_id only): {cur.fetchone()[0]}")
    conn.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
