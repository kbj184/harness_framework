"""KEV 매칭 행을 직접 조회 + SSVC 업데이트가 왜 안 됐는지 진단."""
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
        print("=== status x ssvc_priority distribution ===")
        cur.execute("""SELECT status, ssvc_priority, COUNT(*) FROM tb_asset_vulnerability
                       GROUP BY status, ssvc_priority ORDER BY 3 DESC""")
        for row in cur.fetchall():
            print(f"  status={row[0]:8} ssvc={row[1] or 'NULL':8} count={row[2]}")

        print("\n=== KEV-linked rows (JOIN tb_kev_catalog) ===")
        cur.execute("""SELECT v.vuln_no, v.cve_id, v.status, v.ssvc_priority, v.is_kev,
                              v.criticality_score, m.criticality_score AS m_crit,
                              v.asset_id_hash
                       FROM tb_asset_vulnerability v
                       JOIN tb_kev_catalog k ON k.cve_id = v.cve_id
                       LEFT JOIN tb_asset_master m ON m.asset_id_hash = v.asset_id_hash
                       LIMIT 10""")
        for row in cur.fetchall():
            print(f"  vuln={row[0]:5} cve={row[1]:20} status={row[2]:8} ssvc={row[3] or 'NULL':6} is_kev={row[4]} v_crit={row[5]} m_crit={row[6]}")

        print("\n=== Rows with status OPEN (counts) ===")
        cur.execute("SELECT status, COUNT(*) FROM tb_asset_vulnerability GROUP BY status")
        for row in cur.fetchall():
            print(f"  {row[0]:20s} {row[1]}")
    conn.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
