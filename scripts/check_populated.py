"""tb_asset_master 채워진 결과 확인."""
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
        print("=== cpe_vendor distribution ===")
        cur.execute("""SELECT cpe_vendor, COUNT(*) FROM tb_asset_master
                       GROUP BY cpe_vendor ORDER BY 2 DESC""")
        for row in cur.fetchall():
            print(f"  {(row[0] or 'NULL'):20s} {row[1]:>5}")

        print("\n=== criticality_score distribution ===")
        cur.execute("""SELECT criticality_score, COUNT(*) FROM tb_asset_master
                       GROUP BY criticality_score ORDER BY 1""")
        for row in cur.fetchall():
            print(f"  {row[0]:>4} {row[1]:>5}")

        print("\n=== isms_yn distribution ===")
        cur.execute("""SELECT isms_yn, COUNT(*) FROM tb_asset_master
                       GROUP BY isms_yn ORDER BY 2 DESC""")
        for row in cur.fetchall():
            print(f"  {row[0] or 'NULL':5s} {row[1]:>5}")
    conn.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
