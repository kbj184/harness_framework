"""tb_asset_master 데이터 패턴 분석 — CPE 추론용."""
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
        # 1) category_cd 분포
        print("=== category_cd distribution ===")
        cur.execute("""SELECT category_cd, COUNT(*) FROM tb_asset_master
                       GROUP BY category_cd ORDER BY 2 DESC""")
        for row in cur.fetchall():
            print(f"  {row[0] or 'NULL':20s} {row[1]:>5}")

        # 2) os_name 패턴
        print("\n=== os_name samples (top 15) ===")
        cur.execute("""SELECT os_name, COUNT(*) FROM tb_asset_master
                       WHERE os_name IS NOT NULL
                       GROUP BY os_name ORDER BY 2 DESC LIMIT 15""")
        for row in cur.fetchall():
            print(f"  {row[0]:50s} {row[1]:>5}")

        # 3) manufacturer + model 패턴
        print("\n=== manufacturer + model samples (top 15) ===")
        cur.execute("""SELECT manufacturer, model, COUNT(*) FROM tb_asset_master
                       WHERE manufacturer IS NOT NULL OR model IS NOT NULL
                       GROUP BY manufacturer, model ORDER BY 3 DESC LIMIT 15""")
        for row in cur.fetchall():
            print(f"  {(row[0] or '-'):20s} {(row[1] or '-'):30s} {row[2]:>5}")

        # 4) env_type 분포
        print("\n=== env_type distribution ===")
        cur.execute("""SELECT env_type, COUNT(*) FROM tb_asset_master
                       GROUP BY env_type ORDER BY 2 DESC""")
        for row in cur.fetchall():
            print(f"  {row[0] or 'NULL':20s} {row[1]:>5}")

        # 5) lifecycle_state 분포
        print("\n=== lifecycle_state distribution ===")
        cur.execute("""SELECT lifecycle_state, COUNT(*) FROM tb_asset_master
                       GROUP BY lifecycle_state ORDER BY 2 DESC""")
        for row in cur.fetchall():
            print(f"  {row[0] or 'NULL':20s} {row[1]:>5}")

    conn.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
