"""tb_asset_vulnerability — 운영자 액션 컬럼 추가 DDL 적용."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import boto3
import psycopg2

DDL = Path(__file__).parent.parent / "src" / "agents" / "trivy_scan" / "ddl_action.sql"


def main() -> int:
    sm = boto3.client("secretsmanager", region_name="ap-northeast-2")
    cfg = json.loads(sm.get_secret_value(SecretId="cmdb/db-writer")["SecretString"])
    conn = psycopg2.connect(
        host=cfg["host"], port=int(cfg.get("port", 5432)),
        dbname=cfg.get("dbname", "postgres"),
        user=cfg["user"], password=cfg["password"],
        sslmode="require", connect_timeout=10,
    )
    try:
        with conn, conn.cursor() as cur:
            cur.execute(DDL.read_text(encoding="utf-8"))
            print(f"applied: {DDL.name}")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
