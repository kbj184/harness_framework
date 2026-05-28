"""invoke 결과 확인 — tb_collection_log 최근 항목 + 각 테이블 행수."""

import json
import boto3
import psycopg2

sm = boto3.client("secretsmanager", region_name="ap-northeast-2")
cfg = json.loads(sm.get_secret_value(SecretId="cmdb/db-writer")["SecretString"])

conn = psycopg2.connect(
    host=cfg.get("host"),
    port=int(cfg.get("port") or 5432),
    dbname=cfg.get("dbname") or cfg.get("database"),
    user=cfg.get("username") or cfg.get("user"),
    password=cfg.get("password"),
    connect_timeout=10,
)

with conn.cursor() as cur:
    # 1) tb_threat_collection_log 최근 항목
    cur.execute("""
        SELECT log_no, source, status, total_count, upserted_count,
               started_at, completed_at, error_message
        FROM tb_threat_collection_log
        WHERE started_at > NOW() - INTERVAL '30 minutes'
        ORDER BY started_at DESC
        LIMIT 20
    """)
    rows = cur.fetchall()
    print(f"=== 최근 30분 collection_log ({len(rows)} 건) ===")
    for r in rows:
        log_no, source, status, total, upsert, start, end, err = r
        elapsed = (end - start).total_seconds() if end else None
        print(f"  [{status or '?':8s}] {source:25s} total={total or 0} upsert={upsert or 0} "
              f"elapsed={elapsed}s")
        if err:
            print(f"    error: {err[:200]}")

    # 2) 테이블 행수
    print("\n=== 적재 테이블 행수 ===")
    for table in [
        "tb_cwe_dictionary", "tb_exploit_signal",
        "tb_vendor_advisory", "tb_asset_vulnerability", "tb_vex",
    ]:
        try:
            cur.execute(f"SELECT COUNT(*) FROM {table}")
            n = cur.fetchone()[0]
            print(f"  {table:30s} {n:>10,} rows")
        except Exception as e:
            print(f"  {table:30s} ERROR: {e}")

conn.close()
