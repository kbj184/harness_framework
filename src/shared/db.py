"""Aurora PostgreSQL 공용 접속 유틸 (Lambda 전용, 백엔드 API 경유 X).

환경변수 우선: DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD
폴백: Secrets Manager(DB_SECRET_NAME, 기본 cmdb/db-writer)
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Any

import psycopg2

logger = logging.getLogger("collect_cmdb")


def load_db_config() -> dict[str, Any]:
    host = os.environ.get("DB_HOST")
    port = int(os.environ.get("DB_PORT", "5432"))
    dbname = os.environ.get("DB_NAME", "postgres")
    user = os.environ.get("DB_USER")
    pwd = os.environ.get("DB_PASSWORD")

    if host and user and pwd:
        return {"host": host, "port": port, "dbname": dbname, "user": user, "password": pwd}

    import json as _json

    import boto3

    secret_name = os.environ.get("DB_SECRET_NAME", "cmdb/db-writer")
    client = boto3.client("secretsmanager")
    secret = _json.loads(client.get_secret_value(SecretId=secret_name)["SecretString"])
    return {
        "host": secret["host"],
        "port": int(secret.get("port", 5432)),
        "dbname": secret.get("dbname", "postgres"),
        "user": secret["user"],
        "password": secret["password"],
    }


@contextmanager
def connect(cfg: dict[str, Any]):
    conn = psycopg2.connect(sslmode="require", connect_timeout=10, **cfg)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def log_collection_start(conn, source: str, started_at) -> int:
    """위협 인텔 수집 로그 시작 행 추가 → log_no 반환."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO tb_threat_collection_log (source, started_at, status)
            VALUES (%s, %s, 'RUNNING') RETURNING log_no
            """,
            (source, started_at),
        )
        return cur.fetchone()[0]


def log_collection_end(
    conn,
    log_no: int,
    status: str,
    total: int,
    upserted: int,
    completed_at,
    error: str | None = None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE tb_threat_collection_log
               SET completed_at = %s, status = %s,
                   total_count = %s, upserted_count = %s, error_message = %s
             WHERE log_no = %s
            """,
            (completed_at, status, total, upserted, error, log_no),
        )
