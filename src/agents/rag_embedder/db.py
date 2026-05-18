"""Aurora PostgreSQL 접속 (임베더 Lambda 전용, 백엔드 API 경유 X)."""

from __future__ import annotations

import hashlib
import logging
import os
from collections.abc import Iterable
from contextlib import contextmanager
from typing import Any

import psycopg2

logger = logging.getLogger("collect_cmdb")


def load_db_config() -> dict[str, Any]:
    """환경변수 우선, 없으면 Secrets Manager cmdb/db-writer."""
    host = os.environ.get("DB_HOST")
    port = int(os.environ.get("DB_PORT", "5432"))
    dbname = os.environ.get("DB_NAME", "postgres")
    user = os.environ.get("DB_USER")
    pwd = os.environ.get("DB_PASSWORD")

    if host and user and pwd:
        return {"host": host, "port": port, "dbname": dbname, "user": user, "password": pwd}

    # Secrets Manager fallback
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


def fetch_perception_rows(conn) -> list[dict[str, Any]]:
    """tb_asset_master × tb_asset_perception INNER JOIN.

    각 행은 (asset, perception) 조합 하나. 자산 1개 × 5관점 = 5행.
    """
    sql = """
        SELECT
            m.asset_id_hash, m.hostname, m.primary_ip, m.os_name, m.category_cd,
            m.service_name, m.env_type, m.location,
            m.source_count, m.confidence_score, m.attributes,
            p.perspective, p.perceived_priority, p.perceived_role, p.reasoning
        FROM tb_asset_master m
        JOIN tb_asset_perception p ON p.asset_id_hash = m.asset_id_hash
        WHERE m.use_yn = 'Y'
        ORDER BY m.asset_id_hash, p.perspective
    """
    cols = [
        "asset_id_hash",
        "hostname",
        "primary_ip",
        "os_name",
        "category_cd",
        "service_name",
        "env_type",
        "location",
        "source_count",
        "confidence_score",
        "attributes",
        "perspective",
        "perceived_priority",
        "perceived_role",
        "reasoning",
    ]
    with conn.cursor() as cur:
        cur.execute(sql)
        rows = cur.fetchall()
    return [dict(zip(cols, r, strict=True)) for r in rows]


def fetch_existing_hashes(conn) -> dict[tuple[str, str], str]:
    """(asset_id_hash, perspective) → content_hash 매핑. 재임베딩 스킵용."""
    with conn.cursor() as cur:
        cur.execute("SELECT asset_id_hash, perspective, content_hash FROM tb_rag_asset")
        return {(r[0], r[1]): r[2] for r in cur.fetchall()}


def upsert_rag_rows(conn, rows: Iterable[dict[str, Any]]) -> int:
    """UPSERT tb_rag_asset. embedding은 pgvector '[...]' 문자열."""
    sql = """
        INSERT INTO tb_rag_asset (
            asset_id_hash, perspective, content, embedding,
            priority, service_name, category_cd, visible_to_roles,
            content_hash, computed_at, embedded_at
        ) VALUES (
            %(asset_id_hash)s, %(perspective)s, %(content)s, %(embedding)s,
            %(priority)s, %(service_name)s, %(category_cd)s, %(visible_to_roles)s,
            %(content_hash)s, LOCALTIMESTAMP, LOCALTIMESTAMP
        )
        ON CONFLICT (asset_id_hash, perspective) DO UPDATE SET
            content          = EXCLUDED.content,
            embedding        = EXCLUDED.embedding,
            priority         = EXCLUDED.priority,
            service_name     = EXCLUDED.service_name,
            category_cd      = EXCLUDED.category_cd,
            visible_to_roles = EXCLUDED.visible_to_roles,
            content_hash     = EXCLUDED.content_hash,
            computed_at      = LOCALTIMESTAMP,
            embedded_at      = LOCALTIMESTAMP
    """
    count = 0
    with conn.cursor() as cur:
        for r in rows:
            cur.execute(sql, r)
            count += 1
    return count


def md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def embedding_to_pg(vec: list[float]) -> str:
    """pgvector text 형식 '[0.1, 0.2, ...]'."""
    return "[" + ",".join(f"{x:.6f}" for x in vec) + "]"
