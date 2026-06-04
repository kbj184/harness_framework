"""S3 raw 자산(CommonAsset JSONL) → tb_asset UPSERT 적재기.

백엔드 `POST /api/cmdb/assets/bulk`(CmdbMapper.upsertAsset)와 동일한 컬럼·충돌키를
psycopg2 로 직접 수행한다. Phase 2 전환으로 적재 권위가 Parser 로 이동.

tb_asset 충돌키: (source, source_id). asset_id_hash/IDR/master 병합은 하위 레이어 책임.
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger("collect_cmdb")


UPSERT_SQL = """
INSERT INTO tb_asset (
    source, source_id, hostname, fqdn,
    os_name, os_version, os_build,
    ip_addresses, mac_addresses,
    serial_number, manufacturer, model,
    agent_version, last_seen, first_seen,
    domain, ou, tags, raw_data,
    collected_at, use_yn, reg_no, reg_dt, upd_no, upd_dt
) VALUES (
    %(source)s, %(source_id)s, %(hostname)s, %(fqdn)s,
    %(os_name)s, %(os_version)s, %(os_build)s,
    COALESCE(%(ip_addresses)s::jsonb, '[]'::jsonb),
    COALESCE(%(mac_addresses)s::jsonb, '[]'::jsonb),
    %(serial_number)s, %(manufacturer)s, %(model)s,
    %(agent_version)s,
    %(last_seen)s::timestamp, %(first_seen)s::timestamp,
    %(domain)s, %(ou)s,
    COALESCE(%(tags)s::jsonb, '{}'::jsonb),
    %(raw_data)s::jsonb,
    %(collected_at)s::timestamp, 'Y', 0, current_timestamp, 0, current_timestamp
)
ON CONFLICT (source, source_id) DO UPDATE SET
    hostname      = EXCLUDED.hostname,
    fqdn          = EXCLUDED.fqdn,
    os_name       = EXCLUDED.os_name,
    os_version    = EXCLUDED.os_version,
    os_build      = EXCLUDED.os_build,
    ip_addresses  = EXCLUDED.ip_addresses,
    mac_addresses = EXCLUDED.mac_addresses,
    serial_number = EXCLUDED.serial_number,
    manufacturer  = EXCLUDED.manufacturer,
    model         = EXCLUDED.model,
    agent_version = EXCLUDED.agent_version,
    last_seen     = EXCLUDED.last_seen,
    first_seen    = EXCLUDED.first_seen,
    domain        = EXCLUDED.domain,
    ou            = EXCLUDED.ou,
    tags          = EXCLUDED.tags,
    raw_data      = EXCLUDED.raw_data,
    collected_at  = EXCLUDED.collected_at,
    upd_dt        = current_timestamp
"""


def to_row(asset: dict[str, Any]) -> dict[str, Any]:
    """CommonAsset JSON dict → UPSERT 파라미터(리스트/딕트는 JSON 직렬화)."""
    raw = asset.get("raw_data")
    return {
        "source": asset["source"],
        "source_id": asset["source_id"],
        "hostname": asset.get("hostname"),
        "fqdn": asset.get("fqdn"),
        "os_name": asset.get("os_name"),
        "os_version": asset.get("os_version"),
        "os_build": asset.get("os_build"),
        "ip_addresses": json.dumps(asset.get("ip_addresses") or []),
        "mac_addresses": json.dumps(asset.get("mac_addresses") or []),
        "serial_number": asset.get("serial_number"),
        "manufacturer": asset.get("manufacturer"),
        "model": asset.get("model"),
        "agent_version": asset.get("agent_version"),
        "last_seen": asset.get("last_seen"),
        "first_seen": asset.get("first_seen"),
        "domain": asset.get("domain"),
        "ou": asset.get("ou"),
        "tags": json.dumps(asset.get("tags") or {}),
        "raw_data": json.dumps(raw) if raw is not None else None,
        "collected_at": asset["collected_at"],
    }


def upsert_assets(conn, assets: list[dict[str, Any]]) -> int:
    """CommonAsset dict 리스트를 tb_asset 에 UPSERT. 처리 건수 반환."""
    n = 0
    with conn.cursor() as cur:
        for asset in assets:
            cur.execute(UPSERT_SQL, to_row(asset))
            n += 1
    logger.info("tb_asset UPSERT 완료: %d건", n)
    return n


def log_start(conn, source: str, total: int) -> int:
    """tb_asset_collection_log RUNNING 행 추가 → log_no 반환."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO tb_asset_collection_log (source, started_at, status, total_count, reg_dt)
            VALUES (%s, LOCALTIMESTAMP, 'RUNNING', %s, current_timestamp)
            RETURNING log_no
            """,
            (source, total),
        )
        return cur.fetchone()[0]


def log_end(
    conn,
    log_no: int,
    status: str,
    created: int,
    updated: int,
    error: str | None = None,
) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE tb_asset_collection_log
               SET completed_at = LOCALTIMESTAMP, status = %s,
                   created_count = %s, updated_count = %s, error_message = %s
             WHERE log_no = %s
            """,
            (status, created, updated, error, log_no),
        )
