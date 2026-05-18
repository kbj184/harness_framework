"""CrowdStrike Alerts v2 수집 (실시간 위협)."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

import httpx

logger = logging.getLogger("collect_cmdb")


def oauth_token(base_url: str, client_id: str, client_secret: str, timeout: int = 30) -> str:
    with httpx.Client(timeout=timeout) as c:
        r = c.post(
            f"{base_url}/oauth2/token",
            data={"client_id": client_id, "client_secret": client_secret},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        r.raise_for_status()
        return r.json()["access_token"]


def fetch_alert_ids(base_url: str, token: str, limit: int = 500, filter_expr: str | None = None) -> list[str]:
    params: dict[str, Any] = {"limit": limit, "sort": "created_timestamp.desc"}
    if filter_expr:
        params["filter"] = filter_expr
    with httpx.Client(timeout=30) as c:
        r = c.get(
            f"{base_url}/alerts/queries/alerts/v2",
            headers={"Authorization": f"Bearer {token}"},
            params=params,
        )
        r.raise_for_status()
        return r.json().get("resources", [])


def fetch_alerts(base_url: str, token: str, composite_ids: list[str]) -> list[dict[str, Any]]:
    if not composite_ids:
        return []
    results: list[dict[str, Any]] = []
    # 100개씩 배치
    for i in range(0, len(composite_ids), 100):
        batch = composite_ids[i : i + 100]
        with httpx.Client(timeout=60) as c:
            r = c.post(
                f"{base_url}/alerts/entities/alerts/v2",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                json={"composite_ids": batch},
            )
            r.raise_for_status()
            results.extend(r.json().get("resources", []))
    return results


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def transform(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for a in alerts:
        agent_id = a.get("agent_id") or a.get("device_id")
        rows.append({
            "composite_id": a.get("composite_id") or a.get("id"),
            "alert_id": a.get("id"),
            "cid": a.get("cid"),
            "agent_id": agent_id,
            "asset_id_hash": None,  # 매칭은 upsert 후 SQL JOIN 으로 수행
            "name": (a.get("name") or "")[:200] or None,
            "display_name": (a.get("display_name") or "")[:200] or None,
            "description": a.get("description"),
            "product": (a.get("product") or "")[:50] or None,
            "type": (a.get("type") or "")[:50] or None,
            "scenario": (a.get("scenario") or "")[:100] or None,
            "pattern_disposition": a.get("pattern_disposition"),
            "severity": a.get("severity"),
            "severity_name": (a.get("severity_name") or "")[:30] or None,
            "confidence": a.get("confidence"),
            "status": (a.get("status") or "")[:30] or None,
            "tactic": (a.get("tactic") or "")[:100] or None,
            "technique": (a.get("technique") or "")[:200] or None,
            "objective": (a.get("objective") or "")[:100] or None,
            "hostname": _first(a, ["hostname", "host_names", "device.hostname"]),
            "filename": (a.get("filename") or "")[:500] or None,
            "filepath": a.get("filepath"),
            "cmdline": a.get("cmdline"),
            "user_name": (a.get("user_name") or "")[:255] or None,
            "falcon_host_link": a.get("falcon_host_link"),
            "created_timestamp": _parse_ts(a.get("created_timestamp")),
            "updated_timestamp": _parse_ts(a.get("updated_timestamp")),
            "raw_data": json.dumps(a, default=str),
        })
    return rows


def _first(d: dict[str, Any], paths: list[str]) -> str | None:
    for p in paths:
        parts = p.split(".")
        cur: Any = d
        try:
            for k in parts:
                cur = cur[k] if isinstance(cur, dict) else (cur[0] if isinstance(cur, list) else None)
                if cur is None:
                    break
            if cur:
                if isinstance(cur, list):
                    cur = cur[0] if cur else None
                if cur:
                    return str(cur)[:255]
        except (KeyError, TypeError, IndexError):
            continue
    return None


UPSERT_SQL = """
INSERT INTO tb_cs_alert (
    composite_id, alert_id, cid, agent_id, asset_id_hash,
    name, display_name, description, product, type, scenario, pattern_disposition,
    severity, severity_name, confidence, status, tactic, technique, objective,
    hostname, filename, filepath, cmdline, user_name, falcon_host_link,
    created_timestamp, updated_timestamp, raw_data, fetched_at
) VALUES (
    %(composite_id)s, %(alert_id)s, %(cid)s, %(agent_id)s, %(asset_id_hash)s,
    %(name)s, %(display_name)s, %(description)s, %(product)s, %(type)s, %(scenario)s, %(pattern_disposition)s,
    %(severity)s, %(severity_name)s, %(confidence)s, %(status)s, %(tactic)s, %(technique)s, %(objective)s,
    %(hostname)s, %(filename)s, %(filepath)s, %(cmdline)s, %(user_name)s, %(falcon_host_link)s,
    %(created_timestamp)s, %(updated_timestamp)s, %(raw_data)s::jsonb, LOCALTIMESTAMP
)
ON CONFLICT (composite_id) DO UPDATE SET
    status             = EXCLUDED.status,
    severity           = EXCLUDED.severity,
    severity_name      = EXCLUDED.severity_name,
    updated_timestamp  = EXCLUDED.updated_timestamp,
    raw_data           = EXCLUDED.raw_data,
    fetched_at         = LOCALTIMESTAMP
"""


def upsert_rows(conn, rows: list[dict[str, Any]]) -> int:
    count = 0
    with conn.cursor() as cur:
        for r in rows:
            if not r["composite_id"]:
                continue
            cur.execute(UPSERT_SQL, r)
            count += 1
    return count


MATCH_SQL_SERIAL = """
UPDATE tb_cs_alert a SET asset_id_hash = m.asset_id_hash
FROM tb_asset s, tb_asset_master m
WHERE a.asset_id_hash IS NULL
  AND s.source='CROWDSTRIKE' AND s.source_id = a.agent_id
  AND s.serial_number IS NOT NULL AND m.serial_number = s.serial_number
"""

MATCH_SQL_HOSTNAME = """
UPDATE tb_cs_alert a SET asset_id_hash = m.asset_id_hash
FROM tb_asset s, tb_asset_master m
WHERE a.asset_id_hash IS NULL
  AND s.source='CROWDSTRIKE' AND s.source_id = a.agent_id
  AND s.hostname IS NOT NULL AND m.hostname = s.hostname
"""


def backfill_asset_match(conn) -> tuple[int, int]:
    """Alert 의 agent_id 를 tb_asset(CROWDSTRIKE) 경유로 tb_asset_master 와 매칭."""
    with conn.cursor() as cur:
        cur.execute(MATCH_SQL_SERIAL)
        by_serial = cur.rowcount
        cur.execute(MATCH_SQL_HOSTNAME)
        by_host = cur.rowcount
    logger.info("Asset 매칭: serial=%d, hostname=%d", by_serial, by_host)
    return by_serial, by_host


def collect_all(
    conn,
    base_url: str,
    client_id: str,
    client_secret: str,
    limit: int = 500,
) -> tuple[int, int]:
    token = oauth_token(base_url, client_id, client_secret)
    ids = fetch_alert_ids(base_url, token, limit=limit)
    logger.info("Alerts 조회: %d IDs", len(ids))
    alerts = fetch_alerts(base_url, token, ids)
    rows = transform(alerts)
    upserted = upsert_rows(conn, rows)
    logger.info("Alerts upsert: %d/%d", upserted, len(rows))
    backfill_asset_match(conn)
    return len(rows), upserted
