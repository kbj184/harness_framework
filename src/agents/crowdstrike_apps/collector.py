"""CrowdStrike Falcon Discover — Applications 수집기."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from src.agents.crowdstrike_apps.transformer import transform

logger = logging.getLogger("collect_cmdb")

QUERY_PAGE_SIZE = 100   # Discover queries 한 페이지
DETAIL_BATCH_SIZE = 50  # Discover entities 한 배치 (100은 timeout 발생 가능)


def oauth_token(base_url: str, client_id: str, client_secret: str, timeout: int = 30) -> str:
    with httpx.Client(timeout=timeout) as c:
        r = c.post(
            f"{base_url}/oauth2/token",
            data={"client_id": client_id, "client_secret": client_secret},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        r.raise_for_status()
        return r.json()["access_token"]


def fetch_all_app_ids(
    base_url: str,
    token: str,
    page_size: int = QUERY_PAGE_SIZE,
    max_pages: int | None = None,
    filter_expr: str | None = None,
) -> list[str]:
    """offset 페이지네이션으로 application ID 전체 조회."""
    headers = {"Authorization": f"Bearer {token}"}
    all_ids: list[str] = []
    offset = 0
    pages = 0
    with httpx.Client(timeout=60) as c:
        while True:
            params: dict[str, Any] = {"limit": page_size, "offset": offset, "sort": "last_used_timestamp|desc"}
            if filter_expr:
                params["filter"] = filter_expr
            # CrowdStrike Discover API 는 offset 10,000 이 상한 — 그 이상 요청 시 400
            # total > 10,000 인 경우 filter 분할 권장 (last_used_timestamp 기간 분할)
            if offset >= 10000:
                logger.warning(
                    "CrowdStrike Discover offset 10,000 한계 도달 — 잔여 %s 건 미수집 "
                    "(filter 분할 필요)",
                    body.get("meta", {}).get("pagination", {}).get("total"),
                )
                break

            r = c.get(f"{base_url}/discover/queries/applications/v1", headers=headers, params=params)
            r.raise_for_status()
            body = r.json()
            ids = body.get("resources") or []
            if not ids:
                break
            all_ids.extend(ids)
            pages += 1
            total = body.get("meta", {}).get("pagination", {}).get("total")
            logger.info("Discover queries page %d: %d ids (offset=%d, total=%s)",
                        pages, len(ids), offset, total)
            offset += len(ids)
            if total is not None and offset >= total:
                break
            if max_pages and pages >= max_pages:
                break
    return all_ids


def fetch_app_details(base_url: str, token: str, app_ids: list[str]) -> list[dict[str, Any]]:
    """DETAIL_BATCH_SIZE 씩 entities 상세 조회."""
    if not app_ids:
        return []
    headers = {"Authorization": f"Bearer {token}"}
    results: list[dict[str, Any]] = []
    with httpx.Client(timeout=120) as c:
        for i in range(0, len(app_ids), DETAIL_BATCH_SIZE):
            batch = app_ids[i : i + DETAIL_BATCH_SIZE]
            r = c.get(
                f"{base_url}/discover/entities/applications/v1",
                headers=headers,
                params=[("ids", x) for x in batch],
            )
            r.raise_for_status()
            results.extend(r.json().get("resources") or [])
            logger.info("Discover entities batch %d/%d: 누계 %d건",
                        i // DETAIL_BATCH_SIZE + 1,
                        (len(app_ids) + DETAIL_BATCH_SIZE - 1) // DETAIL_BATCH_SIZE,
                        len(results))
    return results


UPSERT_SQL = """
INSERT INTO tb_asset_software (
    asset_id_hash, source, ecosystem,
    name, vendor, version, release, epoch, arch,
    purl, name_vendor, name_vendor_version, cpe_uri,
    software_type, category, versioning_scheme, distribution, source_rpm,
    installation_timestamp, last_used_user_name, last_used_user_sid,
    last_used_file_name, last_used_file_hash, last_used_timestamp, first_seen_timestamp,
    is_suspicious, is_normalized,
    cs_app_id, cs_agent_id, cid,
    host_hostname, sbom_doc_id, raw_data, collected_at, fetched_at
) VALUES (
    %(asset_id_hash)s, %(source)s, %(ecosystem)s,
    %(name)s, %(vendor)s, %(version)s, %(release)s, %(epoch)s, %(arch)s,
    %(purl)s, %(name_vendor)s, %(name_vendor_version)s, %(cpe_uri)s,
    %(software_type)s, %(category)s, %(versioning_scheme)s, %(distribution)s, %(source_rpm)s,
    %(installation_timestamp)s, %(last_used_user_name)s, %(last_used_user_sid)s,
    %(last_used_file_name)s, %(last_used_file_hash)s, %(last_used_timestamp)s, %(first_seen_timestamp)s,
    %(is_suspicious)s, %(is_normalized)s,
    %(cs_app_id)s, %(cs_agent_id)s, %(cid)s,
    %(host_hostname)s, %(sbom_doc_id)s, %(raw_data)s::jsonb, %(collected_at)s, LOCALTIMESTAMP
)
ON CONFLICT (cs_app_id) WHERE source = 'CROWDSTRIKE' AND cs_app_id IS NOT NULL
DO UPDATE SET
    version              = EXCLUDED.version,
    name_vendor_version  = EXCLUDED.name_vendor_version,
    last_used_user_name  = EXCLUDED.last_used_user_name,
    last_used_timestamp  = EXCLUDED.last_used_timestamp,
    is_suspicious        = EXCLUDED.is_suspicious,
    is_normalized        = EXCLUDED.is_normalized,
    raw_data             = EXCLUDED.raw_data,
    fetched_at           = LOCALTIMESTAMP
"""


def upsert_rows(conn, rows: list[dict[str, Any]]) -> int:
    count = 0
    with conn.cursor() as cur:
        for r in rows:
            if not r["cs_app_id"] or not r["cs_agent_id"]:
                continue
            cur.execute(UPSERT_SQL, r)
            count += 1
    return count


# agent_id → tb_asset(CROWDSTRIKE) → tb_asset_master.asset_id_hash
# tb_asset_source 는 미적재(설계만 존재) — 실제 수집 디바이스는 tb_asset 에 있음.
MATCH_SQL_SERIAL = """
UPDATE tb_asset_software a SET asset_id_hash = m.asset_id_hash
FROM tb_asset s, tb_asset_master m
WHERE a.asset_id_hash IS NULL
  AND s.source = 'CROWDSTRIKE' AND s.source_id = a.cs_agent_id
  AND s.serial_number IS NOT NULL AND m.serial_number = s.serial_number
"""

MATCH_SQL_HOSTNAME = """
UPDATE tb_asset_software a SET asset_id_hash = m.asset_id_hash
FROM tb_asset s, tb_asset_master m
WHERE a.asset_id_hash IS NULL
  AND s.source = 'CROWDSTRIKE' AND s.source_id = a.cs_agent_id
  AND s.hostname IS NOT NULL AND LOWER(m.hostname) = LOWER(s.hostname)
"""


def backfill_asset_match(conn) -> tuple[int, int]:
    """cs_agent_id 를 tb_asset(CROWDSTRIKE) 경유로 tb_asset_master 와 매칭."""
    with conn.cursor() as cur:
        cur.execute(MATCH_SQL_SERIAL)
        by_serial = cur.rowcount
        cur.execute(MATCH_SQL_HOSTNAME)
        by_host = cur.rowcount
    logger.info("Software asset 매칭: serial=%d, hostname=%d", by_serial, by_host)
    return by_serial, by_host


def collect_all(
    conn,
    base_url: str,
    client_id: str,
    client_secret: str,
    max_pages: int | None = None,
) -> tuple[int, int]:
    """전체 수집 → upsert → 자산 매칭. (total_fetched, upserted) 반환."""
    token = oauth_token(base_url, client_id, client_secret)
    ids = fetch_all_app_ids(base_url, token, max_pages=max_pages)
    logger.info("Discover Applications 조회: %d IDs", len(ids))
    if not ids:
        return 0, 0

    apps = fetch_app_details(base_url, token, ids)
    rows = transform(apps)
    upserted = upsert_rows(conn, rows)
    logger.info("Applications upsert: %d/%d", upserted, len(rows))
    backfill_asset_match(conn)
    return len(rows), upserted
