"""SBOM 적재기 — Ansible 결과 JSON → tb_asset_software UPSERT + asset 매칭."""

from __future__ import annotations

import logging
from typing import Any

from src.agents.sbom_ingest.transformer import transform

logger = logging.getLogger("collect_cmdb")


# 부분 UNIQUE 인덱스 (asset_id_hash, source, purl) WHERE source != 'CROWDSTRIKE'
# 단 INSERT 시점엔 asset_id_hash가 NULL이라 충돌 안 남 → DELETE-then-INSERT 전략 사용 (sbom_doc_id 단위)
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
"""

# 같은 호스트의 이전 Ansible SBOM 행 삭제 (한 번 수집된 전체 SBOM 으로 갱신)
DELETE_PREV_SQL = """
DELETE FROM tb_asset_software
WHERE source IN ('ANSIBLE_RPM','ANSIBLE_DPKG','ANSIBLE_APK','ANSIBLE_PACMAN','ANSIBLE_PORTAGE','ANSIBLE_OTHER')
  AND host_hostname = %s
"""


# Ansible SBOM은 hostname 만 가지고 매칭 (Ansible은 device_id 없음)
MATCH_SQL_HOSTNAME = """
UPDATE tb_asset_software a SET asset_id_hash = m.asset_id_hash
FROM tb_asset_master m
WHERE a.asset_id_hash IS NULL
  AND a.source LIKE 'ANSIBLE_%%'
  AND a.host_hostname IS NOT NULL
  AND (m.hostname = a.host_hostname OR m.fqdn = a.host_hostname)
"""


def ingest_sbom(conn, sbom_json: dict[str, Any], sbom_doc_id: str | None = None) -> tuple[int, int]:
    """단일 SBOM JSON 적재.

    Returns: (inserted_rows, matched_assets)
    """
    sbom, rows = transform(sbom_json, sbom_doc_id=sbom_doc_id)
    if not rows:
        logger.warning("SBOM 패키지 없음: host=%s", sbom.hostname)
        return 0, 0

    inserted = 0
    with conn.cursor() as cur:
        # 같은 호스트의 이전 Ansible SBOM 삭제 (full snapshot 갱신)
        if sbom.hostname:
            cur.execute(DELETE_PREV_SQL, (sbom.hostname,))
            logger.info("이전 Ansible SBOM 삭제: host=%s, rows=%d", sbom.hostname, cur.rowcount)

        for r in rows:
            cur.execute(UPSERT_SQL, r)
            inserted += 1

        # 자산 매칭 backfill
        cur.execute(MATCH_SQL_HOSTNAME)
        matched = cur.rowcount

    logger.info("SBOM 적재 완료: host=%s, packages=%d, matched=%d",
                sbom.hostname, inserted, matched)
    return inserted, matched
