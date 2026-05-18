"""CISA KEV JSON Feed 수집 (공개, 인증 불필요)."""

from __future__ import annotations

import logging
from datetime import date, datetime
from typing import Any

import httpx

logger = logging.getLogger("collect_cmdb")

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def fetch_kev_feed(url: str = KEV_URL, timeout: int = 60) -> list[dict[str, Any]]:
    """CISA KEV JSON을 다운로드하여 `vulnerabilities` 배열 반환."""
    logger.info("KEV 피드 다운로드: %s", url)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        data = resp.json()
    vulns = data.get("vulnerabilities", [])
    logger.info("KEV 항목 %d건 다운로드 완료", len(vulns))
    return vulns


def _parse_date(s: str | None) -> date | None:
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except ValueError:
        return None


def transform_kev(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """KEV vulnerabilities 엔트리를 tb_kev_catalog 스키마 dict로 변환."""
    rows: list[dict[str, Any]] = []
    for v in vulns:
        cve_id = v.get("cveID")
        if not cve_id:
            continue
        rows.append({
            "cve_id": cve_id,
            "vendor_project": v.get("vendorProject"),
            "product": v.get("product"),
            "vulnerability_name": v.get("vulnerabilityName"),
            "date_added": _parse_date(v.get("dateAdded")),
            "short_description": v.get("shortDescription"),
            "required_action": v.get("requiredAction"),
            "due_date": _parse_date(v.get("dueDate")),
            "known_ransomware_campaign_use": (
                "Y" if v.get("knownRansomwareCampaignUse", "").lower() == "known" else "N"
            ),
            "notes": v.get("notes"),
        })
    return rows


UPSERT_SQL = """
INSERT INTO tb_kev_catalog (
    cve_id, vendor_project, product, vulnerability_name, date_added,
    short_description, required_action, due_date,
    known_ransomware_campaign_use, notes, reg_dt, upd_dt
) VALUES (
    %(cve_id)s, %(vendor_project)s, %(product)s, %(vulnerability_name)s, %(date_added)s,
    %(short_description)s, %(required_action)s, %(due_date)s,
    %(known_ransomware_campaign_use)s, %(notes)s, LOCALTIMESTAMP, LOCALTIMESTAMP
)
ON CONFLICT (cve_id) DO UPDATE SET
    vendor_project                  = EXCLUDED.vendor_project,
    product                         = EXCLUDED.product,
    vulnerability_name              = EXCLUDED.vulnerability_name,
    date_added                      = EXCLUDED.date_added,
    short_description               = EXCLUDED.short_description,
    required_action                 = EXCLUDED.required_action,
    due_date                        = EXCLUDED.due_date,
    known_ransomware_campaign_use   = EXCLUDED.known_ransomware_campaign_use,
    notes                           = EXCLUDED.notes,
    upd_dt                          = LOCALTIMESTAMP
"""


def upsert_kev_rows(conn, rows: list[dict[str, Any]]) -> int:
    count = 0
    with conn.cursor() as cur:
        for r in rows:
            cur.execute(UPSERT_SQL, r)
            count += 1
    return count
