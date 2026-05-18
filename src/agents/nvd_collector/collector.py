"""NVD CVE 2.0 API 증분 수집기.

API: https://services.nvd.nist.gov/rest/json/cves/2.0
  - Without API key: 5 req/30s
  - With API key:   50 req/30s
  - resultsPerPage 최대 2000, startIndex로 페이지네이션
  - lastModStartDate/lastModEndDate 로 증분 (최대 120일 범위)
  - pubStartDate/pubEndDate 로 초기 수집
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

logger = logging.getLogger("collect_cmdb")

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
# NVD는 req/30s 제한이므로 안전하게 페이지 간 delay
THROTTLE_SEC = 6  # API key 없는 경우


def _fmt_dt(dt: datetime) -> str:
    """NVD API 요구 포맷: ISO8601 with ms and Z (예: 2024-03-15T00:00:00.000)."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_cves(
    last_mod_start: datetime | None = None,
    last_mod_end: datetime | None = None,
    api_key: str | None = None,
    page_delay: int = THROTTLE_SEC,
    max_pages: int | None = None,
) -> list[dict[str, Any]]:
    """NVD에서 CVE 목록을 페이지네이션으로 수집.

    last_mod_start/end 없으면 기본으로 최근 30일 수집.
    """
    if last_mod_start is None:
        last_mod_start = datetime.now(UTC) - timedelta(days=30)
    if last_mod_end is None:
        last_mod_end = datetime.now(UTC)

    # NVD는 한 번에 최대 120일
    if (last_mod_end - last_mod_start).days > 119:
        raise ValueError("NVD API: lastMod 범위는 최대 120일")

    headers = {"User-Agent": "cmdb-collector/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    all_cves: list[dict[str, Any]] = []
    start_idx = 0
    page = 0
    params_base: dict[str, Any] = {
        "lastModStartDate": _fmt_dt(last_mod_start),
        "lastModEndDate": _fmt_dt(last_mod_end),
        "resultsPerPage": PAGE_SIZE,
    }

    with httpx.Client(timeout=120, headers=headers) as client:
        while True:
            page += 1
            params = dict(params_base)
            params["startIndex"] = start_idx
            logger.info("NVD 페이지 %d (startIndex=%d) 요청", page, start_idx)
            resp = client.get(NVD_BASE, params=params)
            resp.raise_for_status()
            body = resp.json()

            total = body.get("totalResults", 0)
            vulns = body.get("vulnerabilities", [])
            all_cves.extend(vulns)
            logger.info("  페이지 수신: %d건 (누적 %d / %d)", len(vulns), len(all_cves), total)

            start_idx += len(vulns)
            if start_idx >= total or not vulns:
                break
            if max_pages and page >= max_pages:
                logger.info("  max_pages 도달, 중단")
                break
            time.sleep(page_delay)  # rate limit 준수

    return all_cves


def _get_cvss_v3(metrics: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """metrics에서 CVSSv3 우선순위대로 추출: v31 → v30."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key) or []
        if arr:
            d = arr[0].get("cvssData") or {}
            return (
                d.get("baseScore"),
                d.get("baseSeverity"),
                d.get("vectorString"),
            )
    return None, None, None


def parse_cve(entry: dict[str, Any]) -> dict[str, Any]:
    """NVD 응답 엔트리 하나를 (meta, cpe_matches) 로 분해."""
    cve = entry.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return {}

    descriptions = cve.get("descriptions") or []
    desc = next(
        (d.get("value") for d in descriptions if d.get("lang") == "en"),
        (descriptions[0].get("value") if descriptions else None),
    )

    metrics = cve.get("metrics") or {}
    score, severity, vector = _get_cvss_v3(metrics)

    meta = {
        "cve_id": cve_id,
        "description": desc,
        "cvss_v3_score": score,
        "cvss_v3_severity": severity,
        "cvss_v3_vector": vector,
        "published_date": cve.get("published"),
        "last_modified": cve.get("lastModified"),
    }

    # configurations → nodes → cpeMatch[]
    matches: list[dict[str, Any]] = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                criteria = m.get("criteria")
                if not criteria:
                    continue
                matches.append({
                    "cve_id": cve_id,
                    "cpe_uri": criteria,
                    "vulnerable": m.get("vulnerable", True),
                    "version_start_including": m.get("versionStartIncluding"),
                    "version_start_excluding": m.get("versionStartExcluding"),
                    "version_end_including": m.get("versionEndIncluding"),
                    "version_end_excluding": m.get("versionEndExcluding"),
                })

    return {"meta": meta, "matches": matches}


def split_cpe(cpe_uri: str) -> dict[str, str | None]:
    """cpe:2.3:part:vendor:product:version:... 를 파싱."""
    parts = cpe_uri.split(":")
    # cpe:2.3:part:vendor:product:version
    if len(parts) < 6 or parts[0] != "cpe":
        return {"part": None, "vendor": None, "product": None, "version": None}
    return {
        "part": parts[2] if parts[2] != "*" else None,
        "vendor": parts[3] if parts[3] != "*" else None,
        "product": parts[4] if parts[4] != "*" else None,
        "version": parts[5] if parts[5] != "*" else None,
    }


CVE_UPSERT = """
INSERT INTO tb_cve_meta (
    cve_id, description, cvss_v3_score, cvss_v3_severity, cvss_v3_vector,
    published_date, last_modified, reg_dt, upd_dt
) VALUES (
    %(cve_id)s, %(description)s, %(cvss_v3_score)s, %(cvss_v3_severity)s, %(cvss_v3_vector)s,
    %(published_date)s, %(last_modified)s, LOCALTIMESTAMP, LOCALTIMESTAMP
)
ON CONFLICT (cve_id) DO UPDATE SET
    description      = EXCLUDED.description,
    cvss_v3_score    = EXCLUDED.cvss_v3_score,
    cvss_v3_severity = EXCLUDED.cvss_v3_severity,
    cvss_v3_vector   = EXCLUDED.cvss_v3_vector,
    published_date   = EXCLUDED.published_date,
    last_modified    = EXCLUDED.last_modified,
    upd_dt           = LOCALTIMESTAMP
"""

CPE_UPSERT = """
INSERT INTO tb_cpe_dictionary (cpe_uri, part, vendor, product, version, reg_dt)
VALUES (%(cpe_uri)s, %(part)s, %(vendor)s, %(product)s, %(version)s, LOCALTIMESTAMP)
ON CONFLICT (cpe_uri) DO NOTHING
"""

MATCH_UPSERT = """
INSERT INTO tb_cve_cpe_match (
    cve_id, cpe_uri, vulnerable,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding, reg_dt
) VALUES (
    %(cve_id)s, %(cpe_uri)s, %(vulnerable)s,
    %(version_start_including)s, %(version_start_excluding)s,
    %(version_end_including)s, %(version_end_excluding)s, LOCALTIMESTAMP
)
ON CONFLICT (cve_id, cpe_uri,
             version_start_including, version_start_excluding,
             version_end_including, version_end_excluding) DO NOTHING
"""


def upsert_cves(conn, entries: list[dict[str, Any]]) -> tuple[int, int, int]:
    """(cve_count, cpe_count, match_count) 반환."""
    cve_n = 0
    cpe_n = 0
    match_n = 0
    seen_cpe: set[str] = set()

    with conn.cursor() as cur:
        for entry in entries:
            parsed = parse_cve(entry)
            if not parsed:
                continue
            cur.execute(CVE_UPSERT, parsed["meta"])
            cve_n += 1
            for m in parsed["matches"]:
                cpe = m["cpe_uri"]
                if cpe not in seen_cpe:
                    seen_cpe.add(cpe)
                    parts = split_cpe(cpe)
                    cur.execute(
                        CPE_UPSERT,
                        {"cpe_uri": cpe, **parts},
                    )
                    cpe_n += 1
                cur.execute(MATCH_UPSERT, m)
                match_n += 1

    return cve_n, cpe_n, match_n
