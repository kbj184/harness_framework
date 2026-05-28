"""CSAF 2.0 VEX 문서 파서 + tb_vex UPSERT.

Red Hat CSAF VEX (주간) + OpenVEX (CNCF) 두 소스 지원.
SVC_VULN 이 Trivy 결과 INSERT 직전 tb_vex JOIN — not_affected 자동 dismiss.
"""

from __future__ import annotations

import csv
import io
import logging
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

import httpx

logger = logging.getLogger("collect_cmdb")

# Red Hat CSAF VEX 인덱스 — 최근 변경된 VEX 문서 목록 (CSV)
REDHAT_CSAF_CHANGES_URL = "https://access.redhat.com/security/data/csaf/v2/vex/changes.csv"
# 개별 VEX URL 형식: https://access.redhat.com/security/data/csaf/v2/vex/{year}/cve-XXXX-XXXX.json


@dataclass
class VexStatement:
    """단일 (CVE × 제품) VEX 선언."""
    cve_id: str
    product_purl: str | None
    product_cpe: str | None
    status: str                       # not_affected / affected / fixed / under_investigation
    justification: str | None
    impact_statement: str
    action_statement: str
    published_at: date | None


# ───────────────────── CSAF product_tree 평탄화 ─────────────────────

def flatten_product_tree(tree: dict[str, Any]) -> dict[str, dict[str, str | None]]:
    """CSAF product_tree 의 branches 를 재귀 순회해 product_id → {purl, cpe} 매핑.

    CSAF 2.0 spec 의 product 객체:
      product.product_id
      product.product_identification_helper.purl
      product.product_identification_helper.cpe
    """
    mapping: dict[str, dict[str, str | None]] = {}

    def walk(node: dict[str, Any]) -> None:
        product = node.get("product")
        if isinstance(product, dict):
            pid = product.get("product_id")
            helper = product.get("product_identification_helper", {}) or {}
            if pid:
                mapping[pid] = {
                    "purl": helper.get("purl"),
                    "cpe": helper.get("cpe"),
                }
        for child in node.get("branches", []) or []:
            walk(child)
        # relationships 도 product_id 정의 가능
        for rel in node.get("relationships", []) or []:
            fp = rel.get("full_product_name", {}) or {}
            pid = fp.get("product_id")
            helper = fp.get("product_identification_helper", {}) or {}
            if pid:
                mapping[pid] = {
                    "purl": helper.get("purl"),
                    "cpe": helper.get("cpe"),
                }

    # tree 자체가 root branch — branches 키만 진입
    for child in tree.get("branches", []) or []:
        walk(child)
    # 단일 product node (test 의 평탄 구조 대응)
    if tree.get("product"):
        walk(tree)
    return mapping


# ───────────────────── 외부 fetch ─────────────────────

def fetch_redhat_csaf_changes(
    url: str = REDHAT_CSAF_CHANGES_URL, timeout: int = 60
) -> list[str]:
    """Red Hat CSAF VEX changes.csv → 최근 갱신된 VEX 문서 URL 리스트.

    CSV 형식 (예): "{path}","2024-03-15T00:00:00+00:00"
    """
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        text = resp.text

    urls: list[str] = []
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row:
            continue
        path = row[0].strip()
        if path.endswith(".json"):
            urls.append(f"https://access.redhat.com/security/data/csaf/v2/vex/{path}")
    logger.info("Red Hat CSAF changes — %d 문서 후보", len(urls))
    return urls


def fetch_csaf_vex(url: str, timeout: int = 60) -> dict[str, Any]:
    """개별 CSAF VEX JSON 문서 다운로드."""
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.json()


# ───────────────────── parser ─────────────────────

def _parse_iso_date(s: str | None) -> date | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
    except ValueError:
        return None


# CSAF product_status 키 → 우리 status 값 매핑
STATUS_MAP = {
    "known_not_affected":  "not_affected",
    "known_affected":      "affected",
    "fixed":               "fixed",
    "first_fixed":         "fixed",
    "under_investigation": "under_investigation",
}


def parse_csaf_vex(doc: dict[str, Any]) -> list[VexStatement]:
    """CSAF 2.0 VEX 문서 → VexStatement 리스트.

    vulnerabilities[].product_status 의 각 status × 각 product_id 마다 1 statement.
    """
    tracking = (doc.get("document", {}) or {}).get("tracking", {}) or {}
    published_at = _parse_iso_date(tracking.get("current_release_date"))

    product_map = flatten_product_tree(doc.get("product_tree", {}) or {})

    statements: list[VexStatement] = []
    for vuln in doc.get("vulnerabilities", []) or []:
        cve_id = vuln.get("cve")
        if not cve_id:
            continue

        # justification — flags[].label (product_id 별 다를 수 있음, 첫 항목 채택)
        flags_by_product: dict[str, str] = {}
        for flag in vuln.get("flags", []) or []:
            label = flag.get("label")
            if not label:
                continue
            for pid in flag.get("product_ids", []) or []:
                flags_by_product.setdefault(pid, label)

        # impact / action — threats / remediations 첫 항목
        impact = ""
        for threat in vuln.get("threats", []) or []:
            if threat.get("category") == "impact":
                impact = threat.get("details", "")
                break
        action = ""
        for rem in vuln.get("remediations", []) or []:
            if rem.get("details"):
                action = rem["details"]
                break

        # product_status 각 키 처리
        product_status = vuln.get("product_status", {}) or {}
        for csaf_key, our_status in STATUS_MAP.items():
            for pid in product_status.get(csaf_key, []) or []:
                ident = product_map.get(pid, {})
                statements.append(VexStatement(
                    cve_id=cve_id,
                    product_purl=ident.get("purl"),
                    product_cpe=ident.get("cpe"),
                    status=our_status,
                    justification=flags_by_product.get(pid),
                    impact_statement=impact,
                    action_statement=action,
                    published_at=published_at,
                ))

    return statements


# ───────────────────── transform / upsert ─────────────────────

def transform_vex(
    statements: list[VexStatement], *, vex_source: str
) -> list[dict[str, Any]]:
    """VexStatement → tb_vex INSERT 입력."""
    return [
        {
            "cve_id": s.cve_id,
            "product_purl": s.product_purl,
            "product_cpe": s.product_cpe,
            "status": s.status,
            "justification": s.justification,
            "impact_statement": s.impact_statement,
            "action_statement": s.action_statement,
            "vex_source": vex_source,
            "published_at": s.published_at,
        }
        for s in statements
    ]


UPSERT_SQL = """
INSERT INTO tb_vex (
    cve_id, product_purl, product_cpe,
    status, justification, impact_statement, action_statement,
    vex_source, published_at, fetched_at
) VALUES (
    %(cve_id)s, %(product_purl)s, %(product_cpe)s,
    %(status)s, %(justification)s, %(impact_statement)s, %(action_statement)s,
    %(vex_source)s, %(published_at)s, NOW()
)
ON CONFLICT (cve_id, vex_source, COALESCE(product_purl, ''), COALESCE(product_cpe, '')) DO UPDATE SET
    status           = EXCLUDED.status,
    justification    = COALESCE(EXCLUDED.justification, tb_vex.justification),
    impact_statement = COALESCE(NULLIF(EXCLUDED.impact_statement, ''), tb_vex.impact_statement),
    action_statement = COALESCE(NULLIF(EXCLUDED.action_statement, ''), tb_vex.action_statement),
    published_at     = COALESCE(EXCLUDED.published_at, tb_vex.published_at),
    fetched_at       = NOW()
"""


def upsert_vex_rows(conn, rows: list[dict[str, Any]]) -> int:
    """tb_vex UPSERT. 처리 행수 반환."""
    count = 0
    with conn.cursor() as cur:
        for r in rows:
            cur.execute(UPSERT_SQL, r)
            count += 1
    return count
