"""MITRE CWE XML 수집 (공개, 인증 불필요).

cwec_latest.xml.zip → unzip → XML parse → tb_cwe_dictionary UPSERT.
"""

from __future__ import annotations

import io
import json
import logging
import zipfile
from dataclasses import dataclass, field
from typing import Any
from xml.etree import ElementTree as ET

import httpx

logger = logging.getLogger("collect_cmdb")

CWE_ZIP_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

# MITRE CWE XML 기본 namespace — 매번 prefix 붙이는 게 번거로워 헬퍼 사용
NS = {"cwe": "http://cwe.mitre.org/cwe-7"}


@dataclass
class CweWeakness:
    """파싱된 CWE 약점 1건."""
    cwe_id: str                         # CWE-79
    name_en: str
    abstraction: str | None             # Class / Base / Variant / Compound
    status: str | None                  # Draft / Incomplete / Stable / Deprecated
    description: str
    parent_cwe: str | None              # CWE-74 (Related_Weakness Nature=ChildOf)
    mitigations: list[dict[str, str]] = field(default_factory=list)


def fetch_cwe_zip(url: str = CWE_ZIP_URL, timeout: int = 120) -> bytes:
    """CWE XML zip 다운로드 후 압축 풀어서 XML 바이트 반환."""
    logger.info("CWE zip 다운로드: %s", url)
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url)
        resp.raise_for_status()
        zip_bytes = resp.content
    logger.info("CWE zip %d bytes 다운로드 완료", len(zip_bytes))

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        # zip 안에는 cwec_v4.X.xml 하나
        xml_names = [n for n in zf.namelist() if n.endswith(".xml")]
        if not xml_names:
            raise ValueError("zip 안에 XML 파일 없음")
        with zf.open(xml_names[0]) as xf:
            xml_bytes = xf.read()
    logger.info("CWE XML %d bytes 압축 해제 완료 (%s)", len(xml_bytes), xml_names[0])
    return xml_bytes


def _text(elem: ET.Element | None) -> str:
    """element 의 text 안전 추출 (None → 빈 문자열)."""
    if elem is None:
        return ""
    return (elem.text or "").strip()


def parse_cwe_xml(xml_bytes: bytes) -> list[CweWeakness]:
    """CWE XML 바이트 → CweWeakness 리스트."""
    root = ET.fromstring(xml_bytes)
    weaknesses_elem = root.find("cwe:Weaknesses", NS)
    if weaknesses_elem is None:
        # namespace 없는 경우 (test 환경 등) — 다시 시도
        weaknesses_elem = root.find("Weaknesses")
        ns = {}
    else:
        ns = NS

    if weaknesses_elem is None:
        logger.warning("Weaknesses element 없음")
        return []

    items: list[CweWeakness] = []
    weakness_tag = "cwe:Weakness" if ns else "Weakness"
    for w in weaknesses_elem.findall(weakness_tag, ns):
        cwe_num = w.get("ID")
        if not cwe_num:
            continue

        description_tag = "cwe:Description" if ns else "Description"
        related_tag = "cwe:Related_Weaknesses" if ns else "Related_Weaknesses"
        related_w_tag = "cwe:Related_Weakness" if ns else "Related_Weakness"
        mitigations_tag = "cwe:Potential_Mitigations" if ns else "Potential_Mitigations"
        mitigation_tag = "cwe:Mitigation" if ns else "Mitigation"
        phase_tag = "cwe:Phase" if ns else "Phase"
        strategy_tag = "cwe:Strategy" if ns else "Strategy"

        # 부모 CWE (Nature=ChildOf 의 첫 항목)
        parent_cwe = None
        related = w.find(related_tag, ns)
        if related is not None:
            for rw in related.findall(related_w_tag, ns):
                if rw.get("Nature") == "ChildOf":
                    parent_id = rw.get("CWE_ID")
                    if parent_id:
                        parent_cwe = f"CWE-{parent_id}"
                        break

        # 조치 가이드
        mitigations: list[dict[str, str]] = []
        mitigations_elem = w.find(mitigations_tag, ns)
        if mitigations_elem is not None:
            for m in mitigations_elem.findall(mitigation_tag, ns):
                mitigations.append({
                    "phase": _text(m.find(phase_tag, ns)),
                    "strategy": _text(m.find(strategy_tag, ns)),
                    "description": _text(m.find(description_tag, ns)),
                })

        items.append(CweWeakness(
            cwe_id=f"CWE-{cwe_num}",
            name_en=w.get("Name", ""),
            abstraction=w.get("Abstraction"),
            status=w.get("Status"),
            description=_text(w.find(description_tag, ns)),
            parent_cwe=parent_cwe,
            mitigations=mitigations,
        ))

    logger.info("CWE %d개 파싱 완료", len(items))
    return items


def transform_cwe(items: list[CweWeakness]) -> list[dict[str, Any]]:
    """CweWeakness → DB upsert dict."""
    rows: list[dict[str, Any]] = []
    for w in items:
        rows.append({
            "cwe_id": w.cwe_id,
            "name_en": w.name_en,
            "name_ko": None,                              # 추후 번역
            "description": w.description,
            "abstraction": w.abstraction,
            "parent_cwe": w.parent_cwe,
            "deprecated": (w.status == "Deprecated"),
            "mitigations": json.dumps(w.mitigations, ensure_ascii=False),
        })
    return rows


UPSERT_SQL = """
INSERT INTO tb_cwe_dictionary (
    cwe_id, name_en, name_ko, description,
    abstraction, parent_cwe, deprecated, mitigations,
    reg_dt, upd_dt
) VALUES (
    %(cwe_id)s, %(name_en)s, %(name_ko)s, %(description)s,
    %(abstraction)s, %(parent_cwe)s, %(deprecated)s, %(mitigations)s::jsonb,
    LOCALTIMESTAMP, LOCALTIMESTAMP
)
ON CONFLICT (cwe_id) DO UPDATE SET
    name_en      = EXCLUDED.name_en,
    description  = EXCLUDED.description,
    abstraction  = EXCLUDED.abstraction,
    parent_cwe   = EXCLUDED.parent_cwe,
    deprecated   = EXCLUDED.deprecated,
    mitigations  = EXCLUDED.mitigations,
    upd_dt       = LOCALTIMESTAMP
"""


def upsert_cwe_rows(conn, rows: list[dict[str, Any]]) -> int:
    """tb_cwe_dictionary UPSERT. 처리 행수 반환."""
    count = 0
    with conn.cursor() as cur:
        for r in rows:
            cur.execute(UPSERT_SQL, r)
            count += 1
    return count
