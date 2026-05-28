"""VEX 수집 Lambda 진입점.

주 1회 (CSAF VEX 갱신 주기 동조) — Red Hat changes.csv 읽어 변경된 VEX 문서만
다운로드 + 파싱 → tb_vex UPSERT. 한 문서 실패해도 나머지 계속.

OPENVEX_URLS 환경변수 (콤마구분) 로 추가 OpenVEX 문서 URL 지정 가능.
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime
from typing import Any

from src.agents.vex_collector.collector import (
    fetch_csaf_vex,
    fetch_redhat_csaf_changes,
    parse_csaf_vex,
    transform_vex,
    upsert_vex_rows,
)
from src.shared import db as dbm
from src.shared.logging_config import setup_logging

logger = setup_logging()

# 처리할 최대 문서 수 (안전 장치)
MAX_REDHAT_DOCS = int(os.environ.get("VEX_MAX_DOCS", "500"))


def _collect_redhat_csaf() -> tuple[list, int]:
    """Red Hat CSAF VEX changes.csv → 개별 VEX 다운로드 → statement 리스트."""
    all_statements = []
    docs_processed = 0
    failures = 0
    try:
        urls = fetch_redhat_csaf_changes()
    except Exception:
        logger.exception("Red Hat CSAF changes.csv 다운로드 실패")
        return [], 0

    urls = urls[:MAX_REDHAT_DOCS]
    for url in urls:
        try:
            doc = fetch_csaf_vex(url)
            stmts = parse_csaf_vex(doc)
            all_statements.extend(stmts)
            docs_processed += 1
        except Exception:
            failures += 1
            logger.warning("VEX 문서 처리 실패: %s", url, exc_info=True)
    logger.info(
        "Red Hat CSAF — %d 문서 처리 (%d 실패) → %d statement",
        docs_processed, failures, len(all_statements),
    )
    return all_statements, docs_processed


def _collect_openvex() -> list:
    """OPENVEX_URLS 환경변수에 콤마 구분으로 지정된 OpenVEX 문서 수집."""
    raw = os.environ.get("OPENVEX_URLS", "").strip()
    if not raw:
        return []
    urls = [u.strip() for u in raw.split(",") if u.strip()]
    statements = []
    for url in urls:
        try:
            doc = fetch_csaf_vex(url)            # OpenVEX 도 JSON 호환
            statements.extend(parse_csaf_vex(doc))
        except Exception:
            logger.warning("OpenVEX 문서 처리 실패: %s", url, exc_info=True)
    return statements


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """VEX 통합 수집 → tb_vex UPSERT."""
    start = time.monotonic()
    started_at = datetime.now(UTC)
    logger.info("VEX 수집 시작", extra={"agent": "vex_collector"})

    try:
        redhat_stmts, redhat_docs = _collect_redhat_csaf()
        openvex_stmts = _collect_openvex()

        rows_redhat = transform_vex(redhat_stmts, vex_source="REDHAT_CSAF")
        rows_openvex = transform_vex(openvex_stmts, vex_source="OPENVEX")
        all_rows = rows_redhat + rows_openvex

        cfg = dbm.load_db_config()
        with dbm.connect(cfg) as conn:
            log_no = dbm.log_collection_start(conn, "VEX", started_at)
            try:
                upserted = upsert_vex_rows(conn, all_rows)
                dbm.log_collection_end(
                    conn, log_no, "SUCCESS", len(all_rows), upserted, datetime.now(UTC)
                )
            except Exception as e:
                dbm.log_collection_end(
                    conn, log_no, "FAILED", 0, 0, datetime.now(UTC), str(e)
                )
                raise

        duration_ms = int((time.monotonic() - start) * 1000)
        result = {
            "status": "SUCCESS",
            "started_at": started_at.isoformat(),
            "redhat_docs": redhat_docs,
            "redhat_statements": len(redhat_stmts),
            "openvex_statements": len(openvex_stmts),
            "total_count": len(all_rows),
            "upserted_count": upserted,
            "duration_ms": duration_ms,
        }
        logger.info("VEX 수집 완료: %s", result)
        return result

    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.exception("VEX 수집 실패")
        return {
            "status": "FAILED",
            "error": str(e),
            "started_at": started_at.isoformat(),
            "duration_ms": duration_ms,
        }
