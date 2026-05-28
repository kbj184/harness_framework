"""MITRE CWE 수집 Lambda 진입점.

EventBridge 분기 cron으로 호출되어 cwec_latest.xml.zip 을 다운로드,
파싱 후 tb_cwe_dictionary 에 UPSERT.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from src.agents.mitre_cwe_collector.collector import (
    fetch_cwe_zip,
    parse_cwe_xml,
    transform_cwe,
    upsert_cwe_rows,
)
from src.shared import db as dbm
from src.shared.logging_config import setup_logging

logger = setup_logging()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """MITRE CWE XML zip 다운로드 + 파싱 + tb_cwe_dictionary UPSERT."""
    start = time.monotonic()
    started_at = datetime.now(UTC)
    logger.info("CWE 수집 시작", extra={"agent": "mitre_cwe_collector"})

    try:
        cfg = dbm.load_db_config()
        with dbm.connect(cfg) as conn:
            log_no = dbm.log_collection_start(conn, "MITRE_CWE", started_at)
            try:
                xml_bytes = fetch_cwe_zip()
                items = parse_cwe_xml(xml_bytes)
                rows = transform_cwe(items)
                upserted = upsert_cwe_rows(conn, rows)
                dbm.log_collection_end(
                    conn, log_no, "SUCCESS", len(rows), upserted, datetime.now(UTC)
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
            "total_count": len(rows),
            "upserted_count": upserted,
            "duration_ms": duration_ms,
        }
        logger.info("CWE 수집 완료: %s", result)
        return result

    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.exception("CWE 수집 실패")
        return {
            "status": "FAILED",
            "error": str(e),
            "started_at": started_at.isoformat(),
            "duration_ms": duration_ms,
        }
