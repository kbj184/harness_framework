"""NVD CVE 수집 Lambda 진입점.

Event:
  - days_back: int (기본 30)      - 최근 N일 수집 (초기 수집 시 크게)
  - start_date / end_date (ISO)   - 명시적 범위
  - max_pages: int                - 테스트용 페이지 제한
"""

from __future__ import annotations

import os
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from src.agents.nvd_collector.collector import fetch_cves, upsert_cves
from src.shared import db as dbm
from src.shared.logging_config import setup_logging

logger = setup_logging()


def _parse_event_date(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    start = time.monotonic()
    started_at = datetime.now(UTC)
    logger.info("NVD 수집 시작", extra={"agent": "nvd_collector"})

    days_back = int(event.get("days_back", 30)) if isinstance(event, dict) else 30
    explicit_start = _parse_event_date(event.get("start_date")) if isinstance(event, dict) else None
    explicit_end = _parse_event_date(event.get("end_date")) if isinstance(event, dict) else None
    max_pages = event.get("max_pages") if isinstance(event, dict) else None

    last_end = explicit_end or datetime.now(UTC)
    last_start = explicit_start or (last_end - timedelta(days=days_back))

    api_key = os.environ.get("NVD_API_KEY") or None

    try:
        cfg = dbm.load_db_config()
        with dbm.connect(cfg) as conn:
            log_no = dbm.log_collection_start(conn, "NVD", started_at)
            try:
                entries = fetch_cves(
                    last_mod_start=last_start,
                    last_mod_end=last_end,
                    api_key=api_key,
                    max_pages=max_pages,
                )
                cve_n, cpe_n, match_n = upsert_cves(conn, entries)

                # 동기화 포인터 저장
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO tb_nvd_sync_state (state_key, last_sync_at, last_mod_end_date, total_processed, reg_dt, upd_dt)
                        VALUES ('LAST_MOD', LOCALTIMESTAMP, %s, %s, LOCALTIMESTAMP, LOCALTIMESTAMP)
                        ON CONFLICT (state_key) DO UPDATE SET
                            last_sync_at = LOCALTIMESTAMP,
                            last_mod_end_date = EXCLUDED.last_mod_end_date,
                            total_processed = tb_nvd_sync_state.total_processed + EXCLUDED.total_processed,
                            upd_dt = LOCALTIMESTAMP
                        """,
                        (last_end, cve_n),
                    )

                dbm.log_collection_end(
                    conn, log_no, "SUCCESS", len(entries), cve_n, datetime.now(UTC)
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
            "range": {"start": last_start.isoformat(), "end": last_end.isoformat()},
            "total_entries": len(entries),
            "cve_upserted": cve_n,
            "cpe_upserted": cpe_n,
            "match_upserted": match_n,
            "duration_ms": duration_ms,
        }
        logger.info("NVD 수집 완료: %s", result)
        return result

    except Exception as e:
        duration_ms = int((time.monotonic() - start) * 1000)
        logger.exception("NVD 수집 실패")
        return {
            "status": "FAILED",
            "error": str(e),
            "started_at": started_at.isoformat(),
            "duration_ms": duration_ms,
        }
