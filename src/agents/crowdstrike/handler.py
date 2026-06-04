"""CrowdStrike 수집 Lambda 진입점."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from src.agents.crowdstrike.collector import CrowdStrikeCollector
from src.agents.crowdstrike.transformer import transform_devices
from src.shared.config import load_crowdstrike_config
from src.shared.logging_config import setup_logging
from src.shared.models import AssetSource
from src.shared.s3_client import put_assets

logger = setup_logging()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """CrowdStrike Hosts API에서 디바이스를 수집하여 S3 raw 버킷에 적재한다.

    Phase 0(백엔드 bulk API 직행) → Phase 2(S3 → Parser) 전환.
    """
    start_time = time.monotonic()
    collected_at = datetime.now(UTC)

    logger.info("CrowdStrike 자산 수집 시작", extra={"agent": "crowdstrike"})

    try:
        cs = load_crowdstrike_config()

        # 1. CrowdStrike에서 디바이스 수집
        collector = CrowdStrikeCollector(
            client_id=cs.client_id,
            client_secret=cs.client_secret,
            base_url=cs.base_url,
        )
        fql_filter = event.get("fql_filter", "")
        devices = collector.collect_all_devices(fql_filter=fql_filter)

        if not devices:
            logger.info("수집된 디바이스 없음", extra={"agent": "crowdstrike"})
            return _result(collected_at, 0, None, start_time)

        # 2. CommonAsset으로 변환
        assets = transform_devices(devices, collected_at)
        logger.info("변환 완료: %d건", len(assets), extra={"agent": "crowdstrike", "count": len(assets)})

        # 3. S3 raw 버킷에 JSONL.gz 적재 (Parser 가 s3:ObjectCreated 로 소비)
        s3_key = put_assets(assets, AssetSource.CROWDSTRIKE.value, collected_at)

        return _result(collected_at, len(assets), s3_key, start_time)

    except Exception as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        logger.exception("CrowdStrike 자산 수집 실패", extra={"agent": "crowdstrike", "duration_ms": duration_ms})
        return {
            "status": "FAILED",
            "error": str(e),
            "collected_at": collected_at.isoformat(),
            "duration_ms": duration_ms,
        }


def _result(collected_at: datetime, total: int, s3_key: str | None, start_time: float) -> dict[str, Any]:
    duration_ms = int((time.monotonic() - start_time) * 1000)
    logger.info(
        "CrowdStrike 자산 수집 완료: total=%d, s3_key=%s, duration=%dms",
        total,
        s3_key,
        duration_ms,
        extra={"agent": "crowdstrike", "count": total, "duration_ms": duration_ms},
    )
    return {
        "status": "SUCCESS",
        "collected_at": collected_at.isoformat(),
        "total_count": total,
        "s3_key": s3_key,
        "duration_ms": duration_ms,
    }
