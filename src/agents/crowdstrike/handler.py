"""CrowdStrike 수집 Lambda 진입점."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from src.agents.crowdstrike.collector import CrowdStrikeCollector
from src.agents.crowdstrike.transformer import transform_devices
from src.shared.api_client import BackendApiClient
from src.shared.config import load_config
from src.shared.logging_config import setup_logging
from src.shared.models import AssetSource, BulkAssetPayload

logger = setup_logging()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """CrowdStrike Hosts API에서 디바이스를 수집하여 백엔드에 전송한다."""
    start_time = time.monotonic()
    collected_at = datetime.now(UTC)

    logger.info("CrowdStrike 자산 수집 시작", extra={"agent": "crowdstrike"})

    try:
        config = load_config()

        # 1. CrowdStrike에서 디바이스 수집
        collector = CrowdStrikeCollector(
            client_id=config.crowdstrike.client_id,
            client_secret=config.crowdstrike.client_secret,
            base_url=config.crowdstrike.base_url,
        )
        fql_filter = event.get("fql_filter", "")
        devices = collector.collect_all_devices(fql_filter=fql_filter)

        if not devices:
            logger.info("수집된 디바이스 없음", extra={"agent": "crowdstrike"})
            return _result(collected_at, 0, 0, 0, start_time)

        # 2. CommonAsset으로 변환
        assets = transform_devices(devices, collected_at)
        logger.info("변환 완료: %d건", len(assets), extra={"agent": "crowdstrike", "count": len(assets)})

        # 3. 백엔드 API로 배치 전송
        api_client = BackendApiClient(
            base_url=config.backend.base_url,
            api_key=config.backend.api_key,
            timeout=config.backend.timeout_seconds,
        )

        total_created = 0
        total_updated = 0

        for i in range(0, len(assets), config.batch_size):
            batch = assets[i : i + config.batch_size]
            payload = BulkAssetPayload(source=AssetSource.CROWDSTRIKE, collected_at=collected_at, assets=batch)
            response = api_client.send_assets(payload)
            total_created += response.created_count
            total_updated += response.updated_count
            logger.info(
                "배치 전송 완료 (%d~%d): created=%d, updated=%d",
                i,
                i + len(batch),
                response.created_count,
                response.updated_count,
            )

        return _result(collected_at, len(assets), total_created, total_updated, start_time)

    except Exception as e:
        duration_ms = int((time.monotonic() - start_time) * 1000)
        logger.exception("CrowdStrike 자산 수집 실패", extra={"agent": "crowdstrike", "duration_ms": duration_ms})
        return {
            "status": "FAILED",
            "error": str(e),
            "collected_at": collected_at.isoformat(),
            "duration_ms": duration_ms,
        }


def _result(collected_at: datetime, total: int, created: int, updated: int, start_time: float) -> dict[str, Any]:
    duration_ms = int((time.monotonic() - start_time) * 1000)
    logger.info(
        "CrowdStrike 자산 수집 완료: total=%d, created=%d, updated=%d, duration=%dms",
        total,
        created,
        updated,
        duration_ms,
        extra={"agent": "crowdstrike", "count": total, "duration_ms": duration_ms},
    )
    return {
        "status": "SUCCESS",
        "collected_at": collected_at.isoformat(),
        "total_count": total,
        "created_count": created,
        "updated_count": updated,
        "duration_ms": duration_ms,
    }
