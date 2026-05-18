"""AWS EC2 수집 Lambda 진입점."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

import boto3

from src.agents.aws.collector import AwsEc2Collector
from src.agents.aws.transformer import transform_instances
from src.shared.api_client import BackendApiClient
from src.shared.config import load_aws_target_config, load_backend_config
from src.shared.logging_config import setup_logging
from src.shared.models import AssetSource, BulkAssetPayload

logger = setup_logging()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS EC2 인스턴스를 수집하여 백엔드에 전송한다.

    Event 지원 필드:
        filters: EC2 describe_instances Filters 리스트 (선택).
                 예: [{"Name": "instance-state-name", "Values": ["running"]}]
    """
    start_time = time.monotonic()
    collected_at = datetime.now(UTC)

    logger.info("AWS EC2 자산 수집 시작", extra={"agent": "aws_ec2"})

    try:
        # 1. 설정 로드 (대상 AWS 자격증명 + 백엔드 API)
        target = load_aws_target_config()
        backend = load_backend_config()

        # 2. 대상 AWS EC2 client 생성 (cross-account Access Key)
        ec2 = boto3.client(
            "ec2",
            aws_access_key_id=target.access_key_id,
            aws_secret_access_key=target.secret_access_key,
            region_name=target.region,
        )

        # 3. describe_instances 수집
        filters = event.get("filters") if isinstance(event, dict) else None
        collector = AwsEc2Collector(ec2_client=ec2)
        instances = collector.collect_all_instances(filters=filters)

        if not instances:
            logger.info("수집된 EC2 인스턴스 없음", extra={"agent": "aws_ec2"})
            return _result(collected_at, 0, 0, 0, start_time)

        # 4. CommonAsset으로 변환
        assets = transform_instances(instances, collected_at)
        logger.info(
            "변환 완료: %d건",
            len(assets),
            extra={"agent": "aws_ec2", "count": len(assets)},
        )

        # 5. 백엔드 API로 배치 전송
        api_client = BackendApiClient(
            base_url=backend.base_url,
            api_key=backend.api_key,
            timeout=backend.timeout_seconds,
        )

        batch_size = 500
        total_created = 0
        total_updated = 0

        for i in range(0, len(assets), batch_size):
            batch = assets[i : i + batch_size]
            payload = BulkAssetPayload(source=AssetSource.AWS_EC2, collected_at=collected_at, assets=batch)
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
        logger.exception(
            "AWS EC2 자산 수집 실패",
            extra={"agent": "aws_ec2", "duration_ms": duration_ms},
        )
        return {
            "status": "FAILED",
            "error": str(e),
            "collected_at": collected_at.isoformat(),
            "duration_ms": duration_ms,
        }


def _result(
    collected_at: datetime,
    total: int,
    created: int,
    updated: int,
    start_time: float,
) -> dict[str, Any]:
    duration_ms = int((time.monotonic() - start_time) * 1000)
    logger.info(
        "AWS EC2 자산 수집 완료: total=%d, created=%d, updated=%d, duration=%dms",
        total,
        created,
        updated,
        duration_ms,
        extra={"agent": "aws_ec2", "count": total, "duration_ms": duration_ms},
    )
    return {
        "status": "SUCCESS",
        "collected_at": collected_at.isoformat(),
        "total_count": total,
        "created_count": created,
        "updated_count": updated,
        "duration_ms": duration_ms,
    }
