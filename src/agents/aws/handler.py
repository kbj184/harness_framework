"""AWS EC2 수집 Lambda 진입점."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

import boto3

from src.agents.aws.collector import AwsEc2Collector
from src.agents.aws.transformer import transform_instances
from src.shared.config import load_aws_target_config
from src.shared.logging_config import setup_logging
from src.shared.models import AssetSource
from src.shared.s3_client import put_assets

logger = setup_logging()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS EC2 인스턴스를 수집하여 S3 raw 버킷에 적재한다.

    Phase 0(백엔드 bulk API 직행) → Phase 2(S3 → Parser) 전환.
    적재된 JSONL.gz 는 asset_parser 가 s3:ObjectCreated 로 소비.

    Event 지원 필드:
        filters: EC2 describe_instances Filters 리스트 (선택).
                 예: [{"Name": "instance-state-name", "Values": ["running"]}]
    """
    start_time = time.monotonic()
    collected_at = datetime.now(UTC)

    logger.info("AWS EC2 자산 수집 시작", extra={"agent": "aws_ec2"})

    try:
        # 1. 대상 AWS 자격증명 로드
        target = load_aws_target_config()

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
            return _result(collected_at, 0, None, start_time)

        # 4. CommonAsset으로 변환
        assets = transform_instances(instances, collected_at)
        logger.info(
            "변환 완료: %d건",
            len(assets),
            extra={"agent": "aws_ec2", "count": len(assets)},
        )

        # 5. S3 raw 버킷에 JSONL.gz 적재 (Parser 가 s3:ObjectCreated 로 소비)
        s3_key = put_assets(assets, AssetSource.AWS_EC2.value, collected_at)

        return _result(collected_at, len(assets), s3_key, start_time)

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
    s3_key: str | None,
    start_time: float,
) -> dict[str, Any]:
    duration_ms = int((time.monotonic() - start_time) * 1000)
    logger.info(
        "AWS EC2 자산 수집 완료: total=%d, s3_key=%s, duration=%dms",
        total,
        s3_key,
        duration_ms,
        extra={"agent": "aws_ec2", "count": total, "duration_ms": duration_ms},
    )
    return {
        "status": "SUCCESS",
        "collected_at": collected_at.isoformat(),
        "total_count": total,
        "s3_key": s3_key,
        "duration_ms": duration_ms,
    }
