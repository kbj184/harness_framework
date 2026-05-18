"""AWS EC2 describe_instances API 수집기."""

from __future__ import annotations

import logging
from typing import Any

from src.agents.aws.models import AwsEc2Instance

logger = logging.getLogger("collect_cmdb")


class AwsEc2Collector:
    """EC2 describe_instances를 페이지네이션으로 전수 수집한다."""

    def __init__(self, ec2_client: Any) -> None:
        """
        Args:
            ec2_client: boto3.client('ec2', ...) 인스턴스. 테스트를 위해 외부 주입.
        """
        self._ec2 = ec2_client

    def collect_all_instances(self, filters: list[dict[str, Any]] | None = None) -> list[AwsEc2Instance]:
        """모든 EC2 인스턴스를 페이지네이션으로 수집한다.

        Args:
            filters: EC2 describe_instances Filters (예: instance-state-name=running)

        Returns:
            AwsEc2Instance 리스트. 개별 파싱 실패 건은 스킵하고 계속 진행.
        """
        paginator = self._ec2.get_paginator("describe_instances")
        if filters:
            pages = paginator.paginate(Filters=filters)
        else:
            pages = paginator.paginate()

        instances: list[AwsEc2Instance] = []
        total_raw = 0

        for page in pages:
            for reservation in page.get("Reservations", []):
                for raw in reservation.get("Instances", []):
                    total_raw += 1
                    try:
                        instances.append(AwsEc2Instance(**raw))
                    except Exception:
                        logger.exception(
                            "EC2 인스턴스 파싱 실패: raw=%s",
                            {k: raw.get(k) for k in ("InstanceId", "InstanceType")},
                        )

        logger.info(
            "EC2 수집 완료: raw=%d, parsed=%d",
            total_raw,
            len(instances),
            extra={"raw_count": total_raw, "parsed_count": len(instances)},
        )
        return instances
