"""CrowdStrike Falcon Hosts API 수집기."""

from __future__ import annotations

import logging
from typing import Any

from falconpy import Hosts

from src.agents.crowdstrike.models import CrowdStrikeDevice

logger = logging.getLogger("collect_cmdb")

SCROLL_LIMIT = 5000
DETAIL_BATCH_SIZE = 5000


class CrowdStrikeCollector:
    """CrowdStrike Hosts API에서 디바이스 목록을 수집한다."""

    def __init__(self, client_id: str, client_secret: str, base_url: str = "https://api.crowdstrike.com") -> None:
        self._hosts = Hosts(client_id=client_id, client_secret=client_secret, base_url=base_url)

    def collect_all_devices(self, fql_filter: str = "") -> list[CrowdStrikeDevice]:
        """모든 디바이스를 스크롤 페이지네이션으로 조회하고 상세 정보를 반환한다."""
        device_ids = self._scroll_all_device_ids(fql_filter)
        logger.info("디바이스 ID %d건 조회 완료", len(device_ids), extra={"count": len(device_ids)})

        if not device_ids:
            return []

        devices = self._fetch_device_details(device_ids)
        logger.info("디바이스 상세 %d건 조회 완료", len(devices), extra={"count": len(devices)})
        return devices

    def _scroll_all_device_ids(self, fql_filter: str) -> list[str]:
        """스크롤 페이지네이션으로 전체 디바이스 ID 목록을 조회한다."""
        all_ids: list[str] = []
        offset: str | None = None

        while True:
            params: dict[str, Any] = {"limit": SCROLL_LIMIT}
            if fql_filter:
                params["filter"] = fql_filter
            if offset:
                params["offset"] = offset

            response = self._hosts.query_devices_by_filter_scroll(**params)
            body = response.get("body", {})
            status_code = response.get("status_code", 0)

            if status_code != 200:
                errors = body.get("errors", [])
                raise RuntimeError(f"CrowdStrike 디바이스 조회 실패 (HTTP {status_code}): {errors}")

            resources = body.get("resources", [])
            if not resources:
                break

            all_ids.extend(resources)
            offset = body.get("meta", {}).get("pagination", {}).get("offset")

            # offset이 없거나 반환된 건수가 limit 미만이면 종료
            if not offset or len(resources) < SCROLL_LIMIT:
                break

        return all_ids

    def _fetch_device_details(self, device_ids: list[str]) -> list[CrowdStrikeDevice]:
        """디바이스 ID 배치로 상세 정보를 조회한다."""
        devices: list[CrowdStrikeDevice] = []

        for i in range(0, len(device_ids), DETAIL_BATCH_SIZE):
            batch = device_ids[i : i + DETAIL_BATCH_SIZE]
            response = self._hosts.get_device_details_v2(ids=batch)
            body = response.get("body", {})
            status_code = response.get("status_code", 0)

            if status_code != 200:
                errors = body.get("errors", [])
                logger.error("디바이스 상세 조회 실패 (배치 %d~%d): %s", i, i + len(batch), errors)
                continue

            for raw in body.get("resources", []):
                devices.append(CrowdStrikeDevice.model_validate(raw))

        return devices
