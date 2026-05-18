"""CrowdStrike collector 단위 테스트."""

from unittest.mock import MagicMock, patch

import pytest

from src.agents.crowdstrike.collector import CrowdStrikeCollector


def _mock_scroll_response(resources: list[str], offset: str | None = None, status_code: int = 200):
    return {
        "status_code": status_code,
        "body": {
            "resources": resources,
            "meta": {"pagination": {"offset": offset}},
        },
    }


def _mock_details_response(devices: list[dict], status_code: int = 200):
    return {
        "status_code": status_code,
        "body": {"resources": devices},
    }


SAMPLE_DEVICE = {
    "device_id": "abc123",
    "hostname": "server-01",
    "local_ip": "192.168.1.10",
    "external_ip": "203.0.113.1",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "os_version": "Windows 10",
    "platform_name": "Windows",
    "system_manufacturer": "Dell Inc.",
    "system_product_name": "OptiPlex 7080",
    "serial_number": "SN12345",
    "agent_version": "7.10.16303.0",
    "last_seen": "2026-04-16T01:00:00Z",
    "first_seen": "2025-01-15T08:00:00Z",
    "machine_domain": "corp.example.com",
    "status": "normal",
}


class TestCrowdStrikeCollector:
    @patch("src.agents.crowdstrike.collector.Hosts")
    def test_collect_single_page(self, mock_hosts_cls):
        """단일 페이지 디바이스 수집."""
        mock_hosts = MagicMock()
        mock_hosts_cls.return_value = mock_hosts

        mock_hosts.query_devices_by_filter_scroll.return_value = _mock_scroll_response(
            resources=["abc123"], offset=None
        )
        mock_hosts.get_device_details_v2.return_value = _mock_details_response([SAMPLE_DEVICE])

        collector = CrowdStrikeCollector(client_id="id", client_secret="secret")
        devices = collector.collect_all_devices()

        assert len(devices) == 1
        assert devices[0].device_id == "abc123"
        assert devices[0].hostname == "server-01"
        assert devices[0].system_manufacturer == "Dell Inc."

    @patch("src.agents.crowdstrike.collector.Hosts")
    def test_collect_multiple_pages(self, mock_hosts_cls):
        """여러 페이지 스크롤 페이지네이션."""
        mock_hosts = MagicMock()
        mock_hosts_cls.return_value = mock_hosts

        # 2 pages: first returns 5000 IDs with offset, second returns 100 IDs without offset
        page1_ids = [f"dev-{i}" for i in range(5000)]
        page2_ids = [f"dev-{i}" for i in range(5000, 5100)]

        mock_hosts.query_devices_by_filter_scroll.side_effect = [
            _mock_scroll_response(resources=page1_ids, offset="next-offset-token"),
            _mock_scroll_response(resources=page2_ids, offset=None),
        ]

        # Details: return matching devices
        all_devices = [{"device_id": f"dev-{i}", "hostname": f"host-{i}"} for i in range(5100)]
        mock_hosts.get_device_details_v2.side_effect = [
            _mock_details_response(all_devices[:5000]),
            _mock_details_response(all_devices[5000:]),
        ]

        collector = CrowdStrikeCollector(client_id="id", client_secret="secret")
        devices = collector.collect_all_devices()

        assert len(devices) == 5100
        assert mock_hosts.query_devices_by_filter_scroll.call_count == 2

    @patch("src.agents.crowdstrike.collector.Hosts")
    def test_collect_empty(self, mock_hosts_cls):
        """디바이스 없는 경우 빈 리스트 반환."""
        mock_hosts = MagicMock()
        mock_hosts_cls.return_value = mock_hosts

        mock_hosts.query_devices_by_filter_scroll.return_value = _mock_scroll_response(resources=[])

        collector = CrowdStrikeCollector(client_id="id", client_secret="secret")
        devices = collector.collect_all_devices()

        assert devices == []
        mock_hosts.get_device_details_v2.assert_not_called()

    @patch("src.agents.crowdstrike.collector.Hosts")
    def test_scroll_api_error_raises(self, mock_hosts_cls):
        """스크롤 API 에러 시 RuntimeError 발생."""
        mock_hosts = MagicMock()
        mock_hosts_cls.return_value = mock_hosts

        mock_hosts.query_devices_by_filter_scroll.return_value = {
            "status_code": 403,
            "body": {"errors": [{"message": "Access denied"}]},
        }

        collector = CrowdStrikeCollector(client_id="id", client_secret="secret")

        with pytest.raises(RuntimeError, match="403"):
            collector.collect_all_devices()

    @patch("src.agents.crowdstrike.collector.Hosts")
    def test_collect_with_fql_filter(self, mock_hosts_cls):
        """FQL 필터가 API 호출에 전달된다."""
        mock_hosts = MagicMock()
        mock_hosts_cls.return_value = mock_hosts

        mock_hosts.query_devices_by_filter_scroll.return_value = _mock_scroll_response(resources=[])

        collector = CrowdStrikeCollector(client_id="id", client_secret="secret")
        collector.collect_all_devices(fql_filter="platform_name:'Windows'")

        call_kwargs = mock_hosts.query_devices_by_filter_scroll.call_args[1]
        assert call_kwargs["filter"] == "platform_name:'Windows'"
