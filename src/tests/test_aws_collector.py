"""AWS EC2 collector 단위 테스트 (Boto3 모킹)."""

from __future__ import annotations

from unittest.mock import MagicMock

from src.agents.aws.collector import AwsEc2Collector


def _paginator(pages: list[dict]) -> MagicMock:
    """paginate()가 pages를 iterate하도록 MagicMock 구성."""
    paginator = MagicMock()
    paginator.paginate.return_value = iter(pages)
    return paginator


def _ec2_client_with_pages(pages: list[dict]) -> MagicMock:
    client = MagicMock()
    client.get_paginator.return_value = _paginator(pages)
    return client


class TestAwsEc2Collector:
    def test_collects_instances_single_page(self):
        pages = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {"InstanceId": "i-1", "InstanceType": "t3.micro"},
                            {"InstanceId": "i-2", "InstanceType": "t3.small"},
                        ]
                    }
                ]
            }
        ]
        client = _ec2_client_with_pages(pages)
        collector = AwsEc2Collector(ec2_client=client)

        instances = collector.collect_all_instances()
        assert len(instances) == 2
        assert instances[0].InstanceId == "i-1"
        assert instances[1].InstanceId == "i-2"

    def test_collects_instances_multiple_pages(self):
        pages = [
            {"Reservations": [{"Instances": [{"InstanceId": "i-1"}]}]},
            {"Reservations": [{"Instances": [{"InstanceId": "i-2"}]}]},
            {"Reservations": [{"Instances": [{"InstanceId": "i-3"}]}]},
        ]
        client = _ec2_client_with_pages(pages)
        collector = AwsEc2Collector(ec2_client=client)

        instances = collector.collect_all_instances()
        assert len(instances) == 3
        assert [i.InstanceId for i in instances] == ["i-1", "i-2", "i-3"]

    def test_handles_empty_result(self):
        pages = [{"Reservations": []}]
        client = _ec2_client_with_pages(pages)
        collector = AwsEc2Collector(ec2_client=client)

        instances = collector.collect_all_instances()
        assert instances == []

    def test_handles_multi_instance_reservation(self):
        """한 Reservation에 여러 Instance가 있는 경우."""
        pages = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {"InstanceId": "i-1"},
                            {"InstanceId": "i-2"},
                        ]
                    },
                    {"Instances": [{"InstanceId": "i-3"}]},
                ]
            }
        ]
        client = _ec2_client_with_pages(pages)
        collector = AwsEc2Collector(ec2_client=client)

        instances = collector.collect_all_instances()
        assert len(instances) == 3

    def test_skips_malformed_instance(self):
        """필수 필드(InstanceId) 누락 인스턴스는 스킵하고 계속."""
        pages = [
            {
                "Reservations": [
                    {
                        "Instances": [
                            {"InstanceId": "i-ok"},
                            {"NoInstanceId": True},  # malformed
                            {"InstanceId": "i-ok2"},
                        ]
                    }
                ]
            }
        ]
        client = _ec2_client_with_pages(pages)
        collector = AwsEc2Collector(ec2_client=client)

        instances = collector.collect_all_instances()
        ids = [i.InstanceId for i in instances]
        assert "i-ok" in ids
        assert "i-ok2" in ids
        assert len(instances) == 2

    def test_passes_filters_to_paginator(self):
        """filter 인자를 paginator에 전달."""
        pages = [{"Reservations": []}]
        client = _ec2_client_with_pages(pages)
        collector = AwsEc2Collector(ec2_client=client)

        filters = [{"Name": "instance-state-name", "Values": ["running"]}]
        collector.collect_all_instances(filters=filters)

        client.get_paginator.assert_called_once_with("describe_instances")
        client.get_paginator.return_value.paginate.assert_called_once_with(Filters=filters)

    def test_no_filter_when_not_provided(self):
        pages = [{"Reservations": []}]
        client = _ec2_client_with_pages(pages)
        collector = AwsEc2Collector(ec2_client=client)
        collector.collect_all_instances()

        # paginate()가 Filters 없이 호출
        client.get_paginator.return_value.paginate.assert_called_once_with()
