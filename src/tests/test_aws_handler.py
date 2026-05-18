"""AWS EC2 handler 단위 테스트."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from src.agents.aws.handler import lambda_handler
from src.shared.models import AssetSource, BulkAssetResponse

SAMPLE_RESERVATIONS = [
    {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-1",
                        "InstanceType": "t3.micro",
                        "State": {"Name": "running"},
                        "PrivateIpAddress": "10.0.0.1",
                        "Tags": [{"Key": "Name", "Value": "web-01"}],
                    },
                    {
                        "InstanceId": "i-2",
                        "InstanceType": "t3.small",
                        "State": {"Name": "running"},
                        "PrivateIpAddress": "10.0.0.2",
                        "Tags": [{"Key": "Name", "Value": "web-02"}],
                    },
                ]
            }
        ]
    }
]


def _mock_boto3_client(reservations):
    """boto3.client('ec2', ...) 가 paginator를 통해 reservations를 반환하도록."""
    ec2 = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = iter(reservations)
    ec2.get_paginator.return_value = paginator
    return ec2


@patch("src.agents.aws.handler.boto3")
@patch("src.agents.aws.handler.BackendApiClient")
@patch("src.agents.aws.handler.load_aws_target_config")
@patch("src.agents.aws.handler.load_backend_config")
def test_lambda_handler_success(
    mock_load_backend,
    mock_load_target,
    mock_api_client_cls,
    mock_boto3,
):
    # Backend 설정 mock
    mock_load_backend.return_value = MagicMock(base_url="http://backend", api_key="k", timeout_seconds=30)
    # AWS target 설정 mock
    mock_load_target.return_value = MagicMock(
        access_key_id="AKIA_TEST",
        secret_access_key="SECRET_TEST",
        region="ap-northeast-2",
    )
    # EC2 client mock
    mock_ec2 = _mock_boto3_client(SAMPLE_RESERVATIONS)
    mock_boto3.client.return_value = mock_ec2

    # Backend API client mock — 성공 응답
    mock_api = MagicMock()
    mock_api.send_assets.return_value = BulkAssetResponse(success=True, total_count=2, created_count=2, updated_count=0)
    mock_api_client_cls.return_value = mock_api

    result = lambda_handler({}, MagicMock())

    assert result["status"] == "SUCCESS"
    assert result["total_count"] == 2
    assert result["created_count"] == 2
    # boto3.client가 EC2로 호출됐는지 (대상 AWS 자격증명 주입 확인)
    mock_boto3.client.assert_called_once()
    call_args = mock_boto3.client.call_args
    assert call_args.args[0] == "ec2"
    assert call_args.kwargs["aws_access_key_id"] == "AKIA_TEST"
    assert call_args.kwargs["aws_secret_access_key"] == "SECRET_TEST"
    assert call_args.kwargs["region_name"] == "ap-northeast-2"

    # BackendApiClient.send_assets 호출되고, source가 AWS_EC2
    mock_api.send_assets.assert_called_once()
    payload = mock_api.send_assets.call_args.args[0]
    assert payload.source == AssetSource.AWS_EC2
    assert len(payload.assets) == 2


@patch("src.agents.aws.handler.boto3")
@patch("src.agents.aws.handler.BackendApiClient")
@patch("src.agents.aws.handler.load_aws_target_config")
@patch("src.agents.aws.handler.load_backend_config")
def test_lambda_handler_empty_result(
    mock_load_backend,
    mock_load_target,
    mock_api_client_cls,
    mock_boto3,
):
    mock_load_backend.return_value = MagicMock(base_url="u", api_key="k", timeout_seconds=30)
    mock_load_target.return_value = MagicMock(access_key_id="k", secret_access_key="s", region="ap-northeast-2")
    mock_boto3.client.return_value = _mock_boto3_client([{"Reservations": []}])
    mock_api_client_cls.return_value = MagicMock()

    result = lambda_handler({}, MagicMock())

    assert result["status"] == "SUCCESS"
    assert result["total_count"] == 0
    # 빈 결과일 땐 send_assets 호출하지 않음
    mock_api_client_cls.return_value.send_assets.assert_not_called()


@patch("src.agents.aws.handler.boto3")
@patch("src.agents.aws.handler.load_aws_target_config")
@patch("src.agents.aws.handler.load_backend_config")
def test_lambda_handler_failure(mock_load_backend, mock_load_target, mock_boto3):
    mock_load_backend.return_value = MagicMock(base_url="u", api_key="k", timeout_seconds=30)
    mock_load_target.return_value = MagicMock(access_key_id="k", secret_access_key="s", region="ap-northeast-2")
    # boto3 client에서 예외 발생
    mock_boto3.client.side_effect = RuntimeError("boom")

    result = lambda_handler({}, MagicMock())

    assert result["status"] == "FAILED"
    assert "boom" in result["error"]


@patch("src.agents.aws.handler.boto3")
@patch("src.agents.aws.handler.BackendApiClient")
@patch("src.agents.aws.handler.load_aws_target_config")
@patch("src.agents.aws.handler.load_backend_config")
def test_lambda_handler_passes_event_filters(
    mock_load_backend,
    mock_load_target,
    mock_api_client_cls,
    mock_boto3,
):
    """event로부터 filter를 받아 paginator에 전달."""
    mock_load_backend.return_value = MagicMock(base_url="u", api_key="k", timeout_seconds=30)
    mock_load_target.return_value = MagicMock(access_key_id="k", secret_access_key="s", region="ap-northeast-2")
    mock_ec2 = _mock_boto3_client([{"Reservations": []}])
    mock_boto3.client.return_value = mock_ec2
    mock_api_client_cls.return_value = MagicMock()

    event = {"filters": [{"Name": "instance-state-name", "Values": ["running"]}]}
    lambda_handler(event, MagicMock())

    # paginate 호출 시 Filters 전달됐는지
    mock_ec2.get_paginator.return_value.paginate.assert_called_once_with(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
    )
