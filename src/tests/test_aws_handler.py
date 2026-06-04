"""AWS EC2 handler 단위 테스트 (Phase 2 — S3 적재)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from src.agents.aws.handler import lambda_handler

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
@patch("src.agents.aws.handler.put_assets")
@patch("src.agents.aws.handler.load_aws_target_config")
def test_lambda_handler_success(mock_load_target, mock_put_assets, mock_boto3):
    mock_load_target.return_value = MagicMock(
        access_key_id="AKIA_TEST",
        secret_access_key="SECRET_TEST",
        region="ap-northeast-2",
    )
    mock_boto3.client.return_value = _mock_boto3_client(SAMPLE_RESERVATIONS)
    mock_put_assets.return_value = "AWS_EC2/20260604/run.jsonl.gz"

    result = lambda_handler({}, MagicMock())

    assert result["status"] == "SUCCESS"
    assert result["total_count"] == 2
    assert result["s3_key"] == "AWS_EC2/20260604/run.jsonl.gz"
    # 대상 AWS 자격증명 주입 확인
    call_args = mock_boto3.client.call_args
    assert call_args.args[0] == "ec2"
    assert call_args.kwargs["aws_access_key_id"] == "AKIA_TEST"
    assert call_args.kwargs["region_name"] == "ap-northeast-2"
    # put_assets 가 AWS_EC2 source 로 호출되고 자산 2건 전달
    mock_put_assets.assert_called_once()
    pa_args = mock_put_assets.call_args.args
    assert len(pa_args[0]) == 2
    assert pa_args[1] == "AWS_EC2"


@patch("src.agents.aws.handler.boto3")
@patch("src.agents.aws.handler.put_assets")
@patch("src.agents.aws.handler.load_aws_target_config")
def test_lambda_handler_empty_result(mock_load_target, mock_put_assets, mock_boto3):
    mock_load_target.return_value = MagicMock(access_key_id="k", secret_access_key="s", region="ap-northeast-2")
    mock_boto3.client.return_value = _mock_boto3_client([{"Reservations": []}])

    result = lambda_handler({}, MagicMock())

    assert result["status"] == "SUCCESS"
    assert result["total_count"] == 0
    assert result["s3_key"] is None
    # 빈 결과일 땐 S3 적재하지 않음
    mock_put_assets.assert_not_called()


@patch("src.agents.aws.handler.boto3")
@patch("src.agents.aws.handler.load_aws_target_config")
def test_lambda_handler_failure(mock_load_target, mock_boto3):
    mock_load_target.return_value = MagicMock(access_key_id="k", secret_access_key="s", region="ap-northeast-2")
    mock_boto3.client.side_effect = RuntimeError("boom")

    result = lambda_handler({}, MagicMock())

    assert result["status"] == "FAILED"
    assert "boom" in result["error"]


@patch("src.agents.aws.handler.boto3")
@patch("src.agents.aws.handler.put_assets")
@patch("src.agents.aws.handler.load_aws_target_config")
def test_lambda_handler_passes_event_filters(mock_load_target, mock_put_assets, mock_boto3):
    """event로부터 filter를 받아 paginator에 전달."""
    mock_load_target.return_value = MagicMock(access_key_id="k", secret_access_key="s", region="ap-northeast-2")
    mock_ec2 = _mock_boto3_client([{"Reservations": []}])
    mock_boto3.client.return_value = mock_ec2

    event = {"filters": [{"Name": "instance-state-name", "Values": ["running"]}]}
    lambda_handler(event, MagicMock())

    mock_ec2.get_paginator.return_value.paginate.assert_called_once_with(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
    )
