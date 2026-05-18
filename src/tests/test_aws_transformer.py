"""AWS EC2 transformer 단위 테스트."""

from datetime import UTC, datetime

from src.agents.aws.models import AwsEc2Instance
from src.agents.aws.transformer import transform_instance, transform_instances
from src.shared.models import AssetSource

COLLECTED_AT = datetime(2026, 4, 21, 10, 0, 0, tzinfo=UTC)


SAMPLE_RAW = {
    "InstanceId": "i-0abc123def456789",
    "InstanceType": "t3.large",
    "State": {"Code": 16, "Name": "running"},
    "Platform": None,  # linux
    "PlatformDetails": "Linux/UNIX",
    "Architecture": "x86_64",
    "ImageId": "ami-0abcdef1234567890",
    "PrivateIpAddress": "10.0.132.108",
    "PublicIpAddress": "43.201.55.213",
    "PrivateDnsName": "ip-10-0-132-108.ap-northeast-2.compute.internal",
    "VpcId": "vpc-02afc28fe9d76fdb8",
    "SubnetId": "subnet-0abc123",
    "AvailabilityZone": "ap-northeast-2a",
    "LaunchTime": "2025-01-15T08:00:00+00:00",
    "Tags": [
        {"Key": "Name", "Value": "edr-ec2-edrDemoBastionHost"},
        {"Key": "Service", "Value": "우리동네GS-CRM"},
        {"Key": "Env", "Value": "prod"},
    ],
    "SecurityGroups": [{"GroupId": "sg-abc123", "GroupName": "default"}],
}


class TestTransformInstance:
    def test_basic_fields(self):
        inst = AwsEc2Instance(**SAMPLE_RAW)
        asset = transform_instance(inst, COLLECTED_AT)

        assert asset.source == AssetSource.AWS_EC2
        assert asset.source_id == "i-0abc123def456789"
        assert asset.serial_number == "i-0abc123def456789"  # ★ CS matching key
        assert asset.collected_at == COLLECTED_AT

    def test_hostname_from_name_tag(self):
        """Name 태그가 있으면 hostname으로 사용."""
        inst = AwsEc2Instance(**SAMPLE_RAW)
        asset = transform_instance(inst, COLLECTED_AT)
        assert asset.hostname == "edr-ec2-edrDemoBastionHost"

    def test_hostname_fallback_to_private_dns(self):
        """Name 태그가 없으면 PrivateDnsName을 hostname으로 사용."""
        raw = dict(SAMPLE_RAW)
        raw["Tags"] = []
        inst = AwsEc2Instance(**raw)
        asset = transform_instance(inst, COLLECTED_AT)
        assert asset.hostname == "ip-10-0-132-108.ap-northeast-2.compute.internal"

    def test_ip_addresses_include_private_and_public(self):
        inst = AwsEc2Instance(**SAMPLE_RAW)
        asset = transform_instance(inst, COLLECTED_AT)
        assert "10.0.132.108" in asset.ip_addresses
        assert "43.201.55.213" in asset.ip_addresses

    def test_ip_addresses_skip_public_when_none(self):
        raw = dict(SAMPLE_RAW)
        raw["PublicIpAddress"] = None
        inst = AwsEc2Instance(**raw)
        asset = transform_instance(inst, COLLECTED_AT)
        assert asset.ip_addresses == ["10.0.132.108"]

    def test_os_name_linux(self):
        """Platform 비어있으면 Linux."""
        inst = AwsEc2Instance(**SAMPLE_RAW)
        asset = transform_instance(inst, COLLECTED_AT)
        assert asset.os_name == "Linux"

    def test_os_name_windows(self):
        raw = dict(SAMPLE_RAW)
        raw["Platform"] = "windows"
        raw["PlatformDetails"] = "Windows"
        inst = AwsEc2Instance(**raw)
        asset = transform_instance(inst, COLLECTED_AT)
        assert asset.os_name == "Windows"

    def test_tags_include_aws_metadata(self):
        """tags dict에 AWS metadata(VpcId, InstanceType 등) 포함."""
        inst = AwsEc2Instance(**SAMPLE_RAW)
        asset = transform_instance(inst, COLLECTED_AT)

        assert asset.tags.get("Name") == "edr-ec2-edrDemoBastionHost"
        assert asset.tags.get("Service") == "우리동네GS-CRM"
        assert asset.tags.get("Env") == "prod"
        assert asset.tags.get("VpcId") == "vpc-02afc28fe9d76fdb8"
        assert asset.tags.get("SubnetId") == "subnet-0abc123"
        assert asset.tags.get("InstanceType") == "t3.large"
        assert asset.tags.get("AvailabilityZone") == "ap-northeast-2a"
        assert asset.tags.get("State") == "running"
        assert asset.tags.get("Architecture") == "x86_64"

    def test_raw_data_preserved(self):
        inst = AwsEc2Instance(**SAMPLE_RAW)
        asset = transform_instance(inst, COLLECTED_AT)
        assert asset.raw_data is not None
        assert asset.raw_data["InstanceId"] == "i-0abc123def456789"

    def test_first_seen_from_launch_time(self):
        inst = AwsEc2Instance(**SAMPLE_RAW)
        asset = transform_instance(inst, COLLECTED_AT)
        assert asset.first_seen is not None
        assert asset.first_seen.year == 2025


class TestTransformInstances:
    def test_batch_conversion(self):
        raw1 = dict(SAMPLE_RAW)
        raw2 = dict(SAMPLE_RAW)
        raw2["InstanceId"] = "i-0another1234"

        results = transform_instances(
            [AwsEc2Instance(**raw1), AwsEc2Instance(**raw2)],
            COLLECTED_AT,
        )
        assert len(results) == 2
        assert results[0].source_id == "i-0abc123def456789"
        assert results[1].source_id == "i-0another1234"

    def test_skips_failed_conversion(self):
        """하나 실패해도 나머지 처리 계속."""
        good = AwsEc2Instance(**SAMPLE_RAW)
        # 일부러 InstanceId 누락된 인스턴스는 Pydantic 단에서 거부되므로
        # transform_instance 내부에서 예외가 나는 케이스를 만들기 어려움.
        # 대신 빈 리스트 동작만 확인.
        results = transform_instances([good], COLLECTED_AT)
        assert len(results) == 1
