"""AWS EC2 전용 데이터 모델."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AwsEc2Tag(BaseModel):
    """EC2 태그."""

    model_config = ConfigDict(extra="allow")

    Key: str
    Value: str = ""


class AwsEc2Instance(BaseModel):
    """EC2 describe_instances 응답의 단일 인스턴스를 표현한다.

    Boto3가 반환하는 dict를 그대로 수용하기 위해 `extra="allow"`로 설정하고,
    필드명은 AWS API 응답의 PascalCase를 그대로 따른다.
    """

    model_config = ConfigDict(extra="allow")

    InstanceId: str
    InstanceType: str | None = None
    State: dict | None = None  # {"Code": int, "Name": str}
    Platform: str | None = None  # "windows" | None(=linux)
    PlatformDetails: str | None = None
    Architecture: str | None = None
    ImageId: str | None = None
    PrivateIpAddress: str | None = None
    PublicIpAddress: str | None = None
    PrivateDnsName: str | None = None
    PublicDnsName: str | None = None
    VpcId: str | None = None
    SubnetId: str | None = None
    AvailabilityZone: str | None = None
    LaunchTime: datetime | None = None
    Tags: list[AwsEc2Tag] = Field(default_factory=list)
    SecurityGroups: list[dict] = Field(default_factory=list)
    NetworkInterfaces: list[dict] = Field(default_factory=list)

    @property
    def state_name(self) -> str | None:
        if self.State and isinstance(self.State, dict):
            return self.State.get("Name")
        return None

    @property
    def tags_dict(self) -> dict[str, str]:
        """Tags 리스트를 dict로 변환."""
        return {t.Key: t.Value for t in self.Tags}
