"""설정 로더 — 환경변수 + AWS Secrets Manager."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class CrowdStrikeConfig:
    """CrowdStrike Falcon API 자격 증명."""

    client_id: str
    client_secret: str
    base_url: str = "https://api.crowdstrike.com"


@dataclass(frozen=True)
class BackendApiConfig:
    """Spring Boot 백엔드 API 설정."""

    base_url: str
    api_key: str
    timeout_seconds: int = 30


@dataclass(frozen=True)
class AwsTargetConfig:
    """수집 대상 AWS 계정의 IAM User 자격 증명 (cross-account)."""

    access_key_id: str
    secret_access_key: str
    region: str = "ap-northeast-2"


@dataclass(frozen=True)
class AppConfig:
    """전체 애플리케이션 설정."""

    crowdstrike: CrowdStrikeConfig
    backend: BackendApiConfig
    batch_size: int = 500


def _get_secret(secret_name: str) -> dict:
    """Secrets Manager에서 시크릿을 가져온다. 로컬 환경에서는 환경변수 fallback."""
    import boto3

    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])


def _load_crowdstrike_config() -> CrowdStrikeConfig:
    """CrowdStrike 설정 로드. 환경변수 우선, 없으면 Secrets Manager."""
    client_id = os.environ.get("CS_CLIENT_ID")
    client_secret = os.environ.get("CS_CLIENT_SECRET")
    base_url = os.environ.get("CS_BASE_URL", "https://api.crowdstrike.com")

    if client_id and client_secret:
        return CrowdStrikeConfig(client_id=client_id, client_secret=client_secret, base_url=base_url)

    secret_name = os.environ.get("CS_SECRET_NAME", "cmdb/crowdstrike")
    secret = _get_secret(secret_name)
    return CrowdStrikeConfig(
        client_id=secret["client_id"],
        client_secret=secret["client_secret"],
        base_url=secret.get("base_url", base_url),
    )


def _load_backend_config() -> BackendApiConfig:
    """백엔드 API 설정 로드. 환경변수 우선, 없으면 Secrets Manager."""
    base_url = os.environ.get("BACKEND_API_URL")
    api_key = os.environ.get("BACKEND_API_KEY")

    if base_url and api_key:
        return BackendApiConfig(base_url=base_url, api_key=api_key)

    secret_name = os.environ.get("BACKEND_SECRET_NAME", "cmdb/backend-api")
    secret = _get_secret(secret_name)
    return BackendApiConfig(
        base_url=secret["base_url"],
        api_key=secret["api_key"],
        timeout_seconds=int(secret.get("timeout_seconds", 30)),
    )


def load_aws_target_config() -> AwsTargetConfig:
    """수집 대상 AWS IAM User 자격 증명 로드. 환경변수 우선, 없으면 Secrets Manager."""
    access_key_id = os.environ.get("AWS_TARGET_ACCESS_KEY_ID")
    secret_access_key = os.environ.get("AWS_TARGET_SECRET_ACCESS_KEY")
    region = os.environ.get("AWS_TARGET_REGION", "ap-northeast-2")

    if access_key_id and secret_access_key:
        return AwsTargetConfig(
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
            region=region,
        )

    secret_name = os.environ.get("AWS_TARGET_SECRET_NAME", "cmdb/aws-target")
    secret = _get_secret(secret_name)
    return AwsTargetConfig(
        access_key_id=secret["access_key_id"],
        secret_access_key=secret["secret_access_key"],
        region=secret.get("region", region),
    )


def load_backend_config() -> BackendApiConfig:
    """백엔드 API 설정을 독립적으로 로드 (다른 에이전트에서 재사용)."""
    return _load_backend_config()


@lru_cache(maxsize=1)
def load_config() -> AppConfig:
    """애플리케이션 전체 설정을 로드한다. Lambda invocation당 1회만 실행."""
    return AppConfig(
        crowdstrike=_load_crowdstrike_config(),
        backend=_load_backend_config(),
        batch_size=int(os.environ.get("BATCH_SIZE", "500")),
    )
