"""Ansible package_facts 결과의 데이터 모델."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class AnsiblePackage(BaseModel):
    """Ansible package_facts 에서 반환하는 단일 패키지 항목.

    rpm/dpkg/portage 등 모듈에 따라 필드 일부 NULL 가능.
    """

    model_config = ConfigDict(extra="allow")

    name: str
    version: str | None = None
    release: str | None = None       # rpm only
    epoch: str | int | None = None   # rpm only
    arch: str | None = None
    source: str | None = None        # rpm / dpkg / portage / ...


class AnsibleSbom(BaseModel):
    """전체 Ansible SBOM JSON 루트 구조."""

    model_config = ConfigDict(extra="allow")

    hostname: str | None = None
    fqdn: str | None = None
    architecture: str | None = None
    distribution: str | None = None
    distribution_version: str | None = None
    kernel: str | None = None
    os_family: str | None = None
    package_manager: str | None = None    # dnf / apt / portage
    collected_at: str | None = None
    packages: dict[str, list[dict]] = {}
