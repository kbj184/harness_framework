"""Ansible SBOM JSON → tb_asset_software row 변환."""

from __future__ import annotations

import json
import logging
import urllib.parse
from datetime import datetime
from typing import Any

from src.agents.sbom_ingest.models import AnsibleSbom

logger = logging.getLogger("collect_cmdb")


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return None


def _truncate(value: str | None, max_len: int) -> str | None:
    if value is None:
        return None
    return value[:max_len] if len(value) > max_len else value


def _distribution_tag(sbom: AnsibleSbom) -> str | None:
    """distribution+version → 짧은 태그 (amzn2023 / rhel9 / ubuntu22)."""
    d = (sbom.distribution or "").lower()
    v = sbom.distribution_version or ""
    if not d:
        return None
    if d.startswith("amazon"):
        return f"amzn{v.split('.')[0]}"
    if d in ("redhat", "red hat", "rhel"):
        return f"rhel{v.split('.')[0]}"
    if d == "centos":
        return f"centos{v.split('.')[0]}"
    if d == "rocky":
        return f"rocky{v.split('.')[0]}"
    if d == "ubuntu":
        return f"ubuntu{v.replace('.', '')[:4]}"
    if d == "debian":
        return f"debian{v.split('.')[0]}"
    return f"{d}{v}"


def _purl_namespace(distribution: str | None) -> str:
    """purl 의 namespace (rpm/amzn, rpm/rhel, deb/ubuntu, ...)."""
    if not distribution:
        return "generic"
    d = distribution.lower()
    if d.startswith("amazon"):  return "amzn"
    if d in ("redhat", "red hat", "rhel"): return "rhel"
    if d == "centos":   return "centos"
    if d == "rocky":    return "rocky"
    if d == "ubuntu":   return "ubuntu"
    if d == "debian":   return "debian"
    return "generic"


def _ecosystem_of(source: str | None, package_manager: str | None) -> str:
    """package_facts.source 또는 package_manager 로 ecosystem 결정."""
    src = (source or "").lower()
    pm = (package_manager or "").lower()
    if src == "rpm" or pm == "dnf" or pm == "yum":
        return "rpm"
    if src == "apt" or src == "dpkg" or pm == "apt":
        return "deb"
    if src == "portage" or pm == "emerge":
        return "portage"
    if pm == "pacman":
        return "pacman"
    if pm == "apk":
        return "apk"
    return src or "unknown"


def _source_label(ecosystem: str) -> str:
    return {
        "rpm":  "ANSIBLE_RPM",
        "deb":  "ANSIBLE_DPKG",
        "apk":  "ANSIBLE_APK",
        "pacman": "ANSIBLE_PACMAN",
        "portage": "ANSIBLE_PORTAGE",
    }.get(ecosystem, "ANSIBLE_OTHER")


def _build_purl(
    ecosystem: str,
    namespace: str,
    name: str,
    version: str | None,
    release: str | None,
    epoch: str | int | None,
    arch: str | None,
) -> str:
    """purl(Package URL) 생성.

    예시:
      pkg:rpm/amzn/openssl@3.5.5-1.amzn2023.0.3?arch=x86_64&epoch=1
      pkg:deb/ubuntu/openssh-server@8.9p1-3ubuntu0.4?arch=amd64
    """
    n = urllib.parse.quote(name, safe="")
    # rpm: version-release 결합
    if ecosystem == "rpm":
        ver_part = version or "0"
        if release:
            ver_part = f"{ver_part}-{release}"
    elif ecosystem == "deb":
        ver_part = version or "0"
    else:
        ver_part = version or "0"
    v = urllib.parse.quote(ver_part, safe="")

    qs = []
    if arch:
        qs.append(f"arch={urllib.parse.quote(arch, safe='')}")
    if epoch not in (None, 0, "0", ""):
        qs.append(f"epoch={urllib.parse.quote(str(epoch), safe='')}")
    suffix = "?" + "&".join(qs) if qs else ""

    return f"pkg:{ecosystem}/{namespace}/{n}@{v}{suffix}"


def transform(sbom_json: dict[str, Any], sbom_doc_id: str | None = None) -> tuple[AnsibleSbom, list[dict[str, Any]]]:
    """SBOM JSON 전체 → (메타, row 리스트). row 는 tb_asset_software 컬럼 키."""
    sbom = AnsibleSbom.model_validate(sbom_json)
    if not sbom.packages:
        return sbom, []

    distribution_tag = _distribution_tag(sbom)
    namespace = _purl_namespace(sbom.distribution)
    collected_at = _parse_ts(sbom.collected_at)

    rows: list[dict[str, Any]] = []

    for pkg_name, entries in sbom.packages.items():
        for entry in entries:
            try:
                name = entry.get("name") or pkg_name
                version = entry.get("version")
                release = entry.get("release")
                epoch_raw = entry.get("epoch")
                epoch = str(epoch_raw) if epoch_raw not in (None, "None") else None
                arch = entry.get("arch")
                source_field = entry.get("source")

                ecosystem = _ecosystem_of(source_field, sbom.package_manager)
                source_label = _source_label(ecosystem)
                purl = _build_purl(ecosystem, namespace, name, version, release, epoch, arch)

                rows.append({
                    "asset_id_hash":          None,
                    "source":                 source_label,
                    "ecosystem":              ecosystem,
                    "name":                   _truncate(name, 500),
                    "vendor":                 None,
                    "version":                _truncate(version, 200),
                    "release":                _truncate(release, 200),
                    "epoch":                  _truncate(epoch, 20),
                    "arch":                   _truncate(arch, 20),
                    "purl":                   _truncate(purl, 800),
                    "name_vendor":            None,
                    "name_vendor_version":    None,
                    "cpe_uri":                None,
                    "software_type":          None,
                    "category":               None,
                    "versioning_scheme":      "nevra" if ecosystem == "rpm" else None,
                    "distribution":           _truncate(distribution_tag, 50),
                    "source_rpm":             None,
                    "installation_timestamp": None,
                    "last_used_user_name":    None,
                    "last_used_user_sid":     None,
                    "last_used_file_name":    None,
                    "last_used_file_hash":    None,
                    "last_used_timestamp":    None,
                    "first_seen_timestamp":   None,
                    "is_suspicious":          None,
                    "is_normalized":          None,
                    "cs_app_id":              None,
                    "cs_agent_id":            None,
                    "cid":                    None,
                    "host_hostname":          _truncate(sbom.hostname, 255),
                    "sbom_doc_id":            _truncate(sbom_doc_id, 100),
                    "raw_data":               json.dumps(entry, default=str),
                    "collected_at":           collected_at,
                })
            except Exception:
                logger.exception("패키지 변환 실패: pkg=%s", pkg_name)

    return sbom, rows
