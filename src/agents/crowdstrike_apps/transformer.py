"""DiscoverApplication → tb_asset_software row 변환."""

from __future__ import annotations

import json
import logging
import urllib.parse
from datetime import datetime
from typing import Any

from src.agents.crowdstrike_apps.models import DiscoverApplication

logger = logging.getLogger("collect_cmdb")


def _parse_ts(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _truncate(value: str | None, max_len: int) -> str | None:
    if value is None:
        return None
    return value[:max_len] if len(value) > max_len else value


def _infer_ecosystem(platform_name: str | None, software_type: str | None) -> str | None:
    """host platform 으로 ecosystem 추정.
    CrowdStrike Discover 는 Linux/Windows 양쪽에서 NEVRA/MSI 단위 수집."""
    if not platform_name:
        return None
    p = platform_name.lower()
    if p == "linux":
        return "rpm"   # Amazon Linux / RHEL 기반 가정. Ubuntu 호스트는 deb 처리 별도 분기 가능
    if p == "windows":
        return "msi"
    if p == "mac":
        return "macos"
    return None


def _build_purl(ecosystem: str | None, name: str | None, version: str | None, vendor: str | None) -> str | None:
    """purl(Package URL) 생성. CrowdStrike 응답은 release 분리가 안 돼 있어 version 통째로 사용."""
    if not ecosystem or not name:
        return None
    n = urllib.parse.quote(name, safe="")
    v = urllib.parse.quote(version or "0", safe="")
    if ecosystem == "rpm":
        ns = "amzn" if (vendor or "").lower().startswith("amazon") else "generic"
        return f"pkg:rpm/{ns}/{n}@{v}"
    if ecosystem == "msi":
        return f"pkg:generic/{n}@{v}"
    return f"pkg:{ecosystem}/{n}@{v}"


def transform(apps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """원본 응답 dict 리스트 → DB row 리스트."""
    rows: list[dict[str, Any]] = []
    for raw in apps:
        try:
            app = DiscoverApplication.model_validate(raw)
        except Exception:
            logger.exception("application 검증 실패: id=%s", raw.get("id"))
            continue

        agent_id = (app.host.aid if app.host else None) or ""
        if not agent_id:
            logger.warning("agent_id 없음, 스킵: app_id=%s", app.id)
            continue

        platform = app.host.platform_name if app.host else None
        ecosystem = _infer_ecosystem(platform, app.software_type)
        purl = _build_purl(ecosystem, app.name, app.version, app.vendor)

        rows.append({
            # 자산 매칭
            "asset_id_hash":          None,
            # 소스 구분
            "source":                 "CROWDSTRIKE",
            "ecosystem":              ecosystem,
            # SW 식별
            "name":                   _truncate(app.name, 500),
            "vendor":                 _truncate(app.vendor, 500),
            "version":                _truncate(app.version, 200),
            "release":                None,            # CrowdStrike 응답엔 V/R 분리 없음
            "epoch":                  None,
            "arch":                   None,            # 응답에 명시 없음
            # 식별 키
            "purl":                   _truncate(purl, 800),
            "name_vendor":            _truncate(app.name_vendor, 800),
            "name_vendor_version":    _truncate(app.name_vendor_version, 1000),
            "cpe_uri":                None,
            # 분류 / 메타
            "software_type":          _truncate(app.software_type, 30),
            "category":               _truncate(app.category, 100),
            "versioning_scheme":      _truncate(app.versioning_scheme, 30),
            "distribution":           None,
            "source_rpm":             None,
            # 사용 흔적
            "installation_timestamp": _parse_ts(app.installation_timestamp),
            "last_used_user_name":    _truncate(app.last_used_user_name, 255),
            "last_used_user_sid":     _truncate(app.last_used_user_sid, 100),
            "last_used_file_name":    _truncate(app.last_used_file_name, 500),
            "last_used_file_hash":    _truncate(app.last_used_file_hash, 100),
            "last_used_timestamp":    _parse_ts(app.last_used_timestamp),
            "first_seen_timestamp":   _parse_ts(app.first_seen_timestamp),
            "is_suspicious":          app.is_suspicious,
            "is_normalized":          app.is_normalized,
            # CrowdStrike 전용
            "cs_app_id":              app.id,
            "cs_agent_id":            agent_id,
            "cid":                    _truncate(app.cid, 50),
            # 참조용
            "host_hostname":          _truncate(app.host.hostname if app.host else None, 255),
            "sbom_doc_id":            None,
            "raw_data":               json.dumps(raw, default=str),
            "collected_at":           _parse_ts(app.last_used_timestamp) or None,
        })
    return rows
