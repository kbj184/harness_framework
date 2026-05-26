"""DiscoverApplication → tb_asset_software row 변환."""

from __future__ import annotations

import json
import logging
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
            # agent_id 없으면 자산 매칭 불가 → 스킵
            logger.warning("agent_id 없음, 스킵: app_id=%s", app.id)
            continue

        rows.append({
            "cs_app_id":              app.id,
            "cs_agent_id":            agent_id,
            "asset_id_hash":          None,  # backfill 단계에서 채움
            "name":                   _truncate(app.name, 500),
            "vendor":                 _truncate(app.vendor, 500),
            "version":                _truncate(app.version, 200),
            "name_vendor":            _truncate(app.name_vendor, 800),
            "name_vendor_version":    _truncate(app.name_vendor_version, 1000),
            "software_type":          _truncate(app.software_type, 30),
            "category":               _truncate(app.category, 100),
            "versioning_scheme":      _truncate(app.versioning_scheme, 30),
            "installation_timestamp": _parse_ts(app.installation_timestamp),
            "last_used_user_name":    _truncate(app.last_used_user_name, 255),
            "last_used_user_sid":     _truncate(app.last_used_user_sid, 100),
            "last_used_file_name":    _truncate(app.last_used_file_name, 500),
            "last_used_file_hash":    _truncate(app.last_used_file_hash, 100),
            "last_used_timestamp":    _parse_ts(app.last_used_timestamp),
            "first_seen_timestamp":   _parse_ts(app.first_seen_timestamp),
            "is_suspicious":          app.is_suspicious,
            "is_normalized":          app.is_normalized,
            "cpe_uri":                None,  # 별도 후처리
            "cid":                    _truncate(app.cid, 50),
            "host_hostname":          _truncate(app.host.hostname if app.host else None, 255),
            "raw_data":               json.dumps(raw, default=str),
        })
    return rows
