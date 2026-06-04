"""LedgerAsset → tb_asset_source 적재 payload 매핑 + 배치 (§9.1).

★ 실제 백엔드 POST는 하지 않는다(단일소스 적재 미착수 — "계획만").
EXCEL 경로는 우리가 §8로 계산한 asset_id_hash를 그대로 실어야 하므로
(백엔드 generic 해싱과 다름) CommonAsset/기존 bulk 계약이 아닌 전용 payload를 쓴다.
백엔드 수신 엔드포인트 신설은 계약 확정 후 follow-up.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime

from src.agents.excel_ledger.models import LedgerAsset

# 백엔드 신설 예정 (follow-up) — EXCEL 단일소스 전용 수신.
LEDGER_BULK_ENDPOINT = "/api/cmdb/assets/excel-ledger/bulk"


def to_source_row(asset: LedgerAsset, collected_at: datetime) -> dict:
    """LedgerAsset → tb_asset_source 행 (§9.1).

    raw_data = {ledger: 계산된 master/분류/attributes 전체, original_row: 원본 행}.
    단일소스라 raw_data의 ledger.* 가 그대로 golden master 매핑(§9.2)이 된다.
    """
    dump = asset.model_dump()
    original = dump.pop("raw_data")
    return {
        "asset_id_hash": asset.asset_id_hash,
        "source_type": asset.source_type,  # EXCEL
        "source_id": asset.source_id,
        "hostname": asset.hostname,
        "primary_ip": asset.primary_ip,
        "raw_data": {"ledger": dump, "original_row": original},
        "collected_at": collected_at.isoformat(),
    }


def build_batches(
    assets: list[LedgerAsset], collected_at: datetime, batch_size: int = 500
) -> Iterator[dict]:
    """배치별 payload 생성 (백엔드 bulk 1회 분량). ALB 타임아웃 회피용 분할."""
    for start in range(0, len(assets), batch_size):
        chunk = assets[start : start + batch_size]
        yield {
            "source_type": "EXCEL",
            "collected_at": collected_at.isoformat(),
            "count": len(chunk),
            "rows": [to_source_row(a, collected_at) for a in chunk],
        }
