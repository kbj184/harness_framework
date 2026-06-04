"""asset_id_hash 생성 (§8 카테고리별 정본키, MD5 surrogate PK)."""

from __future__ import annotations

import hashlib


def asset_hash(category_cd: str, parts: list[str], no: str | None = None) -> str:
    """MD5('CATEGORY|part1|part2|...[|NO]').

    parts = §8 카테고리별 natural key 구성요소(정규화 완료).
    no가 주어지면(시트내 충돌 모호행) NO를 분별자로 덧붙여 유니크 PK 보장.
    """
    key = category_cd + "|" + "|".join(p or "" for p in parts)
    if no is not None:
        key += "|" + str(no)
    return hashlib.md5(key.encode("utf-8")).hexdigest()  # noqa: S324 (식별 surrogate, 보안용 아님)
