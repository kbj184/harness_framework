"""Bedrock Cohere Embed v4 (Global cross-region) 호출 래퍼.

Titan Embed v2가 ap-northeast-2에서 adjustable=False(증설 불가)라
Cohere Embed v4 Global inference profile을 사용한다.

API 시그니처 차이 (Titan → Cohere):
  Titan  : {"inputText": str, "dimensions": N}
  Cohere : {"texts": [str], "input_type": "search_document", "output_dimension": N}

응답 차이:
  Titan  : {"embedding": [...]}
  Cohere : {"embeddings": {"float": [[...]]}} (v4는 embedding_types 기본 포함)
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

logger = logging.getLogger("collect_cmdb")


class BedrockEmbedder:
    """Cohere Embed v4 Global profile 기반 임베딩 생성기.

    output_dimension은 256/512/1024/1536 선택 가능. DDL과 맞춰 1024 고정.
    """

    MODEL_ID = "arn:aws:bedrock:ap-northeast-2:926776803482:inference-profile/global.cohere.embed-v4:0"
    DIMENSIONS = 1024
    INPUT_TYPE_DOCUMENT = "search_document"  # 저장용 벡터
    INPUT_TYPE_QUERY = "search_query"  # 검색 쿼리용 벡터

    def __init__(self, bedrock_client: Any, max_retries: int = 3) -> None:
        self._bedrock = bedrock_client
        self._max_retries = max_retries

    def embed(self, text: str, input_type: str = INPUT_TYPE_DOCUMENT) -> list[float]:
        """단일 텍스트를 임베딩. Throttling 재시도 포함."""
        body = json.dumps(
            {
                "texts": [text],
                "input_type": input_type,
                "output_dimension": self.DIMENSIONS,
                "embedding_types": ["float"],
            }
        )

        last_err: Exception | None = None
        for attempt in range(1, self._max_retries + 1):
            try:
                resp = self._bedrock.invoke_model(
                    modelId=self.MODEL_ID,
                    body=body,
                    contentType="application/json",
                    accept="application/json",
                )
                data = json.loads(resp["body"].read())
                # Cohere v4 응답: {"embeddings": {"float": [[...]]}} 또는 하위 호환 {"embeddings": [[...]]}
                embeddings = data.get("embeddings")
                if isinstance(embeddings, dict):
                    vec = embeddings.get("float", [[]])[0]
                elif isinstance(embeddings, list):
                    vec = embeddings[0]
                else:
                    raise RuntimeError(f"예상 외 Cohere 응답 형식: {data}")
                if not vec or len(vec) != self.DIMENSIONS:
                    raise RuntimeError(f"임베딩 차원 불일치: expected {self.DIMENSIONS}, got {len(vec) if vec else 0}")
                return vec
            except Exception as e:
                last_err = e
                if attempt < self._max_retries:
                    wait = 2**attempt
                    logger.warning(
                        "Bedrock embed 실패 (%d/%d), %ds 후 재시도: %s",
                        attempt,
                        self._max_retries,
                        wait,
                        e,
                    )
                    time.sleep(wait)
        raise RuntimeError(f"Bedrock embed 재시도 실패: {last_err}")
