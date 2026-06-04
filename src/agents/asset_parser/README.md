# asset_parser

S3 raw 버킷에 적재된 자산(CommonAsset JSONL.gz)을 `tb_asset` 에 UPSERT 하는 파서 Lambda.

| 항목 | 내용 |
|---|---|
| 트리거 | `s3:ObjectCreated:*` (suffix `.jsonl.gz`) on `ASSET_RAW_BUCKET` |
| 입력 | `s3://<bucket>/<source>/<YYYYmmdd>/<run>.jsonl.gz` (prefix[0] = source) |
| 출력 | `tb_asset` UPSERT (`ON CONFLICT (source, source_id)`) + `tb_asset_collection_log` |
| 실패 처리 | 객체를 `failed/<key>` 로 복사·격리 (멱등 재처리) |
| 자격증명 | `DB_SECRET_NAME` (기본 `cmdb/db-writer`) 또는 `DB_*` 환경변수 |

## 데이터 흐름 (Phase 2)

```
aws_collector / crowdstrike_collector  →  S3 AssetRaw (JSONL.gz)
                                            │  s3:ObjectCreated
                                            ▼
                                       asset_parser  →  tb_asset
```

Phase 0(수집기 → 백엔드 `POST /api/cmdb/assets/bulk` 직행)에서 전환.
S3 가 환경 간 데이터 원천 — **prod→dev 이관 시 이 버킷 스냅샷만 복사 후 dev 에서
Parser 재실행**하면 동일 자산이 재구성된다.

`asset_id_hash`/Identity Resolution/`tb_asset_master` 병합은 하위 레이어 책임이며
이 파서의 범위가 아니다 (소스 원본 `tb_asset` 적재까지).
