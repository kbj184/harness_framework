# asset_enrich — ECS Ansible 보강 데이터 적재 Lambda

ECS Fargate Ansible Container가 카테고리별로 수집한 JSON을 S3 PutObject 하면,
이 Lambda가 S3 이벤트로 호출되어 `tb_asset_master` UPDATE + `tb_asset_software` UPSERT 한다.

## 위치

- 디렉터리: `src/agents/asset_enrich/`
- S3 트리거 버킷: `gsretail-asset-enrich`
- Key 컨벤션: `{CATEGORY}/{hostname}/{date}.json`

## 4 카테고리

| CATEGORY | 대상 | Connection | 매퍼 |
|---|---|---|---|
| `IDC_NW` | Cisco/F5/PA/Fortinet 라우터·스위치·FW | network_cli | `mappers/idc_nw.py` |
| `ONPREM_UNIX` | AIX/Solaris/HP-UX/RHEL 서버 | ssh + ansible.builtin | `mappers/onprem_unix.py` |
| `STORE_NW` | 점포 라우터·스위치 | network_cli | `mappers/store_nw.py` |
| `STORE_PC` | Windows 점포 PC (5만대, 4지역) | winrm + ansible.windows | `mappers/store_pc.py` |

별도 트랙(이 Lambda 아님):
- AhnLab EPP/EDR → `ahnlab_epp_collector` Lambda → `tb_asset_security`

## Phase별 작업

본 디렉터리는 Phase 별로 점진 구현된다. 상세: `collect_cmdb/docs/asset-enrich-pipeline.md`

| Phase | 작업 | 상태 |
|---|---|---|
| **P1** | DDL (tb_asset_master ALTER + tb_asset_security CREATE) + S3 버킷 + Secrets Manager 구조 | ✅ 본 커밋 |
| **P2** | ECS Task Definition + Dockerfile + `build_inventory.py` | 예정 |
| **P3** | `playbooks/ONPREM_UNIX.yml` (선검증용) | 예정 |
| **P4** | Lambda `asset_enrich/handler.py` + `mappers/onprem_unix.py` | 예정 |
| **P5** | EventBridge `rule_onprem_unix` + ECS RunTask 통합 테스트 | 예정 |
| **P6** | `IDC_NW.yml` + `mappers/idc_nw.py` | 예정 |
| **P7** | `STORE_NW.yml` + `mappers/store_nw.py` | 예정 |
| **P8** | `STORE_PC.yml` × 4 지역 + `mappers/store_pc.py` + WinRM 라우팅 검증 | 예정 |
| **P9** | `ahnlab_epp_collector` Lambda (별도 트랙) + `tb_asset_security` 활용 | 예정 |

## 파일 구성 (최종 모습)

```
asset_enrich/
  ├── __init__.py
  ├── handler.py            # S3 이벤트 진입점 (lambda_handler)        — P4
  ├── models.py             # Pydantic 모델                            — P4
  ├── mappers/
  │     ├── __init__.py
  │     ├── onprem_unix.py  # facts/packages → master + software       — P4
  │     ├── idc_nw.py       # 모델/OS → master                          — P6
  │     ├── store_nw.py     # 모델/OS → master                          — P7
  │     └── store_pc.py     # OS/hotfix/sw → master + software         — P8
  ├── ddl.sql               # tb_asset_master ALTER + tb_asset_security — P1 ✅
  ├── Dockerfile            # Lambda 컨테이너 이미지                    — P4
  └── README.md             # 본 문서                                   — P1 ✅
```

## DDL 적용

P1 단계에서 DB에 직접 적용한다:

```bash
# 운영
psql -h $DB_HOST -U $DB_WRITER -d cmdb -f src/agents/asset_enrich/ddl.sql

# 또는 backend Flyway 마이그레이션으로 통합 시 V*__asset_enrich_baseline.sql 로 이관
```

## SAM 리소스 (template.yaml)

P1 에서 추가되는 리소스:

- `AssetEnrichBucket` (S3, `gsretail-asset-enrich`) — Lifecycle 90일→Glacier, 365일→삭제
- `AssetEnrichBucketName` 파라미터

P4 이후 추가될 리소스:
- `AssetEnrichFunction` (Lambda, S3 트리거)
- `AssetEnrichTaskDefinition` (ECS Fargate)
- `AssetEnrichRule*` (EventBridge × 4 카테고리)
