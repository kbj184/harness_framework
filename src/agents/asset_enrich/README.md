# asset_enrich — 자산 보강 데이터 적재 Lambda (Ansible + EPP 공통)

**2 트랙 ECS 컨테이너**(Ansible / EPP)가 카테고리별 결과를 S3에 PutObject 하면,
이 Lambda 가 S3 이벤트로 호출되어 `tb_asset_master` UPDATE + `tb_asset_software` UPSERT 한다.

## 위치

- 디렉터리: `src/agents/asset_enrich/`
- S3 트리거 버킷: `gsretail-asset-enrich`
- Key 컨벤션: `{PREFIX}/{date}.jsonl.gz`

## 수집 채널 — 2 트랙

### Track A — Ansible (ECS Fargate · SSH/CLI)

| CATEGORY | 대상 | Connection | 매퍼 |
|---|---|---|---|
| `IDC_NW` | Cisco/F5/PA/Fortinet 라우터·스위치·FW | network_cli | `mappers/idc_nw.py` |
| `ONPREM_UNIX` | AIX/Solaris/HP-UX/RHEL 서버 | ssh + ansible.builtin | `mappers/onprem_unix.py` |
| `STORE_NW` | 점포 라우터·스위치 | network_cli | `mappers/store_nw.py` |

### Track B — EPP (ECS Fargate · asyncio + httpx)

안랩 EPP API 1 호출 → 자산 분류 필드로 카테고리 자동 분기:

| category_cd | 대상 | 매퍼 |
|---|---|---|
| `EPP_STORE_OA` | 점포 PC (Windows, ~5만대) | `mappers/epp.py` (공용) |
| `EPP_OFFICE_OA` | 본사·사무실 PC (~1만대) | `mappers/epp.py` (공용) |
| `EPP_ETC_SERVER` | Ansible 미적용 기타 서버 (~5천대) | `mappers/epp.py` (공용) |

### 별도 트랙 (보안 정보, 추후)

- `ahnlab_epp_security_collector` Lambda → `tb_asset_security`
- 본 디렉터리 범위 외

## Phase별 작업

상세: `collect_cmdb/docs/asset-enrich-pipeline.md`

| Phase | 작업 | 상태 |
|---|---|---|
| **P1** | DDL (tb_asset_master ALTER + tb_asset_security CREATE) + S3 버킷 + Secrets Manager 구조 | ✅ 완료 |
| **P2** | Ansible ECS Task Definition + Dockerfile + `build_inventory.py` + `upload_to_s3.py` | 예정 |
| **P3** | `playbooks/ONPREM_UNIX.yml` | 예정 |
| **P4** | Lambda `handler.py` + `mappers/onprem_unix.py` | 예정 |
| **P5** | EPP ECS Task Definition + Dockerfile + `fetch_epp.py` + `mappers/epp.py` | 예정 |
| **P6** | `IDC_NW.yml` + `STORE_NW.yml` + 매퍼 2종 | 예정 |
| **P7** | EventBridge rules 4종 + 통합 E2E 테스트 | 예정 |
| **P8** (별도) | `ahnlab_epp_security_collector` Lambda + `tb_asset_security` 활용 | 예정 |

## 파일 구성 (최종 모습)

```
asset_enrich/
  ├── __init__.py
  ├── handler.py            # S3 이벤트 진입점 (Ansible/EPP 공통)        — P4
  ├── models.py             # Pydantic 모델                              — P4
  ├── mappers/
  │     ├── __init__.py
  │     ├── onprem_unix.py  # facts/packages → master + software         — P4
  │     ├── idc_nw.py       # 모델/OS → master                            — P6
  │     ├── store_nw.py     # 모델/OS → master                            — P6
  │     └── epp.py          # EPP 응답 → master + software (3 카테고리 공용) — P5
  ├── ansible_ecs/          # Ansible Container                          — P2~P3·P6
  │     ├── Dockerfile
  │     ├── playbooks/
  │     │     ├── ONPREM_UNIX.yml
  │     │     ├── IDC_NW.yml
  │     │     └── STORE_NW.yml
  │     └── scripts/
  │           ├── run.sh
  │           ├── build_inventory.py
  │           └── upload_to_s3.py
  ├── epp_ecs/              # EPP Container                               — P5
  │     ├── Dockerfile
  │     └── scripts/
  │           └── fetch_epp.py
  ├── ddl.sql               # tb_asset_master ALTER + tb_asset_security  — P1 ✅
  ├── Dockerfile            # Lambda 컨테이너 이미지                      — P4
  └── README.md             # 본 문서                                    — P1 ✅
```

## ECS 구조 (Ansible Task / EPP Task)

- 같은 ECS Cluster · VPC · IAM 패턴 공유
- 컨테이너 이미지는 별개 (Ansible은 SSH·Ansible 의존성, EPP는 httpx만)

## DDL 적용

P1 단계에서 DB에 직접 적용:

```bash
psql -h $DB_HOST -U $DB_WRITER -d cmdb -f src/agents/asset_enrich/ddl.sql
```

(또는 backend Flyway 마이그레이션으로 통합 시 `V*__asset_enrich_baseline.sql` 로 이관)

## SAM 리소스 (template.yaml)

**P1 (완료)**:
- `AssetEnrichBucket` (S3, `gsretail-asset-enrich`) — Lifecycle 90d→Glacier, 365d→삭제
- `AssetEnrichBucketName` 파라미터

**P2~P7 (예정)**:
- `AssetEnrichFunction` (Lambda, S3 트리거)
- `AssetEnrichAnsibleTaskDefinition` (ECS Fargate, Ansible 이미지)
- `AssetEnrichEppTaskDefinition` (ECS Fargate, EPP 이미지)
- `AssetEnrichCluster` (ECS Cluster, 공유)
- EventBridge rules 4종 (Ansible 3 + EPP 1)
