# 자산 보강 파이프라인 구현 계획 (ECS Ansible × EventBridge × S3 × Lambda)

**문서 버전**: v1.0 · 2026-05-27
**범위**: CrowdStrike Agent 미커버 자산(온프레미스/점포)의 자동 보강 파이프라인
**구현 기간**: 10일 (P1~P9)

---

## 1. 배경 및 목표

CrowdStrike Falcon Agent는 **클라우드 서버(EC2)만 대상**. 다음 자산군은 자체 수집 채널 필요:

| 자산군 | 규모(추정) | 현 상태 |
|---|---|---|
| 온프레미스 Unix (AIX/Solaris/HP-UX/Linux) | ~수백대 | 수집 채널 없음 |
| IDC 네트워크 장비 (Cisco/F5/Palo Alto/Fortinet) | ~수백대 | 수집 채널 없음 |
| 점포 네트워크 (라우터/스위치) | ~수천대 | 수집 채널 없음 |
| 점포 PC (Windows) | ~5만대 | 수집 채널 없음 |
| 본사 PC | ~수천대 | (별도 검토) |

**목표**: 위 자산군에 대해 자동 수집 파이프라인 구축 → tb_asset_master/tb_asset_software 보강

---

## 2. 아키텍처

```
┌─────────────────────────────────────────────────────────────────────┐
│  EventBridge (cron rules)                                            │
│    rule_idc_nw      cron(0 19 * * ? *)   일 1회 KST 04:00            │
│    rule_onprem_unix cron(0 19 * * ? *)   일 1회 KST 04:00            │
│    rule_store_nw    cron(0 19 * * ? *)   일 1회 KST 04:00            │
│    rule_store_pc_kr1 cron(0 17 ? * SUN *) 주 1회 KST 02:00 — 수도권   │
│    rule_store_pc_kr2 cron(0 17 ? * SUN *) 주 1회 KST 02:00 — 영남     │
│    rule_store_pc_kr3 cron(0 17 ? * SUN *) 주 1회 KST 02:00 — 호남     │
│    rule_store_pc_kr4 cron(0 17 ? * SUN *) 주 1회 KST 02:00 — 충청     │
└──────────────┬──────────────────────────────────────────────────────┘
               │ ECS RunTask + env CATEGORY=xxx [+ REGION=xxx]
               ↓
┌─────────────────────────────────────────────────────────────────────┐
│  ECS Fargate Task — Ansible Container (단일 이미지)                  │
│                                                                       │
│  1) CMDB 조회 — tb_asset_master WHERE category_cd = ${CATEGORY}      │
│     [AND region_cd = ${REGION}] (STORE_PC 한정)                      │
│                                                                       │
│  2) Ansible Dynamic Inventory 생성 (/tmp/inventory.yml)              │
│                                                                       │
│  3) Secrets Manager → SSH 키 / AD 자격증명 로드                       │
│                                                                       │
│  4) ansible-playbook /playbooks/${CATEGORY}.yml --forks 100          │
│                                                                       │
│  5) 결과 JSON 정규화 → S3 PutObject                                  │
│     s3://gsretail-asset-enrich/${CATEGORY}/{hostname}/{date}.json    │
└──────────────┬──────────────────────────────────────────────────────┘
               │ S3 PutObject 이벤트
               ↓
┌─────────────────────────────────────────────────────────────────────┐
│  Lambda asset_enrich_agent (Python · S3 트리거)                       │
│                                                                       │
│  1) S3 key 경로 → 카테고리 추출                                       │
│  2) JSON 파싱                                                         │
│  3) 카테고리별 매퍼 분기                                              │
│  4) tb_asset_master UPDATE + tb_asset_software UPSERT (NEVRA/purl)   │
│  5) raw_json·collected_at 보존                                       │
└─────────────────────────────────────────────────────────────────────┘
```

별도 트랙 (AhnLab):

```
┌─────────────────────────────────────────────────────────────────────┐
│  Lambda ahnlab_epp_collector (EventBridge cron)                       │
│    AhnLab V3 Manager API → 점포 PC 보안 상태 → tb_asset_security      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. 카테고리별 수집 범위

### 3.1 IDC 네트워크 (`category_cd = IDC_NW`)

| 항목 | 값 |
|---|---|
| 대상 OS | Cisco IOS/IOS-XE/NX-OS, F5 TMOS, Palo Alto PAN-OS, Fortinet FortiOS, Juniper Junos |
| 프로토콜 | SSH CLI (Ansible `network_cli` connection) |
| 자격증명 | SSH 키 (NW admin 계정, Secrets Manager) |
| 수집 항목 | 모델, OS 버전, hostname, interface 상태, ACL 요약, uptime, BGP/OSPF neighbor |
| 빈도 | 일 1회 (KST 04:00) |
| 예상 자산 수 | ~수백대 |

### 3.2 온프레미스 Unix (`category_cd = ONPREM_UNIX`)

| 항목 | 값 |
|---|---|
| 대상 OS | AIX 7.x, Solaris 10/11, HP-UX 11.x, RHEL/CentOS/Oracle Linux, Ubuntu |
| 프로토콜 | SSH + Ansible 표준 (`ansible.builtin`) |
| 자격증명 | SSH 키 + sudo (서버군별 별도 키) |
| 수집 항목 | hostname, OS·커널·아키텍처, 설치 패키지(NEVRA), 서비스, 사용자, 마운트, 네트워크 |
| 빈도 | 일 1회 (KST 04:00) |
| 예상 자산 수 | ~수백대 |

### 3.3 점포 네트워크 (`category_cd = STORE_NW`)

| 항목 | 값 |
|---|---|
| 대상 | 점포 라우터·스위치 (주로 Cisco) |
| 프로토콜 | SSH CLI (`network_cli`) |
| 자격증명 | SSH 키 (NW admin) |
| 수집 항목 | 모델, OS 버전, hostname, interface, MAC 테이블, uptime |
| 빈도 | 일 1회 (KST 04:00) |
| 예상 자산 수 | ~수천대 |

### 3.4 점포 PC (`category_cd = STORE_PC`)

| 항목 | 값 |
|---|---|
| 대상 | Windows 10/11 (점포 단말 + POS) |
| 프로토콜 | WinRM (`ansible.windows`) |
| 자격증명 | AD 도메인 계정 (Secrets Manager) |
| 수집 항목 | hostname, OS 빌드, 설치 SW (Uninstall registry), hotfix, AV 상태, 도메인 가입, BIOS serial |
| 빈도 | 주 1회 (KST 일요일 02:00) |
| 분할 실행 | **지역 4개 병렬** (수도권/영남/호남/충청) |
| 예상 자산 수 | ~5만대 (지역당 ~1.25만) |

### 3.5 AhnLab EPP/EDR (별도 트랙, `category_cd 무관`)

| 항목 | 값 |
|---|---|
| 대상 | 점포 PC + 본사 PC (AhnLab Agent 설치된 모든 PC) |
| 프로토콜 | AhnLab V3 Manager API |
| 자격증명 | API Token (Secrets Manager) |
| 수집 항목 | Agent ID, AV 패턴 버전, 정책 그룹, 최근 검사 결과, 격리 상태 |
| 빈도 | 시간당 |
| 적재 | tb_asset_security (별도 테이블) — hostname/MAC으로 tb_asset_master 매칭 |

---

## 4. DB 스키마 변경

### 4.1 tb_asset_master 추가 컬럼 (P1)

```sql
ALTER TABLE tb_asset_master ADD COLUMN IF NOT EXISTS ansible_user        VARCHAR(50);
ALTER TABLE tb_asset_master ADD COLUMN IF NOT EXISTS ansible_connection  VARCHAR(30);
  -- ssh / winrm / network_cli
ALTER TABLE tb_asset_master ADD COLUMN IF NOT EXISTS ansible_network_os  VARCHAR(30);
  -- ios / iosxr / nxos / panos / fortios / junos
ALTER TABLE tb_asset_master ADD COLUMN IF NOT EXISTS credentials_secret_arn VARCHAR(500);
  -- Secrets Manager ARN
ALTER TABLE tb_asset_master ADD COLUMN IF NOT EXISTS region_cd           VARCHAR(20);
  -- KR1/KR2/KR3/KR4 (STORE_PC 한정)
ALTER TABLE tb_asset_master ADD COLUMN IF NOT EXISTS ansible_enriched_at TIMESTAMPTZ;
  -- 마지막 보강 시각
```

### 4.2 tb_asset_software (이미 존재) — source 컬럼 값 추가

```
기존: CROWDSTRIKE / ANSIBLE_RPM / ANSIBLE_DPKG / NPM / PYPI
신규 추가: ANSIBLE_AIX_LSLPP / ANSIBLE_SOLARIS_PKG / ANSIBLE_WIN_INSTALLED
```

### 4.3 tb_asset_security (신규, P9)

```sql
CREATE TABLE IF NOT EXISTS tb_asset_security (
    sec_no             BIGSERIAL PRIMARY KEY,
    asset_id_hash      CHAR(32) NOT NULL,
    source             VARCHAR(30) NOT NULL,   -- AHNLAB_EPP / CROWDSTRIKE_FALCON
    agent_id           VARCHAR(100),
    av_pattern_version VARCHAR(50),
    policy_group       VARCHAR(100),
    last_scan_at       TIMESTAMPTZ,
    scan_result        VARCHAR(30),            -- CLEAN / DETECTED / QUARANTINED
    isolation_status   VARCHAR(30),            -- NORMAL / ISOLATED
    collected_at       TIMESTAMPTZ DEFAULT NOW(),
    raw_data           JSONB,
    FOREIGN KEY (asset_id_hash) REFERENCES tb_asset_master(asset_id_hash)
);
CREATE UNIQUE INDEX uk_asset_sec_source ON tb_asset_security (asset_id_hash, source);
```

---

## 5. ECS Task 설계

### 5.1 Dockerfile

```dockerfile
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        ansible==9.* \
        ansible-pylibssh \
        pywinrm[kerberos] \
        boto3 \
        psycopg2-binary \
        PyYAML

# 네트워크 장비 collection
RUN ansible-galaxy collection install \
        cisco.ios cisco.iosxr cisco.nxos \
        paloaltonetworks.panos \
        fortinet.fortios \
        junipernetworks.junos \
        ansible.windows

WORKDIR /opt/enrich
COPY playbooks/ /opt/enrich/playbooks/
COPY scripts/   /opt/enrich/scripts/
RUN chmod +x /opt/enrich/scripts/*.sh /opt/enrich/scripts/*.py

ENTRYPOINT ["/opt/enrich/scripts/run.sh"]
```

### 5.2 run.sh

```bash
#!/bin/bash
set -euo pipefail

CATEGORY="${CATEGORY:?CATEGORY env required}"
REGION="${REGION:-}"

# 1. CMDB 조회 → inventory 생성
python3 /opt/enrich/scripts/build_inventory.py \
    --category "$CATEGORY" \
    ${REGION:+--region "$REGION"} \
    --output /tmp/inventory.yml

# 2. Ansible playbook 실행
ansible-playbook \
    -i /tmp/inventory.yml \
    "/opt/enrich/playbooks/${CATEGORY}.yml" \
    --forks "${ANSIBLE_FORKS:-100}" \
    --extra-vars "output_dir=/tmp/results category=${CATEGORY}"

# 3. S3 업로드
python3 /opt/enrich/scripts/upload_to_s3.py \
    --category "$CATEGORY" \
    --results /tmp/results \
    --bucket "$S3_BUCKET"
```

### 5.3 ECS Task Definition

```yaml
Family: gsretail-asset-enrich
TaskRoleArn: !GetAtt EnrichTaskRole.Arn    # CMDB 조회 + S3 PutObject + Secrets 읽기
ExecutionRoleArn: !GetAtt EcsExecutionRole.Arn
NetworkMode: awsvpc                          # collect subnet에 배치
RequiresCompatibilities: [FARGATE]
Cpu: '2048'                                  # 2 vCPU
Memory: '4096'                               # 4 GB (forks=100 기준)
ContainerDefinitions:
  - Name: ansible
    Image: !Sub '${EcrRepo}:latest'
    Environment:
      - {Name: DB_URL, Value: !Ref DbUrl}
      - {Name: S3_BUCKET, Value: !Ref EnrichBucket}
      - {Name: ANSIBLE_FORKS, Value: '100'}
    Secrets:
      - {Name: DB_PASSWORD, ValueFrom: !Ref DbSecretArn}
```

---

## 6. Ansible Playbook (카테고리별)

### 6.1 playbooks/ONPREM_UNIX.yml

```yaml
- hosts: all
  gather_facts: yes
  tasks:
    - name: 설치 패키지 (RPM/DPKG/PKG/LSLPP)
      package_facts:
        manager: auto
      register: pkg

    - name: 결과 정규화 → 로컬 저장
      copy:
        content: >-
          {{
            {
              'asset_id_hash': asset_id_hash,
              'category': category,
              'collected_at': ansible_date_time.iso8601,
              'facts': {
                'os': ansible_facts.distribution + ' ' + ansible_facts.distribution_version,
                'kernel': ansible_facts.kernel,
                'arch': ansible_facts.architecture,
                'hostname': ansible_facts.hostname,
                'ip_addrs': ansible_facts.all_ipv4_addresses,
                'memory_mb': ansible_facts.memtotal_mb,
                'cpu_cores': ansible_facts.processor_vcpus,
              },
              'packages': ansible_facts.packages,
            } | to_nice_json
          }}
        dest: "{{ output_dir }}/{{ inventory_hostname }}.json"
      delegate_to: localhost
```

### 6.2 playbooks/IDC_NW.yml (Cisco IOS 예시)

```yaml
- hosts: all
  gather_facts: no
  connection: network_cli
  vars:
    ansible_network_os: "{{ ansible_network_os | default('ios') }}"
  tasks:
    - name: 모델/OS 정보
      cisco.ios.ios_facts:
        gather_subset: [hardware, interfaces, config]
      register: facts

    - name: ACL 추출
      cisco.ios.ios_command:
        commands:
          - show running-config | section access-list
          - show ip interface brief
      register: acl_int
      ignore_errors: yes

    - name: 결과 저장
      copy:
        content: >-
          {{
            {
              'asset_id_hash': asset_id_hash,
              'category': category,
              'facts': facts.ansible_facts | default({}),
              'acl': acl_int.stdout[0] | default(''),
              'interfaces': acl_int.stdout[1] | default(''),
            } | to_nice_json
          }}
        dest: "{{ output_dir }}/{{ inventory_hostname }}.json"
      delegate_to: localhost
```

### 6.3 playbooks/STORE_NW.yml

IDC_NW와 동일 구조 (Cisco 명령). 단, store-specific 룰 추가.

### 6.4 playbooks/STORE_PC.yml

```yaml
- hosts: all
  gather_facts: yes
  connection: winrm
  tasks:
    - name: 설치 SW (Uninstall 레지스트리)
      ansible.windows.win_shell: |
        Get-ItemProperty `
          HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, `
          HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* `
        | Where-Object { $_.DisplayName } `
        | Select-Object DisplayName, DisplayVersion, Publisher `
        | ConvertTo-Json -Compress
      register: installed

    - name: Hotfix
      ansible.windows.win_shell: Get-HotFix | ConvertTo-Json -Compress
      register: hotfix

    - name: BIOS Serial
      ansible.windows.win_shell: (Get-CimInstance Win32_BIOS).SerialNumber
      register: serial

    - name: 결과 저장
      copy:
        content: >-
          {{
            {
              'asset_id_hash': asset_id_hash,
              'category': category,
              'facts': {
                'hostname': ansible_facts.hostname,
                'os': ansible_facts.distribution + ' ' + ansible_facts.distribution_version,
                'os_build': ansible_facts.os_version,
                'domain': ansible_facts.windows_domain,
                'serial': serial.stdout | trim,
              },
              'software': installed.stdout | from_json,
              'hotfix': hotfix.stdout | from_json,
            } | to_nice_json
          }}
        dest: "{{ output_dir }}/{{ inventory_hostname }}.json"
      delegate_to: localhost
```

---

## 7. Lambda asset_enrich_agent

### 7.1 디렉터리 구조

```
collect_cmdb/src/agents/asset_enrich/
  ├── __init__.py
  ├── handler.py            # S3 이벤트 핸들러
  ├── mappers/
  │     ├── onprem_unix.py
  │     ├── idc_nw.py
  │     ├── store_nw.py
  │     └── store_pc.py
  ├── models.py             # Pydantic 모델
  ├── ddl.sql               # tb_asset_master ALTER + tb_asset_security CREATE
  └── README.md
```

### 7.2 handler.py 골격

```python
import json
import os
import boto3
from collect_cmdb.src.agents.asset_enrich.mappers import (
    onprem_unix, idc_nw, store_nw, store_pc
)

s3 = boto3.client('s3')

MAPPERS = {
    'ONPREM_UNIX': onprem_unix.enrich,
    'IDC_NW':      idc_nw.enrich,
    'STORE_NW':    store_nw.enrich,
    'STORE_PC':    store_pc.enrich,
}

def handler(event, context):
    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        # key 예: ONPREM_UNIX/aix-erp-01/2026-05-27.json

        parts = key.split('/', 2)
        if len(parts) < 3:
            continue
        category, hostname, _ = parts

        obj = s3.get_object(Bucket=bucket, Key=key)
        data = json.loads(obj['Body'].read())

        mapper = MAPPERS.get(category)
        if not mapper:
            print(f'no mapper for category={category}')
            continue

        mapper(data)
```

### 7.3 매퍼 예시 — onprem_unix.py

```python
def enrich(data: dict) -> None:
    asset_id_hash = data['asset_id_hash']
    facts = data['facts']
    packages = data.get('packages', {})

    # 1) tb_asset_master UPDATE
    db_execute("""
        UPDATE tb_asset_master SET
            os_name        = %(os)s,
            kernel_version = %(kernel)s,
            arch           = %(arch)s,
            memory_mb      = %(memory)s,
            cpu_cores      = %(cpu)s,
            ip_addr        = %(ip)s,
            last_seen      = NOW(),
            ansible_enriched_at = NOW()
        WHERE asset_id_hash = %(asset_id_hash)s
    """, {
        'asset_id_hash': asset_id_hash,
        'os': facts['os'], 'kernel': facts['kernel'], 'arch': facts['arch'],
        'memory': facts['memory_mb'], 'cpu': facts['cpu_cores'],
        'ip': facts['ip_addrs'][0] if facts.get('ip_addrs') else None,
    })

    # 2) tb_asset_software UPSERT (NEVRA + purl)
    for pkg_name, versions in packages.items():
        for pkg in versions:
            purl = build_purl(pkg)   # transformer 재활용
            db_execute("""
                INSERT INTO tb_asset_software
                    (asset_id_hash, source, name, version, release, arch, epoch, purl, collected_at)
                VALUES (...)
                ON CONFLICT (asset_id_hash, source, purl)
                  WHERE source != 'CROWDSTRIKE' AND purl IS NOT NULL
                DO UPDATE SET version=EXCLUDED.version, ...
            """, {...})
```

---

## 8. S3 + IAM 구조

### 8.1 S3 버킷

```
gsretail-asset-enrich
  ├── IDC_NW/
  ├── ONPREM_UNIX/
  ├── STORE_NW/
  └── STORE_PC/
```

**Lifecycle Policy**:
- 30일 후 INTELLIGENT_TIERING
- 90일 후 GLACIER
- 365일 후 DELETE

### 8.2 EventBridge S3 알림

```yaml
NotificationConfiguration:
  LambdaConfigurations:
    - Event: s3:ObjectCreated:Put
      Function: !GetAtt AssetEnrichFunction.Arn
      Filter:
        Key:
          FilterRules:
            - Name: suffix
              Value: .json
```

### 8.3 IAM 역할

**EnrichTaskRole** (ECS Task용)
- `secretsmanager:GetSecretValue` (자격증명)
- `s3:PutObject` on `gsretail-asset-enrich/*`
- VPC subnet에서 DB 접근 (Security Group)

**AssetEnrichLambdaRole** (Lambda용)
- `s3:GetObject` on `gsretail-asset-enrich/*`
- DB 접근 (Security Group)

---

## 9. Phasing

| Phase | 작업 | 산출물 | 기간 |
|---|---|---|---|
| **P1** | DDL 보강 (tb_asset_master + tb_asset_security) + S3 버킷·Lifecycle + Secrets Manager 구조 | DDL.sql, SAM 템플릿 일부 | 0.5일 |
| **P2** | ECS Task Definition + Dockerfile + `build_inventory.py` + `upload_to_s3.py` | ECR 이미지, Task Def | 1일 |
| **P3** | `ONPREM_UNIX.yml` playbook (가장 표준화 쉬움 — 우선 검증) | playbook, 샘플 결과 JSON | 1일 |
| **P4** | Lambda `asset_enrich` agent — `onprem_unix.py` 매퍼만 | Lambda 함수, ddl.sql | 1일 |
| **P5** | EventBridge rule `rule_onprem_unix` + 통합 E2E 테스트 | SAM 배포 | 0.5일 |
| **P6** | `IDC_NW.yml` + `idc_nw.py` 매퍼 (모델/펌웨어 → PSIRT 매칭 키) | playbook + 매퍼 | 1일 |
| **P7** | `STORE_NW.yml` + `store_nw.py` 매퍼 (P6와 유사) | playbook + 매퍼 | 0.5일 |
| **P8** | `STORE_PC.yml` + `store_pc.py` 매퍼 + 지역별 4 EventBridge rule | playbook + 매퍼 + WinRM 검증 | 3일 |
| **P9** | `ahnlab_epp_collector` Lambda + tb_asset_security | Lambda + DDL | 1.5일 |
| **합계** | | | **10일** |

**P8 사전 검증 (별도)**:
- 본사 → 점포 PC WinRM 라우팅 (포트 5985/5986) 방화벽 확인
- AD 도메인 계정으로 5만대 인증 부하 검증
- 점포당 1대 샘플로 PoC

---

## 10. 운영 고려사항

### 10.1 모니터링
- ECS Task CloudWatch Logs (수집 성공/실패)
- Lambda 실행 메트릭 (asset_enrich 호출 수, 에러율)
- DLQ 구성 (Lambda 실패 시)

### 10.2 비용 추정
- ECS Fargate: $0.04/vCPU/hour, $0.004/GB/hour
  - 일일 평균 1시간 실행 × 5 카테고리 = ~$1/일 = **$30/월**
- 점포 PC 주 1회 4지역 병렬 (2시간 × 4 Task) = ~$2/주 = **$10/월**
- S3 저장: 100KB × 5만 파일 × 30일 = 150GB = **$3/월**
- Lambda 호출: ~5만/주 = ~20만/월 × $0.0000002 = **$0.04/월** (무시)
- **총 ~$50/월**

### 10.3 보안
- Secrets Manager에 SSH 키·AD 계정 보관 (KMS 암호화)
- ECS Task는 collect subnet 한정 (인터넷 outbound는 NAT 경유)
- S3 버킷 SSE-KMS + Public Access Block
- DB 접근은 IAM DB Auth + Security Group

### 10.4 실패 처리
- Ansible 자산 한 대 실패 → 전체 batch 계속 (--forks 100 + --ignore-errors)
- S3 업로드 실패 → ECS Task 재시도 (최대 2회)
- Lambda 처리 실패 → SQS DLQ → 운영자 알림

---

## 11. 시각화

본 파이프라인은 `pipearchi/src/scenarios/asset-enrichment.ts`에 동기화됨.
시각 청사진: `npm run dev` → 시나리오 "자산 보강" 선택.

---

## 12. 관련 문서

- `docs/PRD.md` — 전체 제품 요구사항
- `docs/ARCHITECTURE.md` — collect_cmdb 아키텍처
- `pipearchi/src/scenarios/asset-enrichment.ts` — 시각 청사진
- `pipearchi/src/scenarios/infrastructure.ts` — 전체 인프라 (Deloitte 1.1~1.4)
- `pipearchi/src/scenarios/cve-pipeline.ts` — CVE 매칭 (Trivy)
