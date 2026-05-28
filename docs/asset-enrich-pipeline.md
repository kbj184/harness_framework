# 자산 보강 파이프라인 구현 계획 (ECS Ansible + ECS EPP × EventBridge × S3 × Lambda)

**문서 버전**: v2.0 · 2026-05-28 (수집 채널 재배치 반영)
**범위**: CrowdStrike Agent 미커버 자산의 자동 보강 파이프라인
**구현 기간**: 8일 (P1~P8)

---

## 1. 배경 및 목표

CrowdStrike Falcon Agent는 **클라우드 서버(EC2)만 대상**. 다음 자산군은 자체 수집 채널이 필요하며, 수집 채널을 **2 트랙으로 재배치** (2026-05-28 결정):

### Ansible 트랙 (ECS Ansible Container — SSH/CLI 직접 접속)

| 자산군 | 규모(추정) | category_cd |
|---|---|---|
| 온프레미스 Unix (AIX/Solaris/HP-UX/Linux) | ~수백대 | `ONPREM_UNIX` |
| IDC 네트워크 장비 (Cisco/F5/Palo Alto/Fortinet) | ~수백대 | `IDC_NW` |
| 점포 네트워크 (라우터/스위치) | ~수천대 | `STORE_NW` |

### EPP 트랙 (ECS Fargate + asyncio — 안랩 EPP API)

| 자산군 | 규모(추정) | category_cd |
|---|---|---|
| 점포 PC (Windows) | ~5만대 | `EPP_STORE_OA` |
| 본사·사무실 PC | ~1만대 | `EPP_OFFICE_OA` |
| 기타 서버 (Ansible 미적용) | ~5천대 | `EPP_ETC_SERVER` |

> **변경 이유 (2026-05-28):** 점포 PC를 Ansible WinRM으로 수집하던 계획은 본사 → 점포 라우팅·AD 인증·시간 부담이 큼. 점포 PC·본사 PC·기타 서버는 모두 안랩 EPP Agent가 깔려있으므로 EPP API로 통합 수집이 효율적. EPP 호출 패턴(목록 1회 + 자산별 SBOM 6.5만 회)은 Lambda 15분 한도를 초과하므로 ECS Fargate + asyncio로 처리.

**목표**: 위 자산군에 대해 자동 수집 파이프라인 구축 → tb_asset_master/tb_asset_software 보강

---

## 2. 아키텍처

**2 트랙 + 공통 Lambda 매퍼 + 보안정보 별도 트랙**

```
┌─────────────────────────────────────────────────────────────────────┐
│  EventBridge (cron rules)                                            │
│    rule_idc_nw      cron(0 19 * * ? *)   일 1회 KST 04:00 (Ansible)  │
│    rule_onprem_unix cron(0 19 * * ? *)   일 1회 KST 04:00 (Ansible)  │
│    rule_store_nw    cron(0 19 * * ? *)   일 1회 KST 04:00 (Ansible)  │
│    rule_epp_assets  cron(0 18 * * ? *)   일 1회 KST 03:00 (EPP)      │
└──────────────┬──────────────────────────────────────────────────────┘
               │ ECS RunTask
               ↓
┌─────────────────────────────────────────────────────────────────────┐
│  Track A — ECS Fargate · Ansible Container (env CATEGORY=xxx)        │
│                                                                       │
│  1) CMDB 조회 — tb_asset_master WHERE category_cd = ${CATEGORY}      │
│  2) Ansible Dynamic Inventory 생성 (/tmp/inventory.yml)              │
│  3) Secrets Manager → SSH 키 로드                                     │
│  4) ansible-playbook /playbooks/${CATEGORY}.yml --forks 100          │
│  5) 호스트별 JSON → 카테고리 1 JSONL.gz 묶음 → S3 PutObject          │
│     s3://gsretail-asset-enrich/${CATEGORY}/{date}.jsonl.gz           │
│                                                                       │
│  대상 카테고리: IDC_NW / ONPREM_UNIX / STORE_NW (3 파일/일)          │
└──────────────┬──────────────────────────────────────────────────────┘
               │
               │  ──────── Track B (병렬) ────────
               │
┌──────────────┴──────────────────────────────────────────────────────┐
│  Track B — ECS Fargate · EPP Collector Container (asyncio + httpx)   │
│                                                                       │
│  1) Secrets Manager → 안랩 EPP API Token 로드                         │
│  2) 안랩 EPP 목록 API 1회 호출 → ~65,000 자산 응답                    │
│  3) 자산별 SBOM API 동시 호출 (asyncio.Semaphore(100))                │
│     · 처리 시간 ~11~22분                                              │
│  4) EPP 응답의 자산 분류 필드 → category_cd 결정                      │
│     EPP_STORE_OA / EPP_OFFICE_OA / EPP_ETC_SERVER                    │
│  5) 결과 → JSONL.gz 1 파일 (카테고리 혼합, 줄별 category_cd 명시)    │
│     s3://gsretail-asset-enrich/EPP/{date}.jsonl.gz                   │
└──────────────┬──────────────────────────────────────────────────────┘
               │ S3 PutObject 이벤트 (.jsonl.gz suffix 필터)
               ↓
┌─────────────────────────────────────────────────────────────────────┐
│  Lambda asset_enrich_agent (Python · S3 트리거) — Ansible/EPP 공통    │
│                                                                       │
│  1) S3 key prefix 또는 JSONL 줄의 category_cd 로 분기                 │
│     (Ansible: prefix=IDC_NW/ONPREM_UNIX/STORE_NW)                    │
│     (EPP:     prefix=EPP, 줄별 category_cd=EPP_STORE_OA/...)         │
│  2) gzip stream 해제 → 한 줄씩 JSON 파싱 (메모리 안전)                │
│  3) 카테고리별 매퍼 분기                                              │
│  4) tb_asset_master UPDATE + tb_asset_software UPSERT (NEVRA/purl)   │
│  5) 부분 실패 호스트는 별도 quarantine S3 키로 보존                   │
└─────────────────────────────────────────────────────────────────────┘
```

**보안 정보 트랙 (자산 정보 트랙 안정화 후 별도 phase로 진행)**:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Lambda ahnlab_epp_security_collector (EventBridge cron, 시간당)      │
│    안랩 EPP 보안 상태 endpoint → tb_asset_security                    │
│    (Agent ID, AV 패턴 버전, 정책 그룹, 검사 결과, 격리 상태)          │
└─────────────────────────────────────────────────────────────────────┘
```

**ECS 구조**:
- Ansible Task와 EPP Task는 **같은 ECS Cluster·VPC·IAM 패턴 공유**, **컨테이너 이미지는 별개** (Ansible은 SSH·Ansible 의존성 필요, EPP는 httpx만 필요)

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

### 3.4 EPP (안랩) 자산 정보 트랙 — `category_cd = EPP_*`

> **결정 (2026-05-28):** 점포 PC를 Ansible WinRM으로 수집하는 계획(이전 `STORE_PC`)은 본사 → 점포 라우팅·AD 인증·시간 부담으로 폐기. **안랩 EPP API**로 통합 수집. EPP 응답에 자산 분류 필드가 있어 카테고리 3종으로 분기.

| 항목 | 값 |
|---|---|
| 대상 | 안랩 Agent 설치된 모든 자산 (~65,000대) — 점포 PC + 본사·사무실 PC + 기타 서버 |
| 프로토콜 | 안랩 EPP V3 Manager API (`httpx`) |
| 자격증명 | API Token (Secrets Manager — `cmdb/ansible/ahnlab-epp` 등 별도 ARN) |
| **수집 채널** | **ECS Fargate Task (asyncio + httpx)** — Lambda 아님 (15분 한도 초과) |
| 동시성 | `asyncio.Semaphore(100)` (안랩 API rate limit 실측 후 조정) |
| 수집 항목 | hostname, OS·빌드, 설치 SW, hotfix, BIOS serial, IP/MAC, 자산 분류 필드 (보안 정보는 §3.5 별도 트랙) |
| 빈도 | 일 1회 (KST 03:00) |
| 호출 흐름 | 목록 API 1회 (≈65,000 자산 응답) → 자산별 SBOM API 동시 100 호출 → JSONL.gz 묶음 → S3 |
| 예상 처리 시간 | 11~22분 (동시 100 기준) |

EPP 카테고리 3종 — 안랩 API 응답의 자산 분류 필드로 결정:

| `category_cd` | 대상 |
|---|---|
| `EPP_STORE_OA` | 점포 PC (Windows) — 약 5만대 |
| `EPP_OFFICE_OA` | 본사·사무실 PC — 약 1만대 |
| `EPP_ETC_SERVER` | Ansible 미적용 기타 서버 (Windows·Linux 혼재) — 약 5천대 |

### 3.5 AhnLab EPP/EDR 보안 정보 트랙 — `tb_asset_security` (별도, 추후)

> **본 작업 범위 외** — 자산 정보(§3.4) 트랙 안정화 후 별도 phase로 진행.

| 항목 | 값 |
|---|---|
| 대상 | 안랩 Agent 설치된 모든 자산 |
| 프로토콜 | 안랩 EPP V3 Manager API (보안 상태 endpoint) |
| 수집 채널 | **별도 Lambda** (자산 정보보다 가볍고 시간당 갱신) |
| 수집 항목 | Agent ID, AV 패턴 버전, 정책 그룹, 최근 검사 결과, 격리 상태 |
| 빈도 | 시간당 |
| 적재 | `tb_asset_security` (별도 테이블) — asset_id_hash로 tb_asset_master 매칭 |

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
  -- KR1/KR2/KR3/KR4 (지역 분류, 보조)
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

# 3. S3 업로드 — 호스트별 JSON 을 카테고리 단일 JSONL 로 묶어서 PutObject
python3 /opt/enrich/scripts/upload_to_s3.py \
    --category "$CATEGORY" \
    --results /tmp/results \
    --bucket "$S3_BUCKET" \
    ${REGION:+--region "$REGION"}
```

`upload_to_s3.py` 동작:
```python
# /tmp/results/*.json (호스트별) → JSONL 1 파일로 묶어 S3 업로드.
# 결과 파일 수: 카테고리당 1 (STORE_PC는 지역당 1 → 총 4).
import argparse, json, gzip, boto3, glob, datetime, io

ap = argparse.ArgumentParser()
ap.add_argument('--category', required=True)
ap.add_argument('--results',  required=True)
ap.add_argument('--bucket',   required=True)
ap.add_argument('--region',   default=None)   # STORE_PC 한정
args = ap.parse_args()

date    = datetime.date.today().isoformat()
key_pfx = args.category + (f'/{args.region}' if args.region else '')
key     = f'{key_pfx}/{date}.jsonl.gz'

# 호스트별 JSON → 한 줄 JSONL 로 concat + gzip 압축
buf = io.BytesIO()
with gzip.GzipFile(fileobj=buf, mode='wb') as gz:
    for path in sorted(glob.glob(f'{args.results}/*.json')):
        with open(path) as f:
            data = json.load(f)
        gz.write((json.dumps(data, ensure_ascii=False) + '\n').encode())

boto3.client('s3').put_object(
    Bucket=args.bucket,
    Key=key,
    Body=buf.getvalue(),
    ContentEncoding='gzip',
    ContentType='application/x-ndjson',
)
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

### 5.4 build_inventory.py — CMDB 조회 + Static YAML 생성

ECS Task 시작 시 1회 실행. `tb_asset_master`에서 카테고리(+지역)별 자산을 조회해 `/tmp/inventory.yml` 작성.

**조회 쿼리**:
```sql
SELECT
    asset_id_hash,
    hostname,
    ip_addr,
    ansible_user,
    ansible_connection,         -- ssh / winrm / network_cli
    ansible_network_os,         -- ios / nxos / panos / fortios / ...
    credentials_secret_arn      -- 6 그룹 중 하나
FROM tb_asset_master
WHERE category_cd = %(category)s
  AND lifecycle_state = 'ACTIVE'
  AND (%(region)s IS NULL OR region_cd = %(region)s)
ORDER BY ansible_network_os, hostname;
```

**핵심 동작**:
```python
# scripts/build_inventory.py
import psycopg2, yaml, boto3, os, json, stat
from collections import defaultdict

CATEGORY = os.environ['CATEGORY']
REGION   = os.environ.get('REGION')

# 1) CMDB 조회
with psycopg2.connect(os.environ['DB_URL']) as conn:
    cur = conn.cursor()
    cur.execute(SELECT_SQL, {'category': CATEGORY, 'region': REGION})
    assets = cur.fetchall()

# 2) Unique secret_arn 만 Secrets Manager 호출 (자산별 X, 그룹 6개만)
sm = boto3.client('secretsmanager')
unique_arns = {a.credentials_secret_arn for a in assets}
group_keys = {}
os.makedirs('/tmp/keys', exist_ok=True)
for arn in unique_arns:
    secret = json.loads(sm.get_secret_value(SecretId=arn)['SecretString'])
    group_name = secret['group_name']   # 예: 'aix' / 'linux' / 'cisco-ios'
    key_path = f'/tmp/keys/{group_name}.pem'
    with open(key_path, 'w') as f:
        f.write(secret['ssh_private_key'])
    os.chmod(key_path, stat.S_IRUSR)    # 600 권한
    group_keys[arn] = (group_name, key_path, secret)

# 3) Inventory YAML 작성 (호스트 그룹 = ansible_network_os 또는 OS family)
inventory = {'all': {'children': {}, 'vars': {}}}
groups = defaultdict(dict)              # group_name → {hostname: host_vars}

for a in assets:
    group_name, key_path, secret = group_keys[a.credentials_secret_arn]
    host_vars = {
        'ansible_host':       a.ip_addr,
        'ansible_user':       a.ansible_user,
        'ansible_connection': a.ansible_connection,
        'asset_id_hash':      a.asset_id_hash,
    }
    if a.ansible_connection == 'ssh':
        host_vars['ansible_ssh_private_key_file'] = key_path
    elif a.ansible_connection == 'winrm':
        host_vars['ansible_password']         = secret['ad_password']
        host_vars['ansible_winrm_transport']  = 'kerberos'
    elif a.ansible_connection == 'network_cli':
        host_vars['ansible_network_os']       = a.ansible_network_os
        host_vars['ansible_ssh_private_key_file'] = key_path

    groups[group_name][a.hostname] = host_vars

inventory['all']['children'] = {g: {'hosts': h} for g, h in groups.items()}
with open('/tmp/inventory.yml', 'w') as f:
    yaml.dump(inventory, f, sort_keys=False)
```

**생성 예시 (ONPREM_UNIX)**:
```yaml
all:
  children:
    aix:
      hosts:
        aix-erp-01:
          ansible_host: 10.10.1.5
          ansible_user: svc-cmdb
          ansible_connection: ssh
          ansible_ssh_private_key_file: /tmp/keys/aix.pem
          asset_id_hash: "abc123..."
    linux:
      hosts:
        rhel-app-01:
          ansible_host: 10.10.2.10
          ansible_user: svc-cmdb
          ansible_connection: ssh
          ansible_ssh_private_key_file: /tmp/keys/linux.pem
          asset_id_hash: "def456..."
```

**Task 종료 시 정리** — `run.sh`에 trap 추가:
```bash
cleanup() {
    rm -rf /tmp/keys /tmp/inventory.yml /tmp/results
}
trap cleanup EXIT
```

### 5.5 자격증명 그룹화 — Secrets Manager 6 항목

**핵심 결정**: 자산별 Secret이 아니라 **OS·벤더 6 그룹**으로 통합. Ansible 자산은 `credentials_secret_arn` 컬럼으로 자기 그룹의 Secret을 가리킴. EPP는 단일 API Token.

| Secret ARN 이름 | group_name | 적용 카테고리 | 자격증명 형식 |
|---|---|---|---|
| `cmdb/ansible/aix` | `aix` | ONPREM_UNIX (AIX) | SSH private key + sudo password |
| `cmdb/ansible/linux` | `linux` | ONPREM_UNIX (RHEL/Ubuntu) | SSH private key |
| `cmdb/ansible/cisco-ios` | `cisco-ios` | IDC_NW + STORE_NW (Cisco) | SSH private key + enable password |
| `cmdb/ansible/paloalto` | `paloalto` | IDC_NW (Palo Alto) | API key |
| `cmdb/ansible/fortinet` | `fortinet` | IDC_NW (Fortinet) | API token |
| `cmdb/ahnlab-epp` | `ahnlab-epp` | EPP_STORE_OA + EPP_OFFICE_OA + EPP_ETC_SERVER | 안랩 EPP API Token (Bearer) |

→ 기존 `store-pc-ad`(AD 도메인 계정) Secret은 폐기. 점포 PC는 안랩 EPP로 흡수되므로 AD 직접 인증 불필요.

**Secret 내용 표준 형식 (JSON)**:
```json
{
  "group_name": "aix",
  "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
  "ssh_public_key": "ssh-ed25519 AAAA...",
  "sudo_password": "...",
  "enable_password": null,
  "ad_username": null,
  "ad_password": null,
  "rotated_at": "2026-05-27T00:00:00Z"
}
```

**자산 → Secret 매핑 (P1 적용 시)**:
```sql
-- AIX 서버 그룹
UPDATE tb_asset_master
SET ansible_connection = 'ssh',
    ansible_user       = 'svc-cmdb',
    credentials_secret_arn = 'arn:aws:secretsmanager:ap-northeast-2:...:secret:cmdb/ansible/aix-XXXX'
WHERE category_cd = 'ONPREM_UNIX' AND os_name LIKE 'AIX%';

-- Linux 서버 그룹
UPDATE tb_asset_master
SET ansible_connection = 'ssh',
    ansible_user       = 'svc-cmdb',
    credentials_secret_arn = 'arn:aws:secretsmanager:ap-northeast-2:...:secret:cmdb/ansible/linux-XXXX'
WHERE category_cd = 'ONPREM_UNIX' AND os_name ~* '(rhel|ubuntu|centos|rocky)';

-- EPP 자산 (점포 PC / 사무실 PC / 기타 서버 ~65,000대)
-- Ansible 자격증명 컬럼은 사용 안 함. EPP Task는 cmdb/ahnlab-epp Secret 한 개 직접 로드.
-- tb_asset_master 매칭은 EPP 응답의 hostname/MAC 으로 (Lambda 매퍼가 처리).
```

**IAM 권한** — ECS Task Role (Ansible Task + EPP Task 공유):
```yaml
Statement:
  - Effect: Allow
    Action: secretsmanager:GetSecretValue
    Resource:
      - arn:aws:secretsmanager:ap-northeast-2:*:secret:cmdb/ansible/*
      - arn:aws:secretsmanager:ap-northeast-2:*:secret:cmdb/ahnlab-epp-*
```

**키 회전**: 6 개만 회전하면 됨. Secrets Manager 자동 회전 30~90일 설정.

**보안 — 메모리 안전**:
- 키는 ECS 컨테이너 `/tmp/keys/`에만 존재, 권한 600
- Task 종료 시 컨테이너와 함께 소멸 (Fargate는 격리된 미니 VM)
- S3·DB에 절대 평문 저장 X

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

### 6.4 EPP 트랙 — playbook 없음, Python asyncio 스크립트

EPP 트랙은 Ansible playbook을 쓰지 않고 **별도 ECS 컨테이너 안의 Python asyncio 스크립트**로 동작:

```python
# src/agents/asset_enrich/epp_ecs/scripts/fetch_epp.py
import asyncio, httpx, json, gzip, boto3, os
from datetime import date

EPP_BASE_URL = os.environ['EPP_BASE_URL']
EPP_TOKEN    = json.loads(boto3.client('secretsmanager')
                          .get_secret_value(SecretId=os.environ['EPP_SECRET_ARN'])['SecretString'])['token']
S3_BUCKET    = os.environ['S3_BUCKET']

CATEGORY_MAP = {
    'STORE_PC':   'EPP_STORE_OA',
    'OFFICE_PC':  'EPP_OFFICE_OA',
    'SERVER':     'EPP_ETC_SERVER',
}

async def fetch_sbom(client, sem, asset):
    async with sem:
        for attempt in range(2):
            try:
                r = await client.get(f"/api/assets/{asset['id']}/sbom", timeout=30)
                r.raise_for_status()
                return {
                    "category_cd": CATEGORY_MAP.get(asset['type'], 'EPP_ETC_SERVER'),
                    "asset_id":    asset['id'],
                    "hostname":    asset['hostname'],
                    "mac":         asset.get('mac'),
                    "ip":          asset.get('ip'),
                    "os":          asset.get('os'),
                    "sbom":        r.json(),
                }
            except Exception as e:
                if attempt == 1:
                    return {"error": str(e), "asset_id": asset['id']}
                await asyncio.sleep(60)

async def main():
    headers = {"Authorization": f"Bearer {EPP_TOKEN}"}
    async with httpx.AsyncClient(base_url=EPP_BASE_URL, headers=headers, timeout=60) as client:
        # 1. 목록
        assets = (await client.get("/api/assets")).json()   # ~65,000
        # 2. SBOM 동시 호출
        sem = asyncio.Semaphore(100)
        results = await asyncio.gather(*[fetch_sbom(client, sem, a) for a in assets])
        # 3. JSONL.gz 묶음
        key = f"EPP/{date.today().isoformat()}.jsonl.gz"
        buf = io.BytesIO()
        with gzip.GzipFile(fileobj=buf, mode='wb') as gz:
            for row in results:
                gz.write((json.dumps(row, ensure_ascii=False) + '\n').encode())
        boto3.client('s3').put_object(
            Bucket=S3_BUCKET, Key=key,
            Body=buf.getvalue(), ContentEncoding='gzip',
            ContentType='application/x-ndjson',
        )

asyncio.run(main())
```

→ Ansible playbook과 같은 출력 형식(JSONL.gz)이라 **공통 Lambda 매퍼가 그대로 처리** 가능.

---

## 7. Lambda asset_enrich_agent

### 7.1 디렉터리 구조

```
collect_cmdb/src/agents/asset_enrich/
  ├── __init__.py
  ├── handler.py            # S3 이벤트 핸들러 (Ansible/EPP 공통)
  ├── mappers/
  │     ├── onprem_unix.py        # Ansible 트랙
  │     ├── idc_nw.py             # Ansible 트랙
  │     ├── store_nw.py           # Ansible 트랙
  │     └── epp.py                # EPP 트랙 (EPP_STORE_OA/EPP_OFFICE_OA/EPP_ETC_SERVER 공용)
  ├── models.py             # Pydantic 모델
  ├── ddl.sql               # tb_asset_master ALTER + tb_asset_security CREATE
  ├── ansible_ecs/          # Ansible Container (P2~P3)
  │     ├── Dockerfile
  │     ├── playbooks/
  │     └── scripts/
  ├── epp_ecs/              # EPP Container (P5)
  │     ├── Dockerfile
  │     └── scripts/fetch_epp.py
  └── README.md
```

### 7.2 handler.py 골격 — JSONL stream 처리

S3 객체 1개 = 카테고리 1회 수집 결과 전체 (호스트 수백~수만). **stream 처리**로 메모리 안전.

```python
import json, gzip, os, boto3
from collect_cmdb.src.agents.asset_enrich.mappers import (
    onprem_unix, idc_nw, store_nw, epp,
)

s3 = boto3.client('s3')

# Ansible 트랙: S3 prefix 가 category_cd
PREFIX_MAPPERS = {
    'ONPREM_UNIX': onprem_unix.enrich,
    'IDC_NW':      idc_nw.enrich,
    'STORE_NW':    store_nw.enrich,
    'EPP':         epp.enrich,        # EPP 트랙: prefix=EPP, 줄별 category_cd 로 다시 분기
}

def handler(event, context):
    for record in event['Records']:
        bucket = record['s3']['bucket']['name']
        key    = record['s3']['object']['key']
        # key 예:
        #   ONPREM_UNIX/2026-05-27.jsonl.gz
        #   EPP/2026-05-27.jsonl.gz

        prefix = key.split('/')[0]
        mapper = PREFIX_MAPPERS.get(prefix)
        if not mapper:
            print(f'no mapper for prefix={prefix}')
            continue

        # S3 스트림 → gzip 압축 해제 → 한 줄씩 JSON 파싱 → mapper
        body = s3.get_object(Bucket=bucket, Key=key)['Body']
        successes = failures = 0
        failed = []
        with gzip.GzipFile(fileobj=body) as gz:
            for line in gz:
                if not line.strip():
                    continue
                try:
                    mapper(json.loads(line))
                    successes += 1
                except Exception as e:
                    failures += 1
                    failed.append({'line': line[:200].decode(errors='replace'),
                                   'error': str(e)})

        # 부분 실패 → 별도 quarantine 키로 보존
        if failed:
            qkey = key.replace('.jsonl.gz', '.failures.json')
            s3.put_object(
                Bucket=os.environ['QUARANTINE_BUCKET'],
                Key=qkey,
                Body=json.dumps(failed, ensure_ascii=False).encode(),
            )

        print(f'enriched: success={successes} fail={failures} key={key}')
```

**Lambda 사양**:
- Memory: 1 GB (수만 호스트도 stream 처리라 충분)
- Timeout: 15분 (EPP 트랙 ~65,000 호스트 처리 ≈ 1~2분, 안전 마진)
- 1000행 단위 배치 INSERT 권장 (매퍼 내부 구현)

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

### 8.1 S3 버킷 — 트랙별 JSONL.gz

**파일 단위**:
- Ansible 트랙: 카테고리당 1 파일 (3 카테고리 × 일 1회 = 3 파일/일)
- EPP 트랙: 카테고리 혼합 1 파일 (전 자산 한 파일, 줄별 category_cd로 분기) (1 파일/일)

```
gsretail-asset-enrich/
  ├── IDC_NW/      2026-05-27.jsonl.gz       (~수백 호스트, 일 1회)
  ├── ONPREM_UNIX/ 2026-05-27.jsonl.gz       (~수백 호스트, 일 1회)
  ├── STORE_NW/    2026-05-27.jsonl.gz       (~수천 호스트, 일 1회)
  └── EPP/         2026-05-27.jsonl.gz       (~65,000 호스트, 일 1회)
```

**파일 수**: 일 4개, 주 28개 (실패 quarantine 제외). Lambda 호출도 같음.

**JSONL 한 줄 예시 — Ansible (`category` 필드)**:
```json
{"asset_id_hash":"abc123","category":"ONPREM_UNIX","facts":{"os":"RHEL 9.4","kernel":"5.14.0","arch":"x86_64","memory_mb":16384,"cpu_cores":8,"ip_addrs":["10.10.1.5"]},"packages":{"openssl-libs":[{"name":"openssl-libs","version":"3.0.7","release":"27.el9_4","arch":"x86_64"}]}}
```

**JSONL 한 줄 예시 — EPP (`category_cd` 필드)**:
```json
{"category_cd":"EPP_STORE_OA","asset_id":"epp-12345","hostname":"pos-12345","mac":"AA:BB:CC:DD:EE:FF","ip":"10.200.1.5","os":"Windows 11 Pro","sbom":[{"name":"Chrome","version":"125.0.6422.142","publisher":"Google"},{"name":"V3 Internet Security","version":"9.0.x"}]}
```

**Lifecycle Policy**:
- 30일 후 INTELLIGENT_TIERING
- 90일 후 GLACIER
- 365일 후 DELETE

### 8.2 EventBridge S3 알림 — `.jsonl.gz` suffix 필터

```yaml
NotificationConfiguration:
  LambdaConfigurations:
    - Event: s3:ObjectCreated:Put
      Function: !GetAtt AssetEnrichFunction.Arn
      Filter:
        Key:
          FilterRules:
            - Name: suffix
              Value: .jsonl.gz       # 매퍼가 처리할 카테고리 결과만
```

ECS PutObject → 1~3초 내 Lambda invoke. eventual consistency 누락은 매우 드물지만, P4 구현 시 `quarantine` 큐 + 운영자 수동 재실행 절차로 보완.

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
| **P1** | DDL 보강 (tb_asset_master + tb_asset_security) + S3 버킷·Lifecycle + Secrets Manager 구조 | DDL.sql, SAM 템플릿 일부 | 0.5일 ✅ |
| **P2** | Ansible ECS Task Definition + Dockerfile + `build_inventory.py` + `upload_to_s3.py` | ECR 이미지, Task Def | 1일 |
| **P3** | `ONPREM_UNIX.yml` playbook (가장 표준화 쉬움 — 우선 검증) | playbook, 샘플 결과 JSON | 1일 |
| **P4** | Lambda `asset_enrich` agent — `onprem_unix.py` 매퍼만 + 공통 handler | Lambda 함수 | 1일 |
| **P5** | EPP ECS Task Definition + Dockerfile + `fetch_epp.py` (asyncio + httpx) + `epp.py` 매퍼 | ECR 이미지, Task Def, 매퍼 | 1.5일 |
| **P6** | `IDC_NW.yml` + `STORE_NW.yml` playbook + `idc_nw.py`·`store_nw.py` 매퍼 | playbook + 매퍼 | 1일 |
| **P7** | EventBridge rules 4종 + 통합 E2E 테스트 | SAM 배포 | 1일 |
| **P8** (별도 트랙) | `ahnlab_epp_security_collector` Lambda + `tb_asset_security` 활용 (보안 정보) | Lambda + DDL | 1일 |
| **합계** | | | **8일** |

**변경 사항 (이전 v1 대비)**:
- ❌ 폐기: `STORE_PC.yml` playbook + 지역별 4 EventBridge rule + WinRM 라우팅 검증 (3일 절감)
- ✅ 신규: P5 EPP ECS Task (asyncio + httpx, 1.5일)
- 순서 재정렬: 매퍼별 phase가 작아져 P6·P7로 통합

**P5 사전 확인 (외부 협조 필요)**:
- 안랩 EPP API endpoint·인증 방식 (안랩 측 문서/담당자 확인)
- 안랩 EPP API rate limit (초기 `asyncio.Semaphore(100)` 설정 적합 여부)
- EPP 응답의 자산 분류 필드 정의 (점포/사무실/기타 → category_cd 매핑 룰)

---

## 10. 운영 고려사항

### 10.1 모니터링
- ECS Task CloudWatch Logs (Ansible/EPP 각각, 수집 성공/실패)
- Lambda 실행 메트릭 (asset_enrich 호출 수, 에러율)
- DLQ 구성 (Lambda 실패 시)

### 10.2 비용 추정

**Ansible 트랙** (3 카테고리 × 일 1회):
- ECS Fargate 2 vCPU 4GB × ~30분/Task × 3 Task/일 = ~$0.30/일 = **~$9/월**

**EPP 트랙** (1 Task × 일 1회):
- ECS Fargate 2 vCPU 4GB × ~20분/일 = ~$0.05/일 = **~$1.5/월**

**S3 저장**:
- JSONL.gz × 4 파일/일 × 90일 = ~2GB = **~$0.05/월** (무시)

**Lambda 호출**:
- 4/일 × 30일 = 120/월 × $0.0000002 = **무시**

**총 ~$11/월** (이전 추정 $50 → 점포 PC Ansible 폐기로 대폭 절감)

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
