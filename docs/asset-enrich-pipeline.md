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
│  5) 호스트별 JSON → 카테고리 1 JSONL.gz 묶음 → S3 PutObject          │
│     s3://gsretail-asset-enrich/${CATEGORY}[/${REGION}]/{date}.jsonl.gz│
│     (카테고리당 1 파일, STORE_PC만 지역당 1 → 총 7 파일/주)           │
└──────────────┬──────────────────────────────────────────────────────┘
               │ S3 PutObject 이벤트 (.jsonl.gz suffix 필터)
               ↓
┌─────────────────────────────────────────────────────────────────────┐
│  Lambda asset_enrich_agent (Python · S3 트리거)                       │
│                                                                       │
│  1) S3 key prefix → 카테고리 추출 (IDC_NW / ONPREM_UNIX / STORE_*)    │
│  2) gzip stream 해제 → 한 줄씩 JSON 파싱 (메모리 안전)                │
│  3) 카테고리별 매퍼 분기                                              │
│  4) tb_asset_master UPDATE + tb_asset_software UPSERT (NEVRA/purl)   │
│  5) 부분 실패 호스트는 별도 quarantine S3 키로 보존                   │
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

**핵심 결정**: 자산별 Secret(5만+ 개)이 아니라 **OS·벤더 6 그룹**으로 통합. 자산은 `credentials_secret_arn` 컬럼으로 자기 그룹의 Secret을 가리킴.

| Secret ARN 이름 | group_name | 적용 카테고리 | 자격증명 형식 |
|---|---|---|---|
| `cmdb/ansible/aix` | `aix` | ONPREM_UNIX (AIX) | SSH private key + sudo password |
| `cmdb/ansible/linux` | `linux` | ONPREM_UNIX (RHEL/Ubuntu) | SSH private key |
| `cmdb/ansible/cisco-ios` | `cisco-ios` | IDC_NW + STORE_NW (Cisco) | SSH private key + enable password |
| `cmdb/ansible/paloalto` | `paloalto` | IDC_NW (Palo Alto) | API key |
| `cmdb/ansible/fortinet` | `fortinet` | IDC_NW (Fortinet) | API token |
| `cmdb/ansible/store-pc-ad` | `store-pc-ad` | STORE_PC (Windows) | AD 단일 도메인 서비스 계정 (`GSRETAIL\svc-cmdb`) |

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

-- 점포 PC (5만대) — 모두 단일 AD 계정
UPDATE tb_asset_master
SET ansible_connection = 'winrm',
    ansible_user       = 'GSRETAIL\svc-cmdb',
    credentials_secret_arn = 'arn:aws:secretsmanager:ap-northeast-2:...:secret:cmdb/ansible/store-pc-ad-XXXX'
WHERE category_cd = 'STORE_PC';
```

**IAM 권한** — ECS Task Role:
```yaml
Statement:
  - Effect: Allow
    Action: secretsmanager:GetSecretValue
    Resource:
      - arn:aws:secretsmanager:ap-northeast-2:*:secret:cmdb/ansible/*
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

### 7.2 handler.py 골격 — JSONL stream 처리

S3 객체 1개 = 카테고리 1회 수집 결과 전체 (호스트 수백~수만). **stream 처리**로 메모리 안전.

```python
import json, gzip, os, boto3
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
        key    = record['s3']['object']['key']
        # key 예:
        #   ONPREM_UNIX/2026-05-27.jsonl.gz
        #   STORE_PC/KR1/2026-05-27.jsonl.gz

        parts    = key.split('/')
        category = parts[0]
        mapper   = MAPPERS.get(category)
        if not mapper:
            print(f'no mapper for category={category}')
            continue

        # S3 스트림 → gzip 압축 해제 → 한 줄씩 JSON 파싱 → mapper
        body = s3.get_object(Bucket=bucket, Key=key)['Body']
        successes = failures = 0
        failed_hosts = []
        with gzip.GzipFile(fileobj=body) as gz:
            for line in gz:
                if not line.strip():
                    continue
                try:
                    mapper(json.loads(line))
                    successes += 1
                except Exception as e:
                    failures += 1
                    try:
                        host = json.loads(line).get('asset_id_hash', '?')
                    except Exception:
                        host = '?'
                    failed_hosts.append({'asset_id_hash': host, 'error': str(e)})

        # 부분 실패 → 별도 quarantine 키로 보존
        if failed_hosts:
            qkey = key.replace('.jsonl.gz', '.failures.json')
            s3.put_object(
                Bucket=os.environ['QUARANTINE_BUCKET'],
                Key=qkey,
                Body=json.dumps(failed_hosts, ensure_ascii=False).encode(),
            )

        print(f'enriched: success={successes} fail={failures} key={key}')
```

**Lambda 사양**:
- Memory: 1 GB (5만 호스트도 stream 처리라 충분)
- Timeout: 15분 (STORE_PC 지역 1개 5만 호스트 ≈ 10초 처리, 안전 마진)
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

### 8.1 S3 버킷 — 카테고리별 단일 JSONL.gz

**파일 단위**: 카테고리당 1 파일 (STORE_PC만 지역당 1 = 총 4 파일). 호스트별 줄로 묶음.

```
gsretail-asset-enrich/
  ├── IDC_NW/      2026-05-27.jsonl.gz       (~수백 호스트 1 파일)
  ├── ONPREM_UNIX/ 2026-05-27.jsonl.gz       (~수백 호스트 1 파일)
  ├── STORE_NW/    2026-05-27.jsonl.gz       (~수천 호스트 1 파일)
  └── STORE_PC/
        ├── KR1/   2026-05-27.jsonl.gz       (~1.25만 호스트)
        ├── KR2/   2026-05-27.jsonl.gz       (~1.25만 호스트)
        ├── KR3/   2026-05-27.jsonl.gz       (~1.25만 호스트)
        └── KR4/   2026-05-27.jsonl.gz       (~1.25만 호스트)
```

**파일 수**: 주당 7개 (실패 quarantine 제외). Lambda 호출도 주당 7회.

**JSONL 한 줄 예시**:
```json
{"asset_id_hash":"abc123","category":"ONPREM_UNIX","facts":{"os":"RHEL 9.4","kernel":"5.14.0","arch":"x86_64","memory_mb":16384,"cpu_cores":8,"ip_addrs":["10.10.1.5"]},"packages":{"openssl-libs":[{"name":"openssl-libs","version":"3.0.7","release":"27.el9_4","arch":"x86_64"}]}}
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
- S3 저장: 카테고리당 1 JSONL.gz (gzip 압축 후 ~5MB) × 7 파일/주 × 12주 보관 = ~0.5GB = **$0.01/월** (무시)
- Lambda 호출: 7/주 = ~30/월 × $0.0000002 = **무시**
- **총 ~$40/월** (당초 ~$50 → 파일 수 단순화로 절감)

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
