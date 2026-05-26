# CrowdStrike Falcon 수집 API 샘플

`collect_cmdb`가 호출하는 CrowdStrike Falcon API의 **요청 URL · 설명 · 응답 JSON**.

- Base URL: `https://api.crowdstrike.com` (US-1) · `https://api.eu-1.crowdstrike.com` (EU)
- 인증: 모든 호출 헤더 `Authorization: Bearer <token>`

---

## 0. OAuth2 토큰 발급

**POST** `/oauth2/token`

OAuth2 client credentials. 토큰 유효기간 30분. 매 실행마다 신규 발급.

요청:
```
Content-Type: application/x-www-form-urlencoded

client_id={client_id}&client_secret={client_secret}
```

응답:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImt...",
  "token_type": "bearer",
  "expires_in": 1799
}
```

---

## 1. 자산 수집 (Hosts API)

### 1.1 디바이스 ID 목록 조회

**GET** `/devices/queries/devices/v1`

CID(테넌트) 내 모든 디바이스의 `device_id` 목록. 페이지네이션 사용 (offset 또는 after 토큰).

요청 파라미터:
```
limit=5000
sort=last_seen.desc
filter=(선택)  예: platform_name:'Windows'+last_seen:>'2026-05-01'
```

응답:
```json
{
  "meta": {
    "query_time": 0.012,
    "pagination": { "offset": 0, "limit": 5000, "total": 1234 },
    "trace_id": "..."
  },
  "resources": [
    "abc12345def67890",
    "fedcba0987654321",
    "..."
  ],
  "errors": []
}
```

### 1.2 디바이스 상세 조회

**POST** `/devices/entities/devices/v2`

device_id 배치(최대 100개)로 상세 정보 일괄 조회.

요청:
```json
{ "ids": ["abc12345def67890", "fedcba0987654321"] }
```

응답:
```json
{
  "meta": { "query_time": 0.087, "trace_id": "..." },
  "resources": [
    {
      "device_id": "abc12345def67890",
      "cid": "0123456789abcdef0123456789abcdef",
      "hostname": "app-prd-01",
      "local_ip": "10.1.2.10",
      "external_ip": "203.0.113.55",
      "mac_address": "AA:BB:CC:DD:EE:FF",
      "platform_name": "Windows",
      "os_version": "Windows Server 2019",
      "os_build": "17763.5458",
      "system_manufacturer": "VMware, Inc.",
      "system_product_name": "VMware Virtual Platform",
      "serial_number": "VMware-56 4d ...",
      "bios_version": "VMW71.00V.1234567.B64.2301010000",
      "agent_version": "7.14.18305.0",
      "product_type_desc": "Server",
      "status": "normal",
      "machine_domain": "corp.gsretail.com",
      "ou": "OU=Servers,DC=corp,DC=gsretail,DC=com",
      "service_provider": null,
      "last_seen": "2026-05-22T01:23:45Z",
      "first_seen": "2025-08-15T09:14:22Z",
      "tags": [
        "SensorGroupingTags/env:prod",
        "FalconGroupingTags/team:platform",
        "FalconGroupingTags/svc:crm"
      ]
    }
  ],
  "errors": []
}
```

---

## 2. 알람 수집 (Alerts v2)

### 2.1 알람 ID 목록 조회

**GET** `/alerts/queries/alerts/v2`

신규/갱신된 alert의 `composite_id` 목록. 15분 주기 폴링.

요청 파라미터:
```
limit=500
sort=created_timestamp.desc
filter=(선택)  예: created_timestamp:>'2026-05-22T03:00:00Z'+status:'new'
```

응답:
```json
{
  "meta": {
    "query_time": 0.034,
    "pagination": { "offset": 0, "limit": 500, "total": 87 },
    "trace_id": "..."
  },
  "resources": [
    "abc12345def67890:ind:1234567890abcdef:9876543210",
    "abc12345def67890:ind:0fedcba987654321:1234567890",
    "..."
  ],
  "errors": []
}
```

### 2.2 알람 상세 조회

**POST** `/alerts/entities/alerts/v2`

composite_id 배치(최대 100개)로 alert 상세 일괄 조회.

요청:
```json
{ "composite_ids": ["abc12345def67890:ind:1234567890abcdef:9876543210"] }
```

응답:
```json
{
  "meta": { "query_time": 0.156, "trace_id": "..." },
  "resources": [
    {
      "composite_id": "abc12345def67890:ind:1234567890abcdef:9876543210",
      "id": "1234567890abcdef9876543210fedcba",
      "cid": "0123456789abcdef0123456789abcdef",
      "agent_id": "abc12345def67890",
      "name": "SuspiciousPowerShellExecution",
      "display_name": "Suspicious PowerShell Execution",
      "description": "PowerShell process spawned with encoded command and base64 payload",
      "product": "epp",
      "type": "ldt",
      "scenario": "credential_theft",
      "pattern_disposition": 2048,
      "severity": 70,
      "severity_name": "High",
      "confidence": 80,
      "status": "new",
      "tactic": "Credential Access",
      "technique": "OS Credential Dumping (T1003)",
      "objective": "Gain Access",
      "hostname": "app-prd-01",
      "filename": "powershell.exe",
      "filepath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "cmdline": "powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAg...",
      "user_name": "CORP\\svc_app",
      "falcon_host_link": "https://falcon.crowdstrike.com/activity-v2/detections/abc...",
      "created_timestamp": "2026-05-22T03:45:12.345Z",
      "updated_timestamp": "2026-05-22T03:45:15.000Z"
    }
  ],
  "errors": []
}
```
