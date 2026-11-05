---
title: 설정과 접근 권한
description: KeePass 저장소와 에이전트별 접근 권한, 고급 설정을 관리합니다.
---

# 설정과 접근 권한

대부분의 사용자는 **KeePass 저장소 연결**과 **에이전트 접근 권한 제한**만 먼저 설정하면 됩니다.

## 설정 파일 위치

- **Windows:** `%USERPROFILE%/.config/keepass-agent/config.toml`
- **Linux:** `~/.config/keepass-agent/config.toml`

`kp config show`로 설정을 확인하고, `kp config validate`로 오류를 검사하세요. 이 파일에 마스터 비밀번호를 넣으면 안 됩니다.

## 1. 기본 권한부터 줄이기

::: danger 초기 권한은 광범위합니다
현재 `kp config init`은 `[agents.default]`에 `allowed = ["*"]`를 생성합니다. 처음 실행하기 편하도록 설정된 값이지 **안전한 기본 권한은 아닙니다.** 신뢰할 수 없는 에이전트를 연결하기 전에 축소하거나 삭제하세요.
:::

```sh
kp config set agents.default.allowed "db.list,db.info,unlock,status,search,lock"
kp config set agents.assistant.allowed "unlock,status,search,login,lock"
kp config set agents.assistant.allowed_hosts "github.com"
kp config validate
```

위 예시는 `assistant` 에이전트가 `github.com` 계열 사이트에서만 로그인하도록 제한합니다. 더 엄격히 제한하려면 `allowed_entries`로 특정 계정을 지정하세요.

## 2. 에이전트가 사용할 계정 지정하기

| 설정 | 의미 | 예시 |
| --- | --- | --- |
| `allowed` | 에이전트가 실행할 수 있는 작업 | `search`, `login`, `status` |
| `require_approval` | 지원되는 브라우저 승인 절차가 필요한 작업 | `entry.add` |
| `allowed_entries` | 사용 가능한 계정 ID·제목·사이트 패턴 | `uuid:AB12CD34` |
| `denied_entries` | 명시적으로 차단할 계정. 허용보다 우선 | `*prod*` |
| `allowed_hosts` | 로그인 워커가 접근할 수 있는 사이트 | `github.com` |

`config.toml`에서 `assistant` 에이전트를 제한하는 예시는 다음과 같습니다.

```toml
[agents.assistant]
allowed = ["search", "status", "unlock", "login", "lock"]
allowed_entries = ["github.com"]
allowed_hosts = ["github.com"]
denied_entries = ["*prod*"]
```

::: warning 에이전트 이름만으로 신원을 증명할 수는 없습니다
`--agent assistant`나 `KEEPASS_AGENT_ID=assistant`는 사용할 정책을 선택하지만, **Standard Mode는 실제 호출 프로세스를 인증하지 않습니다.** 보안 경계는 에이전트 이름이 아니라 OS 계정 및 파일 권한 등으로 강제해야 합니다. [보안 모델](/ko/security)을 참고하세요.
:::

## 3. 자주 변경하는 기타 설정

| 설정 영역 | 역할 | 변경하는 경우 |
| --- | --- | --- |
| `[keepass]` | KeePass/KPScript 경로, 기본 저장소 | Windows 설치 |
| `[databases.<alias>]` | KDBX 파일 경로, 키 파일, 세션 유지시간 | 저장소 연결 |
| `[unlock]` | 브라우저 승인 페이지 주소·포트 | 로컬 승인 환경 조정 |
| `[cdp]` | 브라우저 연결 주소·격리 옵션 | 웹사이트 로그인 |
| `[mcp]` / `[mcp.clients.*]` | MCP 클라이언트와 에이전트 이름 연결 | 클라이언트 여러 개 사용 |
| `[hardened]` | 별도 서비스와 IPC 격리 | 관리자용 Hardened Mode |
| `[policy]` | 감사 기록 보관 크기 | 기록 관리 |

`hardened.*`, `cdp.*`, `mcp.*` 등은 **운영자 전용 설정**이므로 `kp config set`으로 변경할 수 없습니다. 신뢰할 수 있는 운영자 계정에서 설정 파일을 직접 편집하세요.

::: details 고급 설정: 설정 파일 예시
아래는 설정 파일의 **구조를 설명하는 예시**입니다. 운영 환경에 그대로 붙여 넣지 말고 경로·계정·사이트를 환경에 맞게 수정하세요.

```toml
schema_version = 1

[keepass]
default_database = "personal"
executable = "C:/Program Files/KeePass Password Safe 2/KeePass.exe"
kpscript = "C:/path/to/KPScript.exe"

[databases.personal]
path = "C:/path/to/personal.kdbx"
session_timeout = 900
unlock_method = "local-web"

[unlock]
host = "127.0.0.1"
port = 8765
auto_open_browser = true

[cdp]
endpoint = "http://127.0.0.1:9222"
allow_default_context = false

[mcp]
agent = "assistant"

[agents.assistant]
allowed = ["unlock", "status", "search", "login", "lock"]
allowed_entries = ["github.com"]
allowed_hosts = ["github.com"]

[policy]
audit_max_bytes = 1048576

[hardened]
enabled = false
```

Hardened Mode에는 OS별 계정, IPC, ACL 설정이 추가로 필요합니다. 보통 `tools/setup-hardened.sh` 또는 `tools/setup-hardened.ps1`에서 작성합니다. `enabled`만 바꿔 활성화하지 마세요. [운영 가이드](/ko/operations)를 참고하세요.

이전 설정에 `transport` 옵션이 남아 있어도 로컬 승인 페이지는 암호화된 POST 요청만 사용합니다.
:::

## 4. 감사 기록과 설정 업데이트

- `kp audit --limit 20`: 허용된 최근 사용 기록 확인
- `kp config migrate`: `schema_version`에 따른 설정 파일 업데이트
- `kp doctor`: 권한·파일 경로·설정 오류 확인

감사 기록에는 작업·정책 판단·결과 코드가 남고, 비밀번호나 쿠키 원문은 기록하지 않도록 설계돼 있습니다. 파일은 `~/.config/keepass-agent/audit.log`에 저장되며, `policy.audit_max_bytes`(기본 1MiB)에 따라 순환 보관됩니다.

::: danger 관리 화면 권한 주의
에이전트에 `ui` 권한을 주면 운영자 수준의 관리 기능에 접근할 수 있습니다. 설정을 맡겨도 되는 신뢰된 주체에게만 허용하세요. 선언된 에이전트는 관리 API를 통해 `ui.agents.write` 권한을 사용할 수 없습니다.
:::

문제가 발생하면 [문제 해결](/ko/troubleshooting)을, Hardened Mode를 사용하려면 [보안 모델](/ko/security)을 확인하세요.
