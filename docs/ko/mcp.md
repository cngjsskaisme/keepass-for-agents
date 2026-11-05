---
title: AI 에이전트 연결 (MCP)
description: MCP 클라이언트를 연결하고 에이전트별 접근 권한을 설정합니다.
---

# AI 에이전트 연결 (MCP)

MCP를 사용하면 AI 에이전트가 저장된 계정을 검색하거나 승인된 로그인 작업을 요청할 수 있습니다. **비밀번호를 직접 가져오는 도구는 제공하지 않습니다.**

::: tip 먼저 확인하세요
[빠른 시작](/ko/quickstart)에서 KeePass 저장소를 연결하고 `doctor` 오류를 해결한 뒤 진행하세요.
:::

## 1. 에이전트 권한 설정하기

프로젝트 폴더에서 다음 명령을 실행합니다.

```sh
node src/cli/kp.ts config set agents.assistant.allowed "status,search,unlock,login,lock"
node src/cli/kp.ts config set agents.assistant.allowed_hosts "github.com"
node src/cli/kp.ts config validate
```

`assistant`는 예시 에이전트 이름이고, `github.com`은 예시 접속 사이트입니다. 실제 사용할 이름과 사이트로 바꾸세요. 중요한 계정은 [접근 권한 설정](/ko/configuration)의 `allowed_entries`로도 제한하세요.

::: warning 에이전트 이름만으로 신원을 확인하지는 않습니다
Agent ID는 호출자가 **직접 선언하는 값**입니다. Standard Mode는 해당 이름을 사용하는 OS 프로세스를 인증하지 못합니다. AI 클라이언트를 연결하기 전에 초기 설정의 `agents.default.allowed = ["*"]` 권한도 반드시 줄이세요.
:::

## 2. MCP 서버 등록하기

사용하는 AI 클라이언트의 MCP 설정 화면이나 파일에 로컬 서버를 등록하세요. 설정 위치는 클라이언트마다 다릅니다. 아래는 **일반적인 stdio MCP 예시**이며 모든 클라이언트에 그대로 적용되는 설정 파일은 아닙니다.

```json
{
  "mcpServers": {
    "keepass-agent": {
      "command": "node",
      "args": ["/absolute/path/to/nougat-worker/src/mcp/server.ts"],
      "env": {
        "KEEPASS_AGENT_ID": "assistant"
      }
    }
  }
}
```

스크립트 경로를 컴퓨터의 **실제 절대 경로**로 바꾸세요. Windows JSON 경로에서는 `/`를 사용하거나 역슬래시를 이스케이프해야 합니다. Node.js 22.18 이상(또는 23.6 이상)이 필요합니다.

MCP 설정에 KeePass 마스터 비밀번호나 API Key를 적지 마세요.

## 3. 연결 확인하기

MCP 클라이언트를 다시 실행하거나 설정을 새로고침한 뒤 다음 순서로 확인합니다.

1. 도구 목록에 `keepass-agent`가 표시되는지 확인합니다.
2. `session_status`로 연결된 저장소의 상태를 조회합니다.
3. 잠겨 있다면 `request_unlock`으로 승인 URL을 받고, **직접 로컬 승인 페이지에서 잠금 해제**합니다.
4. `search_entries`로 저장된 계정 정보를 검색합니다.

도구가 보이지 않는다면 절대 경로, Node.js 버전, 클라이언트의 stdio 로그를 확인하세요.

## 4. 제공되는 도구

| 도구 | 역할 |
| --- | --- |
| `session_status` | KeePass 저장소 잠금 상태 확인 |
| `request_unlock` | 로컬 브라우저 승인 페이지 요청 |
| `search_entries` | 계정 메타데이터 검색(비밀번호 미포함) |
| `request_login` | 허용된 로그인 워커 실행 |
| `logout`, `revoke_session` | 잠금 해제된 세션 종료 |
| `audit_tail` | 권한이 있을 때 감사 기록 조회 |

::: info 웹사이트 로그인은 추가 설정이 필요합니다
지원되는 사이트에 로그인하려면 `playwright` 워커용 로컬 CDP 브라우저 설정이 필요합니다. 이름과 달리 Playwright npm 패키지가 아니라 Chrome DevTools Protocol을 사용합니다. [CLI: 인증과 로그인](/ko/cli#인증과-로그인)과 [보안 모델](/ko/security)을 확인하세요.
:::

`POLICY_DENIED`, `HARDENED_SERVICE_UNAVAILABLE` 등의 오류는 [문제 해결](/ko/troubleshooting)을 참고하세요.
