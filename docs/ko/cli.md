---
title: CLI 명령어
description: 작업별로 명령어와 사용 예시를 빠르게 찾을 수 있습니다.
---

# CLI 명령어

`kp` 명령으로 KeePass 저장소, 로그인 세션, AI 에이전트 요청을 관리합니다. 명령 결과는 자동화 도구에서 읽기 쉬운 **JSON** 형식으로 반환됩니다.

::: tip 처음 사용한다면
[빠른 시작](/ko/quickstart)에서 KDBX 파일을 연결한 후 아래 명령을 사용하세요.
:::

## 자주 사용하는 명령

| 하고 싶은 일 | 명령 |
| --- | --- |
| 설치 환경 확인 | `kp doctor` |
| 연결된 저장소 목록 | `kp db list` |
| 현재 세션 확인 | `kp status --db personal` |
| 저장소 잠금 해제 | `kp unlock --db personal` |
| 계정 검색 | `kp search --db personal --title "예시 계정"` |
| 저장소 다시 잠그기 | `kp lock --db personal` |
| 관리 화면 열기 | `kp ui` |

`kp`가 실행되지 않는다면 프로젝트 폴더에서 `node src/cli/kp.ts`를 대신 사용하세요.

## 설정과 KeePass 저장소 관리

| 명령 | 설명 |
| --- | --- |
| `kp config init` | 초기 설정 파일 생성 |
| `kp config show` / `validate` | 설정 조회 및 검사 |
| `kp config set <key> <value>` | 지원되는 설정 변경 |
| `kp config migrate` | 설정 파일 버전 업데이트 |
| `kp db add personal --path <file.kdbx>` | 기존 KeePass 저장소 연결 |
| `kp db create personal --path <file.kdbx>` | 로컬 브라우저에서 새 저장소 생성 |
| `kp db info` / `list` | 저장소 정보·목록 조회 |
| `kp db default personal` | 기본 저장소 지정 |
| `kp db remove personal` | 설정에서 저장소 등록 제거 |
| `kp db sync [--pull] [--force]` | Sprite와 KDBX 파일 동기화 |

::: warning 원격 동기화 주의
`db sync`는 로컬 KDBX 파일을 바꿀 수 있습니다. 먼저 백업하고 `--pull`/`--force`의 의미를 확인하세요. 다운로드 검증과 `.bak` 파일 보관 기능이 있으며, 자세한 내용은 [운영 가이드](/ko/operations)에 있습니다.
:::

## 인증과 로그인

```sh
kp unlock --db personal
kp search --db personal --site github.com
kp login --db personal --entry <entry-uuid> --worker playwright
kp lock --db personal
```

| 명령 | 설명 |
| --- | --- |
| `kp unlock --db <이름>` | 로컬 브라우저에서 KeePass 저장소 잠금 해제 |
| `kp search --site / --title / --username` | 계정 정보 검색(비밀번호 원문은 반환하지 않음) |
| `kp login --entry <uuid> --worker <이름>` | 허용된 워커로 로그인 실행 |
| `kp entry add [--title ...]` | 로컬 브라우저에서 새 계정 추가 |
| `kp entry login-capture ...` | 사이트를 열고 승인 후 세션 수집 |
| `kp entry sync-cookies ...` | 승인 후 브라우저 쿠키 저장 |
| `kp master change --db <이름>` | KeePass에서 마스터 비밀번호 변경 후 세션 종료 |

`playwright` 워커는 이름과 달리 Playwright npm 패키지가 아닌 **CDP(Chrome DevTools Protocol)** 를 사용합니다. 운영자가 설정한 로컬 브라우저 연결 주소(`cdp.endpoint`)가 필요하며 `login --cdp`는 지원하지 않습니다. 다른 사이트로 전송되는 로그인 폼은 차단됩니다.

::: details 로그인 관련 고급 옵션과 제약
- `--entry <uuid>`로 계정을 지정하거나 `--title`/`--site`로 검색할 수 있습니다. 검색 결과가 여러 개면 UUID를 선택하세요.
- `local-test`는 테스트용 워커이며, `playwright`는 지원되는 웹 로그인 폼용입니다.
- 기본적으로 격리된 브라우저 컨텍스트에서 로그인합니다. `--no-isolate`는 운영자의 `cdp.allow_default_context=true` 설정이 필요하고 전용 브라우저 프로필에만 권장합니다.
- `authenticated_via:url_change`나 `authenticated_via:marker`는 성공 여부를 확정하는 강한 증거가 아닙니다. 새 HttpOnly 쿠키가 확인되지 않으면 `WORKER_OUTCOME_UNCERTAIN`이 발생할 수 있습니다.
- `entry sync-cookies`와 `entry login-capture`는 일회성 브라우저 승인이 필요합니다. CDP 연결은 로컬 주소로 제한됩니다.
- 비밀번호는 워커의 표준 입력으로 전달되며 명령 응답에는 원문이 포함되지 않습니다.
:::

## 에이전트 연결과 관리

| 명령 | 설명 |
| --- | --- |
| `kp mcp` | 로컬 stdio MCP 서버 시작 |
| `kp mcp --agent assistant` | 에이전트 이름을 지정하고 MCP 서버 시작 |
| `kp audit --limit 20` | 권한이 있는 경우 최근 감사 기록 조회 |
| `kp ui` | 세션·접근 권한·감사 기록을 관리하는 로컬 화면 열기 |

설정 예제는 [AI 에이전트 연결](/ko/mcp)을 참고하세요.

::: danger 관리 권한 주의
`ui` 권한은 운영자 수준의 접근을 허용할 수 있습니다. `--agent`나 `KEEPASS_AGENT_ID`의 이름은 Standard Mode에서 **신원 인증을 거치지 않은 선언 값**입니다. [설정](/ko/configuration)과 [보안 모델](/ko/security)을 함께 확인하세요.
:::

## 자주 발생하는 오류

| 오류 코드 | 의미 | 해결 방향 |
| --- | --- | --- |
| `UNLOCK_REQUIRED` | 저장소가 잠김 | `kp unlock` 후 브라우저에서 승인 |
| `POLICY_DENIED` | 작업·계정·사이트에 대한 권한 부족 | 에이전트 권한 확인 |
| `AMBIGUOUS_ENTRY` | 여러 계정이 검색됨 | UUID로 정확히 지정 |
| `WORKER_URL_REJECTED` | 로그인 대상 주소가 허용되지 않음 | 등록된 URL과 정책 확인 |
| `WORKER_MFA_REQUIRED` | 추가 인증 필요 | 브라우저에서 MFA 완료 |
| `WORKER_OUTCOME_UNCERTAIN` | 로그인 성공 여부를 확정할 수 없음 | 실제 로그인 상태 확인 |
| `HARDENED_SERVICE_UNAVAILABLE` | Credential Service에 연결할 수 없음 | `kp doctor`로 서비스 상태 확인 |

::: details 종료 코드와 추가 오류 코드
- **종료 코드 0:** 성공
- **종료 코드 1:** 일반 실패
- **종료 코드 3:** `UNLOCK_REQUIRED`. 종료 코드 2와 4는 구현에 정의되어 있지만 현재 사용하지 않습니다.

그 밖에 `CONFIG_NOT_FOUND`, `INVALID_CONFIG`, `DATABASE_NOT_FOUND`, `AUTHENTICATION_FAILED`, `SESSION_EXPIRED`, `ENTRY_NOT_FOUND`, `ENTRY_NO_URL`, `UNSUPPORTED_WORKER`, `REDIRECT_REJECTED`, `WORKER_TIMEOUT`, `WORKER_OUTPUT_INVALID`, `CDP_ENDPOINT_REJECTED`, `SYNC_DOWNLOAD_FAILED`, `MD5_MISMATCH`, `HARDENED_ACL_UNMET`, `INTERNAL_ERROR` 등이 있습니다.

로컬 승인 페이지는 `PAYLOAD_REQUIRED`, `DECRYPT_FAILED`, `MAX_ATTEMPTS_EXCEEDED`, `INVALID_SECRET_CHARS`를 반환할 수 있습니다. 이 값들은 CLI 종료 코드가 아니라 HTTP 응답 코드입니다.

해결 방법은 [문제 해결](/ko/troubleshooting)을 참고하세요.
:::
