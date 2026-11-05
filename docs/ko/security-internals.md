---
title: 보안 구현 상세
description: IPC, 파일 접근 권한, 로그인 워커, 감사 기능의 상세 설계입니다.
---

::: tip 먼저 읽을 문서
일반 사용자라면 [보안과 한계](/ko/security)부터 확인하세요. 이 문서는 구현을 검토하는 개발자·보안 담당자를 위해 자세한 설명을 보존한 자료입니다.
:::

# 보안 모델

## Hardened Mode (Credential Service 격리, opt-in)

Standard Mode는 `kp`를 실행하는 OS 주체를 신뢰합니다. Hardened Mode는
자격증명을 건드리는 모든 작업을 **별도 OS 주체** — Credential Service
(`src/service/`) — 로 옮깁니다. `kp`는 이 작업들에 대해 얇은 IPC
클라이언트가 되며, 동일 UID 프로세스(에이전트 포함)는 더 이상 세션 파일,
서비스 메모리, 또는 — KeePass 저장소 ACL이 적용된 경우 — KDBX 자체를 읽을 수
없습니다. `hardened.enabled=true`로 opt-in하며 **fail-closed**입니다:
서비스 다운, IPC 인증 실패, 격리 검사 미충족은 명시적 `HARDENED_*`
에러 — 조용한 Standard Mode 폴백이 아닙니다.

### 주체 모델

세 가지 역할, 각각 별도 OS 계정으로 프로비저닝:

- **Operator** — 사람. config.toml 소유, KeePass GUI 실행, `db sync` 수행
  (KDBX 읽기 권한 필요), 브라우저에서 unlock 승인.
- **Agent** — 신뢰되지 않는 호출자. IPC로 작업을 *요청*만 할 수 있음;
  메타데이터와 정제된 워커 결과만 받고 시크릿 자재는 절대 받지 않음.
- **Service** — 전용 계정의 `node src/service/service.ts`. 세션 소유
  (자체 `SESSION_DIR` + DPAPI CurrentUser/localCrypt 스코프), 마스터 키
  검증, KDBX 읽기, 워커 spawn을 직접 수행.

### IPC (인증됨, 인증정보를 전달하지 않는)

- 전송: POSIX unix 소켓 (`chmod 0660` — Linux는 connect 시 쓰기 권한을
  강제; 그룹 = 에이전트 그룹) 또는 Windows 네임드 파이프
  (`\\.\pipe\keepass-agent-svc`).
- 인증: 서비스가 토큰 파일에 쓰는 256비트 **capability 토큰**; 호출자는
  HMAC-SHA256(token, server-nonce)로 소유를 증명. 토큰 파일의 파일시스템
  ACL (POSIX ≤0640 / NTFS 제한)이 곧 호출자 인가 경계 — Node는 네임드
  파이프 DACL을 설정할 수 없으므로 Windows에서는 토큰 읽기가 커널 강제
  검사입니다.
- 선택적 POSIX peer 검증 (`hardened.peer_verify`): `strict` 모드는
  procfs+`ss -xp`로 접속 peer의 uid를 해석하고 `hardened.allowed_uids`에
  있어야 합니다 (strict + 빈 목록이면 서비스 기동 거부). 순수 Node에는
  SO_PEERCRED가 없음 — 네이티브 peer-credential 애드온이 문서화된 향후
  연동 지점입니다.
- Windows 파일 ACL 검사는 deny-list가 아닌 **허용 목록**: 토큰 파일과 각
  KDBX에 부여된 모든 주체가 `hardened.allowed_sids`에 있어야 합니다
  (icacls 표시 형식 또는 raw sid). 미설정 → 검사 fail-closed
  (`allowed_sids_unconfigured`); 어떤 외부 주체든 — `INTERACTIVE`,
  `NETWORK`, 앱 컨테이너 sid 등 — `HARDENED_ACL_UNMET`.
- JSON-lines 프로토콜; 어떤 op도 시크릿을 반환하지 않습니다. `login`은
  서비스가 엔드투엔드로 실행 (엔트리 해석 → 정책 재검사 → 워커 spawn →
  시크릿 파이프 → 결과 정제); 와이어를 지나는 것은
  `{ok,status|code,detail}`뿐입니다.
- 서비스는 선언된 에이전트 id에 대해 모든 op에서 **정책을 재평가**하고
  자체 (에이전트 읽기 불가) 감사 로그에 기록 — CLI를 우회해도 두 레이어
  모두 건너뛸 수 없습니다. 승인 op는 추가로 **파싱 후 제출 게이트**
  (`makeSubmissionGate`)를 실행: `evaluate()`가 *제출된* 값 (엔트리
  url/title, 쿠키 domain/uuid, unlock db)에 대해 재검사되고 최종
  페이로드가 승인된 요청과 일치해야 합니다 — prefill/target 드리프트 →
  `POLICY_DENIED` (페이지에 403, 토큰은 유지).

### 격리 검사 (fail-closed 게이트)

서비스 라우팅 명령 전에 클라이언트가 검증:

- 토큰 파일이 존재하고 other 접근 권한이 없음
  (아니면 `HARDENED_ACL_UNMET`)
- 접촉하는 모든 KDBX에 'other' 비트가 없음 (POSIX) 또는 허용 목록 NTFS
  주체만 있음 (`hardened.allowed_sids` via `icacls`)
- `hardened.service_uid` (POSIX, 선택): KDBX 소유자 uid가 이와 같아야 함 —
  에이전트가 KeePass 저장소를 소유하지 않음을 증명

서비스는 추가로 기동 시 자체 소켓 디렉터리 (POSIX 0750 pre-bind), 토큰
파일, 세션 디렉터리를 자가 검사하고 실패 시 종료합니다
(`KEEPASS_AGENT_SERVICE_SELFTEST` 테스트 훅으로만 건너뛸 수 있음 —
stderr 경고 출력).

모드 전환은 운영자 전용: `kp config set hardened.*`는
`CONFIG_KEY_READONLY`로 거부 (감사 기록) — 동일 UID 호출자가
`config set`으로 hardened mode를 벗어날 수 없습니다. `hardened.enabled`는
config.toml 직접 편집으로만 전환됩니다 (변경 통제 = OS 파일 권한, 정책과
동일).

### Hardened Mode에서도 에이전트 프로세스를 지나는 것

시크릿은 없습니다. 웹 승인 플로우는 서비스 **내부**에서 실행됩니다
(브라우저가 마스터 키를 서비스의 루프백 서버에 직접 POST); CLI는 승인
URL을 사용자 브라우저로 전달만 합니다. `db sync`는 *암호화된* KDBX
파일만 이동 — 로컬에 머물며 읽기 권한이 있는 모든 주체에서 동작하고,
권한 없는 에이전트는 `HARDENED_KDBX_ACCESS_DENIED`를 받습니다.

### 구조적 한계 (문서화됨, 주장하지 않음)

- **승인은 사람 증명이 아님.** 승인 URL은 루프백 GET — URL을 볼 수 있는
  모든 로컬 주체 (동일 UID 에이전트 포함)가 페이지를 가져와 폼을 기계적으로
  완료할 수 있습니다. 승인은 *토큰 TTL 안에 어떤 로컬 주체가 동의했다*는
  것이지 반드시 사람임을 증명하지 않습니다. 이 한계는 Standard Mode에서
  상속됩니다. 후속 권고: 사람 전용 채널 (PIN 판독, OS 네이티브 동의
  다이얼로그, 또는 제2 채널 확인)로 승인이 프로세스가 아닌 사람을 증명하게.
- **시도 소진 사보타주.** 토큰 보유자가 5회 시도 cap을 소진해 대기 중인
  승인을 무효화할 수 있습니다 (유출이 아닌 DoS) — Standard Mode도 동일;
  토큰의 짧은 TTL이 창구를 제한합니다.
- unlock/승인 서버는 `cfg.unlock.port`를 먼저 시도하고 EADDRINUSE 시
  **에페메랄 포트**로 폴백하여 동시 승인이 충돌하거나 스쿼터에게 점유되지
  않게 합니다; 제공되는 URL은 항상 실제 바인드된 포트를 전달합니다.

## MCP 어댑터 (`src/mcp/`)

MCP 서버 (`kp mcp` / `node src/mcp/server.ts`)는 동일 게이트웨이로의 두
번째 전송 경로 — stdio 위 JSON-RPC 2.0, Node 내장만 사용.

- **stdout은 프로토콜 전용.** 모든 줄이 JSON-RPC 프레임; 진단은 전부
  stderr로.
- **구조적으로 인증정보를 전달하지 않는 표면.** 노출된 도구
  (`search_entries`/`request_unlock`/`session_status`/`request_login`/
  `logout`/`revoke_session`/`audit_tail`)는 메타데이터·상태 수준 API만
  호출: `listEntries` (메타데이터만), `pipeSecretToWorker` (정제된 워커
  결과), 웹 승인 채널 (URL만), hardened IPC (설계상 인증정보를 전달하지 않는). 응답
  스키마는 CLI JSON 계열을 따릅니다 — `password`/`secret`/`cookie`/
  `master` 필드는 구조적으로 부재; 테스트가 도구별로 이를 단언합니다.
- **동일 정책 모델.** 각 `tools/call`은 정규 CLI 액션 이름
  (`search`/`unlock`/`status`/`login`/`lock`/`audit.read`) 아래
  deny-by-default로 `evaluate()`됩니다 — `request_login`의 phase-2
  엔트리/호스트 재검사와 파이프 경계의 broker 측 `policyGate` 재평가
  포함. 모든 호출이 `mcp.<tool>` 액션으로 정확히 하나의 감사 레코드를 씁니다.
- **선언된 신원.** 세션의 에이전트 id는 `initialize`에서 해석:
  `params.agent` → `[mcp.clients.<clientInfo.name>]` → `kp mcp --agent` /
  `KEEPASS_AGENT_ID` → `mcp.agent` → `default`. `--agent`와 동일한
  자기 선언 (인증 아님) 모델; 무효 id는 initialize 실패. MCP 클라이언트를
  자체 최소권한 에이전트 id로 스코핑하는 것은 `[mcp.clients.*]` 매핑으로
  합니다.
- **`request_unlock`은 마스터 키를 수집하지 않음.** 일회용 승인 URL
  (`awaiting_user_input`)을 반환하고 사람이 루프백 웹 플로우를 완료합니다.
  `local-web` 외의 `unlock_method`는 거부 — KeePass GUI 실행은 MCP 표면
  밖입니다. 어댑터가 수행하는 유일한 외부 동작은 선택적 브라우저 자동
  열기 (`unlock.auto_open_browser`)로 CLI와 동일합니다.
- **Hardened Mode 지원.** `hardened.enabled` 하에서 도구는 Credential
  Service를 경유합니다 (agent → MCP → service) — 동일한 pre-flight ACL
  게이트와 `HARDENED_*` fail-closed 코드, standard-mode 폴백 없음.
  서비스는 추가로 서비스 측에서 정책을 재검사하므로 수작업 MCP
  클라이언트도 게이트를 건너뛸 수 없습니다.
- `initialize` 전 요청은 거부 (-32002); 깨진 JSON, 비객체 메시지, 배치,
  알 수 없는 메서드/도구는 표준 JSON-RPC 에러; notification은 응답을
  만들지 않습니다.
- 디스패치는 세션당 순차 — 자격증명 게이트웨이에 동시 변경은 필요 없고,
  직렬화가 감사 순서를 정확하게 유지합니다.

## 구현됨 (Standard Mode)
- 비밀번호는 argv/env/TOML/stdout에 절대 없음 — stdin 전용 (KPScript & 워커)
- 마스터 키는 DPAPI 암호화로만 지속 (CurrentUser), DB별 TTL
- KPScript 출력 검증 (진단/다중줄/초과 크기 거부); 원문은 절대 로깅 안 함
- 워커 허용 목록 — 임의 실행 파일 불가
- 워커 egress 정책 — 시크릿이 파이프되기 전 broker가 엔트리 URL을 검증: `https:` 임의 호스트, `http:` 루프백만, 그 외 WORKER_URL_REJECTED. `entry add`는 다른 URL도 저장하되 `warning`으로 보고 (인트라넷 http 호환).
- 리다이렉트 계약 — 워커는 자격증명이 실린 요청에서 리다이렉트를 따라가면 안 됨; `local-test`는 `redirect:'manual'`로 REDIRECT_REJECTED.
- browser-login (`playwright`) 워커 리다이렉트 계약 — 자격증명은 `location.origin === origin(entry.url)`일 때만 타이핑: 네비게이션 후 오리진 드리프트 (settle 폴링), 모든 크로스오리진 제출 목적지 (모든 제출자의 유효 타깃: IDL *form owner* action — `form=` 속성 재연결 포함 — + `formaction` 오버라이드, 전부 `document.baseURI` 기준 해석이라 `<base href>`가 실제 POST를 다른 곳으로 못 돌림; click/requestSubmit 시점에 인페이지 재검사), fill/submit 시점 인페이지 오리진 가드 — 모두 시크릿 입력 전 REDIRECT_REJECTED. 엔트리 오리진을 벗어나는 SSO/OAuth 체인은 문서화된 정책 한계 (허용 도메인 목록은 후속).
- browser-login 엔드포인트 출처 — CDP 엔드포인트는 KeePass 저장소 시크릿이 타이핑되는 곳이므로 운영자 관리: config.toml의 `cdp.endpoint` (루프백 검증; 기본 `http://127.0.0.1:9222`)가 broker stdin으로 워커에 전달. `login --cdp` 플래그는 없음 (에이전트가 고른 엔드포인트는 적대적 소켓의 자격증명 싱크 → INVALID_CONFIG). `KEEPASS_AGENT_CDP_ENDPOINT`는 테스트 훅으로만 잔존 — 엔드포인트를 제공하면 `kp login`과 워커가 각각 일회성 stderr 경고. `sync-cookies`/`login-capture`는 `--cdp` 플래그 유지 (쿠키 수집은 웹 승인 플로우 뒤에서 실행되고 타이핑된 자격증명을 보내지 않음).
- browser-login 워커 격리 — 로그인은 CDP 격리 브라우저 컨텍스트에서 실행 (`Target.createBrowserContext`, fail-closed — `--no-isolate`가 아니면 사용자 기본 프로필 절대 아님; `--no-isolate`도 전용 프로필 인스턴스에 한해 운영자 opt-in `cdp.allow_default_context=true` 필요). 성공은 `authenticated_via:<url_change|marker|cookie>`로 증명 — url_change/marker는 사이트가 조작 가능한 약한 휴리스틱 (실패 페이지가 위조 가능); `cookie` — 엔트리 오리진의 새 HttpOnly 쿠키 — 만이 강한 서버측 증거이고 기존 쿠키 저장소만으로는 WORKER_OUTCOME_UNCERTAIN으로 강등. MFA 탐지는 `mfaWaitMs` 안에서 폴링하며 페이지를 열어두고 (비밀번호 필드는 먼저 비움) 사용자 완료를 기다리고, 아니면 WORKER_MFA_REQUIRED — 명시적 재실행이 재시도 계약. 재시도 정책: 전송 오류 (nav/CDP/connect, `conn.call` 30초 cap)는 1회 재시도; CREDENTIALS_REJECTED/REDIRECT_REJECTED/NO_LOGIN_FORM/MFA_REQUIRED는 절대 재시도 안 함. 라이브 컨텍스트가 세션 핸들 — KDBX 엔트리로의 쿠키 영속화는 전용 프로필/기본 컨텍스트 세션에서 login-capture 계약 (`entry sync-cookies`, 웹 승인 + `updateEntryFields`)을 재사용; 격리 컨텍스트 영속화는 문서화된 갭. 세션 만료 탐지 (저장된 세션의 재로그인 필요 시점)는 후속.
- 워커 출력 화이트리스트 + 리덕션 — 결과는 `{success,status}` 또는 `{success:false,code,detail}`이어야 함; 알 수 없는 필드 폐기; 워커가 낸 코드는 알려진 집합 또는 `WORKER_*` 네임스페이스로 제한 (시스템/broker 코드 위조 불가 → WORKER_OUTPUT_INVALID); `detail`은 200자 cap + 제어문자 제거 + 절대 경로 축약; 워커 stdout/stderr와 파싱된 code/detail/status에서 파이프된 비밀번호/사용자명 발생은 `[redacted]`로 치환, JSON 파싱 전후 모두 적용 (JSON 이스케이프된 에코 포함). 매칭은 대소문자 무관하며 시크릿 문자 사이 삽입 공백을 허용 — **리덕션은 직접 에코와 단순 변형에 대한 최선 노력 백스톱이며 인코딩 수준 변형 (base64, NFC/NFD, URL 인코딩)은 탐지하지 못함** — 따라서 워커는 시크릿을 절대 에코해서는 안 됩니다.
- 워커 타임아웃은 프로세스 트리 전체를 kill — Windows는 taskkill /T /F + child.kill 폴백, POSIX는 detached 프로세스 그룹 SIGKILL; 레지스트리의 워커별 `timeoutMs` (기본 60초).
- 시크릿 입력 문자 집합 — 마스터 키나 엔트리 비밀번호의 CR/LF는 폼 경계 (INVALID_SECRET_CHARS)와 `keyStdin`에서 거부; 비CP949 엔트리 비밀번호는 `entry add`에서 경고 (Windows KPScript가 stdout을 CP949로 디코딩).
- Unlock UI: 루프백 바인드, Host+Origin 검사, 일회용 토큰 (10분), 5회 시도 cap (토큰 무효화), 암호화 페이로드만 (`p` 필수 — 평문 자격증명 필드 없음, POST만), no-store
- 관리 UI (`kp ui`): 동일 전송 모델 — 랜덤 포트 루프백 바인드, Host+Origin 검사, no-store, CSP. 실행당 토큰 두 개: **일회용 페이지 토큰**은 실행 URL (`/?t=`)로 전달되어 첫 페이지 서빙 시 소비 — 이 URL은 브라우저 spawn **argv**를 지나므로 동일 UID 프로세스가 잠시 읽을 수 있지만, 공격자가 재생할 시점에는 그 토큰은 이미 무용; 실제 세션 자격증명은 별도 **apiToken**으로 제공된 페이지에만 임베드되고 모든 `/api` 호출에 `x-kp-ui-token`으로 필요 (없으면 401). apiToken을 실은 `SameSite=Strict` `HttpOnly` 쿠키가 같은 브라우저 리로드에서 URL 토큰 없이 페이지 재서빙을 허용 (변경은 여전히 헤더 필요 — 쿠키/JS만으로는 부족). 토큰은 stdout/stderr에 절대 출력되지 않음 — 브라우저를 열 수 없을 때 (`--no-open`/`unlock.auto_open_browser=false`) 또는 명시적 `--print-url`에서만, 항상 경고와 함께. 변경은 POST + `application/json`만 (커스텀 헤더 요구가 크로스오리진 폼 CSRF도 차단). 시크릿은 지나지 않음: unlock은 기존 일회용 토큰 승인 플로우에 위임 — API는 승인 URL만 반환. 신원: `x-kp-agent`가 에이전트를 선언 → 요청은 `ui.*` 액션 네임스페이스 아래 deny-by-default로 평가; 없으면 예약된 `operator` 신원으로 `[agents.*]`를 우회 (`[agents.operator]` 구성 시 제외 — 콘솔 보유자는 이미 게이트된 `kp ui`를 실행했고 config.toml을 소유). `ui.agents.write`는 **운영자 전용** — 선언된 에이전트는 권한과 무관하게 API로 정책을 쓸 수 없음. **에이전트에게 `ui` (또는 `ui.agents.write`) 부여는 운영자 동급**: `kp ui`는 정책 자기 확장에 쓸 수 있는 토큰을 발행 — 이 액션은 config.toml 자체를 신뢰할 주체에게만 부여하세요. 모든 호출이 `ui.*` 감사 레코드 하나를 씀. 동시 승인 제한 (3개 초과 시 UNLOCK_BUSY). Hardened mode는 세션/감사/lock/unlock을 선언된 (또는 실행한) 신원으로 인증된 서비스 IPC로 라우팅 — 서비스가 op별 정책 재평가 — 그리고 인프로세스 폴백 없이 `HARDENED_*` 코드로 fail-closed
- 쿠키는 인증급 시크릿 — `entry sync-cookies`와 `entry login-capture` 모두 명시적 웹 승인 필요 (일회용 토큰, 동일 cookies-mode 폼); 직접 CLI 수집 경로 없음
- CDP 엔드포인트는 루프백 전용 — `--cdp`와 서버측 쿠키 경로 모두 127.0.0.1/localhost/[::1] 강제 (CDP_ENDPOINT_REJECTED); 원격 디버그 소켓은 쿠키 수확/주입 가능
- 쿠키 도메인 매칭은 dot-boundary만 — `github.com` ↔ `*.github.com`; 접미사 유사도메인 (`mygithub.com`, `github.com.evil.net`)은 절대 불일치
- `db sync`는 원격 명령을 순수 argv로 구성 (`sprite exec -- md5sum|stat|base64 <path>`) — `sh -c` 문자열을 절대 만들지 않음; `--sprite`/`--remote`는 추가로 메타문자 없는 문자 집합으로 검증 (INVALID_SPRITE/INVALID_REMOTE_PATH). pull은 로컬 KDBX를 원자적으로 교체: tmp 스테이징 → md5 검증 → `.bak` 백업 → 같은 디렉터리 rename; rename 전 실패는 원본 보존
- `tools/relay-unlock.mjs`는 순수 프록시 — 원격 unlock 페이지를 verbatim으로 서빙 (원격 RSA 키 임베드)하고 POST 바디를 `sprite exec curl`로 바이트 그대로 전달; 릴레이는 평문 비밀번호를 절대 보지 않음. 루프백 Host/Origin 검사, 릴레이 소유 토큰 강제 (외부 토큰은 업스트림 도달 불가), 64KB 바디 cap, no-store, 원격 채널 불가 시 fail-closed
- `tools/deploy-sprite.sh`는 운영자 전용 스크립트 — sprite 이름과 원격 디렉터리는 원격 `sh -c` 보간 전 메타문자 없는 문자 집합으로 검증되고 모든 변수는 인용됨
- 정책 엔진 — 모든 `kp` 명령 (`config`/`help`/`doctor`/`mcp` 제외 — 읽기 전용 진단과 MCP 어댑터 실행; 각 MCP 도구 호출은 여전히 평가됨)은 config.toml의 `[agents.<id>]`/`[policy]`에 대해 **deny-by-default**로 평가: 미등록 액션 → `POLICY_DENIED`; `require_approval` 액션은 기존 일회용 토큰 웹 승인 플로우 (`unlock`/`entry.add`/`entry.sync-cookies`/`entry.login-capture`/`db.create`)를 통해서만 진행, 아니면 `POLICY_APPROVAL_REQUIRED`. 엔트리 범위는 `allowed_entries`/`denied_entries` (제목/호스트 글롭 또는 `uuid:`; `search` 결과는 필터링, 단일 엔트리 액션은 거부); 워커 목적지는 `allowed_hosts` (dot-boundary 또는 글롭). `pipeSecretToWorker`는 파이프 경계에서 재평가 (`policyGate`)하므로 거부된 시크릿은 워커에 도달하지 않음
- 에이전트 신원은 **선언이며 인증 아님** — `--agent`/`KEEPASS_AGENT_ID`, 문자 집합 강제, 폴백 `default`. 정책과 감사 귀속 스코핑에만 사용; 동일 UID 호출자는 임의 id를 주장 가능 (Hardened Mode의 관심사)
- 감사 로그 — `~/.config/keepass-agent/audit.log`, 추가 전용 JSONL `{ts, agent, action, target, decision, result_code, db}`, POSIX 0600, `policy.audit_max_bytes` (기본 1 MiB)에서 `.1`로 로테이션. 레코드 스키마는 고정 화이트리스트 — 시크릿/비밀번호/쿠키 값은 구조적으로 배제. `config set` 쓰기도 감사; 정책 파일 편집 권한은 OS 파일 권한에 의존
- spawn argv 배열 — 셸 문자열 없음

## 미구현 (명시적)
- 커널 수준 peer 자격증명 (SO_PEERCRED /
  GetNamedPipeClientProcessId)은 네이티브 애드온 필요 — `peer.ts` 연동 지점 +
  `hardened.peer_verify` 노브가 순수 Node 부분집합을 커버. (OS 계정 생성,
  ACL 적용, 자동 시작은 `tools/setup-hardened.{sh,ps1}`로 프로비저닝 —
  운영자 실행, 계획 → 확인 → 적용; docs/operations.md 참조.)
- 평문 제로 메모리 보장 — GC 런타임; 세션 파일이 신뢰 앵커.

## 위협 노트
동일 UID 에이전트는 KDBX/세션 파일을 읽을 수 있음 — Standard Mode는
출력 위생만 보장하고 물리적 시크릿 격리는 보장하지 않습니다.
동일 UID 프로세스는 또한 임의의 `--agent`/`KEEPASS_AGENT_ID`를 주장하고
config.toml을 직접 편집할 수 있음 — 정책 엔진은 *선언된* 신원을 제약하며
문서화된 플로우 어느 것으로도 우회되지 않지만 (deny-by-default, broker
측 재검사), 의도적으로 신원을 위조하는 프로세스에 대한 경계는 아닙니다.
그 분리가 Hardened Mode입니다.
