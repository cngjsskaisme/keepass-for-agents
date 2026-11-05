---
title: 아키텍처 구현 상세
description: 모듈 구성, 내부 호출 경로, IPC와 동기화 흐름을 설명합니다.
---

::: tip 처음 보시나요?
[아키텍처 개요](/ko/architecture)에서 전체 흐름을 먼저 확인하세요. 이 페이지는 개발자용 모듈·호출 경로 참고자료입니다.
:::

# 아키텍처

```
AI Agent → bin/kp (bash) → src/cli/kp.ts → modules
  config/     TOML 로드·검증·원자 저장 (~/.config/keepass-agent/config.toml)
  database/   KDBX 레지스트리 (add/remove/default/info) — config 부기만
  provider/   CredentialProvider 연동 지점 — 하나의 계약, 두 백엔드:
                provider.ts    인터페이스 + createProvider(kpscript) 팩터리
                               (win32 → kpscript, 그 외 → pykeepass) + 에러
                               코드 네임스페이스 (고정 — CLI가 코드를 그대로 출력)
                kpscript.ts    KPScript 백엔드: verifyKey/listEntries/getSecret;
                               쓰기 작업은 PyKeePass 백엔드에서 상속
                pykeepass.ts   PyKeePass 백엔드: 모든 작업이 keepass/*.py 경유
                               (stdin JSON → stdout JSON, 헬퍼 stderr 폐기)
  master-key/ DB별 세션 상태 (LOCKED/UNLOCKED/EXPIRED) — provider로 verifyKey
  security/   DPAPI 세션 저장소 (CurrentUser 스코프, PowerShell stdin)
  keepass/    KPScript 러너 — argv spawn, stdin 키, 출력 검증
              + PyKeePass 헬퍼 스크립트 (*.py) — KPScript 없는 경로
  broker/     listEntries·searchEntries·pipeSecretToWorker (stdin 전용 시크릿,
              KDBX 접근은 provider 경유; 선택적 policyGate 재검사)
  policy/     engine.ts  선언된 에이전트 신원 (--agent/KEEPASS_AGENT_ID),
                         deny-by-default evaluate(agent, action, target),
                         엔트리/호스트 제한, 승인 가능 액션 라우팅
              audit.ts   추가 전용 JSONL audit.log (스키마 화이트리스트,
                         mode 600, 크기 로테이션)
  mcp/          MCP 어댑터 — stdio 위 JSON-RPC 서버 (server.ts:
                핸드셰이크 시대 리비전, initialize/ping/tools.list/
                tools.call, 순차 디스패치, stdout 프로토콜 전용)
                + tools.ts (도구 정의 → CLI가 쓰는 동일 모듈;
                호출당 정규 액션으로 evaluate(), 호출마다 `mcp.<tool>`로
                감사 레코드 하나, hardened IPC 라우팅)
  unlock-server/ 루프백 웹 UI, 일회용 토큰, CSRF/host/origin 검사
  worker/     허용 목록 레지스트리 + local-test 워커 (워커별 timeoutMs)
              + playwright/browser-login (CDP 구동 폼 로그인:
              cdp-driver.ts 페이지 조작 위의 login-core.ts 정책 레이어)
  cdp/        쿠키 리더 + 범용 CDP 클라이언트 (client.ts — 플랫 프로토콜
              WebSocket, 격리 브라우저 컨텍스트)
  service/    Credential Service (Hardened Mode, opt-in) — 마스터 키/
              세션/KDBX 접근을 쥐는 별도 OS 주체:
                mode.ts      엔드포인트/토큰 파일/상태 디렉터리 해석
                protocol.ts  JSON-lines 와이어 포맷 + 에러 코드 네임스페이스
                auth.ts      256비트 capability 토큰 + HMAC 핸드셰이크
                acl.ts       격리 검사 (POSIX stat / icacls 스캔)
                peer.ts      선택적 POSIX peer-uid 검증 (procfs+ss)
                server.ts    unix 소켓/네임드 파이프 리스너 + 핸드셰이크
                handlers.ts  op: status/list/login/lock/approval/audit —
                             서비스 측 정책 재검사 + 감사
                service.ts   데몬 엔트리포인트 (서비스 계정으로 실행)
                client.ts    kp 측 IPC 클라이언트 (callService/probeService)
```

Hardened Mode 데이터 흐름 (`hardened.enabled=true`):

```
agent → kp → policy gate (local audit) → hardGate (token+KDBX ACL checks)
      → capability-token handshake → service
        → policy re-check + service-side audit → provider/worker (secret
          never leaves the service) → sanitized result → kp → JSON out
```

시크릿은 IPC를 절대 지나지 않습니다: `login`은 워커의 정제된 결과만
반환하고, 승인 op는 웹 왕복을 서비스 내부에서 실행한 뒤 승인 URL을
interim 프레임으로 스트리밍합니다. Standard Mode는 변경 없음
(`hardened.enabled=false`, 기본값).

의존 방향: `cli` → `broker`/`master-key`/`unlock-server` →
`provider` → `keepass` 백엔드. 하위 레이어는 상향 import를 하지 않음;
`process.platform` 백엔드 분기는 `provider.createProvider`에만 존재.

핵심 플로우:
- `kp unlock` → 토큰 → 127.0.0.1 UI → POST pw → provider.verifyKey → DPAPI 세션 기록
- `kp search` → DPAPI 복호화 → provider.listEntries (stdin 키) → 필터 → 메타데이터 JSON
- `kp login` → UUID 해석 → provider.getSecret → 검증 → 워커 stdin JSON → status만
- `kp entry add`/`db create` → 웹 폼 → provider.addEntry/createDb (모든 플랫폼에서 PyKeePass)
- `kp entry sync-cookies`/`login-capture` → cookies-mode 승인 페이지 (일회용 토큰) → unlock 서버가 CDP 쿠키 읽기 (루프백 엔드포인트만) → provider.updateEntryFields
- `kp db sync` → sprite exec argv 탐색 (md5sum/stat) → `--file`로 push 또는 `base64`로 pull → pull: tmp 스테이징 → md5 검증 → `.bak` → 원자적 rename
- 원격 unlock → `tools/relay-unlock.mjs` 순수 프록시: 원격 페이지 verbatim + `sprite exec curl`로 POST 패스스루 (평문은 릴레이를 지나지 않음)
- Hardened `kp login` → IPC `list`+`login` op → 서비스가 엔트리 해석 →
  서비스가 정책 재검사 → 서비스가 워커 spawn 후 시크릿 파이프 →
  정제된 결과만 IPC를 지남
- Hardened `kp unlock`/`entry add`/`sync-cookies`/`db create` → IPC
  `approval` op → 서비스가 루프백 웹 플로우 호스팅 (마스터 키는
  브라우저 → 서비스로, 에이전트를 거치지 않음) → 승인 URL이
  interim 프레임으로 스트리밍되어 운영자 브라우저로 전달
