---
title: 빠른 시작
description: 기존 KeePass 저장소 연결부터 잠금 해제, 계정 검색까지 따라 해 보세요.
---

# 빠른 시작

기존 KeePass 저장소를 연결하고 계정을 검색해 보겠습니다. 마스터 비밀번호는 **로컬 브라우저의 승인 페이지에만 입력**합니다.

## 시작 전 준비

- **Windows:** Node.js 22.18 이상(또는 23.6 이상), KeePass 2.x, KPScript
- **Linux:** Node.js 22.18 이상(또는 23.6 이상), Python 3.10 이상, PyKeePass
- 기존 `.kdbx` 파일. 처음에는 테스트용 저장소를 권장합니다.

준비가 되지 않았다면 [설치 가이드](/ko/installation)를 먼저 확인하세요.

## 1. 설치하기

```sh
git clone --branch feat/keepass-for-agents --single-branch https://github.com/cngjsskaisme/nougat-worker.git
cd nougat-worker
```

::: code-group

```powershell [Windows]
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\install.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\install.ps1
```

```sh [Linux]
bash tools/install.sh --dry-run
bash tools/install.sh
```

:::

## 2. 환경 확인하고 KeePass 연결하기

```sh
node src/cli/kp.ts doctor
```

결과에 **fail**이 있다면 먼저 해결하세요. 이어서 KDBX 파일을 등록합니다. 경로는 실제 파일 위치로 변경하세요.

::: code-group

```powershell [Windows]
node src/cli/kp.ts db add personal --path "C:/Vaults/personal.kdbx"
```

```sh [Linux]
node src/cli/kp.ts db add personal --path "/home/you/Vaults/personal.kdbx"
```

:::

## 3. 에이전트 권한 줄이기

::: danger AI 에이전트 연결 전 필수
`kp config init`은 `agents.default.allowed = ["*"]`로 시작합니다. 초기 설정 편의를 위한 값이며 **안전한 기본 권한이 아닙니다.**
:::

```sh
node src/cli/kp.ts config set agents.default.allowed "db.list,db.info,unlock,status,search,login,lock"
node src/cli/kp.ts config validate
```

이는 입문용 예시입니다. 실제 에이전트에는 [설정과 접근 권한](/ko/configuration)에서 사용할 계정과 사이트를 따로 제한하세요.

## 4. 잠금 해제하고 계정 검색하기

```sh
node src/cli/kp.ts unlock --db personal
node src/cli/kp.ts search --db personal --title "예시 계정"
node src/cli/kp.ts lock --db personal
```

잠금 해제 시 **로컬 브라우저 페이지**가 열립니다. 여기에서 마스터 비밀번호를 입력하세요. 검색할 때는 실제 저장된 계정 이름을 입력하면 됩니다. 검색 결과에 비밀번호 원문은 포함되지 않습니다.

::: tip 다음 단계
AI 에이전트를 연결하려면 [MCP 연결](/ko/mcp), 웹사이트 로그인을 실행하려면 [CLI 로그인 명령](/ko/cli#인증과-로그인)을 확인하세요.
:::

::: info 보안 주의사항이 있는 이유
Standard Mode는 일반 도구 응답에 인증정보를 전달하지 않지만, 같은 OS 사용자 권한의 다른 프로세스와 KeePass 저장소를 격리하지는 못합니다. 중요한 계정을 사용하기 전 [보안 모델](/ko/security)을 확인하세요.
:::
