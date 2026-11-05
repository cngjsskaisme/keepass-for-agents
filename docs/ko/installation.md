---
title: 설치
description: Windows와 Linux에서 keepass-agent를 설치하고 실행 환경을 확인합니다.
---

# 설치

운영체제에 맞는 설치 명령을 실행한 뒤 `doctor`로 환경을 확인하세요.

::: tip 처음 사용하시나요?
KDBX 파일 연결까지 따라 하려면 [빠른 시작](/ko/quickstart)이 더 간단합니다.
:::

## 준비물

| 항목 | Windows | Linux |
| --- | --- | --- |
| Node.js | 22.18 이상 또는 23.6 이상 | 22.18 이상 또는 23.6 이상 |
| KeePass 접근 방식 | KeePass 2.x 및 KPScript | PyKeePass |
| Python 3.10 이상 / PyKeePass | 계정 추가·수정에 필요 | 모든 KeePass 작업에 필요 |
| Git | 저장소 다운로드 | 저장소 다운로드 |

::: warning Windows에서 먼저 준비할 것
KeePass와 KPScript는 별도로 설치해야 합니다. 설치 스크립트가 실행 파일을 **자동으로 다운로드하지 않습니다.** [KeePass 설치 파일 안내](/ko/keepass-binaries)를 확인하세요.
:::

## 1. 프로젝트 내려받기

```sh
git clone --branch feat/keepass-for-agents --single-branch https://github.com/cngjsskaisme/nougat-worker.git
cd nougat-worker
```

## 2. 설치 실행하기

::: code-group

```powershell [Windows · PowerShell]
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\install.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\install.ps1
```

```sh [Linux · Bash]
bash tools/install.sh --dry-run
bash tools/install.sh
```

:::

먼저 미리보기 결과를 확인하세요. Windows 설치기는 KeePass/KPScript를 점검하고 Python 의존성 설치를 안내합니다. Linux는 KPScript 대신 PyKeePass를 사용합니다.

## 3. 설치 상태 확인하기

```sh
node src/cli/kp.ts doctor
```

Node.js 버전, 설정, KeePass 관련 프로그램, 파일 권한 등을 검사합니다. Hardened Mode를 활성화했다면 서비스 상태도 확인합니다. **fail** 항목을 해결한 후 AI 에이전트를 연결하세요.

::: details 직접 설치하는 방법
설치 스크립트를 사용하지 않으려면 다음을 실행하세요.

```sh
npm ci
```

Python 의존성을 설치합니다.

::: code-group

```powershell [Windows]
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

```sh [Linux]
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

:::

설정 파일을 만들고 확인합니다.

```sh
node src/cli/kp.ts config init
node src/cli/kp.ts doctor
```

Windows에서 KPScript 경로를 찾지 못한다면 직접 지정하세요.

```sh
node src/cli/kp.ts config set keepass.kpscript "C:/path/to/KPScript.exe"
```

:::

## 업데이트와 제거

| 작업 | 방법 |
| --- | --- |
| 업데이트 | `git pull` → `npm ci` → `kp doctor` → `kp config migrate` |
| Windows 제거 | `tools\install.ps1 -Uninstall` |
| Linux 제거 | `bash tools/install.sh --uninstall` |
| Hardened Mode 제거 | 별도 [운영 가이드](/ko/operations) 참고 |

::: warning 권한을 변경하기 전 백업
제거와 Hardened Mode 설정 과정에서 설정 파일이나 접근 권한이 바뀔 수 있습니다. KDBX 파일과 설정을 미리 백업하세요. 일반 설치만으로는 Hardened Mode 격리가 적용되지 않습니다.
:::
