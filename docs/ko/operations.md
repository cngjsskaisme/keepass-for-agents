---
title: 운영 및 관리
description: 세션 관리, Hardened Mode 설정, 백업과 복구 방법을 안내합니다.
---

# 운영 및 관리

이 문서는 keepass-agent를 **운영하거나 관리하는 사용자**를 위한 안내입니다. 기존 KeePass 저장소를 연결하려는 경우 [빠른 시작](/ko/quickstart)부터 확인하세요.

## 평소에 사용하는 명령

| 작업 | 명령 |
| --- | --- |
| 현재 모드와 세션 상태 확인 | `kp status` |
| 설치 환경과 서비스 점검 | `kp doctor` |
| 로컬 관리 화면 열기 | `kp ui` |
| 최근 사용 기록 확인 | `kp audit --limit 20` |
| KeePass 저장소 다시 잠그기 | `kp lock --db personal` |

::: warning Hardened Mode를 설정하기 전에
Hardened Mode는 **OS 사용자 계정과 파일 접근 권한을 변경합니다.** KDBX 파일과 `config.toml`을 먼저 백업하고 변경 계획을 확인하세요. 설정 후에도 KeePass에서 저장소를 열 수 있도록 복구 방법을 준비해야 합니다.
:::

## Hardened Mode 활성화

Hardened Mode는 인증 작업을 별도의 **Credential Service 계정**에서 실행합니다. 기본 설치만으로 자동 활성화되지는 않습니다.

### 1. 변경 계획 미리보기

::: code-group

```sh [Linux · 미리보기]
sudo bash tools/setup-hardened.sh --dry-run
```

```powershell [Windows · 관리자 권한]
powershell -ExecutionPolicy Bypass -File tools\setup-hardened.ps1 -DryRun
```

:::

### 2. 설정 적용

미리보기 결과를 검토한 뒤 실행하세요.

::: code-group

```sh [Linux · 관리자 권한]
sudo AGENT_USERS="alice bot-runner" bash tools/setup-hardened.sh
```

```powershell [Windows · 관리자 권한]
powershell -ExecutionPolicy Bypass -File tools\setup-hardened.ps1
```

:::

`alice bot-runner`는 실제로 서비스 사용을 허용할 **OS 계정 이름**으로 바꿔야 합니다. 설정 스크립트는 서비스 계정, 파일 권한, 자동 시작 항목을 구성합니다.

### 3. 에이전트 계정에서 검증

```sh
kp status
kp doctor
```

결과에 `mode: hardened`, 서비스 연결 성공, `isolation.ok: true`가 표시되는지 확인하세요. `HARDENED_ACL_UNMET` 같은 오류가 있다면 원인을 수정하기 전까지 사용하지 마세요.

::: details 고급: 설정 과정에서 변경되는 항목
- **Linux:** 전용 서비스 계정과 에이전트 그룹, 보호된 상태 디렉터리, systemd 서비스, 등록된 KDBX 파일의 소유권과 권한을 설정합니다.
- **Windows:** 서비스 계정을 만들고 `icacls`로 NTFS 권한을 제한하며 작업 스케줄러에 자동 실행을 등록합니다.
- IPC 인증 토큰은 파일 권한으로 보호합니다. 서비스도 인증정보 사용 전 접근 정책을 다시 검사합니다.
- KDBX 파일 소유권이 바뀌면 KeePass GUI 사용자의 읽기·쓰기 권한을 따로 설정해야 할 수 있습니다. 모든 사용자에게 권한을 열어두지 마세요.
- Linux의 `peer_verify=strict`는 procfs·`ss`와 허용 UID 설정을 사용합니다. 커널 수준 호출자 검증이 모든 플랫폼에 완전히 구현된 것은 아닙니다.
- 일반 설치기가 만드는 Linux **사용자 수준** systemd 서비스는 별도 OS 계정으로 격리되지 않습니다.
- `KEEPASS_AGENT_SERVICE_SELFTEST`는 **테스트 전용** 설정입니다. 실제 운영 환경에서 사용하지 마세요.

자세한 구조는 [보안 구현 상세](/ko/security-internals)에 있습니다.
:::

## 서비스 상태 확인과 재시작

::: code-group

```sh [Linux]
systemctl status kp-credential
sudo systemctl restart kp-credential
journalctl -u kp-credential -f
```

```powershell [Windows]
Get-ScheduledTask -TaskName kp-credential-service | Get-ScheduledTaskInfo
Start-ScheduledTask -TaskName kp-credential-service
Stop-ScheduledTask -TaskName kp-credential-service
```

:::

Hardened Mode를 켠 상태에서 서비스가 중지되면 인증 작업은 `HARDENED_SERVICE_UNAVAILABLE`로 실패합니다. Standard Mode로 자동 전환되지 않습니다.

## 백업과 복원

| 백업할 항목 | 이유 |
| --- | --- |
| 등록한 `.kdbx` 파일 | KeePass에 저장된 계정 정보 |
| `~/.config/keepass-agent/config.toml` | 저장소 연결 정보와 접근 권한 |
| `audit.log` (선택) | 이전 사용 기록 |
| 세션 파일 (선택) | 암호화돼 있으며 다시 잠금 해제하면 재생성 가능 |

1. 권한을 변경하거나 업데이트하기 전에 KDBX 파일과 설정을 복사하세요.
2. AI 에이전트가 수정할 수 없는 별도 위치에 백업하세요.
3. 필요하면 복사본을 복원한 다음 `kp doctor`를 실행하고 서비스 계정의 접근 권한도 확인하세요.

`db sync --pull`에 성공하면 기존 KDBX 파일의 `<파일>.kdbx.bak` 백업이 함께 보관됩니다.

## 업데이트와 롤백

```sh
git pull
npm ci
kp doctor
kp config migrate
```

Hardened Mode를 사용한다면 업데이트 후 systemd 서비스 또는 Windows 예약 작업을 재시작하고 격리 상태를 재검사하세요. 더 새로운 설정 파일을 오래된 프로그램에서 사용하면 호환성 문제가 발생할 수 있으니 `doctor` 경고를 먼저 확인하세요.

::: danger Hardened Mode 제거 시 주의
서비스 계정이나 상태 폴더를 바로 삭제하지 마세요. 해당 계정이 KDBX 파일을 소유하고 있을 수 있습니다. 먼저 백업을 보존하고 파일 소유권·접근 권한을 복원한 뒤 KeePass에서 정상적으로 열리는지 확인하세요. 이후 설정 스크립트의 복구 안내와 설치 제거 옵션을 따르세요.
:::

오류가 발생한다면 [문제 해결](/ko/troubleshooting)을 확인하세요.
