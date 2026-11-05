---
title: 문제 해결
description: 설치·권한·로그인·동기화 문제를 증상별로 확인하세요.
---

# 문제 해결

먼저 진단 명령을 실행하세요.

```sh
kp doctor
```

항목마다 **ok(정상)**, **warn(확인 필요)**, **fail(오류)**가 표시되며 해결 방법도 안내합니다. `kp` 명령을 찾지 못하면 `node src/cli/kp.ts doctor`를 사용하세요.

## 자주 발생하는 문제

| 증상 또는 오류 코드 | 가능한 원인 | 해결 방법 |
| --- | --- | --- |
| `POLICY_DENIED` | 작업·계정·사이트에 대한 권한 부족 | [접근 권한 설정](/ko/configuration) 확인 |
| `UNLOCK_REQUIRED` | KeePass 저장소가 잠김 | `kp unlock --db <이름>` 실행 후 브라우저에서 승인 |
| `AMBIGUOUS_ENTRY` | 같은 조건으로 여러 계정이 검색됨 | 검색 결과의 UUID로 지정 |
| `python.pykeepass` fail | Python 의존성 누락 | 가상 환경에 `requirements.txt` 설치 |
| KeePass/KPScript 경로 오류 | Windows 실행 파일이 없거나 위치가 다름 | [KeePass 설치](/ko/keepass-binaries) 확인 |
| `HARDENED_SERVICE_UNAVAILABLE` | Credential Service가 실행되지 않음 | [운영 가이드](/ko/operations)에서 서비스 상태 확인 |
| `HARDENED_ACL_UNMET` | 파일 권한 또는 서비스 소유권 불일치 | `doctor` 결과와 Hardened Mode 설정 확인 |
| `CDP_ENDPOINT_REJECTED` | 브라우저 연결 주소가 로컬이 아님 | 신뢰할 수 있는 로컬 주소(`127.0.0.1`) 사용 |
| `WORKER_OUTCOME_UNCERTAIN` | 로그인 성공을 확정할 수 없음 | 실제 사이트 상태와 워커 제약 확인 |
| `MD5_MISMATCH` / `SYNC_DOWNLOAD_FAILED` | 파일 다운로드·무결성 검사 실패 | 원본 KDBX를 덮어쓰지 말고 동기화 상태 확인 |

## 설치 오류가 난다면

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

Windows에서는 KeePass와 KPScript를 별도로 준비해야 합니다. Linux는 PyKeePass가 저장소 작업을 담당합니다.

## 갑자기 명령이 거부된다면

기존 설정에 `[agents.*]` 항목이 없으면 권한이 필요한 명령을 모두 거부합니다. 전체 허용으로 되돌리기보다는 필요한 권한만 설정하세요. 업데이트 후에는 다음 명령을 실행해 보세요.

```sh
kp config validate
kp config migrate
kp doctor
```

`config.schema` 경고는 설정 파일을 업그레이드해야 한다는 뜻일 수도 있고, 현재 프로그램보다 새로운 버전에서 작성됐다는 뜻일 수도 있습니다. 버전을 확인한 뒤 변경하세요.

## Hardened Mode가 연결되지 않는다면

1. Credential Service가 실행 중인지 확인합니다.
2. `kp status`와 `kp doctor`로 격리 검사 결과를 봅니다.
3. 인증 토큰, KDBX 파일 권한, 서비스 계정 설정을 확인합니다.
4. 격리 오류를 피하려고 **무조건 Hardened Mode를 끄지는 마세요.**

Windows·Linux 서비스 명령은 [운영 가이드](/ko/operations)를 참고하세요.

::: details Sprite 동기화와 사용자 승인 문제
- `INVALID_REMOTE_PATH` / `INVALID_SPRITE`: 절대 경로와 지원되는 Sprite 이름만 사용하세요. 공백과 셸 특수문자는 허용되지 않습니다.
- `REMOTE_NEWER` / `LOCAL_NEWER`: `--pull`이나 `--force` 전에 어느 파일이 최신인지 확인하세요.
- 쿠키 수집에는 브라우저 승인이 필요합니다. 브라우저가 열리지 않으면 명령 결과의 `awaiting_user_input` URL을 확인하세요.
- Sprite 승인 중 HTTP 502가 발생하면 원격 서버 또는 `sprite exec` 연결 상태를 확인하세요. [운영 가이드](/ko/operations)에 자세한 내용이 있습니다.
:::
