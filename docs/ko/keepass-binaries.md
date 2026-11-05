---
title: KeePass 설치 파일 준비 (Windows)
description: Windows에서 필요한 KeePass와 KPScript를 준비합니다.
---

# KeePass 설치 파일 준비 (Windows)

Windows에서 KeePass 저장소를 사용하려면 **KeePass 2.x**와 **KPScript**가 필요합니다.

## 설치 순서

1. [KeePass 공식 다운로드 페이지](https://keepass.info/download.html)에서 **KeePass 2.x**를 설치합니다.
2. 같은 사이트에서 호환되는 **KPScript**를 내려받습니다.
3. `KPScript.exe`와 `KeePass.exe`를 같은 폴더에 둡니다. 포터블 버전이라면 함께 제공된 DLL 파일도 유지하세요.
4. 경로를 설정하고 설치 상태를 확인합니다.

```sh
node src/cli/kp.ts config set keepass.kpscript "C:/path/to/KPScript.exe"
node src/cli/kp.ts doctor
```

::: tip 설정 파일이 없다면
먼저 `node src/cli/kp.ts config init`을 실행하세요.
:::

## 알아둘 점

- KeePass 실행 파일은 프로젝트에 **포함되지 않고 자동 다운로드되지도 않습니다.**
- 실행 파일을 Git 저장소에 커밋하지 마세요.
- KeePass는 [GPL 라이선스](https://keepass.info/help/v2/license.html)를 따릅니다. 구성요소별 라이선스를 확인하세요.
- Linux는 KPScript가 필요하지 않습니다. [설치 가이드](/ko/installation)에서 PyKeePass를 준비하세요.

자세한 파일 구성은 [저장소 내 KeePass 안내](https://github.com/cngjsskaisme/nougat-worker/blob/feat/keepass-for-agents/tools/keepass/README.md)를 참고하세요.
