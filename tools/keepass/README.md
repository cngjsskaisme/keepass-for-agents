# KeePass binaries

이 디렉터리에는 KeePass 2.x와 KPScript 바이너리가 필요합니다 (라이선스 문제로 저장소에 포함하지 않음).

1. https://keepass.info/download.html 에서 **KeePass 2.x** (설치판 또는 포터블) 다운로드
2. 같은 페이지의 **KPScript** 플러그인 다운로드
3. 아래 파일을 이 디렉터리에 배치:
   - `KeePass.exe`
   - `KPScript.exe` (KeePass.exe와 같은 디렉터리에 있어야 동작)
   - `KeePassLibN.x32.dll`, `KeePassLibN.x64.dll`, `KeePassLibN.a64.dll` (포터블 패키지에 포함)
4. `kp config set keepass.kpscript "<절대경로>/KPScript.exe"` 로 경로 지정

KeePass는 GPL-2.0+ 라이선스입니다 (https://keepass.info/help/v2/license.html).
`.config` 파일은 기존 설정 그대로 사용하면 됩니다.
