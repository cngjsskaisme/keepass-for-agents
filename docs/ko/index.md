---
layout: home

hero:
  name: keepass for agents
  text: 로그인은 AI에게 맡기고, 비밀번호는 보호하세요.
  tagline: 기존 KeePass 저장소를 AI 에이전트와 연결하는 로컬 인증 도구입니다. 비밀번호를 전달하는 대신, 허용된 로그인 작업만 수행하도록 합니다.
  image:
    src: /hero-icon.avif
    alt: keepass-agent 로고
  actions:
    - theme: brand
      text: 빠른 시작
      link: /ko/quickstart
    - theme: alt
      text: AI 에이전트 연결
      link: /ko/mcp
    - theme: alt
      text: 보안과 한계
      link: /ko/security

features:
  - icon: 🔑
    title: 기존 KeePass 저장소 활용
    details: KDBX 파일을 새 클라우드 서비스로 옮기지 않고 연결할 수 있습니다.
    link: /ko/quickstart
    linkText: 시작하기
  - icon: 🤖
    title: CLI와 MCP 지원
    details: AI 에이전트가 저장된 계정을 검색하고 허용된 로그인 작업을 요청합니다.
    link: /ko/mcp
    linkText: 에이전트 연결
  - icon: 🧭
    title: 에이전트별 접근 권한
    details: 허용할 작업, 계정, 접속 사이트를 지정할 수 있습니다.
    link: /ko/configuration
    linkText: 권한 설정
  - icon: 🛡️
    title: 필요에 따라 실행 환경 분리
    details: 일반 모드는 도구 출력 경로를 보호합니다. Hardened Mode는 인증 작업을 별도 OS 계정으로 분리합니다.
    link: /ko/security
    linkText: 보안 모드 비교
---

## 무엇부터 시작할까요?

| 원하는 작업 | 추천 문서 |
| --- | --- |
| 처음 실행해 보기 | [빠른 시작](/ko/quickstart) |
| Windows 또는 Linux에 설치하기 | [설치](/ko/installation) |
| MCP 지원 AI 에이전트와 연결하기 | [AI 에이전트 연결](/ko/mcp) |
| 명령어 찾아보기 | [CLI 명령어](/ko/cli) |
| 별도 Credential Service 운영하기 | [운영 가이드](/ko/operations) |

::: warning 에이전트 연결 전 확인
최초 설정은 `default` 에이전트에 넓은 권한을 부여합니다. 연결 전에 권한을 줄이세요. 또한 Standard Mode는 **같은 OS 사용자 권한으로 실행하는 프로그램으로부터 KeePass 저장소를 격리하지 못합니다.** 자세한 내용은 [보안과 한계](/ko/security)를 참고하세요.
:::

<div align="center">
  <img src="/brand-wordmark.avif" alt="keepass for agents" width="280" />
</div>
