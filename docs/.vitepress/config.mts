import { defineConfig } from 'vitepress'

const repoUrl = 'https://github.com/cngjsskaisme/keepass-for-agents'
const editPattern = 'https://github.com/cngjsskaisme/keepass-for-agents/edit/main/docs/:path'

const enSidebar = [
  {
    text: 'Start here',
    items: [
      { text: 'Overview', link: '/' },
      { text: 'Quick start', link: '/quickstart' },
      { text: 'Installation', link: '/installation' },
      { text: 'KeePass binaries (Windows)', link: '/keepass-binaries' },
    ],
  },
  {
    text: 'Use the gateway',
    items: [
      { text: 'Connect an AI agent (MCP)', link: '/mcp' },
      { text: 'Configuration & permissions', link: '/configuration' },
      { text: 'CLI reference', link: '/cli' },
      { text: 'Troubleshooting', link: '/troubleshooting' },
    ],
  },
  {
    text: 'For operators & developers',
    items: [
      { text: 'Security model & limits', link: '/security' },
      { text: 'Security internals', link: '/security-internals' },
      { text: 'Daily operations', link: '/operations' },
      { text: 'Architecture', link: '/architecture' },
      { text: 'Architecture internals', link: '/architecture-internals' },
      { text: 'Release checklist', link: '/release-checklist' },
    ],
  },
]

const koSidebar = [
  {
    text: '시작하기',
    items: [
      { text: '소개', link: '/ko/' },
      { text: '빠른 시작', link: '/ko/quickstart' },
      { text: '설치', link: '/ko/installation' },
      { text: 'KeePass 설치 파일 (Windows)', link: '/ko/keepass-binaries' },
    ],
  },
  {
    text: '사용 가이드',
    items: [
      { text: 'AI 에이전트 연결 (MCP)', link: '/ko/mcp' },
      { text: '설정과 접근 권한', link: '/ko/configuration' },
      { text: 'CLI 명령어', link: '/ko/cli' },
      { text: '문제 해결', link: '/ko/troubleshooting' },
    ],
  },
  {
    text: '운영자·개발자 참고자료',
    items: [
      { text: '보안 모델과 한계', link: '/ko/security' },
      { text: '보안 구현 상세', link: '/ko/security-internals' },
      { text: '운영 및 관리', link: '/ko/operations' },
      { text: '아키텍처', link: '/ko/architecture' },
      { text: '아키텍처 구현 상세', link: '/ko/architecture-internals' },
      { text: '릴리스 체크리스트', link: '/ko/release-checklist' },
    ],
  },
]

export default defineConfig({
  title: 'keepass-agent',
  description: 'A KeePass-backed credential gateway for AI agents',
  base: '/keepass-for-agents/',
  cleanUrls: true,
  lastUpdated: true,
  head: [
    ['meta', { name: 'theme-color', content: '#4458bb' }],
    ['link', { rel: 'icon', type: 'image/png', href: '/favicon.png' }],
  ],
  markdown: { lineNumbers: true },

  themeConfig: {
    logo: '/brand-horizontal.avif',
    nav: [
      { text: 'Quick start', link: '/quickstart' },
      { text: 'MCP integration', link: '/mcp' },
      { text: 'Security', link: '/security' },
      { text: 'GitHub', link: repoUrl },
    ],
    sidebar: enSidebar,
    outline: { level: [2, 3], label: 'On this page' },
    search: { provider: 'local' },
    socialLinks: [{ icon: 'github', link: repoUrl }],
    editLink: { pattern: editPattern, text: 'Improve this page on GitHub' },
    docFooter: { prev: 'Previous', next: 'Next' },
    footer: {
      message: 'MIT-licensed gateway. KeePass and KPScript are separate GPL-licensed software.',
      copyright: 'Read the security model before connecting an untrusted agent.',
    },
  },

  locales: {
    root: { label: 'English', lang: 'en-US' },
    ko: {
      label: '한국어',
      lang: 'ko-KR',
      link: '/ko/',
      description: 'AI 에이전트를 위한 KeePass 기반 자격증명 게이트웨이',
      themeConfig: {
        nav: [
          { text: '빠른 시작', link: '/ko/quickstart' },
          { text: 'MCP 연결', link: '/ko/mcp' },
          { text: '보안', link: '/ko/security' },
          { text: 'GitHub', link: repoUrl },
        ],
        sidebar: koSidebar,
        outline: { level: [2, 3], label: '목차' },
        editLink: { pattern: editPattern, text: 'GitHub에서 이 문서 개선하기' },
        docFooter: { prev: '이전', next: '다음' },
        lastUpdated: { text: '최근 수정' },
        darkModeSwitchLabel: '테마',
        lightModeSwitchTitle: '라이트 모드로 전환',
        darkModeSwitchTitle: '다크 모드로 전환',
        sidebarMenuLabel: '메뉴',
        returnToTopLabel: '맨 위로',
        langMenuLabel: '언어',
        footer: {
          message: '게이트웨이는 MIT 라이선스이며, KeePass·KPScript는 별도 GPL 라이선스를 따릅니다.',
          copyright: '신뢰할 수 없는 에이전트를 연결하기 전에 보안 모델을 확인하세요.',
        },
      },
    },
  },
})
