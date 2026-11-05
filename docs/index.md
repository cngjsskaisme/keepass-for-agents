---
layout: home

hero:
  name: keepass for agents
  text: Let agents sign in. Keep your credentials private.
  tagline: Connect your existing KeePass database to AI agents through a local gateway. Agents request approved actions rather than receiving your passwords.
  image:
    src: /hero-icon.avif
    alt: keepass-agent logo
  actions:
    - theme: brand
      text: Get started
      link: /quickstart
    - theme: alt
      text: Connect an AI agent
      link: /mcp
    - theme: alt
      text: Security & limitations
      link: /security

features:
  - icon: 🔑
    title: Use your KeePass database
    details: Connect an existing KDBX file without moving credentials to a new cloud provider.
    link: /quickstart
    linkText: Start with KeePass
  - icon: 🤖
    title: Connect through CLI or MCP
    details: Let an agent search account metadata and request approved login tasks.
    link: /mcp
    linkText: Connect an agent
  - icon: 🧭
    title: Set access rules
    details: Decide which actions, accounts, and destination hosts an agent may use.
    link: /configuration
    linkText: Configure access
  - icon: 🛡️
    title: Choose your security boundary
    details: Standard Mode controls tool output; optional Hardened Mode separates credential operations into an OS service account.
    link: /security
    linkText: Compare the modes
---

## Where should I start?

| Your goal | Go to |
| --- | --- |
| Try the project for the first time | [Quick start](/quickstart) |
| Install on Windows or Linux | [Installation](/installation) |
| Use it with an MCP-capable AI agent | [Connect an AI agent](/mcp) |
| Find a command | [CLI reference](/cli) |
| Run a separate Credential Service | [Operations](/operations) |

::: warning Before connecting an agent
The initial configuration grants broad access to the `default` agent. Restrict its permissions first. Standard Mode also does **not** isolate the KeePass database from programs running as the same OS user. See [Security & limitations](/security).
:::

<div align="center">
  <img src="/brand-wordmark.avif" alt="keepass for agents" width="280" />
</div>
