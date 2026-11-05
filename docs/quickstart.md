---
title: Quick start
description: Connect an existing KeePass database, unlock it in your browser, and search for an account.
---

# Quick start

Connect a KeePass database and search for your first account. You will enter the master password **only in the local browser approval page**.

## Before you begin

- **Windows:** Node.js 22.18+ (or 23.6+), KeePass 2.x, and KPScript.
- **Linux:** Node.js 22.18+ (or 23.6+), Python 3.10+, and PyKeePass.
- An existing `.kdbx` file. Use a test database while learning.

If you haven't installed the prerequisites, see [Installation](/installation).

## 1. Install

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

## 2. Check and connect KeePass

```sh
node src/cli/kp.ts doctor
```

Fix any **fail** check. Register your existing database (replace the path):

::: code-group

```powershell [Windows]
node src/cli/kp.ts db add personal --path "C:/Vaults/personal.kdbx"
```

```sh [Linux]
node src/cli/kp.ts db add personal --path "/home/you/Vaults/personal.kdbx"
```

:::

## 3. Limit agent permissions

::: danger Required before connecting an AI agent
`kp config init` starts with `agents.default.allowed = ["*"]`. This is convenient for initial setup but **not a secure permission policy**.
:::

```sh
node src/cli/kp.ts config set agents.default.allowed "db.list,db.info,unlock,status,search,login,lock"
node src/cli/kp.ts config validate
```

This example is only a starting point. Give real agents separate rules for allowed entries and hosts in [Configuration](/configuration).

## 4. Unlock, search, and lock

```sh
node src/cli/kp.ts unlock --db personal
node src/cli/kp.ts search --db personal --title "Example account"
node src/cli/kp.ts lock --db personal
```

The unlock command opens a **local browser page** for the master password. Replace the example title with a real entry name. Search returns account metadata, not the password.

::: tip Next step
To connect an AI assistant, follow [MCP integration](/mcp). To automate supported website logins, see the [CLI login command](/cli#authentication-and-login).
:::

::: info Why the security warning?
Standard Mode keeps credentials out of ordinary tool responses; it does not protect a database from a process with the same OS-user permissions. See [Security](/security) before using valuable accounts.
:::
