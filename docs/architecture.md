---
title: Architecture
description: Understand how agent requests reach KeePass without exposing raw credentials in tool responses.
---

# Architecture

keepass-agent has one job: **accept a limited authentication request and return an outcome**, while keeping password handling inside trusted components.

## Request flow

```text
                      AI agent
                          │
                     CLI or MCP
                          │
                   Policy + audit
                          │
             ┌────────────┴────────────┐
             ▼                         ▼
        Standard Mode              Hardened Mode
        Local process             Authenticated IPC
             │                         │
             │                 Credential Service
             │                  (separate OS user)
             └────────────┬────────────┘
                          │
               KeePass Provider (KDBX)
                          │
                   Approved worker
                          │
                 Sanitized outcome
```

**Standard Mode** shares its OS account with the calling agent. **Hardened Mode** sends credential-related operations to a separately provisioned service. Both expose the same basic CLI/MCP interface.

## Core components

| Component | Responsibility |
| --- | --- |
| CLI / MCP | Receive requests and return structured responses |
| Policy & audit | Decide which agent action, entry, or host is allowed; record decisions |
| Credential Provider | Use KPScript on Windows and PyKeePass on POSIX |
| Credential Service | In Hardened Mode, own sessions and credential access behind authenticated IPC |
| Authentication workers | Execute allowlisted login tasks without returning raw passwords |
| Local approval UI | Let the user unlock or approve supported operations in a browser |

## Example: website login

1. The agent requests login for a specific entry.
2. The gateway checks the agent's permissions and the destination URL.
3. The trusted component reads the entry from KeePass.
4. An approved worker receives the credentials through stdin and performs the login.
5. The agent receives a sanitized success/failure result, **not the password**.

Browser login is driven through a configured local CDP browser. The worker uses an isolated browser context by default and blocks cross-origin credential submission. See [Security](/security) for limitations.

## What changes on each platform?

- **Windows:** KeePass 2.x and KPScript for credential access; PyKeePass for entry creation and modification.
- **Linux:** Python 3.10+ and PyKeePass for credential operations.
- **Hardened Mode:** An OS service account and file permissions are needed on either platform; it is not enabled automatically.

## For maintainers

See [Architecture internals](/architecture-internals) for the module directory map, call paths, remote sync, and IPC implementation. For setup steps, use [Installation](/installation) and [Operations](/operations).
