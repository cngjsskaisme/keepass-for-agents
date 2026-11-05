---
title: Security and limitations
description: Understand what keepass-agent protects, what it does not, and when to use Hardened Mode.
---

# Security and limitations

keepass-agent helps AI agents **request authentication tasks without receiving raw passwords**. It is not a replacement for operating-system permissions or a guarantee against every kind of credential theft.

## Choose the right mode

| | Standard Mode (default) | Hardened Mode (optional) |
| --- | --- | --- |
| Credentials in agent-facing tool results | Excluded by the API design | Excluded by the API design |
| KeePass database access | Same OS user as the agent | Dedicated Credential Service account |
| File and session separation | **Not isolated** from same-user processes | Enforced by OS permissions if provisioned correctly |
| Setup | Basic installation | Additional service account, ACLs, and IPC setup |
| Failure when service is down | Not applicable | **Fail closed**; no silent fallback |

::: danger Standard Mode is not process isolation
A malicious program running as the **same OS user** may access KeePass files or session material outside the intended tool interface. Use a separately provisioned Hardened Mode if the agent itself is untrusted.
:::

## What is protected?

- **Tool responses:** Search returns account metadata. Login returns a sanitized result, not the password.
- **Unlock:** The user enters the master password in a local browser approval page, not in an AI prompt.
- **Login destinations:** The gateway checks the entry URL and restricts cross-origin credential submissions.
- **Access policies:** Actions, entries, and destination hosts can be restricted per *declared* agent.
- **Audit:** Events record requested actions and outcomes without storing password or cookie values.

For a browser login, the approved worker receives credentials through stdin. A best-effort output filter is a backup safeguard; **it cannot guarantee removal of every encoded or transformed secret**.

## Limits you should know

| Limitation | Why it matters |
| --- | --- |
| First-run policy is permissive | `config init` currently gives the `default` agent `allowed = ["*"]`. Restrict it before connecting an AI agent. |
| Agent names are self-declared | `--agent`, environment variables, and MCP client names are not strong proof of who is calling. |
| Browser approval is not proof of a human | A local process that obtains the approval URL may interact with the page. Do not treat approval as a second-factor identity check. |
| Session cookies are credentials | Cookie capture requires approval, but a captured session may grant access like a password. |
| Login success signals vary | URL changes and page markers are weak indicators; an uncertain result is not proof of successful login. |
| OS-level peer checks are incomplete | Native kernel peer identity verification is not yet implemented for every platform. |
| Runtime memory cannot be guaranteed to be zeroed | JavaScript garbage collection does not provide a plaintext-memory erasure guarantee. |

::: warning Sensitive accounts
Before using real credentials, verify the account boundary on your machine, the agent's permissions, the CDP/browser destination, and any human-approval flow. Keep the KDBX file backed up.
:::

## How the protected flow works

```text
AI agent → CLI / MCP → policy check
                         │
         ┌───────────────┴────────────────┐
         │ Standard Mode                  │ Hardened Mode
         ▼                                ▼
    Local credential path       Authenticated IPC
         │                                │
    KeePass Provider          Separate Credential Service
         │                                │
         └────────── Approved worker ─────┘
                          │
                Sanitized result only
```

**Hardened Mode** moves credential access, sessions, and worker execution to a service running under a different OS account. It checks token-file and KDBX permissions and refuses to proceed when configured isolation requirements are unmet.

Enable it only after reviewing [Operations](/operations) and validating `kp status` and `kp doctor` under the agent account.

## Technical details

For the full threat model, HMAC/IPC handshake, Windows/POSIX ACL checks, CDP restrictions, audit schema, and remaining implementation gaps, see the [security implementation reference](/security-internals).

If you're setting up permissions rather than reviewing the source, start with [Configuration](/configuration).
