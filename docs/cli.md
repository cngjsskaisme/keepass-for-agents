---
title: CLI reference
description: Find keepass-agent commands by task, with short examples and common errors.
---

# CLI reference

The `kp` command manages KeePass databases, authentication sessions, and agent requests. All commands return **JSON** so scripts and agents can read their results.

::: tip First time using the CLI?
Follow [Quick start](/quickstart) to connect a KDBX file before using the commands below.
:::

## Everyday commands

| Task | Command |
| --- | --- |
| Diagnose an installation | `kp doctor` |
| List connected databases | `kp db list` |
| Check the current session | `kp status --db personal` |
| Unlock a database | `kp unlock --db personal` |
| Find an account | `kp search --db personal --title "Example account"` |
| Lock a database | `kp lock --db personal` |
| Open the management UI | `kp ui` |

Use `node src/cli/kp.ts` in place of `kp` if the launcher is not on your PATH.

## Configuration and databases

| Command | What it does |
| --- | --- |
| `kp config init` | Create the initial configuration. |
| `kp config show` / `validate` | View or validate configuration. |
| `kp config set <key> <value>` | Change a supported setting. |
| `kp config migrate` | Save a pending configuration schema upgrade. |
| `kp db add personal --path <file.kdbx>` | Connect an existing KeePass database. |
| `kp db create personal --path <file.kdbx>` | Create a database through a local browser form. |
| `kp db info` / `list` | Inspect registered databases. |
| `kp db default personal` | Set the default database. |
| `kp db remove personal` | Remove a registered database from the configuration. |
| `kp db sync [--pull] [--force]` | Synchronize the KDBX file with Sprite. |

::: warning Remote synchronization
`db sync` can replace local KDBX data. Back up the database and review `--pull`/`--force` before use. The command validates remote paths and retains a `.bak` file after a successful pull replacement. See [Operations](/operations).
:::

## Authentication and login

```sh
kp unlock --db personal
kp search --db personal --site github.com
kp login --db personal --entry <entry-uuid> --worker playwright
kp lock --db personal
```

| Command | What it does |
| --- | --- |
| `kp unlock --db <alias>` | Ask the user to unlock the KeePass database in a local browser. |
| `kp search --site / --title / --username` | Search entry metadata, not passwords. |
| `kp login --entry <uuid> --worker <name>` | Perform login using an allowlisted worker. |
| `kp entry add [--title ...]` | Add an entry through a local browser form. |
| `kp entry login-capture ...` | Open the website and request approval to capture its session. |
| `kp entry sync-cookies ...` | Save selected browser cookies after explicit approval. |
| `kp master change --db <alias>` | Open the KeePass GUI for a master-key change and invalidate the session. |

The `playwright` worker uses **CDP, not the Playwright npm package**. A locally configured browser endpoint (`cdp.endpoint`) is required; `login --cdp` is intentionally unsupported. Cross-origin form submission is rejected. MFA may need manual completion.

::: details Advanced login options and limits
- Specify an entry by `--entry <uuid>` or an eligible `--title`/`--site` match; ambiguous results require choosing a UUID.
- `local-test` is the test worker. `playwright` handles supported browser login forms.
- Browser logins use an isolated CDP context by default. `--no-isolate` requires an operator-managed `cdp.allow_default_context=true` setting and is intended only for dedicated browser profiles.
- `authenticated_via:url_change` and `authenticated_via:marker` are weak heuristics. A new HttpOnly cookie is stronger evidence; otherwise the result may be `WORKER_OUTCOME_UNCERTAIN`.
- `entry sync-cookies` and `entry login-capture` require a one-time browser approval. CDP endpoints must be loopback-only.
- The worker receives credentials through stdin; raw passwords are not part of the command response.
:::

## Agents, MCP, and audit

| Command | What it does |
| --- | --- |
| `kp mcp` | Start the local stdio MCP adapter. |
| `kp mcp --agent assistant` | Start MCP with a declared agent identity. |
| `kp audit --limit 20` | Read recent audit events if permitted. |
| `kp ui` | Open the local management console for sessions, policies, and audit records. |

For a step-by-step MCP setup, see [Connect an AI agent](/mcp).

::: danger Management permissions
Granting the `ui` action can provide operator-level management access. The agent name supplied via `--agent` or `KEEPASS_AGENT_ID` is **self-declared**, not authenticated in Standard Mode. See [Configuration](/configuration) and [Security](/security).
:::

## Common error codes

| Code | Meaning | Next step |
| --- | --- | --- |
| `UNLOCK_REQUIRED` | Database is locked | Run `kp unlock` and approve in the browser |
| `POLICY_DENIED` | Action, entry, or host is not permitted | Review agent permissions |
| `AMBIGUOUS_ENTRY` | Multiple matching entries | Search and use a UUID |
| `WORKER_URL_REJECTED` | Login destination is not allowed | Check the entry URL and policy |
| `WORKER_MFA_REQUIRED` | Additional sign-in step is needed | Complete MFA in the browser |
| `WORKER_OUTCOME_UNCERTAIN` | Login success cannot be confirmed | Check the destination's login state |
| `HARDENED_SERVICE_UNAVAILABLE` | Credential Service cannot be reached | Check service health with `kp doctor` |

::: details Exit codes and additional errors
- **Exit 0:** successful command.
- **Exit 1:** general failure.
- **Exit 3:** `UNLOCK_REQUIRED`. Exit codes 2 and 4 exist in the implementation but are not currently used.

Other errors include `CONFIG_NOT_FOUND`, `INVALID_CONFIG`, `DATABASE_NOT_FOUND`, `AUTHENTICATION_FAILED`, `SESSION_EXPIRED`, `ENTRY_NOT_FOUND`, `ENTRY_NO_URL`, `UNSUPPORTED_WORKER`, `REDIRECT_REJECTED`, `WORKER_TIMEOUT`, `WORKER_OUTPUT_INVALID`, `CDP_ENDPOINT_REJECTED`, `SYNC_DOWNLOAD_FAILED`, `MD5_MISMATCH`, `HARDENED_ACL_UNMET`, and `INTERNAL_ERROR`.

The local unlock server may return `PAYLOAD_REQUIRED`, `DECRYPT_FAILED`, `MAX_ATTEMPTS_EXCEEDED`, or `INVALID_SECRET_CHARS`. These are HTTP form responses, not CLI exit codes.

See [Troubleshooting](/troubleshooting) for fixes.
:::
