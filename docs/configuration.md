---
title: Configuration & permissions
description: Manage KeePass databases, agent permissions, and advanced gateway settings.
---

# Configuration & permissions

Most users need to do just two things: **connect a KeePass database** and **limit what each agent can access**.

## Where settings are stored

- **Windows:** `%USERPROFILE%/.config/keepass-agent/config.toml`
- **Linux:** `~/.config/keepass-agent/config.toml`

Use `kp config show` to inspect settings and `kp config validate` to check them. Never put a master password in this file.

## 1. Start with a limited policy

::: danger Initial permissions are broad
`kp config init` currently creates `[agents.default]` with `allowed = ["*"]`. This is a first-run convenience, **not** a secure default. Restrict or remove it before connecting an untrusted agent.
:::

```sh
kp config set agents.default.allowed "db.list,db.info,unlock,status,search,lock"
kp config set agents.assistant.allowed "unlock,status,search,login,lock"
kp config set agents.assistant.allowed_hosts "github.com"
kp config validate
```

The example gives `assistant` permission to log in only to the `github.com` host family. For stronger control, limit it to specific entry IDs using `allowed_entries`.

## 2. Choose which accounts an agent may use

| Setting | Meaning | Example |
| --- | --- | --- |
| `allowed` | Actions the agent may request | `search`, `login`, `status` |
| `require_approval` | Actions that must use an available browser approval flow | `entry.add` |
| `allowed_entries` | Entry IDs, titles, or site patterns the agent may use | `uuid:AB12CD34` |
| `denied_entries` | Explicitly blocked entries; takes precedence | `*prod*` |
| `allowed_hosts` | Destination hosts for login workers | `github.com` |

For example, this section in `config.toml` restricts an agent named `assistant`:

```toml
[agents.assistant]
allowed = ["search", "status", "unlock", "login", "lock"]
allowed_entries = ["github.com"]
allowed_hosts = ["github.com"]
denied_entries = ["*prod*"]
```

::: warning Identity is declared, not verified
`--agent assistant` or `KEEPASS_AGENT_ID=assistant` selects a policy, but **Standard Mode does not authenticate the process** using that name. The service account and file permissions—not the name alone—must enforce a trust boundary. See [Security](/security).
:::

## 3. Other important settings

| Section | Purpose | When to change it |
| --- | --- | --- |
| `[keepass]` | KeePass/KPScript locations, default database | Installing on Windows |
| `[databases.<alias>]` | KDBX path, optional key file, session timeout | Connecting a database |
| `[unlock]` | Local browser approval host/port | Custom local setup |
| `[cdp]` | Browser endpoint and context isolation | Using website login |
| `[mcp]` / `[mcp.clients.*]` | MCP client-to-agent name mapping | Using multiple clients |
| `[hardened]` | Separate Credential Service and IPC isolation | Admin-managed Hardened Mode |
| `[policy]` | Audit log rotation size | Adjusting audit retention |

Some keys, including `hardened.*`, `cdp.*`, and `mcp.*`, are **operator-managed** and cannot be changed through `kp config set`. Edit `config.toml` using a trusted operator account instead.

::: details Advanced: example configuration structure
This shows the section layout, **not** a ready-to-copy production configuration. Replace all paths, IDs, and hostnames with your own values.

```toml
schema_version = 1

[keepass]
default_database = "personal"
executable = "C:/Program Files/KeePass Password Safe 2/KeePass.exe"
kpscript = "C:/path/to/KPScript.exe"

[databases.personal]
path = "C:/path/to/personal.kdbx"
session_timeout = 900
unlock_method = "local-web"

[unlock]
host = "127.0.0.1"
port = 8765
auto_open_browser = true

[cdp]
endpoint = "http://127.0.0.1:9222"
allow_default_context = false

[mcp]
agent = "assistant"

[agents.assistant]
allowed = ["unlock", "status", "search", "login", "lock"]
allowed_entries = ["github.com"]
allowed_hosts = ["github.com"]

[policy]
audit_max_bytes = 1048576

[hardened]
enabled = false
```

Hardened Mode requires additional platform-specific account, IPC, and ACL settings, normally written by `tools/setup-hardened.sh` or `tools/setup-hardened.ps1`. Do not enable it by changing only `enabled`; see [Operations](/operations).

The local unlock form uses an encrypted POST body even if an older configuration still contains the deprecated `transport` setting.
:::

## 4. Audit and configuration upgrades

- `kp audit --limit 20` reads permitted recent audit records.
- `kp config migrate` saves pending `schema_version` upgrades.
- `kp doctor` highlights missing permissions, invalid paths, or outdated configuration.

Audit records contain action metadata, decisions, and result codes—not raw password or cookie values. Audit is stored under `~/.config/keepass-agent/audit.log` and rotated by `policy.audit_max_bytes` (default 1 MiB).

::: danger Management-console access
Granting `ui` to an agent may permit operator-equivalent management access. Reserve it for principals trusted to manage the configuration. An `ui.agents.write` action cannot be granted to a declared agent through the management API.
:::

Need help? Start with [Troubleshooting](/troubleshooting), or read the [Security model](/security) before enabling Hardened Mode.
