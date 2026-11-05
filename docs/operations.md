---
title: Operations
description: Manage sessions, provision Hardened Mode, and back up or restore a KeePass deployment.
---

# Operations

This guide is for people **running or maintaining** keepass-agent. If you only want to connect an existing KeePass database, start with [Quick start](/quickstart).

## Everyday tasks

| Task | Command |
| --- | --- |
| Check the current mode and sessions | `kp status` |
| Diagnose dependencies and service health | `kp doctor` |
| Open the local management console | `kp ui` |
| Inspect recent permitted actions | `kp audit --limit 20` |
| Lock a KeePass database | `kp lock --db personal` |

::: warning Before enabling Hardened Mode
Hardened Mode changes **OS accounts and file access permissions**. Back up the KDBX file and `config.toml`, review the proposed changes, and make sure you can restore access as a KeePass user.
:::

## Enable Hardened Mode

Hardened Mode moves credential operations to a separate **Credential Service** account. Basic installation does not enable it.

### 1. Review the changes

::: code-group

```sh [Linux · dry run]
sudo bash tools/setup-hardened.sh --dry-run
```

```powershell [Windows · dry run (Administrator)]
powershell -ExecutionPolicy Bypass -File tools\setup-hardened.ps1 -DryRun
```

:::

### 2. Apply the setup

Only after reviewing the plan:

::: code-group

```sh [Linux · administrator]
sudo AGENT_USERS="alice bot-runner" bash tools/setup-hardened.sh
```

```powershell [Windows · Administrator]
powershell -ExecutionPolicy Bypass -File tools\setup-hardened.ps1
```

:::

Replace `alice bot-runner` with the **existing OS usernames** allowed to request work from the service. The script creates the service account, configures filesystem access, and registers service startup.

### 3. Verify as an agent

```sh
kp status
kp doctor
```

Verify that `mode` is `hardened`, the service is reachable, and `isolation.ok` is `true`. A result such as `HARDENED_ACL_UNMET` is a **blocker**, not something to bypass.

::: details Advanced: what setup changes
- **Linux:** Provisions a dedicated service account and agent group, a protected state directory, a systemd service, and file ownership/permissions for registered KDBX files.
- **Windows:** Creates a service user, grants limited NTFS permissions with `icacls`, and creates a Scheduled Task.
- The service's IPC token is protected with filesystem ACLs. The service re-evaluates access policies for credential operations.
- The operator's KeePass GUI may need an explicit file-access grant after KDBX ownership changes. Do not blindly relax permissions for every user.
- Linux `peer_verify=strict` uses procfs and `ss` and needs configured allowed UIDs. Kernel-native peer identification is not yet available across the supported platforms.
- A Linux **user-level** systemd unit created by the regular installer is a convenience only; it does **not** provide a separate security principal.
- `KEEPASS_AGENT_SERVICE_SELFTEST` is a **test-only** bypass. Never enable it for real deployments.

See [Security implementation reference](/security-internals) for the exact trust model.
:::

## Check or restart the service

::: code-group

```sh [Linux]
systemctl status kp-credential
sudo systemctl restart kp-credential
journalctl -u kp-credential -f
```

```powershell [Windows]
Get-ScheduledTask -TaskName kp-credential-service | Get-ScheduledTaskInfo
Start-ScheduledTask -TaskName kp-credential-service
Stop-ScheduledTask -TaskName kp-credential-service
```

:::

If Hardened Mode is enabled but the service is down, credential operations fail with `HARDENED_SERVICE_UNAVAILABLE`; they do not revert to Standard Mode.

## Backup and restore

| Save | Why |
| --- | --- |
| Registered `.kdbx` files | Contain your KeePass accounts |
| `~/.config/keepass-agent/config.toml` | Contains paths and access policies |
| `audit.log` (optional) | Records prior activity |
| Session files (optional) | Encrypted and replaceable by unlocking again |

1. Copy your KDBX files and configuration **before** changing ownership or upgrading.
2. Store the backups somewhere your AI agent cannot modify.
3. Restore the configuration and database files if needed, then run `kp doctor`. Confirm the service account can read the restored files.

A successful `db sync --pull` keeps a neighboring `<file>.kdbx.bak` backup of the replaced file.

## Upgrade or roll back

```sh
git pull
npm ci
kp doctor
kp config migrate
```

After upgrading Hardened Mode, restart its systemd service or Windows Scheduled Task and re-check isolation. A newer configuration schema may not be compatible with an older binary; inspect `doctor` warnings before rolling back.

::: danger Removing Hardened Mode
Do not immediately delete its service account or state directory: the account may own your KDBX files. First preserve your backups, restore the appropriate file ownership/ACLs, and verify access through KeePass. Then follow the setup script's rollback guidance and the documented installer uninstall options.
:::

For symptoms and error codes, continue to [Troubleshooting](/troubleshooting).
