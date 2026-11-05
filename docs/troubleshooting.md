---
title: Troubleshooting
description: Fix common setup, permission, login, and synchronization problems.
---

# Troubleshooting

Start with:

```sh
kp doctor
```

The command reports **ok**, **warn**, or **fail** for each check, with a suggested fix. If `kp` is not on your PATH, use `node src/cli/kp.ts doctor`.

## Common problems

| Symptom or code | Likely cause | What to do |
| --- | --- | --- |
| `POLICY_DENIED` | Agent lacks an action/entry/host permission | Review `[agents.*]`; start with [Configuration](/configuration) |
| `UNLOCK_REQUIRED` | KeePass database is locked | Run `kp unlock --db <alias>` and approve locally |
| `AMBIGUOUS_ENTRY` | More than one account matches | Search first, then use `--entry <uuid>` |
| `python.pykeepass` fail | Python dependencies missing | Create a virtual environment and install `requirements.txt` |
| KeePass/KPScript not found | Windows executables missing or separated | Follow [KeePass setup](/keepass-binaries) |
| `HARDENED_SERVICE_UNAVAILABLE` | Credential Service not running | Check service status in [Operations](/operations) |
| `HARDENED_ACL_UNMET` | File permissions or service ownership are incorrect | Inspect `doctor` failures; review Hardened Mode setup |
| `CDP_ENDPOINT_REJECTED` | CDP endpoint is not loopback | Use a trusted local endpoint (`127.0.0.1`) |
| `WORKER_OUTCOME_UNCERTAIN` | Login worker could not confirm success | Check the website and the worker's documented limits |
| `MD5_MISMATCH` / `SYNC_DOWNLOAD_FAILED` | Remote file download or integrity check failed | Do not overwrite the KDBX; inspect remote sync and backups |

## If installation fails

::: code-group

```powershell [Windows]
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

```sh [Linux]
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

:::

On Windows, KeePass and KPScript must be installed separately. On Linux, PyKeePass handles the database operations.

## If permissions suddenly stop working

An existing configuration with no `[agents.*]` sections denies gated commands. Review the agent policy rather than enabling wildcard access. After an upgrade, run:

```sh
kp config validate
kp config migrate
kp doctor
```

A `config.schema` warning can indicate that the file needs migration—or was written by a newer version. Review compatibility before migrating.

## If Hardened Mode is unavailable

1. Verify the Credential Service is running.
2. Run `kp status` and `kp doctor` to inspect isolation checks.
3. Review the token, KDBX permissions, and service account setup.
4. Do **not** disable Hardened Mode simply to bypass an isolation failure.

See [Operations](/operations) for Windows and Linux service commands.

::: details Remote Sprite synchronization and approval problems
- `INVALID_REMOTE_PATH` / `INVALID_SPRITE`: use a supported absolute POSIX remote path and a simple Sprite name; spaces and shell metacharacters are rejected.
- `REMOTE_NEWER` / `LOCAL_NEWER`: reconcile which copy is authoritative before using `--pull` or `--force`.
- Cookie capture requires a browser approval. If the browser did not open, find the `awaiting_user_input` URL in the appropriate command output.
- The Sprite unlock relay may report HTTP 502 if the remote unlock server or `sprite exec` channel is unavailable. Review the relay in [Operations](/operations) before retrying.
:::
