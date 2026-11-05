---
title: Installation
description: Install keepass-agent on Windows or Linux and check dependencies.
---

# Installation

Choose your operating system, run the installer, and verify the result with `doctor`.

::: tip Just getting started?
For a complete first-use walkthrough, including connecting your KDBX file, use [Quick start](/quickstart).
:::

## Requirements

| Requirement | Windows | Linux |
| --- | --- | --- |
| Node.js | 22.18+ or 23.6+ | 22.18+ or 23.6+ |
| KeePass access | KeePass 2.x + KPScript | PyKeePass |
| Python 3.10+ / PyKeePass | Needed for entry creation and updates | Required for all KeePass operations |
| Git | To clone the repository | To clone the repository |

::: warning Windows prerequisite
KeePass and KPScript must be installed separately. The installer will **not** download their binaries. See [KeePass and KPScript](/keepass-binaries).
:::

## 1. Clone the repository

```sh
git clone --branch feat/keepass-for-agents --single-branch https://github.com/cngjsskaisme/nougat-worker.git
cd nougat-worker
```

## 2. Install dependencies

::: code-group

```powershell [Windows · PowerShell]
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\install.ps1 -DryRun
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\install.ps1
```

```sh [Linux · Bash]
bash tools/install.sh --dry-run
bash tools/install.sh
```

:::

Review the dry-run output before running the installer. The Windows installer checks KeePass/KPScript and offers to prepare Python dependencies. Linux uses PyKeePass rather than KPScript.

## 3. Verify the installation

```sh
node src/cli/kp.ts doctor
```

`doctor` checks the Node version, configuration, KeePass dependencies, file permissions and—when enabled—Hardened Mode. Resolve any **fail** check before connecting an agent.

::: details Manual installation
If you prefer not to use the installer:

```sh
npm ci
```

Then install Python dependencies:

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

Create the configuration and check the environment:

```sh
node src/cli/kp.ts config init
node src/cli/kp.ts doctor
```

On Windows, set the KPScript location if it was not detected:

```sh
node src/cli/kp.ts config set keepass.kpscript "C:/path/to/KPScript.exe"
```

:::

## Upgrade or remove

| Task | What to do |
| --- | --- |
| Upgrade | `git pull`, `npm ci`, `kp doctor`, then `kp config migrate` |
| Remove on Windows | `tools\install.ps1 -Uninstall` |
| Remove on Linux | `bash tools/install.sh --uninstall` |
| Hardened Mode cleanup | Follow the separate [operations guide](/operations) |

::: warning Back up before changing permissions
Uninstall and Hardened Mode setup may change configuration or file permissions. Back up your KDBX file and configuration first. Basic installation **does not** provide Hardened Mode isolation.
:::
