#Requires -Version 5.1
<#
.SYNOPSIS
  setup-hardened.ps1 — Hardened Mode provisioning (Windows). Run elevated.

.DESCRIPTION
  Provisions the full isolation contract verified by src/service/acl.ts:
    1. Dedicated local service account (default: kpa-svc; production should
       prefer a gMSA — note below)
    2. State dir ACL'd to service + SYSTEM + Administrators (sessions/socket/
       token live inside; NO agent grant on the dir itself)
    3. Registered KDBX files — inheritance removed, granted to service +
       SYSTEM + Administrators only (agents cannot read the vault)
    4. Service read+modify on the operator config.toml (db create registers
       service-side; agents keep their existing access)
    5. Scheduled Task 'kp-credential-service' running src/service/service.ts
       as the service account at startup
    6. Capability-token file ACL'd service + SYSTEM + Admins + agent (R)
       after first service start — it IS the IPC authorization boundary
    7. config.toml [hardened] via tools/lib/write-hardened-config.mjs;
       allowed_sids is auto-collected from the REAL ACLs (raw SIDs —
       locale-proof), including any Mandatory Label integrity ACEs

  Prints a full PLAN and requires confirmation (operator typo protection);
  -DryRun prints the plan only. On failure a rollback block is printed.
  Node cannot ACL a named pipe — the token-file ACL is the enforced caller
  check on Windows (see docs/security.md).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\setup-hardened.ps1 -DryRun
  powershell -ExecutionPolicy Bypass -File tools\setup-hardened.ps1
#>
[CmdletBinding()]
param(
  [string]$ServiceUser = 'kpa-svc',
  [string]$AgentSid = '',               # SID of the agent/operator principal allowed to call the service; default = current user
  [string]$ServiceStateDir = 'C:\ProgramData\keepass-agent',
  [string]$PipeName = 'keepass-agent-svc',
  [string]$ConfigPath = "$env:USERPROFILE\.config\keepass-agent\config.toml",
  [switch]$DryRun,                      # plan only
  [switch]$Yes,                         # skip the confirmation prompt
  [switch]$NoStart                      # register the task but don't start it
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$TaskName = 'kp-credential-service'
$TokenFile = Join-Path $ServiceStateDir 'ipc-token'
$ProfileDir = Join-Path $ServiceStateDir 'profile'
$Wrapper = Join-Path $ServiceStateDir 'run-service.cmd'

function Info($m) { Write-Host "[setup] $m" }
function Warn($m) { Write-Warning $m }
function Step($m) { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Confirm($q) {
  if ($Yes) { return $true }
  $r = Read-Host "$q [y/N]"
  return $r -match '^(?i)y(es)?$'
}
function Rollback {
  Warn @"
--- rollback guide (partial state may exist) ---
Stop-ScheduledTask -TaskName '$TaskName' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false
Remove-LocalUser -Name '$ServiceUser'
Remove-Item -Recurse -Force '$ServiceStateDir'
# restore kdbx ACLs manually if changed (files were granted to $ServiceUser)
# remove the [hardened] section from $ConfigPath
"@
}
function Get-IcaclsPrincipals($path) {
  # Same shape as acl.ts parseIcaclsPrincipals — `PRINCIPAL:(perms)` lines.
  $out = & icacls $path 2>&1 | Out-String
  $list = @()
  foreach ($raw in ($out -split "`n")) {
    $line = $raw
    if ($line.ToLower().StartsWith($path.ToLower())) { $line = $line.Substring($path.Length) }
    $m = [regex]::Match($line, '^\s*(.+?):\(')
    if ($m.Success) { $list += $m.Groups[1].Value.Trim().ToLower() }
  }
  return $list
}
function Resolve-SidDisplay($sid) {
  try { return (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value }
  catch { return "*$sid" }   # unresolvable → raw sid form still matches icacls output
}
function Invoke-Icacls {
  # icacls does not throw — check the exit code so a failed grant cannot pass
  # silently as provisioned (the step tracker + trap then print rollback).
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$IcaclsArgs)
  $out = & icacls @IcaclsArgs 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) {
    throw "icacls failed (exit $LASTEXITCODE): icacls $($IcaclsArgs -join ' ') — $out"
  }
}

# ------------------------------------------------------------------ preflight
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  if ($DryRun) { Warn 'not elevated — dry-run plan only' } else { throw 'run this script from an elevated (Administrator) shell' }
}
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) { throw 'node not found on PATH' }
$nodeExe = $node.Source
if (-not (Test-Path $ConfigPath)) { throw "config.toml not found at $ConfigPath — run 'kp config init' as the operator first" }

if (-not $AgentSid) { $AgentSid = $me.User.Value }
$svcExists = $false; $svcSid = $null
try { $svcSid = (Get-LocalUser -Name $ServiceUser -ErrorAction Stop).SID.Value; $svcExists = $true } catch {}

# Registered KDBX paths from the operator config (via the real CLI).
$kdbxPaths = @()
try {
  $show = & $nodeExe (Join-Path $RepoRoot 'src\cli\kp.ts') config show | ConvertFrom-Json
  $kdbxPaths = @($show.config.databases.PSObject.Properties | ForEach-Object { $_.Value.path })
} catch { Warn "could not read databases from config: $_" }

# ---------------------------------------------------------------------- plan
Step 'Hardened Mode provisioning plan'
@"
  service account : $ServiceUser $(if ($svcExists) {"(exists, sid $svcSid)"} else {'(will create — random password, gMSA recommended for production)'})
  agent principal : $AgentSid ($(Resolve-SidDisplay $AgentSid))
  state dir       : $ServiceStateDir  (service+SYSTEM+Admins full; profile\ for service sessions)
  named pipe      : \\.\pipe\$PipeName
  token file      : $TokenFile (service+SYSTEM+Admins F, agent R — applied after service start)
  config          : $ConfigPath (service read+modify)
  kdbx files      : $($kdbxPaths.Count) registered → service+SYSTEM+Admins only
$(foreach ($p in $kdbxPaths) { "                    - $p`n" })
  autostart       : Scheduled Task '$TaskName' at startup as $ServiceUser $(if ($NoStart) {'(register only, --NoStart)'} else {'(register + start)'})
  config write    : [hardened] enabled=true endpoint=$PipeName token_file state_dir allowed_sids=<auto-collected>
"@ | Write-Host
if ($DryRun) { Info 'dry-run complete — nothing changed'; exit 0 }
if (-not (Confirm 'Apply this plan?')) { Info 'aborted — nothing changed'; exit 0 }

$done = 'preflight'
trap { Warn "failed at step: $done — $_"; Rollback; exit 1 }

# --------------------------------------------------------------- 1. account
Step 'service account'
if (-not $svcExists) {
  $pw = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
  $sec = ConvertTo-SecureString $pw -AsPlainText -Force
  New-LocalUser -Name $ServiceUser -Password $sec -PasswordNeverExpires -UserMayNotChangePassword -AccountNeverExpires `
    -Description 'keepass-agent Credential Service (Hardened Mode)' | Out-Null
  $svcSid = (Get-LocalUser -Name $ServiceUser).SID.Value
  Info "created $ServiceUser (sid $svcSid)"
} else {
  # Existing account — we still need its password for the task; regenerate.
  $pw = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
  Set-LocalUser -Name $ServiceUser -Password (ConvertTo-SecureString $pw -AsPlainText -Force)
  Warn "reused existing account $ServiceUser — its password was ROTATED for task registration"
}
$done = 'account'

# --------------------------------------------------------------- 2. state dir
Step 'state dir + ACLs'
New-Item -ItemType Directory -Force -Path $ServiceStateDir, $ProfileDir | Out-Null
# Service + SYSTEM + Administrators only — NO agent grant on the dir (the
# token file gets an explicit agent Read ACE later; nothing else may be read).
Invoke-Icacls $ServiceStateDir /inheritance:r /grant:r "*${svcSid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
Invoke-Icacls $ProfileDir /inheritance:r /grant:r "*${svcSid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
$done = 'statedir'

# ----------------------------------------------------------------- 3. KDBX ACL
Step 'KDBX isolation'
foreach ($p in $kdbxPaths) {
  if (Test-Path $p) {
    Invoke-Icacls $p /inheritance:r /grant:r "*${svcSid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
    Info "acl'd $p"
  } else { Warn "registered KDBX missing: $p — skipped" }
}
$done = 'kdbx'

# -------------------------------------------------------- 4. config access
Step 'config.toml access for the service'
# Service reads the operator config and writes it for service-side
# 'db create' registration (saveConfig does tmp+rename → needs dir create).
Invoke-Icacls (Split-Path -Parent $ConfigPath) /grant "*${svcSid}:(OI)(CI)M"
Invoke-Icacls $ConfigPath /grant "*${svcSid}:M"
$done = 'configacl'

# ------------------------------------------------------- 5. scheduled task
Step "scheduled task '$TaskName'"
# Wrapper sets the environment the service contract requires: the operator's
# config path + a service-owned USERPROFILE (isolated session/DPAPI store).
$nodeQ = $nodeExe
@"
@echo off
set "KEEPASS_AGENT_CONFIG=$ConfigPath"
set "USERPROFILE=$ProfileDir"
cd /d "$RepoRoot"
"$nodeQ" src\service\service.ts %*
"@ | Set-Content -Path $Wrapper -Encoding ascii
Invoke-Icacls $Wrapper /inheritance:r /grant:r "*${svcSid}:(OI)(CI)RX" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
$action = New-ScheduledTaskAction -Execute $Wrapper
$trigger = New-ScheduledTaskTrigger -AtStartup
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
  -User $ServiceUser -Password $pw -RunLevel LeastPrivilege `
  -Description 'keepass-agent Credential Service (Hardened Mode)' | Out-Null
$pw = $null
if (-not $NoStart) { Start-ScheduledTask -TaskName $TaskName }
$done = 'task'

# ------------------------------------------------------- 6. token file ACL
Step 'capability token'
$ok = $false
if (-not $NoStart) {
  for ($i = 0; $i -lt 40 -and -not (Test-Path $TokenFile); $i++) { Start-Sleep -Milliseconds 500 }
  if (Test-Path $TokenFile) { $ok = $true }
}
if ($ok) {
  # The token file IS the caller-authorization boundary on Windows (the pipe
  # cannot carry a Node-set DACL). Grant exactly: service F, SYSTEM F,
  # Admins F, agent R — everything else is a foreign principal.
  Invoke-Icacls $TokenFile /inheritance:r /grant:r "*${svcSid}:F" '*S-1-5-18:F' '*S-1-5-32-544:F' "*${AgentSid}:R"
  Info "token ACL applied: $TokenFile"
} else {
  Warn "token file did not appear at $TokenFile (service not started?)"
  Warn "after the service starts, run:  icacls `"$TokenFile`" /inheritance:r /grant:r `"*${svcSid}:F`" `"*S-1-5-18:F`" `"*S-1-5-32-544:F`" `"*${AgentSid}:R`""
}
$done = 'token'

# ------------------------------------------------ 7. allowed_sids + config
Step 'config.toml [hardened]'
# allowed_sids is an ALLOW-LIST — collect the principals actually granted so
# icacls display quirks (Mandatory Label integrity ACEs, unresolvable sids)
# are captured verbatim rather than assumed.
$principals = @()
if (Test-Path $TokenFile) { $principals += Get-IcaclsPrincipals $TokenFile }
foreach ($p in $kdbxPaths) { if (Test-Path $p) { $principals += Get-IcaclsPrincipals $p } }
# The expected set is always legal even when a file was skipped.
$principals += @("*$svcSid", '*S-1-5-18', '*S-1-5-32-544', "*$AgentSid",
  (Resolve-SidDisplay $svcSid).ToLower(), 'nt authority\system', 'builtin\administrators', (Resolve-SidDisplay $AgentSid).ToLower())
$allowedSids = @($principals | Where-Object { $_ } | Select-Object -Unique)
$sidsJson = '[' + (($allowedSids | ForEach-Object { '"' + ($_ -replace '\\', '\\' -replace '"', '\"') + '"' }) -join ',') + ']'

& $nodeExe (Join-Path $RepoRoot 'tools\lib\write-hardened-config.mjs') --config $ConfigPath `
  --enabled true --endpoint $PipeName --token-file $TokenFile --state-dir $ServiceStateDir `
  --allowed-sids $sidsJson
if ($LASTEXITCODE -ne 0) { throw 'write-hardened-config failed' }
$done = 'config'

# --------------------------------------------------------------------- done
Step 'provisioning complete'
@"
verify (as the agent principal):
  kp status    → mode 'hardened', isolation.ok true, service up
  kp doctor    → hardened.isolation + hardened.service ok

rollback (full undo):
  Stop-ScheduledTask -TaskName '$TaskName'; Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false
  Remove-LocalUser -Name '$ServiceUser'; Remove-Item -Recurse -Force '$ServiceStateDir'
  edit $ConfigPath — remove the [hardened] section (or set enabled = false)

notes:
  - if 'Mandatory Label\...' ACEs appear in icacls output they were captured
    into allowed_sids automatically — do not trim them.
  - kdbx files are now readable only by the service (+SYSTEM/Admins) — KeePass
    GUI access needs its own grant (see docs/operations.md).
  - production deployments should prefer a Group Managed Service Account over
    a local user (the task would not need a stored password).
"@ | Write-Host
