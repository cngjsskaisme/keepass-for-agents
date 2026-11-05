#Requires -Version 5.1
<#
.SYNOPSIS
  keepass-agent installer (Windows).

.DESCRIPTION
  Verifies the runtime contract and bootstraps the gateway:
    1. Node.js >= 22.18 || >= 23.6 (native TS type stripping — no build step)
    2. npm ci (runtime deps: iconv-lite only)
    3. Python >= 3.10 + pykeepass — offers to create .venv + pip install
       (required for `db create`, `entry add`, and every POSIX path)
    4. KeePass 2.x + KPScript presence — GPL, NOT vendored and never
       downloaded by this script; absence exits 2 with install guidance
    5. Optional user-PATH registration for bin/ (`kp` command)
    6. `kp config init` bootstrap + kpscript/executable path registration
    7. Recommends `kp doctor`

  -DryRun prints the whole plan and changes nothing. All mutating steps
  confirm unless -Yes is given. Never downloads or installs KeePass/KPScript.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\install.ps1
  powershell -ExecutionPolicy Bypass -File tools\install.ps1 -Yes -AddToPath
  powershell -ExecutionPolicy Bypass -File tools\install.ps1 -DryRun
  powershell -ExecutionPolicy Bypass -File tools\install.ps1 -Uninstall -Yes
#>
[CmdletBinding()]
param(
  [switch]$Yes,          # answer yes to every confirmation
  [switch]$DryRun,       # print the plan, change nothing
  [switch]$NoDeps,       # skip npm ci
  [switch]$SkipPython,   # skip python/pykeepass verification + venv offer
  [switch]$AddToPath,    # prepend <repo>\bin to the USER PATH (setx-equivalent)
  [switch]$Uninstall     # remove PATH registration; guided config removal
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot
$ConfigDir = Join-Path $env:USERPROFILE '.config\keepass-agent'
$ConfigPath = Join-Path $ConfigDir 'config.toml'
$BinDir = Join-Path $RepoRoot 'bin'
$Exit = 0

function Info($m)  { Write-Host "[install] $m" }
function Warn($m)  { Write-Warning $m }
function Step($m)  { Write-Host "`n=== $m ===" -ForegroundColor Cyan }
function Confirm($q) {
  if ($Yes) { return $true }
  $r = Read-Host "$q [y/N]"
  return $r -match '^(?i)y(es)?$'
}
function Find-Exe($name) {
  $c = Get-Command $name -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  return $null
}
function Test-NodeVersion($v) {
  # engines: >=22.18 || >=23.6
  if ($v -notmatch 'v?(\d+)\.(\d+)') { return $false }
  $maj = [int]$Matches[1]; $min = [int]$Matches[2]
  return ($maj -ge 24) -or ($maj -eq 23 -and $min -ge 6) -or ($maj -eq 22 -and $min -ge 18)
}
function Backup-ConfigDir {
  if (-not (Test-Path $ConfigDir)) { return $null }
  $dst = "$ConfigDir.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
  if ($DryRun) { Info "DRY-RUN would back up $ConfigDir -> $dst"; return $dst }
  Copy-Item $ConfigDir $dst -Recurse
  Info "existing config backed up to $dst"
  return $dst
}

# ------------------------------------------------------------------ uninstall
if ($Uninstall) {
  Step "Uninstall keepass-agent (dry-run default: confirm each step)"
  # 1. PATH registration
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if ($userPath -and ($userPath -split ';') -contains $BinDir) {
    Info "user PATH contains $BinDir"
    if (Confirm 'Remove it from the user PATH?') {
      if (-not $DryRun) {
        $new = ($userPath -split ';' | Where-Object { $_ -and $_ -ne $BinDir }) -join ';'
        [Environment]::SetEnvironmentVariable('Path', $new, 'User')
        Info 'PATH entry removed'
      } else { Info 'DRY-RUN skipped' }
    }
  } else { Info "no PATH registration found for $BinDir" }
  # 2. npm global link (if `npm link` was used)
  $kpShim = Find-Exe 'kp'
  if ($kpShim -and $kpShim -notlike "$RepoRoot*") { Info "a 'kp' shim exists at $kpShim — run 'npm unlink -g keepass-agent' here if this repo was linked" }
  # 3. config dir — never silently delete
  if (Test-Path $ConfigDir) {
    Warn "config dir $ConfigDir still exists (contains audit log, policy, sessions)"
    if (Confirm 'Back it up and remove it?') {
      Backup-ConfigDir | Out-Null
      if (-not $DryRun) { Remove-Item $ConfigDir -Recurse -Force; Info 'config dir removed' }
    }
  }
  # 4. hardened leftovers
  $task = Get-ScheduledTask -TaskName 'kp-credential-service' -ErrorAction SilentlyContinue
  if ($task) {
    Warn "Scheduled Task 'kp-credential-service' is still registered (Hardened Mode)"
    if (Confirm 'Unregister it?') {
      if (-not $DryRun) { Unregister-ScheduledTask -TaskName 'kp-credential-service' -Confirm:$false; Info 'task unregistered' }
    }
    Warn "the service account (kpa-svc) and state dir (C:\ProgramData\keepass-agent) are NOT auto-removed — see docs/operations.md rollback"
  }
  Info "uninstall done. KDBX vault files were never touched."
  exit 0
}

# ---------------------------------------------------------------------- plan
Step 'keepass-agent install plan'
Info "repo:       $RepoRoot"
Info "config dir: $ConfigDir"
Info "mode:       $(if ($DryRun) {'DRY-RUN (no changes)'} else {'install'})"
@'
Steps:
  1. Backup existing config (if any)
  2. Verify Node.js >=22.18 || >=23.6
  3. npm ci (runtime deps)
  4. Verify Python >=3.10 + pykeepass (offer .venv setup)
  5. Verify KeePass 2.x + KPScript (NOT installed by this script — GPL)
  6. PATH registration for bin\ (optional)
  7. kp config init + keepass.* path registration
'@ | Write-Host
if ($DryRun) { Info 'dry-run complete — re-run without -DryRun to apply'; }
if ($DryRun) { exit 0 }

# --------------------------------------------------------------- 1. backup
if ((Test-Path $ConfigPath) -and (Confirm "existing config.toml found — back up $ConfigDir first?")) {
  Backup-ConfigDir | Out-Null
}

# ------------------------------------------------------------------ 2. node
Step 'Node.js'
$node = Find-Exe 'node'
if (-not $node) { Warn 'node not found on PATH'; Warn 'install Node.js >= 22.18 or >= 23.6 from https://nodejs.org (or nvm-windows), then re-run'; exit 3 }
$ver = (& node --version).Trim()
Info "node $ver at $node"
if (-not (Test-NodeVersion $ver)) { Warn "node $ver is below the required >=22.18 || >=23.6 (native TS type stripping)"; exit 3 }

# ----------------------------------------------------------------- 3. npm ci
if (-not $NoDeps) {
  Step 'npm ci'
  Push-Location $RepoRoot
  try { & npm ci; if ($LASTEXITCODE -ne 0) { Warn 'npm ci failed'; exit 4 } }
  finally { Pop-Location }
} else { Info 'npm ci skipped (-NoDeps)' }

# ------------------------------------------------------------------ 4. python
$python = $null
if (-not $SkipPython) {
  Step 'Python + pykeepass'
  $venvPy = Join-Path $RepoRoot '.venv\Scripts\python.exe'
  if (Test-Path $venvPy) {
    $python = $venvPy
  } else {
    foreach ($cand in 'python', 'python3', 'py') {
      $p = Find-Exe $cand
      if ($p) { $python = $p; break }
    }
  }
  if (-not $python) {
    Warn 'no Python interpreter found (looked for .venv, python, python3, py)'
    Warn 'install Python >= 3.10 from https://python.org, then re-run or: python -m venv .venv; .venv\Scripts\python -m pip install -r requirements.txt'
  } else {
    $pv = (& $python -c 'import sys;print("%d.%d" % sys.version_info[:2])' 2>$null)
    if (-not $pv -or [version]$pv -lt [version]'3.10') {
      Warn "$python reports '$pv' — Python >= 3.10 required"
      $python = $null
    } else {
      Info "python $pv at $python"
      & $python -c 'import pykeepass' 2>$null
      if ($LASTEXITCODE -ne 0) {
        Warn "pykeepass not installed for $python"
        if (Confirm "create .venv in $RepoRoot and pip install -r requirements.txt?") {
          if (-not (Test-Path $venvPy)) { & $python -m venv (Join-Path $RepoRoot '.venv') }
          & (Join-Path $RepoRoot '.venv\Scripts\python.exe') -m pip install -r (Join-Path $RepoRoot 'requirements.txt')
          if ($LASTEXITCODE -ne 0) { Warn 'pip install failed — retry manually: .venv\Scripts\python -m pip install -r requirements.txt' }
          else { $python = Join-Path $RepoRoot '.venv\Scripts\python.exe'; Info 'pykeepass installed into .venv' }
        }
      } else { Info 'pykeepass importable' }
    }
  }
} else { Info 'python check skipped (-SkipPython)' }

# ------------------------------------------------------- 5. KeePass/KPScript
Step 'KeePass 2.x + KPScript'
$kpCandidates = @(
  (Join-Path $RepoRoot 'tools\keepass\KPScript.exe'),
  "$env:ProgramFiles\KeePass Password Safe 2\KPScript.exe",
  "${env:ProgramFiles(x86)}\KeePass Password Safe 2\KPScript.exe"
)
$kpscript = $kpCandidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
$kpExeCandidates = @(
  (Join-Path $RepoRoot 'tools\keepass\KeePass.exe'),
  "$env:ProgramFiles\KeePass Password Safe 2\KeePass.exe",
  "${env:ProgramFiles(x86)}\KeePass Password Safe 2\KeePass.exe"
)
$keepassExe = $kpExeCandidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if ($kpscript) { Info "KPScript: $kpscript" } else {
  Warn @'
KPScript.exe not found. KeePass 2.x + KPScript are GPL and are NOT
installed by this script — see tools\keepass\README.md:
  1. download KeePass 2.x and KPScript from https://keepass.info/download.html
  2. place KeePass.exe, KPScript.exe, KeePassLibN.*.dll into tools\keepass\
  3. re-run this installer (or: kp config set keepass.kpscript <path>)
'@
  $Exit = 2
}
if ($keepassExe) { Info "KeePass: $keepassExe" } else { Warn 'KeePass.exe not found (needed for GUI unlock / master key rotation)' }

# -------------------------------------------------------------------- 6. PATH
Step 'PATH / shim'
if ($AddToPath) {
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (($userPath -split ';') -contains $BinDir) { Info "$BinDir already on user PATH" }
  else {
    [Environment]::SetEnvironmentVariable('Path', (($userPath, $BinDir | Where-Object { $_ }) -join ';'), 'User')
    Info "added $BinDir to user PATH (open a new shell to pick it up)"
  }
} else {
  Info "to run 'kp' from anywhere, either:"
  Info "  • re-run with -AddToPath (prepends $BinDir to your user PATH), or"
  Info "  • npm link              (creates the global 'kp' shim), or"
  Info "  • call $BinDir\kp.cmd / bin\kp.ps1 directly"
}

# ------------------------------------------------------------ 7. config init
Step 'config bootstrap'
$kp = @('node', (Join-Path $RepoRoot 'src\cli\kp.ts'))
if (Test-Path $ConfigPath) { Info "config exists: $ConfigPath" }
else {
  & $kp[0] $kp[1] config init | Out-Null
  Info "config initialized: $ConfigPath"
}
if ($kpscript -and ((& $kp[0] $kp[1] config show | ConvertFrom-Json).config.keepass.kpscript) -eq '') {
  & $kp[0] $kp[1] config set keepass.kpscript $kpscript | Out-Null
  Info "keepass.kpscript <- $kpscript"
}
if ($keepassExe -and ((& $kp[0] $kp[1] config show | ConvertFrom-Json).config.keepass.executable) -ne $keepassExe) {
  & $kp[0] $kp[1] config set keepass.executable $keepassExe | Out-Null
  Info "keepass.executable <- $keepassExe"
}

# --------------------------------------------------------------------- done
Step 'install complete'
if ($Exit -eq 2) { Warn 'KPScript still missing — finish the KeePass install, then run: kp doctor' }
else { Info 'next steps:' }
Info "  kp doctor                      # verify every dependency"
Info "  kp db add personal --path <kdbx>"
Info "  kp unlock --db personal"
exit $Exit
