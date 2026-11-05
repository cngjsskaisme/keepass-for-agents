# kp — KeePass agent CLI launcher (PowerShell). Logic lives in src/.
$here = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
& node (Join-Path $here 'src\cli\kp.ts') @args
exit $LASTEXITCODE
