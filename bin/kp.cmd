@echo off
rem kp — KeePass agent CLI launcher (cmd.exe). Logic lives in src/.
setlocal
set "HERE=%~dp0.."
node "%HERE%\src\cli\kp.ts" %*
exit /b %ERRORLEVEL%
