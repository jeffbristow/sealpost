@echo off
REM ===================================================================
REM  Sealpost - apply an update to your existing installation.
REM  Keep this file in the same folder as Install-Update.ps1 and the
REM  Sealpost-x.y.z.sealpost file, then double-click it.
REM ===================================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-Update.ps1"
echo.
pause
