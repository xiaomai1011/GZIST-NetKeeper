@echo off
rem Network diagnosis tool
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0campus_net.ps1" -Diag
pause
