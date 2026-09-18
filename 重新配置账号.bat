@echo off
rem Re-configure account and password
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0campus_net.ps1" -Setup
pause
