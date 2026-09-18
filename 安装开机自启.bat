@echo off
rem Register scheduled task for auto start at logon
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_autostart.ps1"
pause
