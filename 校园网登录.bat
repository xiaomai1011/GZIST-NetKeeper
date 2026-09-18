@echo off
rem Manual login with visible window
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0campus_net.ps1" -Interactive
pause
