@echo off
rem Logout from campus network (for testing auto-relogin)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0logout.ps1"
pause
