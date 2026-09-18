@echo off
rem Uninstall autostart (registry Run key + legacy scheduled task)
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v CampusNetKeepAlive /f
schtasks /Delete /TN "CampusNetAutoLogin" /F >nul 2>&1
echo.
echo Uninstalled. Keepalive will not start at logon anymore.
echo If a daemon is still running, close it in Task Manager (powershell.exe).
pause
