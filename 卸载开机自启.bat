@echo off
rem Uninstall autostart (scheduled task + legacy names + old registry Run key)
schtasks /Delete /TN "CampusNetKeepAlive" /F >nul 2>&1
schtasks /Delete /TN "CampusNetAutoLogin" /F >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v CampusNetKeepAlive /f >nul 2>&1
echo.
echo Uninstalled. Keepalive will not start at logon anymore.
echo If a daemon is still running, close it in Task Manager (powershell.exe).
pause
