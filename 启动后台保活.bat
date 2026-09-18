@echo off
rem Start campus net keepalive daemon silently (no window at all)
rem NOTE: keep this file ASCII-only, cmd.exe mis-parses UTF-8 Chinese text
wscript.exe "%~dp0silent_start.vbs"
echo Background keepalive daemon started (hidden).
echo Verify: open campusnet_log.txt, look for the newest "keepalive started" line.
echo To stop: Task Manager - find powershell.exe
pause
