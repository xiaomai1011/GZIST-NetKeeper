@echo off
chcp 936 >nul
setlocal
title GZIST NetKeeper - install logon task
set "EXE=%~dp0build\windows-amd64\GZIST NetKeeper.exe"
set "TASK=GZIST-NetKeeper"
set "LOG=%TEMP%\nk-task.log"

echo ============================================
echo   GZIST NetKeeper - 安装开机自启（登录任务）
echo ============================================
echo.
if not exist "%EXE%" (
  echo [X] 找不到程序：
  echo     %EXE%
  echo     请把这个文件放在仓库根目录再运行。
  echo.
  pause
  exit /b 1
)

net session >nul 2>&1
if not "%errorlevel%"=="0" (
  echo [!] 需要管理员权限，接下来会弹 UAC，请点「是」。
  echo.
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  if errorlevel 1 (
    echo.
    echo [X] 提权被取消或失败，什么都没改。
    echo     请右键这个文件 -^> 「以管理员身份运行」。
    pause
  )
  exit /b
)

echo [1/4] 创建登录任务 ...
schtasks /Create /F /SC ONLOGON /TN "%TASK%" /TR "\"%EXE%\" --mygo-opened-at-login" >"%LOG%" 2>&1
if errorlevel 1 goto failed

echo [2/4] 复核任务 ...
schtasks /Query /TN "%TASK%" >nul 2>&1
if errorlevel 1 goto failed

echo [3/4] 删除旧的注册表自启项 ...
powershell -NoProfile -Command "Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'io.github.xiaomai1011.gzist-netkeeper' -ErrorAction SilentlyContinue" >nul 2>&1

echo [4/4] 完成。
echo.
echo [OK] 现在由「任务计划程序」在登录时启动，不再排在 Run 队列后面。
echo      可在 任务计划程序 -^> 任务计划程序库 里看到 %TASK%
echo      重启一次后，日志里对比 进程启动 与 登录成功 的时间。
echo.
pause
exit /b 0

:failed
echo.
echo [X] schtasks 失败，什么都没改（注册表自启项保持原样）。
echo     schtasks 的输出：
type "%LOG%"
echo.
pause
exit /b 1
