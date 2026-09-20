# =========================================================
#  设置开机自启 (Windows 计划任务, 无需管理员权限)
#  效果: 每次登录Windows后, 自动在后台启动保活守护
#
#  为什么用计划任务而不是注册表 Run 键:
#    Run 键由 explorer 在 shell 初始化之后才逐个处理, 在自启项多、
#    开机偏慢的机器上常常要等 40 秒以上才轮到它; 而计划任务的"登录时"
#    触发器由任务计划服务直接拉起, 明显更早, 网络空窗期更短。
#    两者都在当前用户权限下运行, 都不需要管理员。
# =========================================================
$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$taskName  = "CampusNetKeepAlive"
$legacy    = "CampusNetAutoLogin"       # 更早期版本用过的任务名, 一并清理
$runKey    = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$valueName = "CampusNetKeepAlive"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$target    = Join-Path $scriptDir "campus_net.ps1"
$vbs       = Join-Path $scriptDir "silent_start.vbs"

if (-not (Test-Path $target)) {
    Write-Host "[ERROR] campus_net.ps1 not found: $target" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $vbs)) {
    Write-Host "[ERROR] silent_start.vbs not found: $vbs" -ForegroundColor Red
    exit 1
}

try {
    # 1) 注册计划任务: 登录时触发、零延迟、静默运行
    $action    = New-ScheduledTaskAction -Execute "wscript.exe" -Argument ('"' + $vbs + '"')
    $trigger   = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
    try { $trigger.Delay = "PT0S" } catch { }   # 不延迟
    $settings  = New-ScheduledTaskSettingsSet `
                    -AllowStartIfOnBatteries `
                    -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable `
                    -MultipleInstances IgnoreNew `
                    -ExecutionTimeLimit ([TimeSpan]::Zero)   # 0 = 不限时长(守护是常驻进程, 默认3天会被强杀)
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Limited

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Settings $settings -Principal $principal -Force `
        -Description "GZIST-NetKeeper 校园网保活守护(登录时静默启动, 无需管理员权限)" | Out-Null
    Write-Host "[OK] 开机自启已设置(计划任务: 登录时触发, 零延迟, VBS静默启动)" -ForegroundColor Green

    # 2) 清理旧的自启方式(注册表 Run 键 + 历史任务名), 避免重复启动
    Remove-ItemProperty -Path $runKey -Name $valueName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $legacy -Confirm:$false -ErrorAction SilentlyContinue

    # 3) 立即启动一次, 无需重启电脑(脚本内部有单实例保护, 重复启动无害)
    Start-ScheduledTask -TaskName $taskName
    Write-Host "[OK] 保活守护已立即启动(无需重启电脑)" -ForegroundColor Green
    Write-Host ""
    Write-Host "验证方法: 双击 诊断检测.bat, 看第 5、6 项是否正常" -ForegroundColor Gray
    Write-Host "验证方法: 打开 campusnet_log.txt 看最新一条 [保活守护已启动]" -ForegroundColor Gray
    Write-Host "取消自启: 双击 卸载开机自启.bat" -ForegroundColor Gray
} catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
