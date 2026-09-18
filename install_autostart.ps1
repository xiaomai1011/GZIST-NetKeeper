# =========================================================
#  设置开机自启 (HKCU 注册表 Run 键, 无需管理员权限)
#  效果: 每次登录Windows后, 自动在后台启动保活守护
# =========================================================
$ErrorActionPreference = "Stop"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$runKey    = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$valueName = "CampusNetKeepAlive"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$target    = Join-Path $scriptDir "campus_net.ps1"

if (-not (Test-Path $target)) {
    Write-Host "[ERROR] campus_net.ps1 not found: $target" -ForegroundColor Red
    exit 1
}

$cmd = 'wscript.exe "' + (Join-Path $scriptDir 'silent_start.vbs') + '"'

try {
    Set-ItemProperty -Path $runKey -Name $valueName -Value $cmd -Type String -Force
    Write-Host "[OK] 开机自启已设置(VBS静默启动, 任务栏完全无窗口)" -ForegroundColor Green

    # 立即启动一次, 无需重启电脑(脚本内部有单实例保护, 重复启动无害)
    Start-Process -FilePath "wscript.exe" -ArgumentList "`"$(Join-Path $scriptDir 'silent_start.vbs')`""
    Write-Host "[OK] 保活守护已立即启动(无需重启电脑)" -ForegroundColor Green
    Write-Host ""
    Write-Host "验证方法: 打开 campusnet_log.txt 看最新一条 [保活守护已启动]" -ForegroundColor Gray
    Write-Host "取消自启: 双击 卸载开机自启.bat" -ForegroundColor Gray
} catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
