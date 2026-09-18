# 注销校园网(用已验证成功的接口变体) - 用于测试自动重连
$ErrorActionPreference = "Continue"
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$cfg = Get-Content (Join-Path $dir "campusnet_config.json") -Raw -Encoding UTF8 | ConvertFrom-Json
if (-not $cfg) { Write-Host "未找到配置文件, 请先运行 重新配置账号.bat" -ForegroundColor Red; exit }

$account = $cfg.Account
$ip = $null; $mac = $null
try {
    $ad = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
    $ip = (Get-NetIPAddress -InterfaceAlias $ad.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like "10.*" } | Select-Object -First 1).IPAddress
    $mac = ($ad.MacAddress -replace "[-:]", "").ToUpper()
} catch {}
if (-not $ip) {
    $cfg2 = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | Where-Object { $_.IPAddress | Where-Object { $_ -like "10.*" } } | Select-Object -First 1
    $ip = ($cfg2.IPAddress | Where-Object { $_ -like "10.*" } | Select-Object -First 1)
    $mac = ($cfg2.MACAddress -replace "[-:]", "").ToUpper()
}
if (-not $ip) { Write-Host "未检测到校园网连接" -ForegroundColor Red; exit }

$accParam = [Uri]::EscapeDataString(",0," + $account)
$v = Get-Random -Maximum 99999
# 新版注销接口(2026-09-18 学校升级后验证可用), 旧接口留作兜底
$logoutUrls = @(
    "http://10.0.10.252:801/eportal/?c=ACSetting&a=Logout&ver=1.0&url=drappall&wlan_user_ip=$ip&wlan_user_mac=$mac",
    "http://10.0.10.252:801/eportal/?c=Portal&a=logout&callback=dr1003&login_method=1" +
        "&user_account=$accParam&wlan_user_ip=$ip&wlan_user_mac=$mac" +
        "&wlan_user_ipv6=&wlan_ac_ip=10.128.255.143&wlan_ac_name=&jsVersion=3.3.2&v=$v"
)
$ok = $false
foreach ($logoutUrl in $logoutUrls) {
    try {
        $r = Invoke-WebRequest -Uri $logoutUrl -UseBasicParsing -TimeoutSec 10
        $content = [string]$r.Content
        Write-Host "服务器响应: $content" -ForegroundColor Cyan
        if ($content -match 'Logout succeed' -or $content -match '"result"\s*:\s*"?1"?') {
            $ok = $true; break
        }
    } catch {
        Write-Host "注销请求失败: $($_.Exception.Message)" -ForegroundColor Red
    }
}
if ($ok) {
    Write-Host "已注销, 网络已断开。什么都不用做, " -ForegroundColor Green
    Write-Host "保活守护(约1分钟内)会自动重连恢复网络。" -ForegroundColor Green
} else {
    Write-Host "注销失败(可能本来就不在线)" -ForegroundColor Yellow
}
