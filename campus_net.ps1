# =====================================================================
#  广州理工学院校园网自动登录 + 保活脚本
#  认证系统: 城市热点 Dr.COM / eportal
#  登录接口: http://10.0.10.252:801/eportal/
#  用法:
#    campus_net.ps1 -Interactive   手动登录(带输出窗口)
#    campus_net.ps1 -Setup         首次配置/重新配置账号
#    campus_net.ps1 -Watch         后台保活守护(掉线自动重登)
#  参考: github.com/YT-O5/GZIST_CampusNet_AutoLogin (MIT License)
# =====================================================================
param(
    [switch]$Setup,
    [switch]$Watch,
    [switch]$Interactive,
    [switch]$Diag
)

$ErrorActionPreference = "Continue"
# PS5.1默认TLS版本过旧, 访问HTTPS网站需要开启TLS1.2
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
} catch {}
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ConfigFile = Join-Path $ScriptDir "campusnet_config.json"
$LogFile    = Join-Path $ScriptDir "campusnet_log.txt"

$PortalHost = "10.0.10.252"          # 认证服务器
$AcIpList   = @("10.128.255.143", "10.128.255.129")   # AC设备IP(两个校区/主备)
$CheckInterval = 10                  # 保活检测间隔(秒)

# ---------------- 日志 ----------------
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    try {
        # 日志超过200KB时只保留最后200行, 防止无限膨胀
        if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt 200KB)) {
            $old = Get-Content $LogFile -Tail 200 -Encoding UTF8
            Set-Content -Path $LogFile -Value $old -Encoding UTF8
        }
        Add-Content -Path $LogFile -Value $logEntry -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch {}
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
        "OK"    { Write-Host $logEntry -ForegroundColor Green }
        default { Write-Host $logEntry -ForegroundColor Gray }
    }
}

# ---------------- 检测是否真的能上网 ----------------
# 探测原理(两层保险):
#   1. HTTPS探测(主力): 未认证时学校设备无法伪造 baidu/qq 的HTTPS证书, TLS握手必然失败;
#      且有些校园网会把 msftconnecttest/miui 等HTTP探测域名加白名单放行, HTTP探测会误判,
#      HTTPS不受白名单影响(除非整站放行, 那等于免费上网, 学校不会这么配)。
#   2. 校验最终响应主机名, 防止被302劫持到门户页还误判在线。
function Test-Online {
    foreach ($site in @("https://www.baidu.com", "https://www.qq.com")) {
        try {
            $req = [System.Net.HttpWebRequest]::Create($site)
            $req.Method = "GET"
            $req.Timeout = 4000
            $req.AllowAutoRedirect = $true
            $resp = $req.GetResponse()
            $finalHost = $resp.ResponseUri.Host
            $resp.Close()
            $expectedHost = ([Uri]$site).Host
            if ($finalHost -eq $expectedHost) { return $true }
            # HTTPS被重定向到别的主机 => 被门户劫持, 视为未认证
        } catch { }
        # HTTPS失败: 认证过期时证书校验必然失败; 真在线时不应失败
    }
    return $false
}

# ---------------- 探测门户重定向参数(仅掉线时有效) ----------------
# 未认证时访问HTTP网站会被302到门户页, URL里带着服务器自己登记的 IP/MAC/AC 参数,
# 用这些参数去登录最保险(比本机检测的网卡信息更权威)。
function Get-PortalInfo {
    try {
        $req = [System.Net.HttpWebRequest]::Create("http://www.baidu.com")
        $req.Method = "GET"
        $req.Timeout = 4000
        $req.AllowAutoRedirect = $true
        $resp = $req.GetResponse()
        $uri = $resp.ResponseUri
        $resp.Close()
        if ($uri.Host -ne "www.baidu.com") {
            $q = $uri.Query
            $info = @{}
            if ($q -match "wlanuserip=([\d\.]+)")          { $info.IP   = $matches[1] }
            if ($q -match "wlanusermac=([0-9A-Fa-f\-:]+)") { $info.MAC  = $matches[1].ToUpper() }
            if ($q -match "wlanacip=([\d\.]+)")            { $info.AcIp = $matches[1] }
            if ($info.Count -gt 0) { return $info }
        }
    } catch { }
    return $null
}

# ---------------- 检测网卡信息(IP/MAC) ----------------
function Get-NetInfo {
    $result = $null

    # 方法1: Get-NetAdapter (Win8+/Win10)
    $adapters = @()
    try {
        $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
                    Where-Object { $_.Status -eq "Up" }
    } catch {}

    if ($adapters) {
        # 排除虚拟网卡
        $real = @($adapters | Where-Object { $_.InterfaceDescription -notmatch "Virtual|VMware|Hyper-V|VEthernet|Loopback|Bluetooth|TAP|TUN" })
        if ($real.Count -eq 0) { $real = @($adapters) }

        foreach ($ad in $real) {
            $ip = $null
            try {
                $ip = (Get-NetIPAddress -InterfaceAlias $ad.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                       Where-Object { $_.IPAddress -notlike "169.254*" } |
                       Select-Object -First 1).IPAddress
            } catch {}
            if ($ip) {
                $mac = ($ad.MacAddress -replace "[-:]", "").ToUpper()
                $type = "有线"
                if ($ad.InterfaceDescription -match "Wi-Fi|Wireless|无线|WLAN|802\.11") { $type = "WiFi" }
                $result = @{ Name = $ad.Name; Description = $ad.InterfaceDescription; IP = $ip; MAC = $mac; MACDashed = $ad.MacAddress.ToUpper(); Type = $type }
                # 优先选内网 10.x 的网卡(校园网网段)
                if ($ip -like "10.*") { return $result }
            }
        }
        if ($result) { return $result }
    }

    # 方法2: WMI/CIM 兜底 (方法1失效时)
    try {
        $cfgs = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
        foreach ($cfg in $cfgs) {
            $ip = ($cfg.IPAddress | Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" -and $_ -notlike "169.254*" } | Select-Object -First 1)
            if ($ip) {
                $mac = ($cfg.MACAddress -replace "[-:]", "").ToUpper()
                $type = "有线"
                if ($cfg.Description -match "Wi-Fi|Wireless|无线|WLAN|802\.11") { $type = "WiFi" }
                return @{ Name = $cfg.Description; Description = $cfg.Description; IP = $ip; MAC = $mac; MACDashed = $cfg.MACAddress.ToUpper(); Type = $type }
            }
        }
    } catch {}

    return $null
}

# ---------------- 配置文件 ----------------
function Save-Config {
    param([string]$Account, [string]$Password, [string]$Suffix = ",0,")
    $config = @{
        Account    = $Account
        Password   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Password))
        Suffix     = $Suffix
        LastUpdate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    try {
        $config | ConvertTo-Json | Out-File $ConfigFile -Encoding UTF8 -Force
        return $true
    } catch {
        Write-Log "配置保存失败: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Load-Config {
    if (-not (Test-Path $ConfigFile)) { return $null }
    try {
        $config = Get-Content $ConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $config | Add-Member -NotePropertyName PlainPwd -NotePropertyValue ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($config.Password))) -Force
        if (-not $config.Suffix) { $config | Add-Member -NotePropertyName Suffix -NotePropertyValue ",0," -Force }
        return $config
    } catch {
        Write-Log "配置读取失败: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

# ---------------- 发送登录请求 ----------------
function Invoke-Login {
    param($Account, $PlainPwd, $Suffix, $NetInfo, $PortalInfo = $null)

    $accountParam = [Uri]::EscapeDataString($Suffix + $Account)
    $pwdParam     = [Uri]::EscapeDataString($PlainPwd)
    $v            = Get-Random -Maximum 99999

    # 参数优先级: 门户重定向里带的参数(服务器自己登记的, 最权威) > 本机网卡检测
    $userIp  = $NetInfo.IP
    $acList  = $AcIpList
    $macList = @()
    if ($PortalInfo) {
        if ($PortalInfo.IP)   { $userIp = $PortalInfo.IP }
        if ($PortalInfo.AcIp) { $acList = @($PortalInfo.AcIp) + $AcIpList | Select-Object -Unique }
        if ($PortalInfo.MAC) {
            $macList += $PortalInfo.MAC
            $nos = ($PortalInfo.MAC -replace "[-:]", "")
            if ($macList -notcontains $nos) { $macList += $nos }
        }
    }
    if (-not $macList) {
        # MAC尝试两种格式: 无分隔符(标准) / 带横线
        $macList += $NetInfo.MAC
        if ($NetInfo.MACDashed -and $NetInfo.MACDashed -ne $NetInfo.MAC) { $macList += $NetInfo.MACDashed }
    }

    $accSuffix = [Uri]::EscapeDataString($Suffix + $Account)
    $accPlain  = [Uri]::EscapeDataString($Account)
    $pwdParam  = [Uri]::EscapeDataString($PlainPwd)

    # ---- 方案1(当前生效): 新版 ACSetting&a=Login, 2026-09-18 学校升级后使用 ----
    # 必须紧跟 Get-PortalInfo 触发的302跳转之后调用(网关需先为该IP建立认证会话),
    # 并携带网关跳转参数; 新旧两种参数命名风格同时发送以兼容后端
    foreach ($acc in @($accSuffix, $accPlain)) {
        foreach ($acIp in $acList) {
            foreach ($mac in $macList) {
                $url = "http://$PortalHost`:801/eportal/?c=ACSetting&a=Login" +
                       "&DDDDD=$acc&upass=$pwdParam&0MKKey=123456" +
                       "&R1=0&R2=0&R3=0&R6=0&para=00&buttonClicked=&redirect_url=&err_flag=&username=&password=&user=&cmd=Login&login=" +
                       "&wlanuserip=$userIp&wlanusermac=$mac&wlanacip=$acIp" +
                       "&wlan_user_ip=$userIp&wlan_user_mac=$mac&wlan_ac_ip=$acIp"
                Write-Log "登录请求[新版ACSetting]: AC=$acIp MAC=$mac IP=$userIp"
                try {
                    $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10
                    $content = [string]$resp.Content
                    if ($content -match "msga='([^']*)'") { Write-Log "服务器回应: $($matches[1])" }
                    Start-Sleep -Seconds 2
                    if (Test-Online) {
                        Write-Log "登录成功！(可以上网了)" "OK"
                        return @{ Success = $true; RetCode = $null; Msg = "认证成功" }
                    }
                } catch {
                    Write-Log "请求失败(ACSetting $acIp): $($_.Exception.Message)" "WARN"
                }
            }
        }
    }

    # ---- 方案2(兜底): 旧版 Portal 接口, 学校若回滚/灰度混合时可用 ----
    foreach ($acIp in $acList) {
        foreach ($mac in $macList) {
            $url = "http://$PortalHost`:801/eportal/?c=Portal&a=login&callback=dr1003&login_method=1" +
                   "&user_account=$accSuffix" +
                   "&user_password=$pwdParam" +
                   "&wlan_user_ip=$userIp" +
                   "&wlan_user_ipv6=&wlan_user_mac=$mac" +
                   "&wlan_ac_ip=$acIp&wlan_ac_name=&jsVersion=3.3.2&v=$v"
            Write-Log "登录请求[旧版Portal]: AC=$acIp MAC=$mac IP=$userIp"
            try {
                $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10
                $content = [string]$resp.Content
                if ($content -match '"result"\s*:\s*"?1"?') {
                    Write-Log "登录成功！(可以上网了)" "OK"
                    return @{ Success = $true; RetCode = $null; Msg = "认证成功" }
                }
                $ret = $null; $msg = ""
                if ($content -match '"ret_code"\s*:\s*"?(\d+)') { $ret = $matches[1] }
                if ($content -match '"msg"\s*:\s*"([^"]*)"')    { $msg = $matches[1] }
                Start-Sleep -Seconds 2
                if (Test-Online) {
                    Write-Log "登录成功！(可以上网了)" "OK"
                    return @{ Success = $true; RetCode = $null; Msg = "认证成功" }
                }
                # 服务器有明确回应就不用再试其他参数组合
                return @{ Success = $false; RetCode = $ret; Msg = $msg }
            } catch {
                Write-Log "请求失败($acIp): $($_.Exception.Message)" "WARN"
            }
        }
    }
    return @{ Success = $false; RetCode = $null; Msg = "服务器无响应" }
}

function Show-RetCodeHelp {
    param([string]$RetCode, [string]$Msg)
    Write-Log "登录失败 [ret_code=$RetCode] $Msg" "WARN"
    switch ($RetCode) {
        "2" { Write-Host "  原因: 账号可能已在其他设备登录, 请先在其他设备上注销, 或稍后再试" -ForegroundColor Yellow }
        "8" {
            Write-Host "  原因: IP/MAC不匹配或密码错误, 可尝试以下步骤:" -ForegroundColor Yellow
            Write-Host "    1. 用手机连校园网, 打开 10.0.10.252 点[注销]下线本机" -ForegroundColor Yellow
            Write-Host "    2. Win+R 输入 cmd, 依次执行: ipconfig /release 回车, ipconfig /renew 回车" -ForegroundColor Yellow
            Write-Host "    3. 重新运行本脚本" -ForegroundColor Yellow
        }
        default { Write-Host "  原因: 服务器返回未知错误, 请确认学号密码是否正确" -ForegroundColor Yellow }
    }
}

# ---------------- 单次登录流程 ----------------
function Invoke-LoginOnce {
    param([switch]$Quiet)

    $config = Load-Config
    if (-not $config) {
        Write-Log "未找到配置文件, 请先运行[重新配置账号.bat]填写学号密码" "ERROR"
        return $false
    }

    if (Test-Online) {
        if (-not $Quiet) { Write-Log "网络正常, 已在线, 无需登录" "OK" }
        return $true
    }

    $netInfo = Get-NetInfo
    if (-not $netInfo) {
        Write-Log "未检测到已连接的网卡, 请先插网线或连WiFi" "ERROR"
        return $false
    }
    if (-not $Quiet) {
        Write-Log "网卡: $($netInfo.Name) | 类型: $($netInfo.Type)"
        Write-Log "IP: $($netInfo.IP) | MAC: $($netInfo.MAC)"
    }

    # 掉线时探测门户重定向: 二次确认未认证 + 拿服务器登记的登录参数
    $portalInfo = Get-PortalInfo
    if ($portalInfo) {
        Write-Log "确认未认证(探测到门户劫持): AC=$($portalInfo.AcIp) IP=$($portalInfo.IP) MAC=$($portalInfo.MAC)"
    }

    $r = Invoke-Login -Account $config.Account -PlainPwd $config.PlainPwd -Suffix $config.Suffix -NetInfo $netInfo -PortalInfo $portalInfo
    if ($r.Success) {
        Start-Sleep -Seconds 3
        if (Test-Online) { Write-Log "验证通过, 网络已恢复" "OK" }
        else { Write-Log "已提交登录但暂未检测到外网, 可能需要1-2分钟生效" "WARN" }
        return $true
    } else {
        Show-RetCodeHelp -RetCode $r.RetCode -Msg $r.Msg
        return $false
    }
}

# ---------------- 首次设置向导 ----------------
function Start-Setup {
    Write-Host ""
    Write-Host "==== 广州理工学院校园网 - 账号配置 ====" -ForegroundColor Cyan
    Write-Host ""
    $account = Read-Host "请输入学号"
    while (-not $account -or $account.Trim() -eq "") {
        Write-Host "学号不能为空!" -ForegroundColor Red
        $account = Read-Host "请输入学号"
    }

    $securePwd = Read-Host "请输入校园网密码" -AsSecureString
    $plainPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePwd))
    if (-not $plainPwd) {
        Write-Host "密码不能为空! 配置未保存。" -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "正在检测网络..." -ForegroundColor Cyan
    $netInfo = Get-NetInfo
    if ($netInfo) {
        Write-Host "检测到网卡: $($netInfo.Name)  类型: $($netInfo.Type)" -ForegroundColor Green
        Write-Host "IP: $($netInfo.IP)   MAC: $($netInfo.MAC)" -ForegroundColor Green
    } else {
        Write-Host "提示: 当前未检测到网络连接, 不影响保存配置, 联网后自动登录时会重新检测" -ForegroundColor Yellow
    }

    if (Save-Config -Account $account.Trim() -Password $plainPwd) {
        Write-Host ""
        Write-Host "配置已保存! 现在可以双击[校园网登录.bat]测试登录," -ForegroundColor Green
        Write-Host "或双击[安装开机自启.bat]实现永久保活。" -ForegroundColor Green
    }
    Write-Host ""
}

# ---------------- 后台保活守护 ----------------
function Hide-ConsoleWindow {
    # 隐藏自己的控制台窗口(开机自启时任务栏不再出现PowerShell图标)
    try {
        Add-Type -Namespace Win32 -Name ConsoleWin -MemberDefinition @'
[DllImport("Kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'@
    } catch { }   # 已加载过则忽略
    try {
        $h = [Win32.ConsoleWin]::GetConsoleWindow()
        if ($h -ne [IntPtr]::Zero) { [Win32.ConsoleWin]::ShowWindow($h, 0) | Out-Null }
    } catch { }
}

function Start-Watch {
    # 隐藏控制台窗口(守护在后台静默运行)
    Hide-ConsoleWindow
    # 单实例保护: 用命名互斥锁(比扫描进程列表可靠, 不会误判包装进程)
    $script:mutexCreated = $false
    $script:KeepAliveMutex = New-Object System.Threading.Mutex($true, "CampusNetGZIST_KeepAlive", [ref]$script:mutexCreated)
    if (-not $script:mutexCreated) {
        Write-Log "已有保活守护在运行, 本次不重复启动" "WARN"
        exit 0
    }
    # 登录后先等网络栈就绪
    Start-Sleep -Seconds 20
    Write-Log "保活守护已启动 (每${CheckInterval}秒检测一次, 掉线自动重登)" "OK"
    $failCount = 0
    while ($true) {
        try {
            if (-not (Test-Online)) {
                $failCount++
                Write-Log "检测到掉线 (第${failCount}次), 尝试自动登录..." "WARN"
                Invoke-LoginOnce -Quiet | Out-Null
                Start-Sleep -Seconds 10
            } else {
                if ($failCount -gt 0) { Write-Log "网络已恢复正常" "OK" }
                $failCount = 0
            }
        } catch {
            Write-Log "守护循环异常: $($_.Exception.Message)" "ERROR"
        }
        Start-Sleep -Seconds $CheckInterval
    }
}

# ---------------- 入口 ----------------
if ($Diag) {
    Write-Host "==== 校园网脚本诊断 ====" -ForegroundColor Cyan
    $online = Test-Online
    Write-Host ("1. HTTPS在线检测 : " + $(if ($online) { "True (已在线)" } else { "False (未认证/离线)" })) -ForegroundColor $(if ($online) { "Green" } else { "Yellow" })
    $pi = Get-PortalInfo
    if ($pi) {
        Write-Host ("2. HTTP劫持探测  : 被门户劫持(未认证) -> AC=" + $pi.AcIp + " IP=" + $pi.IP + " MAC=" + $pi.MAC) -ForegroundColor Yellow
    } else {
        Write-Host "2. HTTP劫持探测  : 无劫持(在线时正常现象)" -ForegroundColor Gray
    }
    $ni = Get-NetInfo
    if ($ni) {
        Write-Host ("3. 网卡          : " + $ni.Name + " | " + $ni.Type + " | IP=" + $ni.IP + " | MAC=" + $ni.MAC) -ForegroundColor Gray
    } else {
        Write-Host "3. 网卡          : 未检测到已连接的网卡!" -ForegroundColor Red
    }
    Write-Host ("4. 配置文件      : " + $(if (Test-Path $ConfigFile) { "存在" } else { "不存在(请先重新配置账号)" }))
    exit 0
}

if ($Setup) {
    Start-Setup
    exit 0
}

if (-not (Test-Path $ConfigFile)) {
    Write-Host "首次使用, 请先配置学号和密码:" -ForegroundColor Cyan
    Start-Setup
    if (-not (Test-Path $ConfigFile)) { exit 1 }
}

if ($Watch) {
    Start-Watch
    exit 0
}

# 默认: 单次登录
if ($Interactive) {
    Write-Host ""
    Write-Host "==== 广州理工学院校园网自动登录 ====" -ForegroundColor Cyan
    Write-Host ""
}
$null = Invoke-LoginOnce
if ($Interactive) {
    Write-Host ""
    Write-Host "本次运行结束, 窗口可以关闭。" -ForegroundColor Gray
}
exit 0
