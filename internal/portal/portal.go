// Package portal speaks the Dr.COM ePortal protocol used by the GZIST
// campus network (10.0.10.252). It knows how to tell whether the machine is
// really online, how to read the parameters the gateway leaks in its 302
// hijack, and how to log in and out.
package portal

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Defaults for the GZIST campus network.
const (
	DefaultPortalHost = "10.0.10.252"
	DefaultPortalBase = "http://10.0.10.252:801/eportal/"
	DefaultSuffix     = ",0,"
	DefaultHijackURL  = "http://www.baidu.com"
)

// DefaultACIPs are the access controllers seen on campus.
var DefaultACIPs = []string{"10.128.255.143", "10.128.255.129"}

// DefaultProbeURLs are fetched over HTTPS; only a valid certificate for the
// expected host proves that the gateway is not hijacking us.
var DefaultProbeURLs = []string{"https://www.baidu.com", "https://www.qq.com"}

// ErrNoNIC is returned when no interface routes to the portal.
var ErrNoNIC = errors.New("未检测到已连接的网卡")

// ErrNoResponse is returned when every login attempt failed at the network
// level.
var ErrNoResponse = errors.New("认证服务器无响应")

// NIC is the local interface that routes to the portal.
type NIC struct {
	Name string
	IP   string
	MAC  string // upper case, no separators
}

// Info is what the gateway leaks in the URL of its hijack redirect.
type Info struct {
	UserIP  string
	UserMAC string
	ACIP    string
}

// Result describes a login attempt the server answered.
type Result struct {
	OK            bool
	AlreadyOnline bool
	RetCode       int // 0 when unknown
	Msg           string
	Warn          string
}

// Client talks to the portal. The zero value is not usable; call New.
type Client struct {
	PortalHost string
	PortalBase string
	ACIPs      []string
	Suffix     string
	ProbeURLs  []string
	HijackURL  string

	// HTTP is used for portal requests and hijack detection, Probe for the
	// HTTPS online checks.
	HTTP  *http.Client
	Probe *http.Client

	// LocalNIC finds the interface that routes to the portal.
	LocalNIC func() (NIC, error)
	// Sleep waits between attempts; tests replace it.
	Sleep func(ctx context.Context, d time.Duration) error
	// Log receives one line per step. Passwords never reach it.
	Log func(string)
}

// New returns a client configured for the campus network.
func New(log func(string)) *Client {
	c := &Client{
		PortalHost: DefaultPortalHost,
		PortalBase: DefaultPortalBase,
		ACIPs:      DefaultACIPs,
		Suffix:     DefaultSuffix,
		ProbeURLs:  DefaultProbeURLs,
		HijackURL:  DefaultHijackURL,
		HTTP:       &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}},
		Probe: &http.Client{Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		}},
		Sleep: sleep,
		Log:   log,
	}
	c.LocalNIC = func() (NIC, error) { return RouteNIC(c.PortalHost) }
	return c
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (c *Client) logf(format string, args ...any) {
	if c.Log != nil {
		c.Log(fmt.Sprintf(format, args...))
	}
}

// RouteNIC asks the routing table which local address talks to host and
// returns the interface that owns it. No packet is sent.
func RouteNIC(host string) (NIC, error) {
	conn, err := net.Dial("udp4", net.JoinHostPort(host, "80"))
	if err != nil {
		return NIC{}, ErrNoNIC
	}
	local := conn.LocalAddr().(*net.UDPAddr).IP
	conn.Close()
	ifaces, err := net.Interfaces()
	if err != nil {
		return NIC{}, ErrNoNIC
	}
	for _, ifc := range ifaces {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(local) {
				return NIC{Name: ifc.Name, IP: local.String(), MAC: NormalizeMAC(ifc.HardwareAddr.String())}, nil
			}
		}
	}
	return NIC{}, ErrNoNIC
}

// NormalizeMAC strips separators and upper-cases a MAC address.
func NormalizeMAC(mac string) string {
	r := strings.NewReplacer(":", "", "-", "", ".", "")
	return strings.ToUpper(r.Replace(mac))
}

// DashedMAC turns AABBCCDDEEFF into AA-BB-CC-DD-EE-FF.
func DashedMAC(mac string) string {
	m := NormalizeMAC(mac)
	if len(m) != 12 {
		return m
	}
	parts := make([]string, 6)
	for i := range parts {
		parts[i] = m[i*2 : i*2+2]
	}
	return strings.Join(parts, "-")
}

// Online reports whether any probe URL loads over HTTPS from its own host.
func (c *Client) Online(ctx context.Context) bool {
	for _, u := range c.ProbeURLs {
		if c.probe(ctx, u) == nil {
			return true
		}
	}
	return false
}

func (c *Client) probe(ctx context.Context, raw string) error {
	want, err := url.Parse(raw)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	resp, err := c.Probe.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if got := resp.Request.URL.Hostname(); got != want.Hostname() {
		return fmt.Errorf("被重定向到 %s", got)
	}
	return nil
}

var (
	reUserIP  = regexp.MustCompile(`wlanuserip=([\d.]+)`)
	reUserMAC = regexp.MustCompile(`wlanusermac=([0-9A-Fa-f\-:]+)`)
	reACIP    = regexp.MustCompile(`wlanacip=([\d.]+)`)
)

// PortalInfo fetches a plain HTTP page and, if the gateway redirected it,
// returns the parameters found in the final URL. hijacked is false when the
// page loaded normally.
func (c *Client) PortalInfo(ctx context.Context) (info Info, hijacked bool, err error) {
	want, _ := url.Parse(c.HijackURL)
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.HijackURL, nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Info{}, false, err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	final := resp.Request.URL
	if final.Hostname() == want.Hostname() {
		return Info{}, false, nil
	}
	s := final.String()
	if m := reUserIP.FindStringSubmatch(s); m != nil {
		info.UserIP = m[1]
	}
	if m := reUserMAC.FindStringSubmatch(s); m != nil {
		info.UserMAC = strings.ToUpper(m[1])
	}
	if m := reACIP.FindStringSubmatch(s); m != nil {
		info.ACIP = m[1]
	}
	return info, true, nil
}

// escape matches .NET's Uri.EscapeDataString.
func escape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

type params struct {
	ip   string
	acs  []string
	macs []string
}

func (c *Client) params(nic NIC, info Info) params {
	p := params{ip: nic.IP}
	if info.UserIP != "" {
		p.ip = info.UserIP
	}
	seen := map[string]bool{}
	for _, ac := range append([]string{info.ACIP}, c.ACIPs...) {
		if ac != "" && !seen[ac] {
			seen[ac] = true
			p.acs = append(p.acs, ac)
		}
	}
	if info.UserMAC != "" {
		p.macs = uniq(info.UserMAC, NormalizeMAC(info.UserMAC))
	} else if nic.MAC != "" {
		p.macs = uniq(NormalizeMAC(nic.MAC), DashedMAC(nic.MAC))
	} else {
		p.macs = []string{""}
	}
	return p
}

func uniq(a, b string) []string {
	if a == b {
		return []string{a}
	}
	return []string{a, b}
}

var (
	reMsga    = regexp.MustCompile(`msga='([^']*)'`)
	reResult  = regexp.MustCompile(`"result"\s*:\s*"?1"?`)
	reRetCode = regexp.MustCompile(`"ret_code"\s*:\s*"?(\d+)`)
	reMsg     = regexp.MustCompile(`"msg"\s*:\s*"([^"]*)"`)
)

func (c *Client) get(ctx context.Context, rawURL string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return string(b), err
}

func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 300 {
		return string(r[:300]) + "…"
	}
	return s
}

// Login signs the account in. It returns an error only when no attempt got
// an answer from the server.
func (c *Client) Login(ctx context.Context, account, password string) (Result, error) {
	if c.Online(ctx) {
		c.logf("已在线，无需登录")
		return Result{OK: true, AlreadyOnline: true}, nil
	}
	nic, err := c.LocalNIC()
	if err != nil {
		c.logf("%v", ErrNoNIC)
		return Result{}, ErrNoNIC
	}
	c.logf("网卡 %s  IP %s  MAC %s", nic.Name, nic.IP, nic.MAC)
	info, hijacked, err := c.PortalInfo(ctx)
	switch {
	case err != nil:
		c.logf("探测网关重定向失败: %v", err)
	case hijacked:
		c.logf("确认未认证（探测到门户劫持）: ip=%s mac=%s ac=%s", info.UserIP, info.UserMAC, info.ACIP)
	default:
		c.logf("未探测到门户劫持")
	}
	p := c.params(nic, info)
	if p.ip == "" {
		return Result{}, ErrNoNIC
	}

	answered := false
	// Scheme 1: ACSetting, the interface used since the 2026-09 upgrade.
	for _, acc := range []string{c.Suffix + account, account} {
		for _, ac := range p.acs {
			for _, mac := range p.macs {
				if err := ctx.Err(); err != nil {
					return Result{}, err
				}
				u := c.acSettingURL(acc, password, p.ip, mac, ac)
				c.logf("ACSetting 登录: %s", c.acSettingURL(acc, "***", p.ip, mac, ac))
				body, err := c.get(ctx, u, 10*time.Second)
				if err != nil {
					c.logf("  请求失败: %v", err)
					continue
				}
				answered = true
				if m := reMsga.FindStringSubmatch(body); m != nil && m[1] != "" {
					c.logf("  服务器提示: %s", m[1])
				}
				c.logf("  响应: %s", clip(body))
				if err := c.Sleep(ctx, 2*time.Second); err != nil {
					return Result{}, err
				}
				if c.Online(ctx) {
					return c.success(ctx, Result{OK: true}), nil
				}
			}
		}
	}

	// Scheme 2: the old Portal JSONP interface.
	for _, ac := range p.acs {
		for _, mac := range p.macs {
			if err := ctx.Err(); err != nil {
				return Result{}, err
			}
			u := c.portalLoginURL(account, password, p.ip, mac, ac)
			c.logf("Portal 登录: %s", c.portalLoginURL(account, "***", p.ip, mac, ac))
			body, err := c.get(ctx, u, 10*time.Second)
			if err != nil {
				c.logf("  请求失败: %v", err)
				continue
			}
			c.logf("  响应: %s", clip(body))
			r := Result{}
			if m := reRetCode.FindStringSubmatch(body); m != nil {
				r.RetCode, _ = strconv.Atoi(m[1])
			}
			if m := reMsg.FindStringSubmatch(body); m != nil {
				r.Msg = m[1]
			}
			if reResult.MatchString(body) {
				r.OK = true
				if err := c.Sleep(ctx, 2*time.Second); err != nil {
					return Result{}, err
				}
				return c.success(ctx, r), nil
			}
			return r, nil
		}
	}
	if answered {
		return Result{Msg: "服务器已响应但仍未上线"}, nil
	}
	return Result{}, ErrNoResponse
}

func (c *Client) success(ctx context.Context, r Result) Result {
	if err := c.Sleep(ctx, 3*time.Second); err == nil && !c.Online(ctx) {
		r.Warn = "认证成功但暂未连通外网，可能需要 1-2 分钟生效"
		c.logf("%s", r.Warn)
	}
	return r
}

func (c *Client) acSettingURL(acc, pwd, ip, mac, ac string) string {
	return c.PortalBase + "?c=ACSetting&a=Login&DDDDD=" + escape(acc) + "&upass=" + escape(pwd) +
		"&0MKKey=123456&R1=0&R2=0&R3=0&R6=0&para=00&buttonClicked=&redirect_url=&err_flag=&username=&password=&user=&cmd=Login&login=" +
		"&wlanuserip=" + ip + "&wlanusermac=" + mac + "&wlanacip=" + ac +
		"&wlan_user_ip=" + ip + "&wlan_user_mac=" + mac + "&wlan_ac_ip=" + ac
}

func (c *Client) portalLoginURL(account, pwd, ip, mac, ac string) string {
	return c.PortalBase + "?c=Portal&a=login&callback=dr1003&login_method=1&user_account=" + escape(c.Suffix+account) +
		"&user_password=" + escape(pwd) + "&wlan_user_ip=" + ip + "&wlan_user_ipv6=&wlan_user_mac=" + mac +
		"&wlan_ac_ip=" + ac + "&wlan_ac_name=&jsVersion=3.3.2&v=" + strconv.Itoa(rand.IntN(99999))
}

// Logout signs the current device out.
func (c *Client) Logout(ctx context.Context, account string) error {
	nic, err := c.LocalNIC()
	if err != nil {
		return ErrNoNIC
	}
	mac := NormalizeMAC(nic.MAC)
	ac := c.ACIPs[0]
	urls := []string{
		c.PortalBase + "?c=ACSetting&a=Logout&ver=1.0&url=drappall&wlan_user_ip=" + nic.IP + "&wlan_user_mac=" + mac,
		c.PortalBase + "?c=Portal&a=logout&callback=dr1003&login_method=1&user_account=" + escape(c.Suffix+account) +
			"&wlan_user_ip=" + nic.IP + "&wlan_user_mac=" + mac + "&wlan_user_ipv6=&wlan_ac_ip=" + ac +
			"&wlan_ac_name=&jsVersion=3.3.2&v=" + strconv.Itoa(rand.IntN(99999)),
	}
	var last error = ErrNoResponse
	for _, u := range urls {
		c.logf("注销: %s", u)
		body, err := c.get(ctx, u, 10*time.Second)
		if err != nil {
			c.logf("  请求失败: %v", err)
			last = err
			continue
		}
		c.logf("  响应: %s", clip(body))
		if strings.Contains(body, "Logout succeed") || reResult.MatchString(body) {
			return nil
		}
		last = errors.New("服务器未确认注销")
	}
	return last
}

// Diagnose checks every link in the chain and logs what it finds.
func (c *Client) Diagnose(ctx context.Context) {
	c.logf("—— 诊断开始 ——")
	if nic, err := c.LocalNIC(); err != nil {
		c.logf("[网卡] ✗ %v", err)
	} else {
		c.logf("[网卡] ✓ %s  IP %s  MAC %s", nic.Name, nic.IP, DashedMAC(nic.MAC))
	}
	if info, hijacked, err := c.PortalInfo(ctx); err != nil {
		c.logf("[网关] ✗ 访问 %s 失败: %v", c.HijackURL, err)
	} else if hijacked {
		c.logf("[网关] ! 被重定向到认证页，未认证 (ip=%s mac=%s ac=%s)", info.UserIP, info.UserMAC, info.ACIP)
	} else {
		c.logf("[网关] ✓ 没有被劫持")
	}
	if _, err := c.get(ctx, c.PortalBase, 4*time.Second); err != nil {
		c.logf("[认证服务器] ✗ %s 不可达: %v", c.PortalBase, err)
	} else {
		c.logf("[认证服务器] ✓ 可以访问")
	}
	for _, u := range c.ProbeURLs {
		if err := c.probe(ctx, u); err != nil {
			c.logf("[外网] ✗ %s: %v", u, err)
		} else {
			c.logf("[外网] ✓ %s", u)
		}
	}
	c.logf("—— 诊断结束 ——")
}

// Advice explains a ret_code in plain words.
func Advice(code int) string {
	switch code {
	case 2:
		return "账号可能已在其他设备登录，请先在其他设备注销或稍后再试。"
	case 8:
		return "IP/MAC 不匹配或密码错误：用手机连校园网打开 10.0.10.252 注销本机，断开重连 Wi-Fi（重新获取 IP）后再试；仍不行请检查密码。"
	case 0:
		return ""
	default:
		return "服务器返回未知错误，请确认学号和密码。"
	}
}
