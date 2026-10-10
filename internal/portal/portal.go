// Package portal speaks the Dr.COM ePortal protocol used by the GZIST
// campus network (10.0.10.252). It knows how to tell whether the machine is
// really online, how to read the parameters the gateway leaks in its 302
// hijack, and how to log in and out.
package portal

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// Defaults for the GZIST campus network.
const (
	DefaultPortalHost = "10.0.10.252"
	DefaultPortalBase = "http://10.0.10.252:801/eportal/"
	DefaultSuffix     = ",0,"
	DefaultHijackURL  = "http://www.baidu.com"
)

// DefaultACIPs are the access controllers seen on campus. Different
// dorms / uplinks report different ones via the hijack redirect; when the
// hijack is not visible we try them all (10.128.255.142 was observed on
// the 10.30.5.x wired segment).
var DefaultACIPs = []string{"10.128.255.142", "10.128.255.143", "10.128.255.129"}

// DefaultProbeURLs are fetched over HTTPS; only a valid certificate for the
// expected host proves that the gateway is not hijacking us.
var DefaultProbeURLs = []string{"https://www.baidu.com", "https://www.qq.com"}

// ErrNoNIC is returned when no interface routes to the portal.
var ErrNoNIC = errors.New("未检测到已连接的网卡")

// ErrNoResponse is returned when every login attempt failed at the network
// level.
var ErrNoResponse = errors.New("认证服务器无响应")

// ErrCampusUnavailable is returned when the portal does not accept a TCP
// connection, usually because the machine is not on the campus network.
var ErrCampusUnavailable = errors.New("认证服务器不可达（是否已连接校园网？）")

// PreflightTimeout bounds the TCP check done before logging in.
const PreflightTimeout = 1500 * time.Millisecond

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

// Outcome classifies what the server said about a login attempt.
type Outcome int

const (
	// Unknown: the answer did not say; only a probe can tell.
	Unknown Outcome = iota
	// Success: the server authenticated the account.
	Success
	// BadCredential: wrong account or password; other parameters will not
	// help.
	BadCredential
	// ParamMismatch: the IP / MAC / AC did not match; another combination
	// may work.
	ParamMismatch
	// InUse: the account is already online, usually on another device.
	InUse
)

func (o Outcome) String() string {
	switch o {
	case Success:
		return "认证成功"
	case BadCredential:
		return "账号或密码错误"
	case ParamMismatch:
		return "参数不匹配"
	case InUse:
		return "账号已在线"
	default:
		return "未知"
	}
}

// Result describes a login attempt the server answered.
type Result struct {
	OK            bool
	AlreadyOnline bool
	Outcome       Outcome
	RetCode       int // 0 when unknown
	Msg           string
	Warn          string
}

// Session is the set of parameters a login succeeded with.
type Session struct {
	Suffixed  bool   // account sent with Suffix
	ACIP      string // access controller
	MACPlain  bool   // MAC sent without separators
	UserIP    string
	UserMAC   string // as sent
	PortalAPI bool   // logged in through the old Portal interface
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
	// Preflight checks that the portal accepts connections.
	Preflight func(ctx context.Context) error
	// Sleep waits between attempts; tests replace it.
	Sleep func(ctx context.Context, d time.Duration) error
	// Log receives one line per step. Passwords never reach it.
	Log func(string)

	mu   sync.Mutex
	last *Session // the most recent successful login
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
	c.Preflight = c.dialPortal
	return c
}

// dialPortal opens and closes a TCP connection to the portal.
func (c *Client) dialPortal(ctx context.Context) error {
	u, err := url.Parse(c.PortalBase)
	if err != nil {
		return err
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "80")
	}
	ctx, cancel := context.WithTimeout(ctx, PreflightTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return err
	}
	return conn.Close()
}

// LastSession returns the parameters of the most recent successful login.
func (c *Client) LastSession() (Session, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil {
		return Session{}, false
	}
	return *c.last, true
}

func (c *Client) remember(s Session) {
	c.mu.Lock()
	c.last = &s
	c.mu.Unlock()
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
	reMsga   = regexp.MustCompile(`msga='([^']*)'`)
	reResult = regexp.MustCompile(`"result"\s*:\s*(?:"1"|1)\s*[,}]`)
	reTitle  = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reTags   = regexp.MustCompile(`<[^>]*>`)

	// What the ACSetting pages say. The success page is titled 认证成功页.
	reSuccess  = regexp.MustCompile(`(?i)认证成功|登录成功|成功登录|Dr\.COMWebLoginID_3`)
	reBadCred  = regexp.MustCompile(`(?i)ldap auth error|userid error|passw(or)?d error|密码错误|账号不存在|用户不存在|账号或密码|用户名或密码`)
	reInUse    = regexp.MustCompile(`(?i)\bin ?use\b|已在线|已经在线|limit users|在线终端|终端数`)
	reMismatch = regexp.MustCompile(`(?i)\b(ip|mac|ac|acip|nas)\b|不匹配|不一致|mismatch|参数`)
)

// Classify reads an ACSetting answer. msg is the server's own message
// (msga), if any.
func Classify(body string) (o Outcome, msg string) {
	if m := reMsga.FindStringSubmatch(body); m != nil {
		msg = strings.TrimSpace(html.UnescapeString(m[1]))
	}
	switch {
	case msg == "":
		// Only the success page is recognizable without a message.
		if reSuccess.MatchString(body) {
			return Success, ""
		}
		return Unknown, ""
	case reSuccess.MatchString(msg):
		return Success, msg
	case reBadCred.MatchString(msg):
		return BadCredential, msg
	case reInUse.MatchString(msg):
		return InUse, msg
	case reMismatch.MatchString(msg):
		return ParamMismatch, msg
	}
	return Unknown, msg
}

// responseError records receipt of an HTTP response even with an empty body.
type responseError struct{ err error }

func (e *responseError) Error() string { return e.err.Error() }
func (e *responseError) Unwrap() error { return e.err }
func receivedResponse(err error) bool {
	var e *responseError
	return errors.As(err, &e)
}

func (c *Client) get(ctx context.Context, rawURL string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		// net/http's URL error includes the query (and therefore the password).
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			return "", urlErr.Err
		}
		return "", err
	}
	defer resp.Body.Close()
	c.logf("  HTTP %d  Content-Type: %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &responseError{fmt.Errorf("认证服务器 HTTP %d", resp.StatusCode)}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, (256<<10)+1))
	if err != nil {
		return "", &responseError{err}
	}
	if len(b) > 256<<10 {
		return "", &responseError{errors.New("认证响应超过 256 KiB")}
	}
	// Dr.COM portals answer in GBK while their Content-Type claims UTF-8 —
	// the raw bytes render as garbage in the logs. Re-encode so the error
	// text inside msga actually reads.
	if !utf8.Valid(b) {
		if dec, derr := simplifiedchinese.GB18030.NewDecoder().Bytes(b); derr == nil {
			b = dec
		}
	}
	body := string(b)
	return body, nil
}

// parsePortal accepts JSON or the expected JSONP callback, not HTML containing
// JSON-looking text. Unknown responses must not stop the candidate loop.
func parsePortal(body string) (Result, bool) {
	s := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(body), "\ufeff"))
	if rest, ok := strings.CutPrefix(s, "dr1003"); ok {
		s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), ";"))
		if !strings.HasPrefix(s, "(") || !strings.HasSuffix(s, ")") {
			return Result{}, false
		}
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	var fields struct {
		Result  json.RawMessage `json:"result"`
		RetCode json.RawMessage `json:"ret_code"`
		Msg     string          `json:"msg"`
	}
	if err := json.Unmarshal([]byte(s), &fields); err != nil {
		return Result{}, false
	}
	result := strings.Trim(string(fields.Result), `"`)
	code, _ := strconv.Atoi(strings.Trim(string(fields.RetCode), `"`))
	r := Result{OK: result == "1", RetCode: code, Msg: fields.Msg}
	return r, result == "0" || result == "1" || code != 0
}

func unexpectedResponse(body string) string {
	if title := reTitle.FindStringSubmatch(body); title != nil {
		text := clip(html.UnescapeString(reTags.ReplaceAllString(title[1], "")))
		return "认证接口返回 HTML 页面：" + text
	}
	if strings.TrimSpace(body) == "" {
		return "认证接口返回空响应"
	}
	return "认证接口返回无法识别的响应（非有效 JSON/JSONP）"
}

func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 300 {
		return string(r[:300]) + "…"
	}
	return s
}

// combo is one way to fill in the ACSetting form.
type combo struct {
	suffixed bool
	ac, mac  string
}

func (cb combo) session(ip string) Session {
	return Session{Suffixed: cb.suffixed, ACIP: cb.ac, MACPlain: NormalizeMAC(cb.mac) == cb.mac, UserIP: ip, UserMAC: cb.mac}
}

// combos lists the forms to try, the one that worked last time first.
func (c *Client) combos(p params) []combo {
	var out []combo
	for _, suffixed := range []bool{true, false} {
		for _, ac := range p.acs {
			for _, mac := range p.macs {
				out = append(out, combo{suffixed, ac, mac})
			}
		}
	}
	last, ok := c.LastSession()
	if !ok || last.PortalAPI {
		return out
	}
	for i, cb := range out {
		s := cb.session(p.ip)
		if s.Suffixed == last.Suffixed && s.ACIP == last.ACIP && s.MACPlain == last.MACPlain {
			copy(out[1:i+1], out[:i])
			out[0] = cb
			break
		}
	}
	return out
}

// Login signs the account in. It returns an error only when no attempt got
// an answer from the server.
//
// Each ACSetting answer is classified: success ends the login even when
// the internet is not routed yet, a credential error ends it without trying
// other parameters, a parameter mismatch moves on to the next combination,
// and anything else is settled by probing the internet.
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
	if c.Preflight != nil {
		if err := c.Preflight(ctx); err != nil {
			if ctx.Err() != nil {
				return Result{}, ctx.Err()
			}
			c.logf("认证服务器 %s 不可达: %v", c.PortalBase, err)
			return Result{}, ErrCampusUnavailable
		}
	}
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
	acMsg, fallbackMsg := "", ""
	// Scheme 1: ACSetting, the interface used since the 2026-09 upgrade.
	for _, cb := range c.combos(p) {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		acc := account
		if cb.suffixed {
			acc = c.Suffix + account
		}
		u := c.acSettingURL(acc, password, p.ip, cb.mac, cb.ac)
		c.logf("ACSetting 登录: %s", c.acSettingURL(acc, "***", p.ip, cb.mac, cb.ac))
		body, err := c.get(ctx, u, 10*time.Second)
		if err != nil {
			c.logf("  请求失败: %v", err)
			answered = answered || receivedResponse(err)
			if acMsg == "" {
				acMsg = err.Error()
			}
			continue
		}
		answered = true
		out, msg := Classify(body)
		if msg != "" {
			acMsg = msg
			c.logf("  服务器提示: %s", msg)
		}
		c.logf("  响应: %s", clip(body))
		c.logf("  判定: %s", out)
		sess := cb.session(p.ip)
		switch out {
		case Success:
			c.remember(sess)
			return c.success(ctx, Result{OK: true, Outcome: Success, Msg: msg}), nil
		case BadCredential:
			return Result{Outcome: BadCredential, Msg: msg}, nil
		case ParamMismatch:
			continue
		}
		// InUse or Unknown: see whether we got through anyway.
		if err := c.Sleep(ctx, 2*time.Second); err != nil {
			return Result{}, err
		}
		if c.Online(ctx) {
			c.remember(sess)
			return Result{OK: true, Outcome: out, Msg: msg}, nil
		}
		if out == InUse {
			return Result{Outcome: InUse, Msg: msg}, nil
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
				answered = answered || receivedResponse(err)
				fallbackMsg = err.Error()
				continue
			}
			answered = true
			c.logf("  响应: %s", clip(body))
			r, recognized := parsePortal(body)
			if !recognized {
				fallbackMsg = unexpectedResponse(body)
				c.logf("  %s，尝试下一组参数", fallbackMsg)
				continue
			}
			if r.OK {
				r.Outcome = Success
				c.remember(Session{Suffixed: true, ACIP: ac, MACPlain: NormalizeMAC(mac) == mac, UserIP: p.ip, UserMAC: mac, PortalAPI: true})
				return c.success(ctx, r), nil
			}
			// A well-formed rejection is authoritative; do not hammer the
			// account with additional candidates (including ret_code 2/8).
			if r.Msg == "" {
				r.Msg = acMsg
			}
			return r, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if answered {
		var reasons []string
		if acMsg != "" {
			reasons = append(reasons, "ACSetting: "+acMsg)
		}
		if fallbackMsg != "" {
			reasons = append(reasons, "Portal: "+fallbackMsg)
		}
		if len(reasons) == 0 {
			reasons = append(reasons, "服务器已响应但仍未上线")
		}
		return Result{Msg: strings.Join(reasons, "；")}, nil
	}
	return Result{}, ErrNoResponse
}

// success waits for the gateway to route us and warns if it does not.
// The login itself is not repeated.
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

// Logout signs the current device out. It uses the parameters of the last
// successful login when they still match this machine, otherwise the
// local interface.
func (c *Client) Logout(ctx context.Context, account string) error {
	nic, nicErr := c.LocalNIC()
	ip, mac, ac := nic.IP, NormalizeMAC(nic.MAC), ""
	if len(c.ACIPs) > 0 {
		ac = c.ACIPs[0]
	}
	if s, ok := c.LastSession(); ok && (nicErr != nil || s.UserIP == nic.IP) {
		ip, mac, ac = s.UserIP, s.UserMAC, s.ACIP
		c.logf("注销使用上次登录的会话参数")
	} else if nicErr != nil {
		return ErrNoNIC
	}
	urls := []string{
		c.PortalBase + "?c=ACSetting&a=Logout&ver=1.0&url=drappall&wlan_user_ip=" + ip + "&wlan_user_mac=" + mac,
	}
	if ac != "" {
		urls = append(urls, c.PortalBase+"?c=Portal&a=logout&callback=dr1003&login_method=1&user_account="+escape(c.Suffix+account)+
			"&wlan_user_ip="+ip+"&wlan_user_mac="+mac+"&wlan_user_ipv6=&wlan_ac_ip="+ac+
			"&wlan_ac_name=&jsVersion=3.3.2&v="+strconv.Itoa(rand.IntN(99999)))
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
