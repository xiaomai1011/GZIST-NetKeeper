package portal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// fakeCampus simulates the gateway, the portal and the outside internet.
type fakeCampus struct {
	t       *testing.T
	online  atomic.Bool
	mu      sync.Mutex
	reqs    []string
	handler func(q map[string]string) string // portal answer

	portal, hijack, internet *httptest.Server
	client                   *Client
	logs                     []string
	rootResponse             atomic.Value // string; served for GET / without a query
}

func newFake(t *testing.T) *fakeCampus {
	f := &fakeCampus{t: t}
	f.portal = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.URL.RawQuery == "" {
			// the discovery probe: answer with the campus default (already
			// online → empty AC) unless the test stages a response
			if rr, ok := f.rootResponse.Load().(string); ok && rr != "" {
				fmt.Fprint(w, rr)
				return
			}
			fmt.Fprint(w, `<script>AC="";</script>`)
			return
		}
		if r.URL.RawQuery != "" {
			f.mu.Lock()
			f.reqs = append(f.reqs, r.URL.RawQuery)
			f.mu.Unlock()
		}
		q := map[string]string{}
		for k, v := range r.URL.Query() {
			q[k] = v[0]
		}
		if f.handler != nil {
			fmt.Fprint(w, f.handler(q))
		}
	}))
	t.Cleanup(f.portal.Close)
	// The "login page" the gateway redirects to lives on a different host
	// name (localhost vs 127.0.0.1).
	loginPage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>请登录</html>")
	}))
	t.Cleanup(loginPage.Close)
	lp := strings.Replace(loginPage.URL, "127.0.0.1", "localhost", 1)
	f.hijack = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.online.Load() {
			fmt.Fprint(w, "baidu")
			return
		}
		http.Redirect(w, r, lp+"/a79.htm?wlanuserip=10.20.30.40&wlanacip=10.128.255.129&wlanacname=&wlanusermac=aa-bb-cc-dd-ee-ff", http.StatusFound)
	}))
	t.Cleanup(f.hijack.Close)
	f.internet = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.online.Load() {
			fmt.Fprint(w, "ok")
			return
		}
		http.Redirect(w, r, lp+"/", http.StatusFound)
	}))
	t.Cleanup(f.internet.Close)

	c := New(func(s string) { f.logs = append(f.logs, s) })
	c.PortalBase = f.portal.URL + "/eportal/"
	c.PortalHost = strings.TrimPrefix(f.portal.URL, "http://")
	c.HijackURL = f.hijack.URL
	c.ProbeURLs = []string{f.internet.URL}
	c.Probe = f.internet.Client()
	c.LocalNIC = func() (NIC, error) { return NIC{Name: "en0", IP: "10.20.30.40", MAC: "AABBCCDDEEFF"}, nil }
	c.Sleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	f.client = c
	return f
}

func (f *fakeCampus) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

func TestOnlineNeedsRealHost(t *testing.T) {
	f := newFake(t)
	ctx := context.Background()
	if f.client.Online(ctx) {
		t.Fatal("hijacked network reported online")
	}
	f.online.Store(true)
	if !f.client.Online(ctx) {
		t.Fatal("open network reported offline")
	}
}

func TestPortalInfoFromRedirect(t *testing.T) {
	f := newFake(t)
	info, hijacked, err := f.client.PortalInfo(context.Background())
	if err != nil || !hijacked {
		t.Fatalf("hijacked=%v err=%v", hijacked, err)
	}
	want := Info{UserIP: "10.20.30.40", UserMAC: "AA-BB-CC-DD-EE-FF", ACIP: "10.128.255.129"}
	if info != want {
		t.Fatalf("got %+v want %+v", info, want)
	}
}

func TestLoginACSetting(t *testing.T) {
	f := newFake(t)
	f.handler = func(q map[string]string) string {
		// Only the account with suffix, the AC from the redirect and the
		// dashed MAC from the redirect work, like the real server.
		if q["c"] == "ACSetting" && q["DDDDD"] == ",0,2023001" && q["upass"] == "p@ss word" &&
			q["wlanacip"] == "10.128.255.142" && q["wlanusermac"] == "AA-BB-CC-DD-EE-FF" && q["wlanuserip"] == "10.20.30.40" {
			f.online.Store(true)
			return "<script>msga='认证成功'</script>"
		}
		return "<script>msga='ldap auth error'</script>"
	}
	r, err := f.client.Login(context.Background(), "2023001", "p@ss word")
	if err != nil || !r.OK || r.Warn != "" {
		t.Fatalf("r=%+v err=%v logs=%q", r, err, f.logs)
	}
	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("expected first combination to win, got %d requests", len(reqs))
	}
	if !strings.Contains(reqs[0], "DDDDD=%2C0%2C2023001") || !strings.Contains(reqs[0], "upass=p%40ss%20word") || !strings.Contains(reqs[0], "wlanacip=10.128.255.142") {
		t.Fatalf("bad query %s", reqs[0])
	}
	for _, l := range f.logs {
		if strings.Contains(l, "p%40ss") || strings.Contains(l, "p@ss") {
			t.Fatalf("password leaked into log: %s", l)
		}
	}
}

func TestLoginTriesCombinations(t *testing.T) {
	f := newFake(t)
	f.handler = func(q map[string]string) string {
		// Without suffix, second AC, MAC without separators.
		if q["c"] == "ACSetting" && q["DDDDD"] == "2023001" && q["wlanacip"] == "10.128.255.143" && q["wlanusermac"] == "AABBCCDDEEFF" {
			f.online.Store(true)
		}
		return ""
	}
	r, err := f.client.Login(context.Background(), "2023001", "x")
	if err != nil || !r.OK {
		t.Fatalf("r=%+v err=%v", r, err)
	}
	// suffix: 3 ACs × 2 MACs = 6, then no suffix until 143 with the plain
	// MAC answers — 6 + 2 + 1 = 9 with the discovered 142 tried first
	if n := len(f.requests()); n != 10 {
		t.Fatalf("got %d requests", n)
	}
}

func TestLoginPortalFallbackRetCodes(t *testing.T) {
	for _, code := range []int{2, 8} {
		f := newFake(t)
		f.handler = func(q map[string]string) string {
			if q["c"] == "Portal" {
				return fmt.Sprintf(`dr1003({"result":"0","msg":"失败","ret_code":%d})`, code)
			}
			return ""
		}
		r, err := f.client.Login(context.Background(), "2023001", "x")
		if err != nil || r.OK || r.RetCode != code || r.Msg != "失败" {
			t.Fatalf("code %d: r=%+v err=%v", code, r, err)
		}
		reqs := f.requests()
		if last := reqs[len(reqs)-1]; !strings.Contains(last, "c=Portal") || len(reqs) != 13 {
			t.Fatalf("code %d: %d requests, last %s", code, len(reqs), last)
		}
		if Advice(code) == "" {
			t.Fatal("missing advice")
		}
	}
}

func TestLoginPortalSuccess(t *testing.T) {
	f := newFake(t)
	f.handler = func(q map[string]string) string {
		if q["c"] == "Portal" {
			f.online.Store(true)
			return `dr1003({"result":"1","msg":"认证成功"})`
		}
		return ""
	}
	r, err := f.client.Login(context.Background(), "2023001", "x")
	if err != nil || !r.OK {
		t.Fatalf("r=%+v err=%v", r, err)
	}
}

func TestLoginAlreadyOnline(t *testing.T) {
	f := newFake(t)
	f.online.Store(true)
	r, err := f.client.Login(context.Background(), "a", "b")
	if err != nil || !r.AlreadyOnline || len(f.requests()) != 0 {
		t.Fatalf("r=%+v err=%v", r, err)
	}
}

func TestLoginCampusUnavailable(t *testing.T) {
	f := newFake(t)
	f.client.PortalBase = "http://127.0.0.1:1/eportal/"
	start := time.Now()
	_, err := f.client.Login(context.Background(), "a", "b")
	if !errors.Is(err, ErrCampusUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if d := time.Since(start); d > PreflightTimeout+time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestLoginNoResponse(t *testing.T) {
	f := newFake(t)
	f.handler = func(map[string]string) string { panic(http.ErrAbortHandler) }
	_, err := f.client.Login(context.Background(), "a", "b")
	if !errors.Is(err, ErrNoResponse) {
		t.Fatalf("err=%v", err)
	}
}

func TestLoginBadCredentialStops(t *testing.T) {
	f := newFake(t)
	f.handler = func(map[string]string) string { return "<script>msga='ldap auth error'</script>" }
	r, err := f.client.Login(context.Background(), "2023001", "wrong")
	if err != nil || r.OK || r.Outcome != BadCredential || r.Msg != "ldap auth error" {
		t.Fatalf("r=%+v err=%v", r, err)
	}
	if n := len(f.requests()); n != 1 {
		t.Fatalf("bad password sent %d requests", n)
	}
}

func TestLoginSuccessBeforeRouting(t *testing.T) {
	f := newFake(t)
	f.handler = func(map[string]string) string { return "<script>msga='认证成功'</script>" }
	r, err := f.client.Login(context.Background(), "2023001", "x")
	if err != nil || !r.OK || r.Warn == "" {
		t.Fatalf("r=%+v err=%v", r, err)
	}
	if n := len(f.requests()); n != 1 {
		t.Fatalf("login resubmitted: %d requests", n)
	}
}

func TestLoginInUseStops(t *testing.T) {
	f := newFake(t)
	f.handler = func(map[string]string) string { return "<script>msga='inuse, login again'</script>" }
	r, err := f.client.Login(context.Background(), "2023001", "x")
	if err != nil || r.OK || r.Outcome != InUse {
		t.Fatalf("r=%+v err=%v", r, err)
	}
	if n := len(f.requests()); n != 1 {
		t.Fatalf("got %d requests", n)
	}
}

func TestLoginMismatchSkipsProbe(t *testing.T) {
	f := newFake(t)
	sleeps := 0
	f.client.Sleep = func(ctx context.Context, d time.Duration) error { sleeps++; return ctx.Err() }
	f.handler = func(q map[string]string) string {
		if q["c"] == "ACSetting" && q["DDDDD"] == "2023001" && q["wlanacip"] == "10.128.255.143" && q["wlanusermac"] == "AABBCCDDEEFF" {
			return "<script>msga='认证成功'</script>"
		}
		return "<script>msga='mac, ip mismatch'</script>"
	}
	f.handler = withOnline(f, f.handler)
	r, err := f.client.Login(context.Background(), "2023001", "x")
	if err != nil || !r.OK {
		t.Fatalf("r=%+v err=%v", r, err)
	}
	// Seven mismatches are skipped without waiting; only success() sleeps.
	if n := len(f.requests()); n != 10 || sleeps != 1 {
		t.Fatalf("%d requests, %d sleeps", n, sleeps)
	}
}

// withOnline puts the fake online whenever h answers with success.
func withOnline(f *fakeCampus, h func(map[string]string) string) func(map[string]string) string {
	return func(q map[string]string) string {
		body := h(q)
		if o, _ := Classify(body); o == Success {
			f.online.Store(true)
		}
		return body
	}
}

func TestLoginRemembersCombination(t *testing.T) {
	f := newFake(t)
	f.handler = withOnline(f, func(q map[string]string) string {
		if q["c"] == "ACSetting" && q["DDDDD"] == "2023001" && q["wlanacip"] == "10.128.255.143" && q["wlanusermac"] == "AABBCCDDEEFF" {
			return "<script>msga='认证成功'</script>"
		}
		return "<script>msga='ac mismatch'</script>"
	})
	ctx := context.Background()
	if r, err := f.client.Login(ctx, "2023001", "x"); err != nil || !r.OK {
		t.Fatalf("r=%+v err=%v", r, err)
	}
	s, ok := f.client.LastSession()
	want := Session{Suffixed: false, ACIP: "10.128.255.143", MACPlain: true, UserIP: "10.20.30.40", UserMAC: "AABBCCDDEEFF"}
	if !ok || s != want {
		t.Fatalf("session %+v", s)
	}
	f.online.Store(false)
	f.mu.Lock()
	f.reqs = nil
	f.mu.Unlock()
	if r, err := f.client.Login(ctx, "2023001", "x"); err != nil || !r.OK {
		t.Fatalf("r=%+v err=%v", r, err)
	}
	if n := len(f.requests()); n != 1 {
		t.Fatalf("reconnect took %d requests", n)
	}
}

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		body string
		want Outcome
	}{
		{"<script>msga='认证成功'</script>", Success},
		{"<title>认证成功页</title>", Success},
		{"<script>msga='ldap auth error'</script>", BadCredential},
		{"<script>msga='userid error1'</script>", BadCredential},
		{"<script>msga='密码错误'</script>", BadCredential},
		{"<script>msga='inuse, login again'</script>", InUse},
		{"<script>msga='Rad:Limit Users Err'</script>", InUse},
		{"<script>msga='mac不匹配'</script>", ParamMismatch},
		{"<script>msga='AC认证失败'</script>", ParamMismatch},
		{"<script>msga='error0'</script>", Unknown},
		{"<html>hello</html>", Unknown},
		{"", Unknown},
	} {
		if got, _ := Classify(c.body); got != c.want {
			t.Errorf("Classify(%q) = %v, want %v", c.body, got, c.want)
		}
	}
}

func TestLogout(t *testing.T) {
	f := newFake(t)
	f.online.Store(true)
	f.handler = func(q map[string]string) string {
		if q["c"] == "ACSetting" && q["a"] == "Logout" && q["wlan_user_mac"] == "AABBCCDDEEFF" {
			return "Logout succeed"
		}
		return ""
	}
	if err := f.client.Logout(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
}

func TestLogoutUsesSession(t *testing.T) {
	f := newFake(t)
	f.client.ACIPs = nil
	f.client.remember(Session{ACIP: "10.128.255.129", UserIP: "10.20.30.40", UserMAC: "AA-BB-CC-DD-EE-FF"})
	f.handler = func(q map[string]string) string {
		if q["c"] == "Portal" && q["a"] == "logout" && q["wlan_ac_ip"] == "10.128.255.129" && q["wlan_user_mac"] == "AA-BB-CC-DD-EE-FF" {
			return `dr1003({"result":"1"})`
		}
		return ""
	}
	if err := f.client.Logout(context.Background(), "a"); err != nil {
		t.Fatal(err)
	}
}

func TestLogoutNoACIPs(t *testing.T) {
	f := newFake(t)
	f.client.ACIPs = nil
	f.handler = func(map[string]string) string { return "" }
	if err := f.client.Logout(context.Background(), "a"); err == nil {
		t.Fatal("unconfirmed logout reported success")
	}
	if n := len(f.requests()); n != 1 {
		t.Fatalf("got %d requests", n)
	}
}

func TestLoginPreservesErrorsFromBothInterfaces(t *testing.T) {
	f := newFake(t)
	f.handler = func(q map[string]string) string {
		if q["c"] == "ACSetting" {
			return `<script>msga='Portal接入控制器拒绝请求';</script>`
		}
		return `<!DOCTYPE html><html><title>系统发生错误</title></html>`
	}
	r, err := f.client.Login(context.Background(), "test", "secret")
	if err != nil || r.OK || !strings.Contains(r.Msg, "Portal接入控制器拒绝请求") || !strings.Contains(r.Msg, "系统发生错误") {
		t.Fatalf("lost server errors: r=%+v err=%v", r, err)
	}
}

func TestLoginPortalContinuesAfterUnexpectedResponse(t *testing.T) {
	for _, body := range []string{`<html><title>系统发生错误</title></html>`, ``, `dr1003({"unexpected":true})`, `dr1003({"result":"10"})`} {
		t.Run(body, func(t *testing.T) {
			f := newFake(t)
			calls := 0
			f.handler = func(q map[string]string) string {
				if q["c"] != "Portal" {
					return ""
				}
				calls++
				if calls == 1 {
					return body
				}
				f.online.Store(true)
				return `dr1003({"result":"1","msg":"认证成功"})`
			}
			r, err := f.client.Login(context.Background(), "test", "secret")
			if err != nil || !r.OK || calls != 2 {
				t.Fatalf("r=%+v err=%v Portal calls=%d, want 2", r, err, calls)
			}
		})
	}
}

func TestLoginPreservesACErrorWhenFallbackUnavailable(t *testing.T) {
	f := newFake(t)
	f.portal.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("c") == "ACSetting" {
			fmt.Fprint(w, `<script>msga='明确的认证失败原因';</script>`)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `<title>维护中</title>`)
	})
	r, err := f.client.Login(context.Background(), "test", "secret")
	if err != nil || r.OK || !strings.Contains(r.Msg, "明确的认证失败原因") || !strings.Contains(r.Msg, "503") {
		t.Fatalf("r=%+v err=%v", r, err)
	}
}

func TestLoginRejectsHTTPSuccessBodyOnErrorStatus(t *testing.T) {
	f := newFake(t)
	f.portal.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, `dr1003({"result":"1"})`)
	})
	r, err := f.client.Login(context.Background(), "test", "secret")
	if r.OK || err != nil || !strings.Contains(r.Msg, "502") {
		t.Fatalf("r=%+v err=%v", r, err)
	}
}

func TestLoginNetworkErrorDoesNotLeakPassword(t *testing.T) {
	f := newFake(t)
	f.client.PortalBase = "http://127.0.0.1:1/eportal/"
	// Exercise credential-bearing HTTP requests, not the earlier TCP check.
	f.client.Preflight = nil
	password := "secret-password-123 &?"
	_, err := f.client.Login(context.Background(), "test", password)
	if !errors.Is(err, ErrNoResponse) {
		t.Fatalf("err=%v", err)
	}
	logs := strings.Join(f.logs, "\n")
	if !strings.Contains(logs, "ACSetting 登录:") || !strings.Contains(logs, "Portal 登录:") || !strings.Contains(logs, "请求失败:") {
		t.Fatalf("did not exercise both HTTP transports: %s", logs)
	}
	for _, secret := range []string{password, escape(password), "secret-password-123"} {
		if strings.Contains(logs, secret) {
			t.Fatalf("password leaked: %s", logs)
		}
	}
}

func TestLoginEmptyHTTPError(t *testing.T) {
	f := newFake(t)
	f.portal.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })
	r, err := f.client.Login(context.Background(), "test", "secret")
	if err != nil || !strings.Contains(r.Msg, "503") {
		t.Fatalf("r=%+v err=%v", r, err)
	}
}

func TestParsePortal(t *testing.T) {
	for _, body := range []string{`{"result":1}`, `dr1003({"result":"1"});`, `dr1003 ({"result":1}) ;`, "\ufeff dr1003( {\"result\":1} ) ;"} {
		r, ok := parsePortal(body)
		if !ok || !r.OK {
			t.Errorf("rejected %q: %+v", body, r)
		}
	}
	for _, body := range []string{`other({"result":1})`, `<html>{"result":1}</html>`, `{"result":10}`, `{"result":true}`} {
		if _, ok := parsePortal(body); ok {
			t.Errorf("accepted %q", body)
		}
	}
	for _, body := range []string{`{"result":0,"ret_code":8,"msg":"\u5bc6\u7801"}`, `{"result":"0","ret_code":"8","msg":"密码"}`} {
		r, ok := parsePortal(body)
		if !ok || r.OK || r.RetCode != 8 || r.Msg != "密码" {
			t.Errorf("%q: %+v", body, r)
		}
	}
}

func TestLoginPortalSuccessBeforeRoutingRemembersSession(t *testing.T) {
	f := newFake(t)
	f.handler = func(q map[string]string) string {
		if q["c"] == "Portal" {
			return "\ufeff dr1003 ( {\"result\":1,\"msg\":\"认证成功\"} ) ;"
		}
		return ""
	}
	r, err := f.client.Login(context.Background(), "test", "secret")
	if err != nil || !r.OK || r.Outcome != Success || r.Warn == "" {
		t.Fatalf("r=%+v err=%v", r, err)
	}
	if n := len(f.requests()); n != 13 {
		t.Fatalf("success resubmitted: %d requests, want 13", n)
	}
	want := Session{Suffixed: true, ACIP: "10.128.255.142", UserIP: "10.20.30.40", UserMAC: "AA-BB-CC-DD-EE-FF", PortalAPI: true}
	if got, ok := f.client.LastSession(); !ok || got != want {
		t.Fatalf("session=%+v present=%v, want %+v", got, ok, want)
	}
}

func TestLoginPortalContinuesAfterHTTPError(t *testing.T) {
	f := newFake(t)
	calls := 0
	f.portal.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("c") != "Portal" {
			return
		}
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `dr1003({"result":1})`)
			return
		}
		fmt.Fprint(w, `dr1003({"result":1})`)
	})
	r, err := f.client.Login(context.Background(), "test", "secret")
	if err != nil || !r.OK || r.Outcome != Success || calls != 2 {
		t.Fatalf("r=%+v err=%v Portal calls=%d, want 2", r, err, calls)
	}
	if got, ok := f.client.LastSession(); !ok || !got.PortalAPI || got.UserMAC != "AABBCCDDEEFF" {
		t.Fatalf("did not cache the successful fallback candidate: %+v present=%v", got, ok)
	}
}

func TestLoginClassifiesDecodedACMessage(t *testing.T) {
	f := newFake(t)
	f.handler = func(map[string]string) string {
		return `<script>msga='ldap auth &#101;rror';</script>`
	}
	r, err := f.client.Login(context.Background(), "test", "secret")
	if err != nil || r.OK || r.Outcome != BadCredential || r.Msg != "ldap auth error" || len(f.requests()) != 1 {
		t.Fatalf("r=%+v err=%v requests=%d", r, err, len(f.requests()))
	}
}

func TestGetBoundsResponseBody(t *testing.T) {
	for _, size := range []int{256 << 10, (256 << 10) + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			f := newFake(t)
			f.handler = func(map[string]string) string { return strings.Repeat("x", size) }
			body, err := f.client.get(context.Background(), f.client.PortalBase, time.Second)
			if size == 256<<10 {
				if err != nil || len(body) != size {
					t.Fatalf("len(body)=%d err=%v", len(body), err)
				}
			} else if err == nil || !receivedResponse(err) || !strings.Contains(err.Error(), "256 KiB") || body != "" {
				t.Fatalf("len(body)=%d err=%v", len(body), err)
			}
		})
	}
}

func TestMACForms(t *testing.T) {
	if got := DashedMAC("aa:bb:cc:dd:ee:ff"); got != "AA-BB-CC-DD-EE-FF" {
		t.Fatal(got)
	}
	if got := NormalizeMAC("aa-bb-cc-dd-ee-ff"); got != "AABBCCDDEEFF" {
		t.Fatal(got)
	}
}

// The campus portal answers in GBK while claiming UTF-8 in its Content-Type.
// The raw bytes used to reach the logs as garbage; they must be re-encoded
// so the human-readable reason inside msga survives.
func TestLoginDecodesGBKPortalErrors(t *testing.T) {
	f := newFake(t)
	toGBK := func(s string) string {
		b, err := simplifiedchinese.GB18030.NewEncoder().Bytes([]byte(s))
		if err != nil {
			t.Fatalf("gbk encode: %v", err)
		}
		return string(b) // Go strings hold arbitrary bytes
	}
	seen := ""
	f.handler = func(q map[string]string) string {
		body := toGBK("<script>msga='Portal3:账号或密码错误,请重新输入';</script>")
		seen = body
		return body
	}
	r, err := f.client.Login(context.Background(), "2023001", "wrong-pass")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if r.OK {
		t.Fatalf("must not succeed")
	}
	// The GBK-decoded reason must reach the logs — that is the whole point.
	for _, l := range f.logs {
		if strings.Contains(l, "账号或密码错误") {
			return // the human-readable reason reached the logs
		}
	}
	t.Fatalf("gbk reason missing from logs: %v", f.logs)
	_ = seen
}

// The root page names the caller's real AC even when the hijack redirect is
// invisible; the discovered controller must be tried first.
func TestDiscoverACPrependsRealController(t *testing.T) {
	f := newFake(t)
	f.rootResponse.Store(`<script>AC="10.128.255.142";</script>`)
	f.handler = func(q map[string]string) string {
		if q["wlanacip"] == "10.128.255.142" && q["DDDDD"] == "2023001" {
			f.online.Store(true)
			return "<script>msga='认证成功'</script>"
		}
		return "<script>msga='Portal协议认证超时！'</script>"
	}
	r, err := f.client.Login(context.Background(), "2023001", "x")
	if err != nil || !r.OK {
		t.Fatalf("r=%+v err=%v", r, err)
	}
	reqs := f.requests()
	if !strings.Contains(reqs[0], "wlanacip=10.128.255.142") {
		t.Fatalf("discovered AC not tried first: %s", reqs[0])
	}
}
