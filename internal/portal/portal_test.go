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
}

func newFake(t *testing.T) *fakeCampus {
	f := &fakeCampus{t: t}
	f.portal = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reqs = append(f.reqs, r.URL.RawQuery)
		f.mu.Unlock()
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
			q["wlanacip"] == "10.128.255.129" && q["wlanusermac"] == "AA-BB-CC-DD-EE-FF" && q["wlanuserip"] == "10.20.30.40" {
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
	if !strings.Contains(reqs[0], "DDDDD=%2C0%2C2023001") || !strings.Contains(reqs[0], "upass=p%40ss%20word") {
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
	// suffix: 2 ACs × 2 MACs = 4, then no suffix: AC1×2 + AC2 first MAC×... = 4+4 = 8
	if n := len(f.requests()); n != 8 {
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
		if last := reqs[len(reqs)-1]; !strings.Contains(last, "c=Portal") || len(reqs) != 9 {
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
	if n := len(f.requests()); n != 8 || sleeps != 1 {
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

func TestMACForms(t *testing.T) {
	if got := DashedMAC("aa:bb:cc:dd:ee:ff"); got != "AA-BB-CC-DD-EE-FF" {
		t.Fatal(got)
	}
	if got := NormalizeMAC("aa-bb-cc-dd-ee-ff"); got != "AABBCCDDEEFF" {
		t.Fatal(got)
	}
}
