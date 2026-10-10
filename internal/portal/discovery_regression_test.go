package portal

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryEncodedURLRegression(t *testing.T) {
	u, _ := url.Parse("http://10.0.10.252/a79.htm?wlanusermac=02-00-00-00-00-16&wlanuserip=192.0.2.16&wlanacip=10%2E128%2E255%2E144")
	want := Info{UserIP: "192.0.2.16", UserMAC: "02-00-00-00-00-16", ACIP: "10.128.255.144"}
	if got := infoFromURL(u); got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
	for _, invalid := range []string{"10", "10.128.255.999", "10.128.255.144junk", "10.128.255.144/24", "::1", "::ffff:10.128.255.144", "010.128.255.144", "10%2E128%2E255%2E144", "10.128.255.144&extra=x", ""} {
		u, _ := url.Parse("http://portal/?wlanacip=" + url.QueryEscape(invalid) + "&wlanuserip=" + url.QueryEscape(invalid))
		if got := infoFromURL(u); got != (Info{}) {
			t.Errorf("accepted %q: %+v", invalid, got)
		}
	}
	u, _ = url.Parse("http://portal/?wlanacip=10%ZZ128&wlanuserip=192.0.2.16")
	if got := infoFromURL(u); got.ACIP != "" || got.UserIP != "192.0.2.16" {
		t.Fatalf("malformed encoding: %+v", got)
	}
}

func TestDiscoveryMACValidationRegression(t *testing.T) {
	for _, mac := range []string{"02--00-00-00-00-16", ".020000000016", "02:00:00:00:00", "02:00:00:00:00:16:00:11", "GG-00-00-00-00-16"} {
		u, _ := url.Parse("http://portal/?wlanusermac=" + url.QueryEscape(mac))
		if got := infoFromURL(u).UserMAC; got != "" {
			t.Errorf("accepted %q as %q", mac, got)
		}
	}
	for _, mac := range []string{"02-00-00-00-00-16", "02:00:00:00:00:16", "0200.0000.0016"} {
		u, _ := url.Parse("http://portal/?wlanusermac=" + url.QueryEscape(mac))
		if got := infoFromURL(u).UserMAC; got != "02-00-00-00-00-16" {
			t.Errorf("rejected %q: %q", mac, got)
		}
	}
}

func TestDiscoveryFinalURLSurvivesBrokenBodyRegression(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/a79.htm?wlanacip=10%2E128%2E255%2E144", http.StatusFound)
			return
		}
		w.Header().Set("Content-Length", "999")
		fmt.Fprint(w, "short body") // net/http returns unexpected EOF if read
	}))
	defer srv.Close()
	c := New(nil)
	c.HijackURL = srv.URL
	info, hijacked, err := c.PortalInfo(context.Background())
	if err != nil || !hijacked || info.ACIP != "10.128.255.144" {
		t.Fatalf("info=%+v hijacked=%v err=%v", info, hijacked, err)
	}
}

func TestDiscoveryPageRegression(t *testing.T) {
	for _, body := range []string{
		`<script>AC = '10.128.255.144';</script>`,
		`<script> AC = "10.128.255.144";</script>`,
		`<script>window.location.href='/a79.htm?wlanuserip=192.0.2.16&amp;wlanacip=10%2E128%2E255%2E144';</script>`,
		`<script>location.replace("http://unrequested.invalid/a79.htm?wlanacip=10%2e128%2e255%2e144")</script>`,
		`<meta http-equiv="refresh" content="0; URL=/a79.htm?wlanuserip=192.0.2.16&amp;wlanacip=10%2E128%2E255%2E144">`,
		`<a href="//unrequested.invalid/a79.htm?wlanacip=10%2E128%2E255%2E144&amp;wlanuserip=192.0.2.16">login</a>`,
		`wlanacip=10%2E128%2E255%2E144`,
	} {
		t.Run(body, func(t *testing.T) {
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; fmt.Fprint(w, body) }))
			defer srv.Close()
			c := New(nil)
			c.PortalHost = strings.TrimPrefix(srv.URL, "http://")
			if got := c.discoverAC(context.Background()); got != "10.128.255.144" {
				t.Fatalf("AC=%q", got)
			}
			if requests != 1 {
				t.Fatalf("followed HTML target: %d requests", requests)
			}
		})
	}
	for _, body := range []string{`AC="10"`, `AC='10.128.255.999'`, `otherAC="10.128.255.144"`, `<a href="/?wlanacip=10.128.255.144junk">`, strings.Repeat("x", discoveryBodyLimit) + ` AC='10.128.255.144'`} {
		if got := infoFromPage(body); got.ACIP != "" {
			t.Errorf("invalid page accepted: %+v", got)
		}
	}
}

func TestDiscoveryFinalRedirectRegression(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/a79.htm?wlanacip=10%2E128%2E255%2E144&wlanuserip=192.0.2.16", http.StatusFound)
			return
		}
		fmt.Fprint(w, `AC="10.128.255.142"`)
	}))
	defer srv.Close()
	c := New(nil)
	c.PortalHost = strings.TrimPrefix(srv.URL, "http://")
	c.HijackURL = srv.URL
	if got := c.discoverAC(context.Background()); got != "10.128.255.144" {
		t.Fatal(got)
	}
	info, hijacked, err := c.PortalInfo(context.Background())
	if err != nil || !hijacked || info.ACIP != "10.128.255.144" {
		t.Fatalf("%+v hijacked=%v err=%v", info, hijacked, err)
	}
}

func TestDiscoveryCandidatePriorityRegression(t *testing.T) {
	c := New(nil)
	c.ACIPs = []string{"10.128.255.142", "10.128.255.143", "10.128.255.144"}
	nic := NIC{IP: "192.0.2.16", MAC: "020000000016"}
	p := c.params(nic, Info{ACIP: "10.128.255.144"}, "10.128.255.129")
	if want := []string{"10.128.255.144", "10.128.255.129", "10.128.255.142", "10.128.255.143"}; !reflect.DeepEqual(p.acs, want) {
		t.Fatalf("%v", p.acs)
	}
	c.remember(Session{ACIP: "10.128.255.142", Suffixed: false, MACPlain: true})
	for i, cb := range c.combos(p) {
		if i < 4 && cb.ac != "10.128.255.144" {
			t.Fatalf("stale candidate %d: %+v", i, cb)
		}
	}
	p = c.params(nic, Info{ACIP: "10", UserIP: "bad"}, "10.128.255.143")
	if p.freshAC != "10.128.255.143" || p.ip != nic.IP {
		t.Fatalf("%+v", p)
	}
	p = c.params(nic, Info{})
	if got := c.combos(p)[0]; got.ac != "10.128.255.142" || got.suffixed {
		t.Fatalf("no discovery should retain cached preference: %+v", got)
	}
	c.remember(Session{ACIP: "10.128.255.144", Suffixed: false, MACPlain: true})
	p = c.params(nic, Info{ACIP: "10.128.255.144"})
	if got := c.combos(p)[0]; got.ac != "10.128.255.144" || got.suffixed || got.mac != nic.MAC {
		t.Fatalf("matching fresh AC should retain cached form: %+v", got)
	}
}

func TestDiscoveryLogin144NoPollutionRegression(t *testing.T) {
	ac := "10.128.255.144"
	var sent []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hijack":
			http.Redirect(w, r, "/a79.htm?wlanuserip=192.0.2.16&wlanusermac=02-00-00-00-00-16&wlanacip="+strings.ReplaceAll(ac, ".", "%2E"), http.StatusFound)
		case "/a79.htm":
			fmt.Fprint(w, "login")
		case "/":
			fmt.Fprint(w, `AC = '10.128.255.142';`)
		case "/eportal/":
			sent = append(sent, r.URL.Query().Get("wlanacip"))
			if r.URL.Query().Get("wlan_ac_ip") != ac || r.URL.Query().Get("wlanuserip") != "192.0.2.16" {
				t.Errorf("wrong parameters %v", r.URL.Query())
			}
			fmt.Fprint(w, `<script>msga='认证成功'</script>`)
		default:
			t.Errorf("unexpected target %s", r.URL)
		}
	}))
	defer srv.Close()
	c := New(nil)
	other := New(nil)
	original := append([]string(nil), DefaultACIPs...)
	c.PortalHost = strings.TrimPrefix(srv.URL, "http://")
	c.PortalBase = srv.URL + "/eportal/"
	c.HijackURL = srv.URL + "/hijack"
	c.ProbeURLs = nil
	c.LocalNIC = func() (NIC, error) { return NIC{IP: "192.0.2.16", MAC: "020000000016"}, nil }
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	c.remember(Session{ACIP: "10.128.255.142", Suffixed: false, MACPlain: true})
	for _, next := range []string{"10.128.255.144", "10.128.255.143"} {
		ac = next
		r, err := c.Login(context.Background(), "account", "password")
		if err != nil || !r.OK {
			t.Fatalf("%+v %v", r, err)
		}
		if s, ok := c.LastSession(); !ok || s.ACIP != next {
			t.Fatalf("session %+v", s)
		}
		if !reflect.DeepEqual(c.ACIPs, original) || !reflect.DeepEqual(other.ACIPs, original) || !reflect.DeepEqual(DefaultACIPs, original) {
			t.Fatal("discovery polluted shared candidates")
		}
	}
	if !reflect.DeepEqual(sent, []string{"10.128.255.144", "10.128.255.143"}) {
		t.Fatalf("requests %v", sent)
	}
	found := false
	for _, ip := range DefaultACIPs {
		found = found || ip == "10.128.255.144"
	}
	if !found {
		t.Fatal("missing 144 fallback")
	}
}
