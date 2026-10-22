package portal

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stateHarness builds a client whose HTTPS probes fail (closed port) unless a
// test points them somewhere else, and whose hijack URL is served by a handler
// the test controls.
func stateHarness(t *testing.T, hijack http.HandlerFunc, entry *PortalEntry) *Client {
	t.Helper()
	h := httptest.NewServer(hijack)
	t.Cleanup(h.Close)

	c := New(func(string) {})
	c.HTTP = &http.Client{Timeout: 2 * time.Second}
	c.Probe = &http.Client{Timeout: 2 * time.Second}
	c.ProbeURLs = []string{"https://127.0.0.1:1"} // connection refused: no internet
	c.HijackURL = h.URL
	c.LocalNIC = func() (NIC, error) {
		return NIC{Name: "eth", IP: "10.20.30.40", MAC: "AABBCCDDEEFF"}, nil
	}
	if entry != nil {
		c.Entries = []PortalEntry{*entry}
	}
	return c
}

// asLocalhost makes the redirect target a different host name, which is what
// "the gateway intercepted us" means: same host, different port is not a
// hijack.
func asLocalhost(raw string) string { return strings.Replace(raw, "127.0.0.1", "localhost", 1) }

func entryFor(t *testing.T, raw string) PortalEntry {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	port := u.Port()
	if port == "" {
		port = "80"
	}
	return PortalEntry{Scheme: u.Scheme, Host: u.Hostname(), Port: port, Path: u.Path}
}

const sampleQuery = "wlanuserip=10.20.30.40&wlanusermac=aa-bb-cc-dd-ee-ff&wlanacip=10.128.255.144"

func TestEntryMatchesWholeURL(t *testing.T) {
	e := PortalEntry{Scheme: "http", Host: "10.0.10.252", Port: "80", Path: "/a79.htm"}
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"the sample address", "http://10.0.10.252/a79.htm?" + sampleQuery, true},
		{"no path", "http://10.0.10.252", false},
		{"submission endpoint on 801", "http://10.0.10.252:801/eportal/?c=ACSetting&a=Login", false},
		{"same path, wrong port", "http://10.0.10.252:8080/a79.htm", false},
		{"https not observed", "https://10.0.10.252/a79.htm", false},
		{"other host", "http://10.0.10.253/a79.htm", false},
		{"path prefix only", "http://10.0.10.252/a79.htm.old", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := entryMatches(u, e); got != tc.want {
				t.Fatalf("%s matched=%v want %v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestFreshForNIC(t *testing.T) {
	nic := NIC{IP: "10.20.30.40", MAC: "AABBCCDDEEFF"}
	cases := []struct {
		name string
		info Info
		want bool
	}{
		{"complete and matching", Info{UserIP: "10.20.30.40", UserMAC: "AA-BB-CC-DD-EE-FF", ACIP: "10.128.255.144"}, true},
		{"plain mac", Info{UserIP: "10.20.30.40", UserMAC: "aabbccddeeff", ACIP: "10.128.255.144"}, true},
		{"another machine", Info{UserIP: "10.20.30.41", UserMAC: "AA-BB-CC-DD-EE-FF", ACIP: "10.128.255.144"}, false},
		{"another mac", Info{UserIP: "10.20.30.40", UserMAC: "00-11-22-33-44-55", ACIP: "10.128.255.144"}, false},
		{"no ac", Info{UserIP: "10.20.30.40", UserMAC: "AA-BB-CC-DD-EE-FF"}, false},
		{"no mac", Info{UserIP: "10.20.30.40", ACIP: "10.128.255.144"}, false},
		{"no ip", Info{UserMAC: "AA-BB-CC-DD-EE-FF", ACIP: "10.128.255.144"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := freshForNIC(tc.info, nic); got != tc.want {
				t.Fatalf("%+v fresh=%v want %v", tc.info, got, tc.want)
			}
		})
	}
}

func TestProbeStateClassifies(t *testing.T) {
	ctx := context.Background()

	t.Run("online wins", func(t *testing.T) {
		site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "ok")
		}))
		defer site.Close()
		c := stateHarness(t, func(w http.ResponseWriter, r *http.Request) {}, nil)
		c.ProbeURLs = []string{site.URL}
		c.Probe = site.Client()
		if st, reason := c.ProbeState(ctx); st != NetOnline || reason != ReasonProbeOK {
			t.Fatalf("%v %s", st, reason)
		}
	})

	t.Run("no redirect is unknown", func(t *testing.T) {
		c := stateHarness(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "hello") }, nil)
		if st, reason := c.ProbeState(ctx); st != NetUnknown || reason != ReasonNoRedirect {
			t.Fatalf("%v %s", st, reason)
		}
	})

	t.Run("untrusted portal is unknown", func(t *testing.T) {
		var target string
		c := stateHarness(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target, http.StatusFound)
		}, nil)
		other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer other.Close()
		target = asLocalhost(other.URL) + "/a79.htm?" + sampleQuery
		c.Entries = []PortalEntry{{Scheme: "http", Host: "10.0.10.252", Port: "80", Path: "/a79.htm"}}
		if st, reason := c.ProbeState(ctx); st != NetUnknown || reason != ReasonUntrusted {
			t.Fatalf("%v %s", st, reason)
		}
	})

	t.Run("stale parameters are unknown", func(t *testing.T) {
		var target string
		c := stateHarness(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target, http.StatusFound)
		}, nil)
		page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer page.Close()
		target = asLocalhost(page.URL) + "/a79.htm?wlanuserip=10.9.9.9&wlanusermac=aa-bb-cc-dd-ee-ff&wlanacip=10.128.255.144"
		e := entryFor(t, target)
		c.Entries = []PortalEntry{e}
		if st, reason := c.ProbeState(ctx); st != NetUnknown || reason != ReasonStaleParams {
			t.Fatalf("%v %s", st, reason)
		}
	})

	t.Run("complete evidence is unauthenticated", func(t *testing.T) {
		var page *httptest.Server
		page = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer page.Close()
		target := asLocalhost(page.URL) + "/a79.htm?" + sampleQuery
		c := stateHarness(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target, http.StatusFound)
		}, nil)
		e := entryFor(t, target)
		c.Entries = []PortalEntry{e}
		if st, reason := c.ProbeState(ctx); st != NetUnauthenticated || reason != ReasonPortalHijack {
			t.Fatalf("%v %s", st, reason)
		}
	})
}

// The automatic path must not send a password when the evidence is incomplete;
// the explicit path may, because the user asked for it.
func TestLoginAutoRefusesWithoutEvidence(t *testing.T) {
	var hits atomic.Int32
	portalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, `<script>Msg=01;msga='AC999';</script>`)
	}))
	defer portalSrv.Close()

	var target string
	c := stateHarness(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	}, nil)
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer page.Close()
	// Parameters of another machine: stale evidence.
	target = asLocalhost(page.URL) + "/a79.htm?wlanuserip=10.9.9.9&wlanusermac=aa-bb-cc-dd-ee-ff&wlanacip=10.128.255.144"
	e := entryFor(t, target)
	c.Entries = []PortalEntry{e}
	c.PortalBase = portalSrv.URL + "/eportal/"
	c.PortalHost = strings.TrimPrefix(portalSrv.URL, "http://")
	c.Sleep = func(context.Context, time.Duration) error { return nil }

	res, err := c.LoginAuto(context.Background(), "2026000000", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !res.NotSubmitted || res.OK {
		t.Fatalf("auto submitted without evidence: %+v", res)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("portal received %d requests", n)
	}

	// The explicit path still tries, which is the documented difference.
	if _, err := c.Login(context.Background(), "2026000000", "pw"); err != nil {
		t.Fatal(err)
	}
	if hits.Load() == 0 {
		t.Fatal("manual login sent nothing")
	}
}

// "The internet came back" must not be stored as "this combination worked".
func TestProbeOnlySuccessDoesNotRemember(t *testing.T) {
	site := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer site.Close()

	var c *Client
	portalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// After the portal answers, the link recovers: from here on the
		// probe succeeds, which is what the old code mistook for success.
		c.ProbeURLs = []string{site.URL}
		c.Probe = site.Client() // trust the test certificate
		fmt.Fprint(w, `<script>Msg=01;msga='AC999';</script>`)
	}))
	defer portalSrv.Close()

	var page *httptest.Server
	page = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer page.Close()
	target := asLocalhost(page.URL) + "/a79.htm?" + sampleQuery

	c = stateHarness(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	}, nil)
	c.Entries = []PortalEntry{entryFor(t, target)}
	c.PortalBase = portalSrv.URL + "/eportal/"
	c.PortalHost = strings.TrimPrefix(portalSrv.URL, "http://")
	c.Sleep = func(context.Context, time.Duration) error { return nil }

	res, err := c.LoginAuto(context.Background(), "2026000000", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Route != RouteProbe {
		t.Fatalf("%+v", res)
	}
	if _, ok := c.LastSession(); ok {
		t.Fatal("a probe-only success was remembered as a working combination")
	}
}

// A conflict must not be resolved by "first value wins": which one the gateway
// meant cannot be known, so it is not evidence at all.
func TestParamConflict(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"consistent aliases", "wlanacip=10.128.255.144&wlan_ac_ip=10.128.255.144", false},
		{"different aliases", "wlanacip=10.128.255.144&wlan_ac_ip=10.128.255.143", true},
		{"duplicate same", "wlanacip=10.128.255.144&wlanacip=10.128.255.144", false},
		{"duplicate different", "wlanacip=10.128.255.144&wlanacip=10.128.255.143", true},
		{"mac aliases disagree", "wlanusermac=aa-bb-cc-dd-ee-ff&wlan_user_mac=00-11-22-33-44-55", true},
		{"ip aliases disagree", "wlanuserip=10.20.30.40&wlan_user_ip=10.20.30.41", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse("http://10.0.10.252/a79.htm?" + tc.raw)
			if err != nil {
				t.Fatal(err)
			}
			if got := paramConflict(u.Query()); got != tc.want {
				t.Fatalf("%s conflict=%v want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// The monitor said "unauthenticated", but the submission entry probes again and
// sees conflicting parameters. It must refuse: one criterion for both paths.
func TestLoginAutoRefusesWhenSecondProbeConflicts(t *testing.T) {
	var hits atomic.Int32
	portalSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, `<script>Msg=01;msga='AC999';</script>`)
	}))
	defer portalSrv.Close()

	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer page.Close()
	good := asLocalhost(page.URL) + "/a79.htm?" + sampleQuery
	// Same page, but two different AC values: which one is real cannot be known.
	conflicting := asLocalhost(page.URL) + "/a79.htm?" + sampleQuery + "&wlanacip=10.128.255.143"

	var useConflicting atomic.Bool
	c := stateHarness(t, func(w http.ResponseWriter, r *http.Request) {
		if useConflicting.Load() {
			http.Redirect(w, r, conflicting, http.StatusFound)
			return
		}
		http.Redirect(w, r, good, http.StatusFound)
	}, nil)
	c.Entries = []PortalEntry{entryFor(t, good)}
	c.PortalBase = portalSrv.URL + "/eportal/"
	c.PortalHost = strings.TrimPrefix(portalSrv.URL, "http://")
	c.Sleep = func(context.Context, time.Duration) error { return nil }

	// First look: complete evidence, the automatic path would be allowed.
	if st, reason := c.ProbeState(context.Background()); st != NetUnauthenticated || reason != ReasonPortalHijack {
		t.Fatalf("first probe: %v %s", st, reason)
	}

	// Second look (right before submitting): conflicting parameters.
	useConflicting.Store(true)
	res, err := c.LoginAuto(context.Background(), "2026000000", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !res.NotSubmitted {
		t.Fatalf("submitted despite conflicting evidence: %+v", res)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("portal received %d requests", n)
	}
}
