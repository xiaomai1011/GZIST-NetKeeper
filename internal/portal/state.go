package portal

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// NetState is what the network itself looks like. It is deliberately separate
// from the result of an authentication attempt: "the internet works" and "the
// portal accepted our credentials" are different facts and must not be folded
// into one boolean (the old Online() did exactly that).
type NetState int

const (
	// NetUnknown means this device cannot tell: timeouts, DNS/TLS errors,
	// connection failures or responses nobody recognises. Unknown never
	// becomes Unauthenticated just because it happened many times.
	NetUnknown NetState = iota
	// NetOnline means a constrained external probe succeeded.
	NetOnline
	// NetUnauthenticated means the gateway redirected an external request to
	// the trusted campus portal AND that portal handed back parameters that
	// match this machine's current interface.
	NetUnauthenticated
)

func (s NetState) String() string {
	switch s {
	case NetOnline:
		return "在线"
	case NetUnauthenticated:
		return "未认证"
	}
	return "未知"
}

// Reasons reported alongside a NetState. They are fixed strings so tests and
// logs stay comparable.
const (
	ReasonProbeOK       = "probe_ok"
	ReasonNoNIC         = "no_nic"
	ReasonPortalFailed  = "portal_unreachable"
	ReasonNoRedirect    = "no_redirect"
	ReasonUntrusted     = "untrusted_portal"
	ReasonStaleParams   = "stale_params"
	ReasonPortalHijack  = "portal_hijack"
	ReasonParamConflict = "param_conflict"
	ReasonRouteRouted   = "route_ok"
	ReasonRouteNotReady = "not_routed"
)

// PortalEntry is one confirmed way the gateway hands a browser to the campus
// portal. scheme, host, port and path are matched as a whole: allowing them
// separately would accept combinations never observed on this campus.
type PortalEntry struct {
	Scheme string
	Host   string
	Port   string
	Path   string
}

// DefaultPortalEntries are the discovery entries actually observed:
//   - http://10.0.10.252/a79.htm?...  (the address the user was given)
//   - http://10.0.10.252/             (used by discovery)
//
// The submission endpoint (http://10.0.10.252:801/eportal/) is NOT a discovery
// entry: "where the browser was redirected" and "where credentials are posted"
// are different questions.
var DefaultPortalEntries = []PortalEntry{
	{Scheme: "http", Host: DefaultPortalHost, Port: "80", Path: "/a79.htm"},
	{Scheme: "http", Host: DefaultPortalHost, Port: "80", Path: "/"},
}

// portalEvidence is what one hijack probe saw.
type portalEvidence struct {
	info     Info
	final    *url.URL
	hijacked bool // an external request was redirected to another host
	trusted  bool // the final URL is one of the confirmed entries
	fresh    bool // the parameters describe the current interface
	conflict bool // duplicated or contradictory parameters
}

func (e portalEvidence) state() (NetState, string) {
	switch {
	case e.conflict:
		return NetUnknown, ReasonParamConflict
	case !e.hijacked:
		return NetUnknown, ReasonNoRedirect
	case !e.trusted:
		return NetUnknown, ReasonUntrusted
	case !e.fresh:
		return NetUnknown, ReasonStaleParams
	}
	return NetUnauthenticated, ReasonPortalHijack
}

// Probe classifies the network without submitting anything.
//
// Order matters: a working HTTPS probe wins, because it proves the internet is
// usable no matter what a portal page says. Only when that fails do we look for
// evidence that this device is merely unauthenticated — and the evidence has to
// be complete (redirect + confirmed entry + parameters matching this NIC),
// otherwise the answer is Unknown.
func (c *Client) ProbeState(ctx context.Context) (NetState, string) {
	if c.online(ctx) {
		return NetOnline, ReasonProbeOK
	}
	if ctx.Err() != nil {
		return NetUnknown, ReasonPortalFailed
	}
	nic, err := c.LocalNIC()
	if err != nil {
		return NetUnknown, ReasonNoNIC
	}
	ev, err := c.evidence(ctx, nic)
	if err != nil {
		return NetUnknown, ReasonPortalFailed
	}
	return ev.state()
}

// evidence fetches the hijack URL and judges the answer. The page itself is
// only read when the redirect URL is missing parameters: a body hint can
// complete the picture but never replaces the redirect.
func (c *Client) evidence(ctx context.Context, nic NIC) (portalEvidence, error) {
	want, err := url.Parse(c.HijackURL)
	if err != nil {
		return portalEvidence{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.HijackURL, nil)
	if err != nil {
		return portalEvidence{}, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return portalEvidence{}, err
	}
	defer resp.Body.Close()

	final := resp.Request.URL
	info := infoFromURL(final)
	// Only a redirect to another host is evidence of interception. Parameters
	// alone are not: reading them from a page we asked for proves nothing.
	hijacked := final.Hostname() != want.Hostname()
	if hijacked && (info.UserIP == "" || info.UserMAC == "" || info.ACIP == "") {
		if b, err := io.ReadAll(io.LimitReader(resp.Body, discoveryBodyLimit+1)); err == nil {
			if !utf8.Valid(b) {
				if dec, derr := simplifiedchinese.GB18030.NewDecoder().Bytes(b); derr == nil {
					b = dec
				}
			}
			mergeInfo(&info, infoFromPage(string(b)))
		}
	}
	ev := portalEvidence{
		info:     info,
		final:    final,
		hijacked: hijacked,
		trusted:  c.trustedEntry(final),
		fresh:    freshForNIC(info, nic),
		conflict: paramConflict(final.Query()),
	}
	return ev, nil
}

// trustedEntry matches the whole URL against the confirmed entries.
func (c *Client) trustedEntry(u *url.URL) bool {
	entries := c.Entries
	if len(entries) == 0 {
		entries = DefaultPortalEntries
	}
	for _, e := range entries {
		if entryMatches(u, e) {
			return true
		}
	}
	return false
}

func entryMatches(u *url.URL, e PortalEntry) bool {
	if u == nil || !strings.EqualFold(u.Scheme, e.Scheme) {
		return false
	}
	if !strings.EqualFold(u.Hostname(), e.Host) {
		return false
	}
	port := u.Port()
	if port == "" {
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	if port != e.Port {
		return false
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return path == e.Path
}

// freshForNIC requires every parameter to describe this machine right now. A
// missing parameter is not filled in from the last session: an old session's
// values must never pass as fresh evidence (the machine may have moved to
// another network since).
func freshForNIC(info Info, nic NIC) bool {
	if info.UserIP == "" || info.UserMAC == "" || info.ACIP == "" {
		return false
	}
	if validIPv4(info.UserIP) == "" || nic.IP == "" {
		return false
	}
	if info.UserIP != nic.IP {
		return false
	}
	if nic.MAC == "" || !strings.EqualFold(NormalizeMAC(info.UserMAC), NormalizeMAC(nic.MAC)) {
		return false
	}
	return true
}

// paramConflict reports duplicated or contradictory parameters. The gateway
// never sends two different values for the same field; when that happens the
// page is not trustworthy, and a conflict must not be resolved by "first value
// wins" because which one is real cannot be known.
func paramConflict(q url.Values) bool {
	for _, k := range []string{"wlanacip", "wlan_ac_ip", "wlanuserip", "wlan_user_ip", "wlanusermac", "wlan_user_mac"} {
		values := q[k]
		if len(values) < 2 {
			continue
		}
		for _, v := range values[1:] {
			if !strings.EqualFold(v, values[0]) {
				return true
			}
		}
	}
	// The two spellings of each field must agree when both are present.
	pairs := [][2]string{
		{"wlanacip", "wlan_ac_ip"},
		{"wlanuserip", "wlan_user_ip"},
	}
	for _, p := range pairs {
		a, b := strings.TrimSpace(q.Get(p[0])), strings.TrimSpace(q.Get(p[1]))
		if a != "" && b != "" && !strings.EqualFold(a, b) {
			return true
		}
	}
	m1, m2 := NormalizeMAC(q.Get("wlanusermac")), NormalizeMAC(q.Get("wlan_user_mac"))
	if m1 != "" && m2 != "" && m1 != m2 {
		return true
	}
	return false
}
