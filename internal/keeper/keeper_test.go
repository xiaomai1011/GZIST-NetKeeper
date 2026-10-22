package keeper

import (
	"context"
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-NetKeeper/internal/portal"
)

type fakePortal struct {
	online       bool
	results      []portal.Result
	errs         []error
	logins       int
	logouts      int
	unknown      bool
	reason       string
	probes       int
	notSubmitted bool
}

func (f *fakePortal) Online(context.Context) bool { return f.online }

// ProbeState mirrors the boolean for these tests: offline means the portal
// handed us evidence that this device is unauthenticated.
func (f *fakePortal) ProbeState(context.Context) (portal.NetState, string) {
	f.probes++
	if f.online {
		return portal.NetOnline, portal.ReasonProbeOK
	}
	if f.unknown {
		reason := f.reason
		if reason == "" {
			reason = portal.ReasonPortalFailed
		}
		return portal.NetUnknown, reason
	}
	return portal.NetUnauthenticated, portal.ReasonPortalHijack
}

// LoginAuto goes through the same fake; tests that need the refusal use
// notSubmitted.
func (f *fakePortal) LoginAuto(ctx context.Context, account, password string) (portal.Result, error) {
	if f.notSubmitted {
		f.logins++
		return portal.Result{Outcome: portal.Unknown, NotSubmitted: true, Route: portal.RouteUnconfirmed}, nil
	}
	return f.Login(ctx, account, password)
}

func (f *fakePortal) Login(context.Context, string, string) (portal.Result, error) {
	i := f.logins
	f.logins++
	var r portal.Result
	var err error
	if i < len(f.results) {
		r = f.results[i]
	}
	if i < len(f.errs) {
		err = f.errs[i]
	}
	if r.OK {
		f.online = true
	}
	return r, err
}

func (f *fakePortal) Logout(context.Context, string) error {
	f.logouts++
	f.online = false
	return nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func setup(p *fakePortal, account string) (*Keeper, *clock, *[]string) {
	c := &clock{t: time.Date(2026, 10, 8, 12, 0, 0, 0, time.Local)}
	k := New(p, func() (string, string) { return account, "pw" }, true)
	k.Now = c.now
	notes := &[]string{}
	k.Notify = func(title, body string) { *notes = append(*notes, body) }
	return k, c, notes
}

var ctx = context.Background()

func TestOnlineDoesNothing(t *testing.T) {
	p := &fakePortal{online: true}
	k, _, _ := setup(p, "a")
	k.Tick(ctx)
	if s := k.State(); s.Phase != Online || p.logins != 0 {
		t.Fatalf("%+v logins=%d", s, p.logins)
	}
}

func TestOfflineLogsIn(t *testing.T) {
	p := &fakePortal{results: []portal.Result{{OK: true}}}
	k, _, _ := setup(p, "a")
	k.Tick(ctx)
	s := k.State()
	if s.Phase != Online || p.logins != 1 || s.LastLogin.IsZero() {
		t.Fatalf("%+v logins=%d", s, p.logins)
	}
}

func TestNoAccount(t *testing.T) {
	p := &fakePortal{}
	k, _, _ := setup(p, "")
	k.Tick(ctx)
	if s := k.State(); s.Phase != NoAccount || p.logins != 0 {
		t.Fatalf("%+v", s)
	}
}

func TestBackoff(t *testing.T) {
	p := &fakePortal{errs: []error{portal.ErrNoResponse, portal.ErrNoResponse, portal.ErrNoResponse, portal.ErrNoResponse, portal.ErrNoResponse}}
	k, c, _ := setup(p, "a")
	for i, wait := range []time.Duration{10 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 2 * time.Minute} {
		k.Tick(ctx)
		if p.logins != i+1 {
			t.Fatalf("step %d: logins=%d", i, p.logins)
		}
		if got := k.State().NextRetry.Sub(c.t); got != wait {
			t.Fatalf("step %d: backoff %v want %v", i, got, wait)
		}
		c.advance(wait - time.Second)
		k.Tick(ctx)
		if p.logins != i+1 {
			t.Fatalf("step %d: retried before backoff elapsed", i)
		}
		c.advance(time.Second)
	}
}

func TestServerCodesPause(t *testing.T) {
	for _, code := range []int{2, 8} {
		p := &fakePortal{results: []portal.Result{{RetCode: code}, {OK: true}}}
		k, c, notes := setup(p, "a")
		k.Tick(ctx)
		s := k.State()
		if s.Pause != PausedByServer || s.RetCode != code || len(*notes) != 1 {
			t.Fatalf("code %d: %+v notes=%v", code, s, *notes)
		}
		c.advance(time.Hour)
		k.Tick(ctx)
		if p.logins != 1 {
			t.Fatalf("code %d: retried while paused", code)
		}
		k.handle(ctx, cmdLogin, false)
		if s := k.State(); s.Phase != Online || s.Pause != NotPaused || p.logins != 2 {
			t.Fatalf("code %d: manual login %+v", code, s)
		}
	}
}

func TestAccountChangeClearsServerPause(t *testing.T) {
	p := &fakePortal{results: []portal.Result{{RetCode: 8}, {OK: true}}}
	k, c, _ := setup(p, "a")
	k.Tick(ctx)
	k.handle(ctx, cmdAccount, false)
	// Saving releases the pause but must not submit on its own.
	if s := k.State(); s.Pause != NotPaused || p.logins != 1 {
		t.Fatalf("after save: %+v logins=%d", s, p.logins)
	}
	c.advance(Interval)
	k.Tick(ctx)
	if s := k.State(); s.Phase != Online || p.logins != 2 {
		t.Fatalf("%+v logins=%d", s, p.logins)
	}
}

func TestOtherRetCodeBacksOff(t *testing.T) {
	p := &fakePortal{results: []portal.Result{{RetCode: 3}}}
	k, _, _ := setup(p, "a")
	k.Tick(ctx)
	if s := k.State(); s.Pause != NotPaused || s.Failures != 1 || s.LastError == "" {
		t.Fatalf("%+v", s)
	}
}

func TestLogoutPausesUntilManualLogin(t *testing.T) {
	p := &fakePortal{online: true, results: []portal.Result{{OK: true}}}
	k, c, _ := setup(p, "a")
	k.Tick(ctx)
	k.handle(ctx, cmdLogout, false)
	if s := k.State(); s.Pause != PausedByLogout || s.Phase != Offline || p.logouts != 1 {
		t.Fatalf("%+v", s)
	}
	c.advance(time.Hour)
	k.Tick(ctx)
	if p.logins != 0 {
		t.Fatal("logged in after logout")
	}
	k.handle(ctx, cmdLogin, false)
	if s := k.State(); s.Phase != Online || p.logins != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestKeepAliveOff(t *testing.T) {
	p := &fakePortal{results: []portal.Result{{OK: true}}}
	k, _, _ := setup(p, "a")
	k.handle(ctx, cmdKeepAlive, false)
	if p.logins != 0 || k.State().Phase != Offline {
		t.Fatal("logged in with keepalive off")
	}
	k.handle(ctx, cmdKeepAlive, true)
	if p.logins != 1 {
		t.Fatal("did not log in after turning keepalive on")
	}
}

func TestRunProcessesCommands(t *testing.T) {
	p := &fakePortal{online: true}
	k, _, _ := setup(p, "a")
	changes := make(chan State, 64)
	k.OnChange = func(s State) { changes <- s }
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go k.Run(cctx)
	k.Logout()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case s := <-changes:
			if s.Pause == PausedByLogout && s.Phase == Offline {
				return
			}
		case <-deadline:
			t.Fatal("logout never processed")
		}
	}
}

func TestRejectionsPause(t *testing.T) {
	for _, o := range []portal.Outcome{portal.BadCredential, portal.InUse} {
		p := &fakePortal{results: []portal.Result{{Outcome: o, Msg: "ldap auth error"}}}
		k, c, notes := setup(p, "a")
		k.Tick(ctx)
		s := k.State()
		if s.Pause != PausedByServer || s.LastError == "" || len(*notes) != 1 {
			t.Fatalf("%v: %+v notes=%v", o, s, *notes)
		}
		c.advance(time.Hour)
		k.Tick(ctx)
		if p.logins != 1 {
			t.Fatalf("%v: retried while paused", o)
		}
	}
}

func TestSuccessBeforeRoutingWaits(t *testing.T) {
	p := &fakePortal{results: []portal.Result{{OK: true, Warn: "等待生效"}}}
	k, c, _ := setup(p, "a")
	p.online = false
	k.login(ctx, false)
	p.online = false // authenticated but not routed yet
	c.advance(30 * time.Second)
	k.Tick(ctx)
	if p.logins != 1 {
		t.Fatalf("login resubmitted before the grace period: %d", p.logins)
	}
}

// A boot that starts before the portal is reachable must not spend its first
// minutes escalating the waits: those failures are "not routed yet", not "wrong
// password". Inside BootWindow every retry is short, and the normal backoff
// comes back afterwards.
func TestBootWindowCapsBackoff(t *testing.T) {
	p := &fakePortal{errs: []error{portal.ErrNoResponse, portal.ErrNoResponse, portal.ErrNoResponse}}
	k, c, _ := setup(p, "a")
	k.mu.Lock()
	k.bootUntil = c.t.Add(BootWindow)
	k.mu.Unlock()

	for i := 1; i <= 2; i++ {
		k.Tick(ctx)
		if p.logins != i {
			t.Fatalf("step %d: logins=%d", i, p.logins)
		}
		if got := k.State().NextRetry.Sub(c.t); got != BootInterval {
			t.Fatalf("step %d: waited %v, want %v inside the boot window", i, got, BootInterval)
		}
		c.advance(BootInterval)
	}
	if got := k.wait(); got != BootInterval {
		t.Fatalf("cadence %v, want %v", got, BootInterval)
	}

	// Past the window the ordinary backoff is back.
	k.mu.Lock()
	k.bootUntil = time.Time{}
	k.mu.Unlock()
	k.Tick(ctx)
	if got := k.State().NextRetry.Sub(c.t); got != Backoff[2] {
		t.Fatalf("after the window waited %v, want %v", got, Backoff[2])
	}
	if got := k.wait(); got != Interval {
		t.Fatalf("cadence %v, want %v", got, Interval)
	}
}
