package keeper

import (
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-NetKeeper/internal/portal"
)

// No evidence that this device is unauthenticated ⇒ nothing is submitted.
func TestUnknownStateDoesNotSubmit(t *testing.T) {
	p := &fakePortal{unknown: true, reason: "portal_unreachable"}
	k, clock, _ := setup(p, "a")
	k.Tick(ctx)
	s := k.State()
	if p.logins != 0 {
		t.Fatalf("submitted %d times on an unknown network state", p.logins)
	}
	if s.Online || s.Phase != Offline {
		t.Fatalf("%+v", s)
	}
	if s.Reason != "portal_unreachable" {
		t.Fatalf("reason %q", s.Reason)
	}
	if got := s.NextProbe.Sub(clock.now()); got != UnknownRecheck {
		t.Fatalf("recheck in %v, want %v", got, UnknownRecheck)
	}
	if !s.NextRetry.IsZero() {
		t.Fatalf("unknown state touched the submit cooldown: %v", s.NextRetry)
	}
}

// Evidence is complete ⇒ the automatic path is allowed to submit.
func TestUnauthenticatedStateSubmits(t *testing.T) {
	p := &fakePortal{results: []portal.Result{{OK: true, Route: portal.RoutePortal}}}
	k, _, _ := setup(p, "a")
	k.Tick(ctx)
	if p.logins != 1 {
		t.Fatalf("logins=%d", p.logins)
	}
	if s := k.State(); !s.Online {
		t.Fatalf("%+v", s)
	}
}

// A refusal (no submission at all) is not a failed attempt and must not push
// the cooldown.
func TestNotSubmittedDoesNotCountFailure(t *testing.T) {
	p := &fakePortal{notSubmitted: true}
	k, _, _ := setup(p, "a")
	k.Tick(ctx)
	s := k.State()
	if s.Failures != 0 {
		t.Fatalf("refusal counted as failure: %+v", s)
	}
	if s.Notice == "" || s.Phase != Offline {
		t.Fatalf("%+v", s)
	}
}

// "The internet came back" does not clear the cooldown ...
func TestProbeOnlySuccessKeepsCooldown(t *testing.T) {
	p := &fakePortal{results: []portal.Result{{OK: true, Route: portal.RouteProbe}}}
	k, clock, _ := setup(p, "a")
	k.update(func(s *State) { s.Failures = 2; s.NextRetry = clock.now() })
	k.Tick(ctx)
	s := k.State()
	if !s.Online {
		t.Fatalf("%+v", s)
	}
	if s.Failures != 2 {
		t.Fatalf("probe-only success cleared the cooldown: %+v", s)
	}
}

// ... while the portal's own confirmation does.
func TestPortalConfirmClearsCooldown(t *testing.T) {
	p := &fakePortal{results: []portal.Result{{OK: true, Route: portal.RoutePortal}}}
	k, _, _ := setup(p, "a")
	k.update(func(s *State) { s.Failures = 2 })
	k.Tick(ctx)
	s := k.State()
	if !s.Online || s.Failures != 0 || !s.NextRetry.IsZero() {
		t.Fatalf("%+v", s)
	}
}

// A plain "login now" must not clear a credential block: one click cannot mean
// "force", "unblock" and "skip cooldown" at the same time.
func TestManualLoginDoesNotClearCredentialBlock(t *testing.T) {
	p := &fakePortal{results: []portal.Result{{OK: true}}}
	k, _, _ := setup(p, "a")
	k.update(func(s *State) {
		s.CredentialBlock, s.Pause, s.LastError = true, PausedByServer, "学号或密码错误"
	})
	k.handle(ctx, cmdLogin, false)
	if p.logins != 0 {
		t.Fatalf("manual click submitted %d times despite the credential block", p.logins)
	}
	s := k.State()
	if !s.CredentialBlock || s.Pause != PausedByServer || s.Notice == "" {
		t.Fatalf("%+v", s)
	}
}

// The explicit confirmation does clear it, once.
func TestRetryCredentialClearsBlock(t *testing.T) {
	p := &fakePortal{results: []portal.Result{{OK: true, Route: portal.RoutePortal}}}
	k, _, _ := setup(p, "a")
	k.update(func(s *State) { s.CredentialBlock, s.Pause = true, PausedByServer })
	k.handle(ctx, cmdRetryCredential, false)
	if p.logins != 1 {
		t.Fatalf("logins=%d", p.logins)
	}
	if s := k.State(); s.CredentialBlock || s.Pause != NotPaused || !s.Online {
		t.Fatalf("%+v", s)
	}
}

// Saving the form again with the same values must not release the block: the
// event fires either way, only a real change counts.
func TestAccountChangeReleasesOnlyOnRealChange(t *testing.T) {
	creds := []string{"a", "pw"}
	p := &fakePortal{results: []portal.Result{
		{Outcome: portal.BadCredential, Msg: "学号或密码错误"},
		{OK: true, Route: portal.RoutePortal},
	}}
	k := New(p, func() (string, string) { return creds[0], creds[1] }, true)
	c := &clock{t: time.Date(2026, 10, 8, 12, 0, 0, 0, time.Local)}
	k.Now = c.now
	k.Tick(ctx)
	if s := k.State(); !s.CredentialBlock {
		t.Fatalf("not blocked after a rejection: %+v", s)
	}

	k.handle(ctx, cmdAccount, false)
	if s := k.State(); !s.CredentialBlock {
		t.Fatalf("block released without a credential change: %+v", s)
	}
	if p.logins != 1 {
		t.Fatalf("submitted again without a change: logins=%d", p.logins)
	}

	creds[1] = "pw2"
	k.handle(ctx, cmdAccount, false)
	if s := k.State(); s.CredentialBlock {
		t.Fatalf("block survived a real change: %+v", s)
	}
}

// A rejection from the server is what sets the block in the first place.
func TestBadCredentialSetsBlock(t *testing.T) {
	p := &fakePortal{results: []portal.Result{{Outcome: portal.BadCredential, Msg: "学号或密码错误"}}}
	k, _, _ := setup(p, "a")
	k.Tick(ctx)
	s := k.State()
	if !s.CredentialBlock || s.Pause != PausedByServer || s.Online {
		t.Fatalf("%+v", s)
	}
}

// A plain click must not skip the cooldown either.
func TestManualLoginRespectsCooldown(t *testing.T) {
	p := &fakePortal{results: []portal.Result{{OK: true}}}
	k, clock, _ := setup(p, "a")
	k.update(func(s *State) {
		s.Failures = 1
		s.NextRetry = clock.now().Add(10 * time.Second)
	})
	k.handle(ctx, cmdLogin, false)
	if p.logins != 0 {
		t.Fatalf("submitted %d times during the cooldown", p.logins)
	}
	if s := k.State(); s.Notice == "" {
		t.Fatalf("%+v", s)
	}

	clock.advance(11 * time.Second)
	k.handle(ctx, cmdLogin, false)
	if p.logins != 1 {
		t.Fatalf("did not submit after the cooldown: %d", p.logins)
	}
}

// The 30 s recheck must decide the schedule: the timer keeps ticking, but no
// inspection may run before NextProbe.
func TestUnknownRecheckLimitsProbes(t *testing.T) {
	p := &fakePortal{unknown: true, reason: "portal_unreachable"}
	k, clock, _ := setup(p, "a")
	k.Tick(ctx)
	if p.probes != 1 {
		t.Fatalf("probes=%d after the first tick", p.probes)
	}
	clock.advance(10 * time.Second)
	k.Tick(ctx)
	if p.probes != 1 {
		t.Fatalf("inspected again before the recheck: probes=%d", p.probes)
	}
	clock.advance(20 * time.Second)
	k.Tick(ctx)
	if p.probes != 2 {
		t.Fatalf("recheck did not run at 30 s: probes=%d", p.probes)
	}
	if p.logins != 0 {
		t.Fatalf("submitted %d times during unknown states", p.logins)
	}
}

// A confirmation releases the block; it does not cancel a running cooldown.
func TestRetryCredentialRespectsCooldown(t *testing.T) {
	p := &fakePortal{results: []portal.Result{{OK: true, Route: portal.RoutePortal}}}
	k, clock, _ := setup(p, "a")
	k.update(func(s *State) {
		s.CredentialBlock, s.Pause = true, PausedByServer
		s.Failures = 1
		s.NextRetry = clock.now().Add(30 * time.Second)
	})
	k.handle(ctx, cmdRetryCredential, false)
	if p.logins != 0 {
		t.Fatalf("submitted during the cooldown: %d", p.logins)
	}
	if s := k.State(); s.CredentialBlock {
		t.Fatalf("block was not released: %+v", s)
	}
	clock.advance(31 * time.Second)
	k.handle(ctx, cmdRetryCredential, false)
	if p.logins != 1 {
		t.Fatalf("did not submit after the cooldown: %d", p.logins)
	}
}

// Saving credentials updates state; it must not submit from that handler and
// must not clear the cooldown.
func TestAccountSaveDoesNotSubmit(t *testing.T) {
	creds := []string{"a", "pw"}
	p := &fakePortal{}
	k := New(p, func() (string, string) { return creds[0], creds[1] }, true)
	c := &clock{t: time.Date(2026, 10, 8, 12, 0, 0, 0, time.Local)}
	k.Now = c.now
	k.update(func(s *State) {
		s.CredentialBlock, s.Pause = true, PausedByServer
		s.Failures = 1
		s.NextRetry = c.now().Add(30 * time.Second)
	})
	k.blockedCred = [2]string{"a", "pw"}

	creds[1] = "pw2"
	k.handle(ctx, cmdAccount, false)
	if p.logins != 0 {
		t.Fatalf("saving credentials started an attempt: %d", p.logins)
	}
	if s := k.State(); s.CredentialBlock {
		t.Fatalf("block survived a real change: %+v", s)
	}
	if s := k.State(); !s.NextRetry.After(c.now()) {
		t.Fatalf("saving cleared the cooldown: %+v", s)
	}
}
