package keeper

import (
	"testing"
	"time"

	"github.com/xiaomai1011/GZIST-NetKeeper/internal/portal"
)

func TestManualOnlineOnlyKeepsAlive(t *testing.T) {
	for _, account := range []string{"a", ""} {
		t.Run("account="+account, func(t *testing.T) {
			p := &fakePortal{online: true}
			k, _, notes := setup(p, account)
			k.handle(ctx, cmdLogin, false)
			s := k.State()
			if p.logins != 0 || p.logouts != 0 || !s.Online || s.Phase != Online || !s.LastLogin.IsZero() || len(*notes) != 0 {
				t.Fatalf("state=%+v logins=%d logouts=%d notes=%v", s, p.logins, p.logouts, *notes)
			}
		})
	}
}

func TestOnlineRecoveryClearsStaleErrorWithoutLogin(t *testing.T) {
	p := &fakePortal{online: true}
	k, clock, _ := setup(p, "a")
	k.update(func(s *State) {
		s.LastError, s.RetCode, s.Failures = "previous failure", 3, 2
		s.NextRetry = clock.now().Add(time.Minute)
	})
	for i := 0; i < 4; i++ {
		k.Tick(ctx)
		clock.advance(Interval)
	}
	s := k.State()
	if s.LastError != "" || s.RetCode != 0 || s.Failures != 0 || !s.NextRetry.IsZero() || !s.LastLogin.IsZero() || p.logins != 0 {
		t.Fatalf("state=%+v logins=%d", s, p.logins)
	}
}

func TestAlreadyOnlineResultDoesNotRecordNewLogin(t *testing.T) {
	p := &fakePortal{results: []portal.Result{{OK: true, AlreadyOnline: true}}}
	k, _, _ := setup(p, "a")
	k.Tick(ctx) // Network becomes reachable between Tick and the protocol guard.
	if s := k.State(); !s.Online || !s.LastLogin.IsZero() {
		t.Fatalf("%+v", s)
	}
}

func TestOnlineKeepAliveStillRecoversActualDrop(t *testing.T) {
	p := &fakePortal{online: true, results: []portal.Result{{OK: true}}}
	k, clock, _ := setup(p, "a")
	k.Tick(ctx)
	p.online = false
	clock.advance(Interval)
	k.Tick(ctx)
	if s := k.State(); p.logins != 1 || !s.Online || s.LastLogin.IsZero() {
		t.Fatalf("state=%+v logins=%d", s, p.logins)
	}
}
