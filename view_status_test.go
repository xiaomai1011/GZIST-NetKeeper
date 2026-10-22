package main

import (
	"strings"
	"testing"

	"github.com/xiaomai1011/GZIST-NetKeeper/internal/keeper"
	"github.com/xiaomai1011/GZIST-NetKeeper/internal/portal"
)

// The two fields are independent: a working connection does not rewrite the
// result of the last authentication attempt, and an unresolved attempt does not
// make the connection look broken.
func TestDescribeSeparatesNetworkAndAuth(t *testing.T) {
	cases := []struct {
		name  string
		st    keeper.State
		title string
	}{
		{"unknown network", keeper.State{Phase: keeper.Offline, KeepAlive: true, Reason: portal.ReasonPortalFailed}, "网络异常"},
		{"confirmed unauthenticated", keeper.State{Phase: keeper.Offline, KeepAlive: true, Reason: portal.ReasonPortalHijack}, "未认证"},
		{"online", keeper.State{Phase: keeper.Online, Online: true}, "在线"},
		{"online, attempt unconfirmed", keeper.State{
			Phase: keeper.Online, Online: true, Auth: "未确认（网络已恢复）",
		}, "在线"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := describe(tc.st, true); got.title != tc.title {
				t.Fatalf("title %q want %q", got.title, tc.title)
			}
		})
	}

	// A failed attempt stays visible while the network is up.
	st := keeper.State{Phase: keeper.Online, Online: true, Auth: "失败：AC999"}
	if got := describe(st, true); got.title != "在线" {
		t.Fatalf("auth text changed the network title: %q", got.title)
	}
	if st.Auth == "" {
		t.Fatal("auth result was lost")
	}
}

func TestNetUnknownOnlyForGenuineUnknown(t *testing.T) {
	m := &model{st: keeper.State{Phase: keeper.Offline, KeepAlive: true, Reason: portal.ReasonPortalFailed}}
	if !m.netUnknown() {
		t.Fatal("unknown state not detected")
	}
	m.st = keeper.State{Phase: keeper.Offline, Reason: portal.ReasonPortalHijack}
	if m.netUnknown() {
		t.Fatal("unauthenticated state asked for confirmation")
	}
	m.st = keeper.State{Phase: keeper.Online, Online: true, Reason: portal.ReasonPortalFailed}
	if m.netUnknown() {
		t.Fatal("online state asked for confirmation")
	}
	m.st = keeper.State{Phase: keeper.LoggingIn, Reason: portal.ReasonPortalFailed}
	if m.netUnknown() {
		t.Fatal("busy state asked for confirmation")
	}
}

func TestNetLabel(t *testing.T) {
	cases := []struct {
		name string
		st   keeper.State
		want string
	}{
		{"online", keeper.State{Phase: keeper.Online, Online: true}, "在线"},
		{"unauthenticated", keeper.State{Reason: portal.ReasonPortalHijack}, "未认证"},
		{"unknown keeps the reason", keeper.State{Reason: portal.ReasonParamConflict}, "未知（param_conflict）"},
		{"nothing known yet", keeper.State{}, "—"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := netLabel(tc.st)
			if got != tc.want {
				t.Fatalf("%q want %q", got, tc.want)
			}
			if tc.name == "unknown keeps the reason" && !strings.Contains(got, "param_conflict") {
				t.Fatalf("reason not shown: %q", got)
			}
		})
	}
}
