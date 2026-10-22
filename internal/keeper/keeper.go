// Package keeper runs the keepalive loop: probe every few seconds, log in
// when the network drops, back off on failures and stop retrying when the
// server says retrying cannot help.
package keeper

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/xiaomai1011/GZIST-NetKeeper/internal/portal"
)

// Portal is what the keeper needs from the protocol client.
type Portal interface {
	// Probe classifies the network without submitting anything.
	ProbeState(ctx context.Context) (portal.NetState, string)
	Online(ctx context.Context) bool
	// Login is the explicit path; LoginAuto refuses to submit when the
	// network state is not confirmed.
	Login(ctx context.Context, account, password string) (portal.Result, error)
	LoginAuto(ctx context.Context, account, password string) (portal.Result, error)
	Logout(ctx context.Context, account string) error
}

// Phase is the coarse state shown to the user.
type Phase int

const (
	Checking Phase = iota
	Online
	Offline
	LoggingIn
	LoggingOut
	NoAccount
)

// Pause explains why automatic login is not happening.
type Pause int

const (
	NotPaused Pause = iota
	PausedByLogout
	PausedByServer // bad credentials, account in use, ret_code 2 or 8: retrying would not help
)

// Backoff is the wait after the n-th consecutive failure.
var Backoff = []time.Duration{10 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute}

// Interval is how often the keeper probes.
const Interval = 10 * time.Second

// UnknownRecheck is how long to wait before looking again when the network
// state cannot be determined. Nothing is submitted meanwhile.
const UnknownRecheck = 30 * time.Second

// Right after login the desktop is already waiting for the network while the
// portal is still unreachable for the first 20–30 seconds. Inside BootWindow
// the keeper probes quickly and does not back off: the normal cadence with
// escalating waits would turn a half-minute wait into more than a minute, which
// is the opposite of what a boot needs.
const (
	BootWindow   = 90 * time.Second
	BootInterval = 2500 * time.Millisecond
)

// State is a snapshot for the UI.
type State struct {
	Phase     Phase
	Online    bool
	KeepAlive bool
	Pause     Pause
	LastLogin time.Time
	LastError string // why the last attempt failed
	Notice    string // non-fatal hint from the last success
	RetCode   int
	Failures  int
	// NextRetry is when the next authentication attempt is allowed (submit
	// cooldown). It has nothing to do with when the network is inspected.
	NextRetry time.Time
	// NextProbe is when the next network inspection may run. Unknown states
	// are rechecked at a lower rate; this is the field that decides it.
	NextProbe time.Time
	// Reason is the fixed reason behind the current network state.
	Reason string
	// Auth is the result of the last authentication attempt, kept separate
	// from the network state: "the internet works" and "the portal accepted
	// us" are different facts and the UI shows both.
	Auth string
	// CredentialBlock means the server rejected the stored credentials.
	// A plain "login now" must not clear it: only a real credential change or
	// an explicit "retry this credential" may.
	CredentialBlock bool
}

// Busy reports whether a login or logout is running.
func (s State) Busy() bool { return s.Phase == LoggingIn || s.Phase == LoggingOut }

type cmdKind int

const (
	cmdProbe cmdKind = iota
	cmdLogin
	cmdLogout
	cmdKeepAlive
	cmdAccount
	cmdRetryCredential
)

type cmd struct {
	kind cmdKind
	on   bool
}

// Keeper is driven by Run; the other methods only queue commands.
type Keeper struct {
	Portal Portal
	// Creds returns the current account and password.
	Creds    func() (account, password string)
	Now      func() time.Time
	Log      func(string)
	Notify   func(title, body string)
	OnChange func(State)

	mu    sync.Mutex
	state State
	cmds  chan cmd
	// blockedCred holds the credentials the server rejected. AccountChanged
	// only releases the block when the stored values really differ: the event
	// itself proves nothing (saving the form with an unchanged password fires
	// it too). Kept in memory only.
	blockedCred [2]string
	// bootUntil bounds the fast start-up cadence; zero before Run.
	bootUntil time.Time
}

// New returns a keeper; keepAlive is the initial switch position.
func New(p Portal, creds func() (string, string), keepAlive bool) *Keeper {
	return &Keeper{
		Portal: p,
		Creds:  creds,
		Now:    time.Now,
		state:  State{Phase: Checking, KeepAlive: keepAlive},
		cmds:   make(chan cmd, 16),
	}
}

// State returns the current snapshot.
func (k *Keeper) State() State {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.state
}

func (k *Keeper) update(fn func(*State)) {
	k.mu.Lock()
	fn(&k.state)
	s := k.state
	k.mu.Unlock()
	if k.OnChange != nil {
		k.OnChange(s)
	}
}

func (k *Keeper) log(s string) {
	if k.Log != nil {
		k.Log(s)
	}
}

func (k *Keeper) send(c cmd) {
	select {
	case k.cmds <- c:
	default: // queue full: the pending commands will cover it
	}
}

// Probe checks the network now (for example after waking from sleep).
func (k *Keeper) Probe() { k.send(cmd{kind: cmdProbe}) }

// Login logs in now and clears any pause.
func (k *Keeper) Login() { k.send(cmd{kind: cmdLogin}) }

// Logout logs out and pauses automatic login until the next manual login.
func (k *Keeper) Logout() { k.send(cmd{kind: cmdLogout}) }

// SetKeepAlive turns automatic login on or off.
func (k *Keeper) SetKeepAlive(on bool) { k.send(cmd{kind: cmdKeepAlive, on: on}) }

// AccountChanged clears server pauses after the user saved new credentials.
func (k *Keeper) AccountChanged() { k.send(cmd{kind: cmdAccount}) }

// RetryCredential is the explicit "try this credential again" action. It is
// separate from the ordinary login button so that one click cannot mean three
// different things at once.
func (k *Keeper) RetryCredential() { k.send(cmd{kind: cmdRetryCredential}) }

// Run processes commands and probes every Interval until ctx ends.
func (k *Keeper) Run(ctx context.Context) {
	k.mu.Lock()
	k.bootUntil = k.Now().Add(BootWindow)
	k.mu.Unlock()
	k.Tick(ctx)
	t := time.NewTimer(k.wait())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			k.Tick(ctx)
		case c := <-k.cmds:
			k.handle(ctx, c.kind, c.on)
		}
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(k.wait())
	}
}

// booting reports whether the fast start-up cadence still applies.
func (k *Keeper) booting() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return !k.bootUntil.IsZero() && k.Now().Before(k.bootUntil)
}

// wait is the delay before the next probe.
func (k *Keeper) wait() time.Duration {
	if k.booting() {
		return BootInterval
	}
	return Interval
}

// handle runs one command synchronously.
func (k *Keeper) handle(ctx context.Context, kind cmdKind, on bool) {
	switch kind {
	case cmdProbe:
		k.inspect(ctx, true)
	case cmdLogin:
		st := k.State()
		// A plain click never overrides a credential block ...
		if st.CredentialBlock {
			k.log("密码错误已阻断：请先在「账号」中修改密码，或用「重试此凭据」确认")
			k.update(func(s *State) { s.Notice = "密码错误已阻断，未提交" })
			return
		}
		// ... nor the submit cooldown. Phase one has no "force" entry on
		// purpose: a button must not mean three different things at once.
		if st.Failures > 0 && k.Now().Before(st.NextRetry) {
			k.log("提交冷却中，暂不重试")
			k.update(func(s *State) { s.Notice = "冷却中，请稍后再试" })
			return
		}
		k.update(func(s *State) {
			s.Failures, s.NextRetry, s.Pause = 0, time.Time{}, NotPaused
		})
		k.login(ctx, true)
	case cmdRetryCredential:
		st := k.State()
		// Releasing the block says nothing about the cooldown: a confirmation
		// is not a "submit right now" ticket.
		k.update(func(s *State) {
			s.CredentialBlock, s.Pause = false, NotPaused
			s.Notice = ""
		})
		if k.Now().Before(st.NextRetry) {
			k.log("凭据阻断已解除，但仍在提交冷却中")
			k.update(func(s *State) { s.Notice = "冷却中，请稍后再试" })
			return
		}
		k.log("按用户确认重试当前凭据")
		k.login(ctx, true)
	case cmdLogout:
		k.logout(ctx)
	case cmdKeepAlive:
		k.update(func(s *State) { s.KeepAlive = on })
		if on {
			k.log("自动保活已开启")
		} else {
			k.log("自动保活已关闭")
		}
		k.inspect(ctx, on)
	case cmdAccount:
		// Only a credential block needs proof that the values changed; other
		// server pauses (ret_code 2/8, in-use) are settled by saving at all.
		released := !k.State().CredentialBlock || k.credentialsChanged()
		k.update(func(s *State) {
			if released {
				s.CredentialBlock = false
				if s.Pause == PausedByServer {
					s.Pause = NotPaused
				}
			} else if s.CredentialBlock {
				s.Notice = "凭据未变，仍需确认后才能重试"
			}
			// Saving updates state only: it neither clears the cooldown nor
			// starts an attempt. The normal tick decides that later.
			_ = s
		})
	}
}

// Tick probes once and logs in if needed.
func (k *Keeper) Tick(ctx context.Context) { k.inspect(ctx, false) }

// inspect runs one probe. Scheduled calls respect NextProbe; explicit events
// (the user asked, the machine resumed, keepalive was switched on) force one.
func (k *Keeper) inspect(ctx context.Context, force bool) {
	if !force {
		if s := k.State(); !s.NextProbe.IsZero() && k.Now().Before(s.NextProbe) {
			return // the scheduler may be faster than the next inspection
		}
	}
	st, reason := k.Portal.ProbeState(ctx)
	switch st {
	case portal.NetOnline:
		k.markOnline()
		return
	case portal.NetUnknown:
		// No evidence that this device is unauthenticated. Submitting
		// credentials here would be guessing: look again later instead.
		k.markUnknown(reason)
		return
	}
	account, _ := k.Creds()
	s := k.State()
	if s.Online {
		k.log("检测到掉线")
	}
	phase := Offline
	if account == "" {
		phase = NoAccount
	}
	now := k.Now()
	next := now.Add(k.wait())
	// If a submit is only waiting for the cooldown, inspect again when it
	// expires rather than later: the two times are separate fields, but this
	// is the earliest moment a decision could change.
	if !s.NextRetry.IsZero() && s.NextRetry.Before(next) {
		next = s.NextRetry
	}
	k.update(func(s *State) {
		s.Phase, s.Online, s.Reason, s.NextProbe = phase, false, reason, next
	})
	if account == "" || !s.KeepAlive || s.Pause != NotPaused || k.Now().Before(s.NextRetry) {
		return
	}
	k.login(ctx, false)
}

// markUnknown records "cannot tell". It deliberately does not touch the submit
// cooldown: that belongs to authentication attempts, not to the network.
func (k *Keeper) markUnknown(reason string) {
	prev := k.State()
	now := k.Now()
	k.update(func(s *State) {
		s.Phase, s.Online, s.Reason = Offline, false, reason
		if s.Notice == "" {
			s.Notice = "网络状态未知，未提交认证"
		}
		s.NextProbe = now.Add(UnknownRecheck)
	})
	if prev.Online || prev.Reason != reason {
		k.log("网络状态未知（" + reason + "），不提交认证，稍后复核")
	}
}

// markOnline does not submit credentials or record a new login. A recovered
// connection clears the visible failure text but leaves the submit cooldown
// alone: reaching the internet says nothing about the last attempt.
func (k *Keeper) markOnline() {
	if !k.State().Online {
		k.log("检测到已在线，跳过登录，仅执行在线监测")
	}
	next := k.Now().Add(k.wait())
	k.update(func(s *State) {
		s.Online, s.NextProbe = true, next
		s.RetCode, s.LastError, s.Notice, s.Reason = 0, "", "", ""
		if s.Pause == PausedByLogout {
			// Still logged out: the network may be up, the session is not ours.
			s.Phase = Offline
		} else {
			s.Phase = Online
		}
	})
}

func (k *Keeper) login(ctx context.Context, manual bool) {
	// Tick already checks automatic attempts. Manual clicks need the same
	// guard BEFORE credential validation, even when no account is configured.
	if manual && k.Portal.Online(ctx) {
		k.markOnline()
		return
	}
	if ctx.Err() != nil {
		return
	}
	account, password := k.Creds()
	if account == "" || password == "" {
		k.log("请先填写学号和密码")
		k.update(func(s *State) { s.Phase, s.LastError = NoAccount, "请先填写学号和密码" })
		return
	}
	if manual {
		k.log("手动登录…")
	} else {
		k.log("自动登录…")
	}
	k.update(func(s *State) { s.Phase = LoggingIn })
	var res portal.Result
	var err error
	if manual {
		res, err = k.Portal.Login(ctx, account, password)
	} else {
		res, err = k.Portal.LoginAuto(ctx, account, password)
	}
	if ctx.Err() != nil {
		return
	}
	now := k.Now()
	switch {
	case err != nil:
		k.log("登录失败: " + err.Error())
		k.fail(err.Error(), 0)
	case res.NotSubmitted:
		// The automatic path refused: no evidence that this device is
		// unauthenticated. Nothing was sent, so nothing is counted.
		k.log("网络状态未确认，未提交认证")
		k.update(func(s *State) {
			s.Phase, s.Online, s.Notice = Offline, false, "网络状态未知，未提交认证"
			s.Auth = "未提交（网络状态未知）"
		})
	case res.OK:
		portalConfirmed := res.Route == portal.RoutePortal
		if !res.AlreadyOnline {
			if portalConfirmed {
				k.log("认证成功（门户确认）")
			} else {
				k.log("网络已恢复，认证未确认")
			}
		}
		k.update(func(s *State) {
			s.Phase, s.Online = Online, true
			if !res.AlreadyOnline {
				s.LastLogin = now
			}
			s.LastError, s.RetCode, s.Notice, s.Reason = "", 0, res.Warn, ""
			if res.AlreadyOnline {
				s.Auth = "已在线，无需认证"
			} else if portalConfirmed {
				s.Auth = "认证成功（门户确认）"
			} else {
				s.Auth = "未确认（网络已恢复）"
			}
			// Only the portal's own confirmation ends the cooldown. "The
			// internet came back" says nothing about the parameters used.
			if portalConfirmed {
				s.Failures, s.NextRetry, s.Pause = 0, time.Time{}, NotPaused
			}
			if res.Warn != "" {
				// Authenticated but not routed yet; give it a minute
				// before logging in again.
				s.Online, s.NextRetry = false, now.Add(time.Minute)
			}
		})
	case res.Outcome == portal.BadCredential || res.Outcome == portal.InUse:
		msg := pauseAdvice(res)
		k.log("登录失败（" + res.Outcome.String() + "），已暂停自动重试: " + msg)
		k.update(func(s *State) {
			s.Phase, s.Online, s.Pause, s.RetCode, s.LastError = Offline, false, PausedByServer, 0, msg
			s.Auth = "失败：" + msg
			s.CredentialBlock = res.Outcome == portal.BadCredential
			if s.CredentialBlock {
				a, p := k.Creds()
				k.blockedCred = [2]string{a, p}
			}
		})
		if k.Notify != nil {
			k.Notify("校园网登录失败", msg)
		}
	case res.RetCode == 2 || res.RetCode == 8:
		msg := portal.Advice(res.RetCode)
		k.log("登录失败 ret_code=" + strconv.Itoa(res.RetCode) + "，已暂停自动重试: " + msg)
		k.update(func(s *State) {
			s.Phase, s.Online, s.Pause, s.RetCode, s.LastError = Offline, false, PausedByServer, res.RetCode, msg
			s.Auth = "失败：ret_code=" + strconv.Itoa(res.RetCode)
		})
		if k.Notify != nil {
			k.Notify("校园网登录失败", msg)
		}
	default:
		msg := res.Msg
		if res.RetCode != 0 {
			msg = portal.Advice(res.RetCode)
		}
		if msg == "" {
			msg = "登录失败"
		}
		k.log("登录失败: " + msg)
		k.fail(msg, res.RetCode)
	}
}

// pauseAdvice explains a credential or in-use answer from ACSetting.
func pauseAdvice(res portal.Result) string {
	var msg string
	if res.Outcome == portal.BadCredential {
		msg = "学号或密码错误，请在「账号」中修改后保存。"
	} else {
		msg = portal.Advice(2)
	}
	if res.Msg != "" {
		msg += "（服务器提示：" + res.Msg + "）"
	}
	return msg
}

func (k *Keeper) fail(msg string, code int) {
	now := k.Now()
	// A boot failure means "not routed yet" far more often than "wrong
	// credentials", so the wait stays short until the window closes.
	fast := k.booting()
	k.update(func(s *State) {
		s.Failures++
		i := min(s.Failures-1, len(Backoff)-1)
		wait := Backoff[i]
		if fast && wait > BootInterval {
			wait = BootInterval
		}
		s.Phase, s.Online, s.LastError, s.RetCode = Offline, false, msg, code
		s.Auth = "失败：" + msg
		s.NextRetry = now.Add(wait)
	})
}

func (k *Keeper) logout(ctx context.Context) {
	account, _ := k.Creds()
	k.update(func(s *State) { s.Phase, s.Pause = LoggingOut, PausedByLogout })
	k.log("注销中…")
	if err := k.Portal.Logout(ctx, account); err != nil {
		k.log("注销失败: " + err.Error())
		k.update(func(s *State) { s.LastError = "注销失败: " + err.Error() })
	} else {
		k.log("已注销，自动保活暂停到下次手动登录")
		k.update(func(s *State) { s.LastError, s.Phase, s.Online = "", Offline, false })
	}
	k.inspect(ctx, true)
}

// credentialsChanged reports whether the stored credentials differ from the
// ones the server rejected. Comparing values is the only honest check: the
// AccountChanged event also fires when the form was saved with an unchanged
// password.
func (k *Keeper) credentialsChanged() bool {
	if k.blockedCred == [2]string{} {
		return false
	}
	account, password := k.Creds()
	return account != k.blockedCred[0] || password != k.blockedCred[1]
}
