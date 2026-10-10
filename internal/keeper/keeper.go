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
	Online(ctx context.Context) bool
	Login(ctx context.Context, account, password string) (portal.Result, error)
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
	NextRetry time.Time
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

// Run processes commands and probes every Interval until ctx ends.
func (k *Keeper) Run(ctx context.Context) {
	k.Tick(ctx)
	t := time.NewTimer(Interval)
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
		t.Reset(Interval)
	}
}

// handle runs one command synchronously.
func (k *Keeper) handle(ctx context.Context, kind cmdKind, on bool) {
	switch kind {
	case cmdProbe:
		k.Tick(ctx)
	case cmdLogin:
		k.update(func(s *State) { s.Pause, s.Failures, s.NextRetry = NotPaused, 0, time.Time{} })
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
		k.Tick(ctx)
	case cmdAccount:
		k.update(func(s *State) {
			if s.Pause == PausedByServer {
				s.Pause = NotPaused
			}
			s.Failures, s.NextRetry, s.RetCode, s.LastError = 0, time.Time{}, 0, ""
		})
		k.Tick(ctx)
	}
}

// Tick probes once and logs in if needed.
func (k *Keeper) Tick(ctx context.Context) {
	online := k.Portal.Online(ctx)
	account, _ := k.Creds()
	s := k.State()
	if online {
		k.markOnline()
		return
	}
	if s.Online {
		k.log("检测到掉线")
	}
	phase := Offline
	if account == "" {
		phase = NoAccount
	}
	k.update(func(s *State) { s.Phase, s.Online = phase, false })
	if account == "" || !s.KeepAlive || s.Pause != NotPaused || k.Now().Before(s.NextRetry) {
		return
	}
	k.login(ctx, false)
}

// markOnline does not submit credentials or record a new login. A recovered
// connection clears old failure messages but preserves explicit logout pauses.
func (k *Keeper) markOnline() {
	if !k.State().Online {
		k.log("检测到已在线，跳过登录，仅执行在线监测")
	}
	k.update(func(s *State) {
		s.Phase, s.Online = Online, true
		s.Failures, s.RetCode, s.LastError, s.Notice = 0, 0, "", ""
		s.NextRetry = time.Time{}
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
	res, err := k.Portal.Login(ctx, account, password)
	if ctx.Err() != nil {
		return
	}
	now := k.Now()
	switch {
	case err != nil:
		k.log("登录失败: " + err.Error())
		k.fail(err.Error(), 0)
	case res.OK:
		if !res.AlreadyOnline {
			k.log("登录成功")
		}
		k.update(func(s *State) {
			s.Phase, s.Online = Online, true
			if !res.AlreadyOnline {
				s.LastLogin = now
			}
			s.LastError, s.RetCode, s.Failures, s.NextRetry, s.Pause = "", 0, 0, time.Time{}, NotPaused
			s.Notice = res.Warn
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
		})
		if k.Notify != nil {
			k.Notify("校园网登录失败", msg)
		}
	case res.RetCode == 2 || res.RetCode == 8:
		msg := portal.Advice(res.RetCode)
		k.log("登录失败 ret_code=" + strconv.Itoa(res.RetCode) + "，已暂停自动重试: " + msg)
		k.update(func(s *State) {
			s.Phase, s.Online, s.Pause, s.RetCode, s.LastError = Offline, false, PausedByServer, res.RetCode, msg
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
	k.update(func(s *State) {
		s.Failures++
		i := min(s.Failures-1, len(Backoff)-1)
		s.Phase, s.Online, s.LastError, s.RetCode = Offline, false, msg, code
		s.NextRetry = now.Add(Backoff[i])
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
		k.update(func(s *State) { s.LastError = "" })
	}
	k.Tick(ctx)
}
