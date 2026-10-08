package main

import (
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/xiaomai1011/GZIST-NetKeeper/internal/keeper"
	"github.com/xiaomai1011/GZIST-NetKeeper/internal/portal"
)

type recorder struct {
	logins, logouts, diags int
	saved                  [][2]string
	keepAlive, autostart   []bool
}

func newModel(r *recorder) *model {
	return &model{
		version:   "2.0.0",
		keepAlive: true,
		act: actions{
			Login:        func() { r.logins++ },
			Logout:       func() { r.logouts++ },
			Diagnose:     func() { r.diags++ },
			Save:         func(a, p string) { r.saved = append(r.saved, [2]string{a, p}) },
			SetAutostart: func(on bool) { r.autostart = append(r.autostart, on) },
			SetKeepAlive: func(on bool) { r.keepAlive = append(r.keepAlive, on) },
			Restart:      func() {},
		},
	}
}

func TestFirstRunSave(t *testing.T) {
	r := &recorder{}
	m := newModel(r)
	m.st = keeper.State{Phase: keeper.NoAccount, KeepAlive: true}
	tt := ui.NewTester(m.view, 440, 780)
	if !tt.HasText("还没有登记账号") {
		t.Fatalf("texts %q", tt.Texts())
	}
	if err := tt.Click("学号"); err != nil {
		t.Fatal(err)
	}
	tt.Type("2023001")
	if err := tt.Click("密码"); err != nil {
		t.Fatal(err)
	}
	tt.Type("secret")
	if err := tt.Click("保存"); err != nil {
		t.Fatal(err)
	}
	if len(r.saved) != 1 || r.saved[0] != [2]string{"2023001", "secret"} {
		t.Fatalf("saved %v", r.saved)
	}
	for _, s := range tt.Texts() {
		if s == "secret" {
			t.Fatal("password shown in clear")
		}
	}
}

func TestButtonsAndSwitches(t *testing.T) {
	r := &recorder{}
	m := newModel(r)
	m.saved, m.account, m.hasPassword = "2023001", "2023001", true
	m.st = keeper.State{Phase: keeper.Online, Online: true, KeepAlive: true, LastLogin: time.Now()}
	m.nic = portal.NIC{IP: "10.20.30.40", MAC: "AABBCCDDEEFF"}
	tt := ui.NewTester(m.view, 440, 780)
	for _, want := range []string{"在线", "10.20.30.40", "AA-BB-CC-DD-EE-FF"} {
		if !tt.HasText(want) {
			t.Fatalf("missing %q in %q", want, tt.Texts())
		}
	}
	for _, b := range []string{"立即登录", "注销", "诊断"} {
		if err := tt.Click(b); err != nil {
			t.Fatal(err)
		}
	}
	if r.logins != 1 || r.logouts != 1 || r.diags != 1 {
		t.Fatalf("%+v", r)
	}
	if err := tt.Click("自动保活"); err != nil {
		t.Fatal(err)
	}
	if len(r.keepAlive) != 1 || r.keepAlive[0] {
		t.Fatalf("keepalive %v", r.keepAlive)
	}
}

func TestBusyDisablesLogin(t *testing.T) {
	r := &recorder{}
	m := newModel(r)
	m.saved = "a"
	m.st = keeper.State{Phase: keeper.LoggingIn}
	tt := ui.NewTester(m.view, 440, 780)
	tt.Click("立即登录")
	if r.logins != 0 {
		t.Fatal("login clicked while busy")
	}
}

func TestServerPauseShowsAdvice(t *testing.T) {
	m := newModel(&recorder{})
	m.saved = "a"
	m.st = keeper.State{Phase: keeper.Offline, Pause: keeper.PausedByServer, RetCode: 8, LastError: portal.Advice(8), KeepAlive: true}
	tt := ui.NewTester(m.view, 440, 780)
	if !tt.HasText("已暂停自动重试") {
		t.Fatalf("texts %q", tt.Texts())
	}
}

func TestUpdateBanner(t *testing.T) {
	restarted := false
	m := newModel(&recorder{})
	m.act.Restart = func() { restarted = true }
	m.update = "v2.0.1"
	tt := ui.NewTester(m.view, 440, 780)
	if err := tt.Click("重启以更新"); err != nil || !restarted {
		t.Fatal(err, restarted)
	}
}

// TestScreenshots writes previews when NETKEEPER_SHOTS names a directory.
func TestScreenshots(t *testing.T) {
	dir := os.Getenv("NETKEEPER_SHOTS")
	if dir == "" {
		t.Skip("set NETKEEPER_SHOTS to write screenshots")
	}
	logs := []string{
		"12:00:01  GZIST NetKeeper v2.0.0 启动 (darwin/arm64)",
		"12:00:02  检测到掉线",
		"12:00:02  自动登录…",
		"12:00:02  网卡 en0  IP 10.20.30.40  MAC AABBCCDDEEFF",
		"12:00:03  确认未认证（探测到门户劫持）: ip=10.20.30.40 mac=AA-BB-CC-DD-EE-FF ac=10.128.255.129",
		"12:00:03  ACSetting 登录: http://10.0.10.252:801/eportal/?c=ACSetting&a=Login&DDDDD=%2C0%2C2023001&upass=***",
		"12:00:05  登录成功",
	}
	shots := map[string]func(m *model){
		"online": func(m *model) {
			m.saved, m.account, m.hasPassword = "2023001", "2023001", true
			m.st = keeper.State{Phase: keeper.Online, Online: true, KeepAlive: true, LastLogin: time.Date(2026, 10, 8, 12, 0, 5, 0, time.Local)}
			m.nic = portal.NIC{IP: "10.20.30.40", MAC: "AABBCCDDEEFF"}
			m.autostart, m.logs = true, logs
		},
		"first-run": func(m *model) { m.st = keeper.State{Phase: keeper.NoAccount, KeepAlive: true} },
		"paused": func(m *model) {
			m.saved, m.account, m.hasPassword = "2023001", "2023001", true
			m.st = keeper.State{Phase: keeper.Offline, Pause: keeper.PausedByServer, RetCode: 8, LastError: portal.Advice(8), KeepAlive: true}
			m.update, m.logs = "v2.0.1", logs[:5]
		},
		"logging-in": func(m *model) {
			m.saved, m.account, m.hasPassword = "2023001", "2023001", true
			m.st = keeper.State{Phase: keeper.LoggingIn, KeepAlive: true}
			m.logs = logs[:4]
		},
	}
	for name, setup := range shots {
		for _, dark := range []bool{false, true} {
			m := newModel(&recorder{})
			setup(m)
			tt := ui.NewTester(m.view, 440, 780)
			tt.SetScale(2)
			tt.SetDark(dark)
			tt.Frame()
			suffix := ""
			if dark {
				suffix = "-dark"
			}
			f, err := os.Create(filepath.Join(dir, name+suffix+".png"))
			if err != nil {
				t.Fatal(err)
			}
			png.Encode(f, tt.Image())
			f.Close()
		}
	}
}
