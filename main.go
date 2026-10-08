// GZIST NetKeeper keeps a GZIST campus network session logged in. It lives
// in the tray (menu bar on macOS) and shows a small window on demand.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/transfer"
	"github.com/egoist/mygo/ui"
	"github.com/xiaomai1011/GZIST-NetKeeper/internal/applog"
	"github.com/xiaomai1011/GZIST-NetKeeper/internal/art"
	"github.com/xiaomai1011/GZIST-NetKeeper/internal/keeper"
	"github.com/xiaomai1011/GZIST-NetKeeper/internal/portal"
	"github.com/xiaomai1011/GZIST-NetKeeper/internal/store"
)

const (
	appTitle    = "GZIST NetKeeper"
	releasesURL = "https://github.com/xiaomai1011/GZIST-NetKeeper/releases/latest"
	updateEvery = 6 * time.Hour
)

type app struct {
	log    *applog.Log
	store  *store.Store
	client *portal.Client
	keeper *keeper.Keeper
	m      *model

	credMu   sync.Mutex
	account  string
	password string

	win      *mygo.Window
	tray     *mygo.Tray
	menu     *mygo.Menu
	trayIcon art.TrayState
	update   *mygo.Update

	onlineOnce  sync.Once
	firstOnline chan struct{}

	// disk runs settings and keyring writes one at a time, in order.
	disk chan func()
}

func main() {
	if !mygo.App.RequestSingleInstanceLock() {
		return // the running instance opens its window
	}
	a := &app{firstOnline: make(chan struct{}), disk: make(chan func(), 16)}
	mygo.App.OnSecondInstance(func([]string, string) { a.showWindow() })
	// Closing the window keeps the keepalive running in the tray.
	mygo.App.OnWindowAllClosed(func() {})
	mygo.App.WhenReady(a.ready)
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}

func (a *app) creds() (string, string) {
	a.credMu.Lock()
	defer a.credMu.Unlock()
	return a.account, a.password
}

func (a *app) ready() {
	if runtime.GOOS == "darwin" {
		mygo.App.SetActivationPolicy(mygo.ActivationPolicyAccessory)
	}
	dataDir, _ := mygo.App.Path(mygo.PathUserData)
	logDir, _ := mygo.App.Path(mygo.PathLogs)
	a.log = applog.New(logDir)
	a.store = store.New(dataDir)
	a.log.Printf("GZIST NetKeeper v%s 启动 (%s/%s)", mygo.App.Version(), runtime.GOOS, runtime.GOARCH)

	if removeLegacyAutostart() {
		if err := mygo.App.SetOpenAtLogin(true); err != nil {
			a.log.Printf("迁移开机自启失败: %v", err)
		} else {
			a.log.Printf("已迁移旧版本的开机自启设置")
		}
	}

	go func() {
		for fn := range a.disk {
			fn()
		}
	}()

	st, loadErr := a.store.Load()
	if loadErr != nil {
		a.log.Printf("读取设置失败，已使用默认设置: %v", loadErr)
	}
	pw, insecure, err := a.store.Password(st.Account)
	if err != nil {
		a.log.Printf("读取密码失败: %v", err)
	}
	a.account, a.password = st.Account, pw
	a.m = &model{
		account:     st.Account,
		saved:       st.Account,
		hasPassword: pw != "",
		insecure:    insecure,
		keepAlive:   st.KeepAlive,
		autostart:   mygo.App.OpenAtLogin(),
		version:     mygo.App.Version(),
	}
	if loadErr != nil {
		a.m.notice = "设置文件损坏，已使用默认设置，请重新保存账号"
	}
	a.m.act = actions{
		Login:        func() { a.keeper.Login() },
		Logout:       func() { a.keeper.Logout() },
		Diagnose:     a.diagnose,
		Save:         a.save,
		SetAutostart: a.setAutostart,
		SetKeepAlive: a.setKeepAlive,
		Restart:      a.restart,
		OpenLogs:     func() { mygo.Shell.ShowItemInFolder(a.log.Path()) },
		CopyLogs:     a.copyLogs,
	}

	a.client = portal.New(a.log.Add)
	a.keeper = keeper.New(a.client, a.creds, st.KeepAlive)
	a.keeper.Log = a.log.Add
	a.keeper.Notify = a.notify
	a.keeper.OnChange = func(s keeper.State) {
		nic, _ := portal.RouteNIC(a.client.PortalHost)
		if s.Phase == keeper.Online && s.Online {
			a.onlineOnce.Do(func() { close(a.firstOnline) })
		}
		a.post(func() {
			a.m.st, a.m.nic = s, nic
			a.syncTray()
		})
	}
	a.log.OnChange(func() {
		lines := a.log.Lines()
		a.post(func() { a.m.logs = lines })
	})
	a.m.logs = a.log.Lines()

	a.makeTray()
	mygo.Power.OnResume(func() {
		a.log.Add("系统已唤醒，立即检测网络")
		a.keeper.Probe()
	})
	go a.keeper.Run(context.Background())
	go a.updateLoop()

	switch {
	case st.Account == "" || pw == "":
		a.showWindow() // first run: ask for the account
	case a.tray == nil:
		a.showWindow() // no tray to come back from
	case !mygo.App.WasOpenedAtLogin():
		a.showWindow()
	}
}

// post runs fn on the main thread and redraws the window.
func (a *app) post(fn func()) {
	mygo.RunOnMain(func() {
		fn()
		if a.win != nil && !a.win.IsDestroyed() {
			a.win.Invalidate()
		}
	})
}

func (a *app) showWindow() {
	if a.win != nil && !a.win.IsDestroyed() {
		a.win.Show()
		a.win.Focus()
		mygo.App.Focus()
		return
	}
	a.win = mygo.NewWindow(mygo.WindowOptions{
		Title:     appTitle,
		Width:     440,
		Height:    780,
		MinWidth:  380,
		MinHeight: 520,
		StateKey:  "main",
		Content:   ui.View(a.m.view),
	})
	mygo.App.Focus()
}

func (a *app) makeTray() {
	a.menu = mygo.NewMenu([]*mygo.MenuItem{
		{ID: "status", Label: "检测中…", Disabled: true},
		mygo.Separator(),
		{ID: "login", Label: "立即登录", Click: func(*mygo.MenuItem, *mygo.Window) { a.keeper.Login() }},
		{ID: "logout", Label: "注销", Click: func(*mygo.MenuItem, *mygo.Window) { a.keeper.Logout() }},
		{Label: "打开主窗口", Click: func(*mygo.MenuItem, *mygo.Window) { a.showWindow() }},
		mygo.Separator(),
		{ID: "autostart", Label: "开机自启", Type: mygo.MenuItemCheckbox, Checked: a.m.autostart,
			Click: func(it *mygo.MenuItem, _ *mygo.Window) { a.setAutostart(it.Checked) }},
		{ID: "update", Label: "重启以更新", Hidden: true, Click: func(*mygo.MenuItem, *mygo.Window) { a.restart() }},
		mygo.Separator(),
		{Label: "退出", Click: func(*mygo.MenuItem, *mygo.Window) { mygo.App.Quit() }},
	})
	a.trayIcon = art.TrayOffline
	tray, err := mygo.NewTray(mygo.TrayOptions{
		Icon:           art.TrayIcon(art.TrayOffline, runtime.GOOS == "darwin"),
		IconIsTemplate: runtime.GOOS == "darwin",
		ToolTip:        appTitle,
		Menu:           a.menu,
	})
	if err != nil {
		a.log.Printf("无法创建托盘图标（Linux 需要安装 libayatana-appindicator3）: %v", err)
		return
	}
	a.tray = tray
	if runtime.GOOS == "windows" {
		tray.OnClick(a.showWindow)
	}
}

// syncTray mirrors the model into the tray. Main thread.
func (a *app) syncTray() {
	if a.tray == nil {
		return
	}
	s := describe(a.m.st, a.m.saved != "")
	label := "状态：" + s.title
	if a.m.nic.IP != "" && a.m.st.Phase == keeper.Online {
		label += "（" + a.m.nic.IP + "）"
	}
	a.menu.ItemByID("status").SetLabel(label)
	busy := a.m.st.Busy()
	a.menu.ItemByID("login").SetEnabled(!busy && a.m.saved != "")
	a.menu.ItemByID("logout").SetEnabled(!busy && a.m.saved != "")
	a.menu.ItemByID("autostart").SetChecked(a.m.autostart)
	if a.m.update != "" {
		up := a.menu.ItemByID("update")
		up.SetLabel("重启以更新到 " + a.m.update)
		up.SetVisible(true)
	}
	a.tray.SetToolTip(appTitle + " · " + s.title)
	if s.tray != a.trayIcon {
		a.trayIcon = s.tray
		mac := runtime.GOOS == "darwin"
		a.tray.SetIcon(art.TrayIcon(s.tray, mac), mac)
	}
}

func (a *app) notify(title, body string) {
	if !mygo.NotificationsSupported() {
		return
	}
	mygo.RunOnMain(func() {
		n := mygo.NewNotification(mygo.NotificationOptions{Title: title, Body: body})
		n.OnClick(a.showWindow)
		if err := n.Show(); err != nil {
			a.log.Printf("通知发送失败: %v", err)
		}
	})
}

// copyLogs puts the recent log on the clipboard with student IDs, IPs and
// MACs masked, ready to paste into an Issue. The log file keeps the
// original.
func (a *app) copyLogs() {
	account, _ := a.creds()
	r := applog.Redactor{
		Accounts: []string{account, a.m.saved},
		KeepIPs:  append([]string{portal.DefaultPortalHost}, portal.DefaultACIPs...),
	}
	text := fmt.Sprintf("GZIST NetKeeper v%s (%s/%s)\n%s\n", mygo.App.Version(), runtime.GOOS, runtime.GOARCH,
		strings.Join(r.Lines(a.log.Lines()), "\n"))
	if err := mygo.Clipboard.Write(transfer.TextData(text)); err != nil {
		a.log.Printf("复制日志失败: %v", err)
		return
	}
	a.log.Add("已复制脱敏日志到剪贴板（学号、IP、MAC 已打码）")
}

func (a *app) diagnose() {
	go a.client.Diagnose(context.Background())
}

// save stores new credentials. Main thread; the keyring work runs aside.
func (a *app) save(account, password string) {
	old := a.m.saved
	if account != old && password == "" {
		a.m.notice = "更换账号时请同时填写密码"
		return
	}
	a.m.notice = "保存中…"
	insecure := a.m.insecure
	a.disk <- func() {
		ins, err := a.store.SaveAccount(account, password)
		if password != "" {
			insecure = ins
		}
		if err != nil {
			a.log.Printf("保存失败: %v", err)
			a.post(func() { a.m.notice = "保存失败：" + err.Error() })
			return
		}
		a.credMu.Lock()
		a.account = account
		if password != "" {
			a.password = password
		}
		a.credMu.Unlock()
		a.log.Printf("账号 %s 已保存", account)
		if insecure {
			a.log.Add("系统钥匙串不可用，密码以明文（权限 0600）保存在本机")
		}
		a.post(func() {
			a.m.saved, a.m.password, a.m.hasPassword, a.m.insecure = account, "", true, insecure
			a.m.notice = "已保存"
			a.syncTray()
		})
		a.keeper.AccountChanged()
	}
}

func (a *app) setAutostart(on bool) {
	if err := mygo.App.SetOpenAtLogin(on); err != nil {
		a.log.Printf("设置开机自启失败: %v", err)
		a.m.notice = "开机自启设置失败：" + err.Error()
	} else if on {
		a.log.Add("已开启开机自启")
	} else {
		a.log.Add("已关闭开机自启")
	}
	a.m.autostart = mygo.App.OpenAtLogin()
	a.syncTray()
	if a.win != nil && !a.win.IsDestroyed() {
		a.win.Invalidate()
	}
}

func (a *app) setKeepAlive(on bool) {
	a.m.keepAlive = on
	a.keeper.SetKeepAlive(on)
	a.disk <- func() {
		if err := a.store.Update(func(st *store.Settings) { st.KeepAlive = on }); err != nil {
			a.log.Printf("保存设置失败: %v", err)
		}
	}
}

func (a *app) restart() {
	a.log.Add("重启以完成更新")
	mygo.App.Relaunch()
}

// updateLoop checks GitHub Releases once the network is up, then every
// few hours, and installs updates in the background.
func (a *app) updateLoop() {
	<-a.firstOnline
	for {
		a.checkUpdate()
		time.Sleep(updateEvery)
	}
}

func (a *app) checkUpdate() {
	if a.update != nil {
		return // already installed, waiting for a restart
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	up, err := mygo.Updater.Check(ctx)
	switch {
	case errors.Is(err, mygo.ErrUpdatesDisabled):
		return
	case err != nil:
		a.log.Printf("检查更新失败: %v", err)
		return
	case up == nil:
		return
	}
	if !mygo.Updater.Enabled() {
		// Installed by a package manager: only tell the user.
		a.log.Printf("发现新版本 v%s，请前往 %s 下载", up.Version, releasesURL)
		a.notify("发现新版本 v"+up.Version, "请前往 GitHub Releases 下载安装")
		return
	}
	a.log.Printf("发现新版本 v%s，正在后台下载…", up.Version)
	if err := up.Install(ctx, nil); err != nil {
		a.log.Printf("更新下载失败: %v", err)
		return
	}
	a.update = up
	a.log.Printf("新版本 v%s 已就绪，重启即可完成更新", up.Version)
	a.post(func() {
		a.m.update = "v" + up.Version
		a.syncTray()
	})
	a.notify("新版本 v"+up.Version+" 已就绪", "点击托盘菜单「重启以更新」完成更新")
}
