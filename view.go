package main

import (
	"fmt"
	"math"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/zzstar101/GZIST-NetKeeper-MyGo/internal/art"
	"github.com/zzstar101/GZIST-NetKeeper-MyGo/internal/keeper"
	"github.com/zzstar101/GZIST-NetKeeper-MyGo/internal/portal"
)

// The look follows BanG Dream! It's MyGO!!!!!: the band's blue, the five
// members' colors, a 迷星 for the status and 灯's notebook for the log.
var (
	colBand   = ui.Hex("#3388BB")
	colTomori = ui.Hex("#77BBDD")
	colAnon   = ui.Hex("#FF8899")
	colRana   = ui.Hex("#77DD77")
	colSoyo   = ui.Hex("#FFDD88")
	colTaki   = ui.Hex("#7777AA")
	members   = []ui.Color{colTomori, colAnon, colRana, colSoyo, colTaki}
)

// actions are what the window can ask the app to do. Tests replace them.
type actions struct {
	Login        func()
	Logout       func()
	Diagnose     func()
	Save         func(account, password string)
	SetAutostart func(on bool)
	SetKeepAlive func(on bool)
	Restart      func()
	OpenLogs     func()
}

// model is everything the main window shows. It is only touched on the
// main thread.
type model struct {
	st          keeper.State
	nic         portal.NIC
	account     string // text field
	password    string // text field, empty means unchanged
	saved       string // account on disk
	hasPassword bool
	insecure    bool
	autostart   bool
	keepAlive   bool
	notice      string // result of the last save or switch
	logs        []string
	logScroll   ui.ScrollState
	update      string // version ready to install
	version     string
	act         actions
}

// status describes the current phase in words and a member's color.
type status struct {
	title, line string
	color       ui.Color
	tray        art.TrayState
}

func describe(st keeper.State, hasAccount bool) status {
	switch {
	case st.Phase == keeper.LoggingIn:
		return status{"正在登录…", "迷星叫 —— 正在呼唤认证服务器", colAnon, art.TrayBusy}
	case st.Phase == keeper.LoggingOut:
		return status{"正在注销…", "下次见", colAnon, art.TrayBusy}
	case st.Phase == keeper.Checking:
		return status{"检测中…", "正在确认网络状态", colTomori, art.TrayBusy}
	case st.Phase == keeper.Online && st.Notice != "":
		return status{"已认证，等待生效", st.Notice, colSoyo, art.TrayBusy}
	case st.Phase == keeper.Online:
		return status{"在线", "碧天伴走 —— 网络一路畅通", colBand, art.TrayOnline}
	case !hasAccount || st.Phase == keeper.NoAccount:
		return status{"还没有登记账号", "填好学号和密码，一起组乐队吧！", colRana, art.TrayOffline}
	case st.Pause == keeper.PausedByServer:
		return status{"已暂停自动重试", "服务器拒绝了登录，按下面的提示处理后点「立即登录」", colSoyo, art.TrayError}
	case st.Pause == keeper.PausedByLogout:
		return status{"已注销", "自动保活已暂停，点「立即登录」继续", colTaki, art.TrayOffline}
	case !st.KeepAlive:
		return status{"离线", "自动保活已关闭", colTaki, art.TrayOffline}
	case st.LastError != "":
		return status{"离线", "迷子中… " + st.LastError, colTaki, art.TrayError}
	default:
		return status{"离线", "迷子中… 马上帮你找回网络", colTaki, art.TrayOffline}
	}
}

func applyTheme(c *ui.Context) *ui.Theme {
	t := *c.Theme()
	if t.Dark {
		t.Background = ui.Hex("#0F151E")
		t.Surface, t.SurfaceHover, t.SurfacePressed = ui.Hex("#1D2733"), ui.Hex("#253242"), ui.Hex("#2D3C4F")
		t.Border = ui.Hex("#2C394A")
		t.Text, t.TextMuted = ui.Hex("#E7EEF6"), ui.Hex("#8E9CAF")
		t.Accent, t.AccentHover, t.AccentPressed = ui.Hex("#4A9FD3"), ui.Hex("#66B2E0"), ui.Hex("#3388BB")
		t.Selection, t.Focus = colBand.Alpha(0.45), colTomori.Alpha(0.6)
	} else {
		t.Background = ui.Hex("#EEF4F9")
		t.Surface, t.SurfaceHover, t.SurfacePressed = ui.Hex("#F3F7FA"), ui.Hex("#E6EEF5"), ui.Hex("#D9E5EF")
		t.Border = ui.Hex("#D3DFE9")
		t.Text, t.TextMuted = ui.Hex("#1E2A38"), ui.Hex("#687789")
		t.Accent, t.AccentHover, t.AccentPressed = colBand, ui.Hex("#2B79A8"), ui.Hex("#236890")
		t.Selection, t.Focus = colBand.Alpha(0.25), colBand.Alpha(0.5)
	}
	t.AccentText = ui.Hex("#FFFFFF")
	t.Radius = 8
	c.SetTheme(&t)
	return &t
}

func cardBG(t *ui.Theme) ui.Color {
	if t.Dark {
		return ui.Hex("#161F2A")
	}
	return ui.Hex("#FFFFFF")
}

func card(c *ui.Context, t *ui.Theme) ui.Element {
	e := ui.Column(c).Padding(14).Gap(10).Radius(14).Background(cardBG(t)).Border(1, t.Border)
	if !t.Dark {
		e.Shadow(0, 2, 10, 0, ui.RGBA(30, 70, 110, 0.07))
	}
	return e
}

// starPath is a five-pointed star in r.
func starPath(r ui.Rect, inner float64, rot float64) *ui.Path {
	cx, cy := float64(r.X+r.W/2), float64(r.Y+r.H/2)+float64(r.H)*0.03
	pts := art.StarPoints(cx, cy, float64(min(r.W, r.H))/2, inner, rot)
	var p ui.Path
	p.MoveTo(float32(pts[0][0]), float32(pts[0][1]))
	for _, q := range pts[1:] {
		p.LineTo(float32(q[0]), float32(q[1]))
	}
	p.Close()
	return &p
}

func (m *model) view(c *ui.Context) {
	t := applyTheme(c)
	s := describe(m.st, m.saved != "")
	ui.Column(c).Fill().Children(func() {
		m.header(c, t)
		ui.Scroll(c).Grow(1).Children(func() {
			ui.Column(c).Padding(14).Gap(12).Children(func() {
				if m.update != "" {
					m.updateBanner(c, t)
				}
				m.statusCard(c, t, s)
				m.accountCard(c, t)
				m.switches(c, t)
				m.logCard(c, t)
				m.footer(c, t)
			})
		})
	})
}

func (m *model) header(c *ui.Context, t *ui.Theme) {
	ui.Column(c).FillWidth().Children(func() {
		ui.Row(c).FillWidth().Padding(16, 18, 14, 18).Gap(12).AlignItems(ui.Center).
			Gradient(headerColors(t)).
			Draw(func(p *ui.Painter, r ui.Rect) {
				// sparkles scattered over the band's blue
				for _, s := range [][3]float32{{0.62, 0.22, 7}, {0.74, 0.70, 5}, {0.86, 0.30, 9}, {0.95, 0.75, 4}, {0.52, 0.78, 4}} {
					sr := ui.Rect{X: r.X + r.W*s[0] - s[2], Y: r.Y + r.H*s[1] - s[2], W: 2 * s[2], H: 2 * s[2]}
					p.FillPath(starPath(sr, 0.42, 0), ui.RGBA(255, 255, 255, 0.35))
				}
			}).
			Children(func() {
				ui.Box(c).Size(34, 34).Draw(func(p *ui.Painter, r ui.Rect) {
					p.FillPath(starPath(r, 0.48, -8), ui.Hex("#FFFFFF"))
				})
				ui.Column(c).Gap(2).Grow(1).Children(func() {
					ui.Text(c, "GZIST NetKeeper").FontSize(19).Bold().TextColor(ui.Hex("#FFFFFF"))
					ui.Text(c, "迷子でもいい、迷子でも進め。").FontSize(11.5).TextColor(ui.RGBA(255, 255, 255, 0.85))
				})
			})
		// the five members, side by side
		ui.Row(c).FillWidth().Height(4).Children(func() {
			for _, col := range members {
				ui.Box(c).Grow(1).Height(4).Background(col)
			}
		})
	})
}

func headerColors(t *ui.Theme) (ui.Color, ui.Color, float32) {
	if t.Dark {
		return ui.Hex("#1E5A82"), ui.Hex("#2F7DAE"), 120
	}
	return colBand, ui.Hex("#5FA9D6"), 120
}

func (m *model) updateBanner(c *ui.Context, t *ui.Theme) {
	ui.Row(c).Padding(10, 14).Gap(10).AlignItems(ui.Center).Radius(12).
		Background(colSoyo.Alpha(0.28)).Border(1, colSoyo).Children(func() {
		ui.Text(c, "新版本 "+m.update+" 已就绪").Grow(1).Bold()
		if ui.PrimaryButton(c, "重启以更新").Clicked() && m.act.Restart != nil {
			m.act.Restart()
		}
	})
}

func (m *model) statusCard(c *ui.Context, t *ui.Theme, s status) {
	card(c, t).Border(1.5, s.color.Alpha(0.75)).Gradient(cardBG(t).Mix(s.color, 0.16), cardBG(t), 180).Children(func() {
		ui.Row(c).Gap(12).AlignItems(ui.Center).Children(func() {
			star := ui.Box(c).Size(40, 40)
			busy := m.st.Busy() || m.st.Phase == keeper.Checking
			if busy {
				star.Rotate(star.Loop("spin", 2400*time.Millisecond, ui.Linear) * 72)
			}
			online := m.st.Phase == keeper.Online && m.st.Notice == ""
			col := s.color
			star.Draw(func(p *ui.Painter, r ui.Rect) {
				if online || busy {
					p.FillPath(starPath(r, 0.48, 0), col)
				} else {
					p.StrokePath(starPath(ui.Rect{X: r.X + 2, Y: r.Y + 2, W: r.W - 4, H: r.H - 4}, 0.48, 0), 2.5, col)
				}
			})
			ui.Column(c).Gap(3).Grow(1).Children(func() {
				ui.Text(c, s.title).FontSize(20).Bold()
				ui.Text(c, s.line).FontSize(12).TextColor(t.TextMuted).Wrap()
			})
		})
		if m.st.RetCode != 0 {
			ui.Text(c, fmt.Sprintf("ret_code=%d：%s", m.st.RetCode, portal.Advice(m.st.RetCode))).
				FontSize(12).Wrap().Padding(8, 10).Radius(8).Background(colSoyo.Alpha(0.22))
		}
		ui.Grid(c).ColumnTracks(ui.Fixed(56), ui.Fr(1)).GapX(12).GapY(4).Children(func() {
			kv := func(k, v string) {
				ui.Text(c, k).FontSize(12).TextColor(t.TextMuted)
				ui.Text(c, v).FontSize(12).Selectable()
			}
			kv("IP", dash(m.nic.IP))
			kv("MAC", dash(portal.DashedMAC(m.nic.MAC)))
			last := "—"
			if !m.st.LastLogin.IsZero() {
				last = m.st.LastLogin.Format("01-02 15:04:05")
			}
			kv("上次登录", last)
		})
		ui.Row(c).Gap(8).Children(func() {
			busy := m.st.Busy()
			if ui.PrimaryButton(c, "立即登录").Grow(1).Disabled(busy || m.saved == "").Clicked() {
				m.act.Login()
			}
			if ui.Button(c, "注销").Grow(1).Disabled(busy || m.saved == "").Clicked() {
				m.act.Logout()
			}
			if ui.Button(c, "诊断").Grow(1).Clicked() {
				m.act.Diagnose()
			}
		})
	})
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func sectionTitle(c *ui.Context, t *ui.Theme, title string, col ui.Color) {
	ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
		ui.Box(c).Size(8, 8).Radius(4).Background(col)
		ui.Text(c, title).FontSize(13).Bold()
	})
}

func (m *model) accountCard(c *ui.Context, t *ui.Theme) {
	card(c, t).Children(func() {
		sectionTitle(c, t, "账号", colAnon)
		ui.TextInput(c, &m.account).Label("学号").Placeholder("学号").FillWidth()
		pw := ui.TextInput(c, &m.password).Label("密码").Password().FillWidth()
		if m.hasPassword {
			pw.Placeholder("已保存，留空则不修改")
		} else {
			pw.Placeholder("校园网密码")
		}
		submitted := pw.Submitted()
		ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
			msg := m.notice
			if msg == "" && m.insecure {
				msg = "系统钥匙串不可用，密码以明文保存在本机"
			}
			ui.Text(c, msg).FontSize(12).TextColor(t.TextMuted).Grow(1).Wrap()
			dirty := m.account != m.saved || m.password != ""
			if (ui.PrimaryButton(c, "保存").Disabled(!dirty || m.account == "").Clicked() || (submitted && dirty)) && m.account != "" {
				m.act.Save(m.account, m.password)
			}
		})
	})
}

func (m *model) switches(c *ui.Context, t *ui.Theme) {
	card(c, t).Children(func() {
		sectionTitle(c, t, "设置", colSoyo)
		row := func(on *bool, label, hint string, set func(bool)) {
			ui.Row(c).Gap(10).AlignItems(ui.Center).Children(func() {
				ui.Column(c).Grow(1).Gap(1).Cursor(ui.CursorPointer).OnClick(func() {
					*on = !*on
					set(*on)
				}).Children(func() {
					ui.Text(c, label)
					ui.Text(c, hint).FontSize(11.5).TextColor(t.TextMuted)
				})
				if ui.Switch(c, on).Label(label).Changed() {
					set(*on)
				}
			})
		}
		row(&m.keepAlive, "自动保活", "每 10 秒检测一次，掉线自动重新登录", m.act.SetKeepAlive)
		row(&m.autostart, "开机自启", "登录系统后在后台默默守护", m.act.SetAutostart)
	})
}

// paper is the cream of 灯's notebook.
func paper(t *ui.Theme) (bg, rule ui.Color) {
	if t.Dark {
		return ui.Hex("#1A2230"), ui.RGBA(119, 187, 221, 0.10)
	}
	return ui.Hex("#FFFDF6"), ui.RGBA(51, 136, 187, 0.13)
}

const logLine = 19

func (m *model) logCard(c *ui.Context, t *ui.Theme) {
	card(c, t).Children(func() {
		ui.Row(c).Gap(8).AlignItems(ui.Center).Children(func() {
			ui.Box(c).Size(8, 8).Radius(4).Background(colRana)
			ui.Text(c, "灯的笔记本").FontSize(13).Bold().Grow(1)
			if m.act.OpenLogs != nil && ui.Button(c, "日志文件").FontSize(12).Clicked() {
				m.act.OpenLogs()
			}
		})
		bg, rule := paper(t)
		sc := ui.Scroll(c).Height(200).TrackScroll(&m.logScroll).Radius(8).Background(bg).Border(1, t.Border)
		if m.logScroll.Y >= m.logScroll.MaxY-1 {
			m.logScroll.Y = math.MaxFloat32 // stay at the newest line
		}
		sc.Children(func() {
			ui.Column(c).FillWidth().MinHeight(200).Padding(4, 10, 4, 22).
				Draw(func(p *ui.Painter, r ui.Rect) {
					for y := r.Y + 4 + logLine; y < r.Y+r.H; y += logLine {
						p.Line(r.X, y, r.X+r.W, y, 1, rule)
					}
					p.Line(r.X+14, r.Y, r.X+14, r.Y+r.H, 1, colAnon.Alpha(0.45))
				}).
				Children(func() {
					if len(m.logs) == 0 {
						ui.Text(c, "这里会记下每一次登录和检测……").FontSize(12).FixedLineHeight(logLine).TextColor(t.TextMuted)
					}
					for i, l := range m.logs {
						ui.Text(c, l).Key(i).FontSize(11.5).FixedLineHeight(logLine).Selectable().Wrap()
					}
				})
		})
	})
}

func (m *model) footer(c *ui.Context, t *ui.Theme) {
	ui.Row(c).Center().Gap(6).Padding(2, 0, 6, 0).Children(func() {
		for _, col := range members {
			ui.Box(c).Size(6, 6).Radius(3).Background(col)
		}
		ui.Text(c, "it's MyGO!!!!!  ·  v"+m.version).FontSize(11).TextColor(t.TextMuted)
	})
}
