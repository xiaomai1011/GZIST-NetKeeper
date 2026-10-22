//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/egoist/mygo"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// Starting at login is a Scheduled Task here, not a Run value.
//
// Explorer starts Run entries one at a time after the shell is up. On a machine
// with a dozen of them the app came up more than a minute after login — and that
// is exactly the window in which the campus network has to be logged in, because
// the portal is unreachable for the first 20–30 seconds after power-on. Task
// Scheduler starts the task at logon through its own service, so the app is up
// in a couple of seconds; the PowerShell build measured 21 s from power-on with
// exactly this mechanism.
//
// Writing a task needs an unfiltered token: from the normal user token Windows
// answers "拒绝访问". The app therefore tries, and when that fails it says so and
// points at the one-shot installer, which does the same thing elevated.
const autostartTask = "GZIST-NetKeeper"

// adminScript is the installer that creates the task with elevation.
const adminScript = "安装开机自启（管理员）.bat"

// taskTarget is the command the task runs. The argument is the one mygo reads
// to know the system started the app, so no window is shown at login.
func taskTarget() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return `"` + exe + `" --mygo-opened-at-login`, nil
}

// consoleText turns schtasks' output into log-safe UTF-8. The tool writes in the
// OEM code page (GBK on this machine), which would otherwise reach the log as
// replacement characters.
func consoleText(b []byte) string {
	b = []byte(strings.TrimSpace(string(b)))
	if utf8.Valid(b) {
		return string(b)
	}
	if out, _, err := transform.Bytes(simplifiedchinese.GBK.NewDecoder(), b); err == nil {
		return strings.TrimSpace(string(out))
	}
	return string(b)
}

// accessDenied reports the one failure the app cannot fix on its own.
func accessDenied(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "拒绝") || strings.Contains(s, "denied") || strings.Contains(s, "Denied")
}

// schtasks runs the tool without a console window and folds its message into
// the error, so a failure says why instead of only "exit status 1".
func schtasks(args ...string) error {
	cmd := exec.Command("schtasks", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	if msg := consoleText(out); msg != "" {
		return fmt.Errorf("%v: %s", err, msg)
	}
	return err
}

// enableAutostart registers the logon task. The Run value is removed first and
// put back only when the task cannot be created: autostart must never end up
// pointing at nothing, even if the slower mechanism is all that is left.
func enableAutostart() (note string, err error) {
	// A task installed once with elevation is already the fast path. Rewriting
	// it would need that elevation again, but nothing here does.
	if schtasks("/Query", "/TN", autostartTask) == nil {
		_ = mygo.App.SetOpenAtLogin(false)
		return "", nil
	}
	target, err := taskTarget()
	if err != nil {
		return "", err
	}
	_ = mygo.App.SetOpenAtLogin(false)
	if taskErr := schtasks("/Create", "/F", "/SC", "ONLOGON", "/TN", autostartTask, "/TR", target); taskErr != nil {
		if fbErr := mygo.App.SetOpenAtLogin(true); fbErr != nil {
			return "", fmt.Errorf("创建计划任务失败: %v；注册表回退也失败: %v", taskErr, fbErr)
		}
		msg := "计划任务创建失败，已回退到注册表启动（会慢一些）: " + taskErr.Error()
		if accessDenied(taskErr) {
			msg += "。请以管理员身份运行「" + adminScript + "」安装一次"
		}
		return msg, nil
	}
	// Both mechanisms must not start the app twice.
	_ = mygo.App.SetOpenAtLogin(false)
	if schtasks("/Query", "/TN", autostartTask) != nil {
		_ = schtasks("/Delete", "/TN", autostartTask, "/F")
		if fbErr := mygo.App.SetOpenAtLogin(true); fbErr != nil {
			return "", fmt.Errorf("计划任务无法确认，注册表回退也失败: %v", fbErr)
		}
		return "计划任务创建后无法确认，已回退到注册表启动（会慢一些）", nil
	}
	return "", nil
}

func disableAutostart() error {
	delErr := schtasks("/Delete", "/TN", autostartTask, "/F")
	// Also drops the Run value and its Task Manager state.
	_ = mygo.App.SetOpenAtLogin(false)
	if autostartOn() {
		if accessDenied(delErr) {
			return fmt.Errorf("删除登录任务需要管理员权限: %v。请以管理员身份运行「%s」，或手动删除任务 %s",
				delErr, adminScript, autostartTask)
		}
		return fmt.Errorf("仍检测到开机自启项，请在「任务计划程序」中删除 %s", autostartTask)
	}
	return nil
}

// autostartOn is what the switch shows: the task, or a Run value left by an
// older build or by the fallback above.
func autostartOn() bool {
	if schtasks("/Query", "/TN", autostartTask) == nil {
		return true
	}
	return mygo.App.OpenAtLogin()
}

// upgradeAutostart moves an autostart that a previous build left as a Run value
// onto the logon task. Without it the fix only applies to users who toggle the
// switch off and on again.
func upgradeAutostart() (note string, err error) {
	if schtasks("/Query", "/TN", autostartTask) == nil {
		return "", nil // already a task
	}
	if !mygo.App.OpenAtLogin() {
		return "", nil // autostart is off; nothing to move
	}
	note, err = enableAutostart()
	if err != nil {
		return "", err
	}
	if note != "" {
		return note, nil // the fallback kept the Run value
	}
	return "开机自启已从注册表升级为登录任务（登录后启动更快）", nil
}
