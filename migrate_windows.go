package main

import (
	"os/exec"
	"syscall"
)

const (
	runKey      = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	approvedKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`
)

func reg(args ...string) error {
	cmd := exec.Command("reg", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	return cmd.Run()
}

// removeLegacyAutostart removes the Run value of 2.0.0 and reports whether
// there was one. It also drops the Apps & features entry of 2.0.0 once an
// installer of this version wrote its own, so the app is not listed twice.
func removeLegacyAutostart() bool {
	const uninstall = `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\`
	if reg("query", uninstall+"io.github.xiaomai1011.gzist-netkeeper") == nil &&
		reg("query", uninstall+legacyID) == nil {
		reg("delete", uninstall+legacyID, "/f")
	}
	if reg("query", runKey, "/v", legacyID) != nil {
		return false
	}
	reg("delete", runKey, "/v", legacyID, "/f")
	reg("delete", approvedKey, "/v", legacyID, "/f")
	return true
}
