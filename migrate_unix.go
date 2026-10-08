//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"runtime"
)

// legacyAutostartPath is where 2.0.0 registered starting at login: the XDG
// autostart entry on Linux, the launch agent (macOS 12) on macOS. A login
// item of macOS 13 and later belongs to the app bundle and needs no
// migration.
func legacyAutostartPath() string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "darwin" {
		return filepath.Join(home, "Library", "LaunchAgents", legacyID+".plist")
	}
	dir := os.Getenv("XDG_CONFIG_HOME")
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "autostart", legacyID+".desktop")
}

// removeLegacyAutostart removes the entry of 2.0.0 and reports whether there
// was one.
func removeLegacyAutostart() bool {
	return os.Remove(legacyAutostartPath()) == nil
}
