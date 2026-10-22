//go:build !windows

package main

import "github.com/egoist/mygo"

// Off Windows the platform's own login item is already the fast path: a launch
// agent on macOS and an XDG autostart entry on Linux.
func enableAutostart() (note string, err error) { return "", mygo.App.SetOpenAtLogin(true) }

func disableAutostart() error { return mygo.App.SetOpenAtLogin(false) }

func autostartOn() bool { return mygo.App.OpenAtLogin() }

// Nothing to move: the platform login item is already the fast path.
func upgradeAutostart() (note string, err error) { return "", nil }
