//go:build !windows && !linux && !darwin

package main

func removeLegacyAutostart() bool { return false }
