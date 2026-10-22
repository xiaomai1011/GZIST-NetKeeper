//go:build windows

package main

import (
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// The task must pass the same argument the Run value used, otherwise mygo
// cannot tell a login start from a click and the window pops up at boot.
func TestTaskTargetCarriesLoginArg(t *testing.T) {
	got, err := taskTarget()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, " --mygo-opened-at-login") {
		t.Fatalf("target %q has no login argument", got)
	}
	if !strings.HasPrefix(got, `"`) || strings.Count(got, `"`) != 2 {
		t.Fatalf("target %q is not one quoted executable", got)
	}
	if strings.Contains(got, "-test.exe") == false && !strings.Contains(got, ".exe") {
		t.Fatalf("target %q does not point at an executable", got)
	}
}

// schtasks answers in the OEM code page here, and the log is UTF-8: without the
// decode the reason for a failure is a row of replacement characters.
func TestConsoleTextDecodesGBK(t *testing.T) {
	want := "错误: 拒绝访问。"
	b, _, err := transform.Bytes(simplifiedchinese.GBK.NewEncoder(), []byte(want))
	if err != nil {
		t.Fatal(err)
	}
	if got := consoleText(b); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got := consoleText([]byte("Access is denied.")); got != "Access is denied." {
		t.Fatalf("plain ASCII changed: %q", got)
	}
}
