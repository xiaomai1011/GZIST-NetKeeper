package applog

import (
	"os"
	"strings"
	"testing"
)

func TestRingAndRotation(t *testing.T) {
	dir := t.TempDir()
	l := New(dir)
	t.Cleanup(func() { l.Close() })
	big := strings.Repeat("x", 4096)
	for i := 0; i < 300; i++ {
		l.Add(big)
	}
	if n := len(l.Lines()); n != Keep {
		t.Fatalf("kept %d lines", n)
	}
	if _, err := os.Stat(l.Path() + ".1"); err != nil {
		t.Fatalf("no rotated file: %v", err)
	}
	fi, _ := os.Stat(l.Path())
	if fi.Size() > MaxSize {
		t.Fatalf("log grew to %d", fi.Size())
	}
}
