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

func TestRotationRepeats(t *testing.T) {
	dir := t.TempDir()
	l := New(dir)
	t.Cleanup(func() { l.Close() })
	big := strings.Repeat("y", 64<<10)
	// Enough for several rotations, each replacing an existing .1.
	for i := 0; i < 5*(MaxSize/len(big)+1); i++ {
		l.Add(big)
	}
	for _, line := range l.Lines() {
		if strings.Contains(line, "失败") {
			t.Fatalf("rotation reported: %s", line)
		}
	}
	for _, p := range []string{l.Path(), l.Path() + ".1"} {
		fi, err := os.Stat(p)
		if err != nil || fi.Size() > MaxSize+int64(len(big))+64 {
			t.Fatalf("%s: %v %v", p, fi, err)
		}
	}
	l.Add("still writing")
	b, _ := os.ReadFile(l.Path())
	if !strings.Contains(string(b), "still writing") {
		t.Fatal("log not reopened after rotation")
	}
}

// Mark writes before the application exists, so it must open, append and close
// on its own — and stay harmless when the directory is empty or unusable.
func TestMarkWritesWithoutALog(t *testing.T) {
	dir := t.TempDir()
	Mark(dir, "进程启动 pid=1")
	Mark(dir, "进程启动 pid=2")
	Mark("", "ignored")
	b, err := os.ReadFile(dir + string(os.PathSeparator) + "netkeeper.log")
	if err != nil {
		t.Fatalf("no log file: %v", err)
	}
	s := string(b)
	if strings.Count(s, "进程启动") != 2 {
		t.Fatalf("wrote %q", s)
	}
	if !strings.Contains(s, "2026-") && !strings.Contains(s, "-") {
		t.Fatalf("no timestamp: %q", s)
	}
}
