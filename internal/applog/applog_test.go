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
