// Package applog keeps the last lines in memory for the window and writes
// everything to a size-rotated file.
package applog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Keep is how many lines stay in memory.
const Keep = 200

// MaxSize is the file size that triggers rotation to <name>.1.
const MaxSize = 1 << 20

// Log is safe for concurrent use.
type Log struct {
	mu       sync.Mutex
	lines    []string
	path     string
	f        *os.File
	size     int64
	now      func() time.Time
	onChange func()
}

// New opens (or creates) dir/netkeeper.log. An empty dir keeps logs in
// memory only.
func New(dir string) *Log {
	l := &Log{now: time.Now}
	if dir != "" {
		os.MkdirAll(dir, 0o700)
		l.path = filepath.Join(dir, "netkeeper.log")
		l.open()
	}
	return l
}

func (l *Log) open() {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	l.f = f
	if fi, err := f.Stat(); err == nil {
		l.size = fi.Size()
	}
}

// rotate moves the full log to <name>.1, replacing an older one. Windows
// cannot rename over an existing file that is open elsewhere, so the old
// copy is removed first. If the move still fails the file is truncated
// rather than left to grow. Called with l.mu held.
func (l *Log) rotate() {
	l.f.Close()
	l.f = nil
	old := l.path + ".1"
	if err := os.Remove(old); err != nil && !errors.Is(err, os.ErrNotExist) {
		l.warn("删除旧日志 %s 失败: %v", old, err)
	}
	if err := os.Rename(l.path, old); err != nil {
		l.warn("日志轮转失败: %v", err)
		if err := os.Truncate(l.path, 0); err != nil {
			l.warn("清空日志失败: %v", err)
		}
	}
	l.size = 0
	l.open()
}

// warn records a problem with the log file itself, in memory only.
func (l *Log) warn(format string, args ...any) {
	l.lines = append(l.lines, l.now().Format("15:04:05")+"  "+fmt.Sprintf(format, args...))
}

// Path is the log file, or "" when logging to memory only.
func (l *Log) Path() string { return l.path }

// OnChange registers a callback run (on the logging goroutine) after each
// line.
func (l *Log) OnChange(fn func()) {
	l.mu.Lock()
	l.onChange = fn
	l.mu.Unlock()
}

// Printf adds a line.
func (l *Log) Printf(format string, args ...any) { l.Add(fmt.Sprintf(format, args...)) }

// Add appends one line.
func (l *Log) Add(msg string) {
	t := l.now()
	l.mu.Lock()
	l.lines = append(l.lines, t.Format("15:04:05")+"  "+msg)
	if len(l.lines) > Keep {
		l.lines = append(l.lines[:0:0], l.lines[len(l.lines)-Keep:]...)
	}
	if l.f != nil {
		n, _ := fmt.Fprintf(l.f, "%s  %s\n", t.Format("2006-01-02 15:04:05"), msg)
		l.size += int64(n)
		if l.size > MaxSize {
			l.rotate()
		}
	}
	fn := l.onChange
	l.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// Lines returns a copy of the recent lines.
func (l *Log) Lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// Close closes the log file; later lines stay in memory only.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
