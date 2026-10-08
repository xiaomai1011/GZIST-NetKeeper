package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

type memKeyring struct {
	mu   sync.Mutex
	m    map[string]string
	fail bool
}

func (k *memKeyring) Set(s, u, p string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail {
		return errors.New("no keyring")
	}
	k.m[s+"/"+u] = p
	return nil
}

func (k *memKeyring) Get(s, u string) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.fail {
		return "", errors.New("no keyring")
	}
	p, ok := k.m[s+"/"+u]
	if !ok {
		return "", errors.New("not found")
	}
	return p, nil
}

func (k *memKeyring) Delete(s, u string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.m, s+"/"+u)
	return nil
}

func TestSettingsRoundTrip(t *testing.T) {
	s := &Store{Dir: t.TempDir(), Keyring: &memKeyring{m: map[string]string{}}}
	if st, err := s.Load(); err != nil || !st.KeepAlive || st.Account != "" {
		t.Fatalf("defaults %+v %v", st, err)
	}
	if err := s.Save(Settings{Account: "2023001", KeepAlive: false}); err != nil {
		t.Fatal(err)
	}
	if st, err := s.Load(); err != nil || st.Account != "2023001" || st.KeepAlive {
		t.Fatalf("got %+v %v", st, err)
	}
}

func TestPasswordKeyringAndFallback(t *testing.T) {
	k := &memKeyring{m: map[string]string{}}
	s := &Store{Dir: t.TempDir(), Keyring: k}
	if insecure, err := s.SetPassword("a", "pw"); err != nil || insecure {
		t.Fatal(insecure, err)
	}
	if p, insecure, _ := s.Password("a"); p != "pw" || insecure {
		t.Fatal(p, insecure)
	}
	k.fail = true
	if insecure, err := s.SetPassword("a", "pw2"); err != nil || !insecure {
		t.Fatal(insecure, err)
	}
	fi, err := os.Stat(s.secretPath())
	if err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatal(fi, err)
	}
	if p, insecure, _ := s.Password("a"); p != "pw2" || !insecure {
		t.Fatal(p, insecure)
	}
	s.DeletePassword("a")
	if p, _, _ := s.Password("a"); p != "" {
		t.Fatal(p)
	}
}

func TestPasswordMigratesLegacyService(t *testing.T) {
	k := &memKeyring{m: map[string]string{legacyService + "/a": "old"}}
	s := &Store{Dir: t.TempDir(), Keyring: k}
	if p, insecure, _ := s.Password("a"); p != "old" || insecure {
		t.Fatal(p, insecure)
	}
	if k.m[service+"/a"] != "old" {
		t.Fatalf("not migrated: %v", k.m)
	}
	if _, ok := k.m[legacyService+"/a"]; ok {
		t.Fatalf("legacy entry kept: %v", k.m)
	}
}

func TestLoadReportsCorruptSettings(t *testing.T) {
	s := &Store{Dir: t.TempDir(), Keyring: &memKeyring{m: map[string]string{}}}
	os.WriteFile(s.settingsPath(), []byte(`{"account": "20`), 0o600)
	st, err := s.Load()
	if err == nil || !st.KeepAlive || st.Account != "" {
		t.Fatalf("got %+v %v", st, err)
	}
	if err := s.Update(func(st *Settings) { st.KeepAlive = false }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.settingsPath() + ".bad"); err != nil {
		t.Fatalf("damaged file not kept: %v", err)
	}
	if st, err := s.Load(); err != nil || st.KeepAlive {
		t.Fatalf("got %+v %v", st, err)
	}
}

func TestConcurrentUpdates(t *testing.T) {
	s := &Store{Dir: t.TempDir(), Keyring: &memKeyring{m: map[string]string{}}}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := s.Update(func(st *Settings) { st.KeepAlive = !st.KeepAlive }); err != nil {
				t.Error(err)
			}
		}()
		go func(i int) {
			defer wg.Done()
			if _, err := s.SaveAccount(fmt.Sprint(i), ""); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	st, err := s.Load()
	if err != nil || !st.KeepAlive { // toggled an even number of times
		t.Fatalf("got %+v %v", st, err)
	}
	if m, _ := filepath.Glob(filepath.Join(s.Dir, "*.tmp")); len(m) != 0 {
		t.Fatalf("temporary files left: %v", m)
	}
}

func TestSaveAccountSwitch(t *testing.T) {
	k := &memKeyring{m: map[string]string{}}
	s := &Store{Dir: t.TempDir(), Keyring: k}
	if _, err := s.SaveAccount("old", "pw1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveAccount("new", "pw2"); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.Load(); st.Account != "new" {
		t.Fatalf("got %+v", st)
	}
	if _, ok := k.m[service+"/old"]; ok || k.m[service+"/new"] != "pw2" {
		t.Fatalf("keyring %v", k.m)
	}
}

func failRename(t *testing.T) {
	rename = func(string, string) error { return errors.New("disk full") }
	t.Cleanup(func() { rename = os.Rename })
}

func TestSaveAccountFailureKeepsOldPassword(t *testing.T) {
	k := &memKeyring{m: map[string]string{}}
	s := &Store{Dir: t.TempDir(), Keyring: k}
	if _, err := s.SaveAccount("old", "pw1"); err != nil {
		t.Fatal(err)
	}
	failRename(t)
	if _, err := s.SaveAccount("new", "pw2"); err == nil {
		t.Fatal("expected failure")
	}
	if p, _, _ := s.Password("old"); p != "pw1" {
		t.Fatalf("old password lost: %q", p)
	}
	if _, ok := k.m[service+"/new"]; ok {
		t.Fatalf("half-saved account left in keyring: %v", k.m)
	}
	if st, _ := s.Load(); st.Account != "old" {
		t.Fatalf("got %+v", st)
	}
}

func TestSaveAccountFailureRestoresFallbackFile(t *testing.T) {
	k := &memKeyring{m: map[string]string{}, fail: true}
	s := &Store{Dir: t.TempDir(), Keyring: k}
	if _, err := s.SaveAccount("old", "pw1"); err != nil {
		t.Fatal(err)
	}
	// Fail only the settings write, after the password file is written.
	rename = func(a, b string) error {
		if filepath.Base(b) == "settings.json" {
			return errors.New("disk full")
		}
		return os.Rename(a, b)
	}
	t.Cleanup(func() { rename = os.Rename })
	if _, err := s.SaveAccount("new", "pw2"); err == nil {
		t.Fatal("expected failure")
	}
	if p, insecure, _ := s.Password("old"); p != "pw1" || !insecure {
		t.Fatalf("old password lost: %q", p)
	}
}
