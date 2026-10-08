package store

import (
	"errors"
	"os"
	"runtime"
	"testing"
)

type memKeyring struct {
	m    map[string]string
	fail bool
}

func (k *memKeyring) Set(s, u, p string) error {
	if k.fail {
		return errors.New("no keyring")
	}
	k.m[s+"/"+u] = p
	return nil
}

func (k *memKeyring) Get(s, u string) (string, error) {
	if k.fail {
		return "", errors.New("no keyring")
	}
	p, ok := k.m[s+"/"+u]
	if !ok {
		return "", errors.New("not found")
	}
	return p, nil
}

func (k *memKeyring) Delete(s, u string) error { delete(k.m, s+"/"+u); return nil }

func TestSettingsRoundTrip(t *testing.T) {
	s := &Store{Dir: t.TempDir(), Keyring: &memKeyring{m: map[string]string{}}}
	if st := s.Load(); !st.KeepAlive || st.Account != "" {
		t.Fatalf("defaults %+v", st)
	}
	if err := s.Save(Settings{Account: "2023001", KeepAlive: false}); err != nil {
		t.Fatal(err)
	}
	if st := s.Load(); st.Account != "2023001" || st.KeepAlive {
		t.Fatalf("got %+v", st)
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
