// Package store keeps the account settings. The password lives in the OS
// credential store (Keychain, Credential Manager, Secret Service); when that
// is unavailable it falls back to a 0600 file next to the settings.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/zalando/go-keyring"
)

const service = "io.github.xiaomai1011.gzist-netkeeper"

// legacyService is the credential service of 2.0.0, released under the
// identifier io.github.zzstar101.gzist-netkeeper; Password moves its
// entries to service.
const legacyService = "io.github.zzstar101.gzist-netkeeper"

// Settings are saved as settings.json in the user data directory.
type Settings struct {
	Account   string `json:"account"`
	KeepAlive bool   `json:"keepAlive"`
}

// Keyring is the subset of go-keyring the store uses; tests replace it.
type Keyring interface {
	Set(service, user, password string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}

type osKeyring struct{}

func (osKeyring) Set(s, u, p string) error        { return keyring.Set(s, u, p) }
func (osKeyring) Get(s, u string) (string, error) { return keyring.Get(s, u) }
func (osKeyring) Delete(s, u string) error        { return keyring.Delete(s, u) }

// Store reads and writes settings in Dir. Writes are serialized and
// atomic, so concurrent saves cannot leave a half-written settings.json.
type Store struct {
	Dir     string
	Keyring Keyring

	mu sync.Mutex
}

// New returns a store backed by the OS credential store.
func New(dir string) *Store { return &Store{Dir: dir, Keyring: osKeyring{}} }

func (s *Store) settingsPath() string { return filepath.Join(s.Dir, "settings.json") }
func (s *Store) secretPath() string   { return filepath.Join(s.Dir, "password") }

// rename is replaced by tests to simulate a failing disk.
var rename = os.Rename

func defaults() Settings { return Settings{KeepAlive: true} }

// Load returns the saved settings, or defaults when none exist. A file that
// cannot be read or decoded is an error; the defaults are returned with it.
func (s *Store) Load() (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

func (s *Store) load() (Settings, error) {
	st := defaults()
	b, err := os.ReadFile(s.settingsPath())
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return defaults(), fmt.Errorf("settings.json 已损坏: %w", err)
	}
	return st, nil
}

// Save writes the settings.
func (s *Store) Save(st Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save(st)
}

// Update changes the saved settings in place. A damaged settings.json is
// kept as settings.json.bad and replaced.
func (s *Store) Update(fn func(*Settings)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load()
	if err != nil {
		if err := s.setAside(); err != nil {
			return err
		}
	}
	fn(&st)
	return s.save(st)
}

func (s *Store) setAside() error {
	if err := os.Rename(s.settingsPath(), s.settingsPath()+".bad"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Store) save(st Settings) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return s.writeFile(s.settingsPath(), b)
}

// writeFile replaces path atomically: write a temporary file next to it,
// flush it to disk, then rename it over path.
func (s *Store) writeFile(path string, b []byte) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(s.Dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// SaveAccount makes account the saved account, storing password for it
// unless password is empty. The old account's password is removed only
// after the new password and the settings are both written, so a failure
// leaves the old account usable. insecure reports that the password went to
// the fallback file.
func (s *Store) SaveAccount(account, password string) (insecure bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.load()
	if err != nil {
		if err := s.setAside(); err != nil {
			return false, err
		}
	}
	old := st.Account
	// The fallback file is shared by all accounts; keep a copy to restore.
	prevFile, prevErr := os.ReadFile(s.secretPath())
	if password != "" {
		if insecure, err = s.setSecret(account, password); err != nil {
			return insecure, err
		}
	}
	st.Account = account
	if err := s.save(st); err != nil {
		if password != "" {
			if insecure {
				if prevErr == nil {
					s.writeFile(s.secretPath(), prevFile)
				} else {
					os.Remove(s.secretPath())
				}
			} else if account != old {
				s.Keyring.Delete(service, account)
			}
		}
		return insecure, err
	}
	if password != "" && !insecure {
		os.Remove(s.secretPath())
	}
	if old != "" && old != account {
		s.Keyring.Delete(service, old)
		s.Keyring.Delete(legacyService, old)
	}
	return insecure, nil
}

// SetPassword stores the password. insecure reports that the credential
// store failed and the password was written to a plain file instead.
func (s *Store) SetPassword(account, password string) (insecure bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	insecure, err = s.setSecret(account, password)
	if err == nil && !insecure {
		os.Remove(s.secretPath())
	}
	return insecure, err
}

// setSecret writes the password to the keyring, or to the fallback file
// when the keyring fails. It leaves any existing fallback file alone after
// a keyring success.
func (s *Store) setSecret(account, password string) (insecure bool, err error) {
	if err := s.Keyring.Set(service, account, password); err == nil {
		return false, nil
	}
	return true, s.writeFile(s.secretPath(), []byte(password))
}

// Password returns the stored password. insecure reports that it came from
// the fallback file.
func (s *Store) Password(account string) (password string, insecure bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, err := s.Keyring.Get(service, account); err == nil {
		return p, false, nil
	}
	if p, err := s.Keyring.Get(legacyService, account); err == nil {
		if s.Keyring.Set(service, account, p) == nil {
			s.Keyring.Delete(legacyService, account)
		}
		return p, false, nil
	}
	b, err := os.ReadFile(s.secretPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", true, err
	}
	return string(b), true, nil
}

// DeletePassword forgets the password for account.
func (s *Store) DeletePassword(account string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if account != "" {
		s.Keyring.Delete(service, account)
		s.Keyring.Delete(legacyService, account)
	}
	os.Remove(s.secretPath())
}
