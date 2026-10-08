// Package store keeps the account settings. The password lives in the OS
// credential store (Keychain, Credential Manager, Secret Service); when that
// is unavailable it falls back to a 0600 file next to the settings.
package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

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

// Store reads and writes settings in Dir.
type Store struct {
	Dir     string
	Keyring Keyring
}

// New returns a store backed by the OS credential store.
func New(dir string) *Store { return &Store{Dir: dir, Keyring: osKeyring{}} }

func (s *Store) settingsPath() string { return filepath.Join(s.Dir, "settings.json") }
func (s *Store) secretPath() string   { return filepath.Join(s.Dir, "password") }

// Load returns the saved settings, or defaults when none exist.
func (s *Store) Load() Settings {
	st := Settings{KeepAlive: true}
	b, err := os.ReadFile(s.settingsPath())
	if err == nil {
		json.Unmarshal(b, &st)
	}
	return st
}

// Save writes the settings.
func (s *Store) Save(st Settings) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	return os.WriteFile(s.settingsPath(), b, 0o600)
}

// SetPassword stores the password. insecure reports that the credential
// store failed and the password was written to a plain file instead.
func (s *Store) SetPassword(account, password string) (insecure bool, err error) {
	if err := s.Keyring.Set(service, account, password); err == nil {
		os.Remove(s.secretPath())
		return false, nil
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return true, err
	}
	return true, os.WriteFile(s.secretPath(), []byte(password), 0o600)
}

// Password returns the stored password. insecure reports that it came from
// the fallback file.
func (s *Store) Password(account string) (password string, insecure bool, err error) {
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
	if account != "" {
		s.Keyring.Delete(service, account)
		s.Keyring.Delete(legacyService, account)
	}
	os.Remove(s.secretPath())
}
