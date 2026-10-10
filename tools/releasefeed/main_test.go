package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBaseURL(t *testing.T) {
	for _, s := range []string{"http://mirror.example/feed", "https://user:pw@mirror.example", "https://mirror.example/?x=1", "https://mirror.example/#x", "https:///feed", "https://mirror.example/../feed"} {
		if _, err := baseURL(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	if got, err := baseURL("https://mirror.example/releases/"); err != nil || got != "https://mirror.example/releases" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestConfigure(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mygo.json")
	original := `{"name":"test","updates":{"github":"owner/repo","publicKey":"pinned"}}`
	os.WriteFile(p, []byte(original), 0600)
	if err := configure(p, "http://bad"); err == nil {
		t.Fatal("accepted HTTP")
	}
	b, _ := os.ReadFile(p)
	if string(b) != original {
		t.Fatal("modified on invalid input")
	}
	if err := configure(p, "https://mirror.example/feed"); err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	b, _ = os.ReadFile(p)
	json.Unmarshal(b, &c)
	u := c["updates"].(map[string]any)
	if u["url"] != "https://mirror.example/feed" || u["publicKey"] != "pinned" || u["github"] != nil {
		t.Fatalf("%v", u)
	}
}

func fixture(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	os.WriteFile(filepath.Join(dir, "app.tar.gz"), []byte("signed archive"), 0600)
	os.WriteFile(filepath.Join(dir, "app.delta"), []byte("signed delta"), 0600)
	ref := func(name, body string) asset {
		sum := sha256.Sum256([]byte(body))
		return asset{URL: "https://github.com/owner/repo/releases/download/v1/" + name, Size: int64(len(body)), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, sum[:]))}
	}
	for _, target := range targets {
		m := manifest{Version: "1.0.0", asset: ref("app.tar.gz", "signed archive"), Deltas: []asset{ref("app.delta", "signed delta")}, Previous: []asset{{URL: "https://github.com/owner/repo/releases/download/v0/old.tar.gz"}}}
		b, _ := json.Marshal(m)
		os.WriteFile(filepath.Join(dir, "update-"+target+".json"), b, 0600)
	}
	os.WriteFile(filepath.Join(dir, "Installer windows x64.exe"), []byte("installer"), 0600)
	return dir, base64.StdEncoding.EncodeToString(pub)
}

func TestStage(t *testing.T) {
	dir, key := fixture(t)
	out := filepath.Join(t.TempDir(), "feed")
	if err := stage(dir, out, "https://mirror.example/feed", key); err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		b, err := os.ReadFile(filepath.Join(out, "update-"+target+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var m manifest
		json.Unmarshal(b, &m)
		if m.URL != "https://mirror.example/feed/app.tar.gz" || m.Deltas[0].URL != "https://mirror.example/feed/app.delta" || len(m.Previous) != 0 {
			t.Fatalf("%+v", m)
		}
	}
	b, _ := os.ReadFile(filepath.Join(out, "index.html"))
	if !strings.Contains(string(b), "Installer%20windows%20x64.exe") || !strings.Contains(string(b), "SHA256SUMS") {
		t.Fatalf("missing static links: %s", b)
	}
	indexHash := sha256.Sum256(b)
	b, _ = os.ReadFile(filepath.Join(out, "SHA256SUMS"))
	if !strings.Contains(string(b), fmt.Sprintf("%x  index.html\n", indexHash)) {
		t.Fatal("missing index hash")
	}
	if !strings.Contains(string(b), "Installer windows x64.exe") {
		t.Fatal("missing installer hash")
	}
	if err := stage(dir, out, "https://mirror.example/feed", key); err == nil {
		t.Fatal("overwrote existing output")
	}
}

func TestValidateReleaseInventory(t *testing.T) {
	for _, mode := range []string{"valid", "missing-installer", "stale-version", "wrong-target"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			for _, target := range targets {
				m := manifest{Version: "1.0.0", asset: asset{URL: "https://mirror.example/app-1.0.0-" + target + ".tar.gz"}}
				if mode == "stale-version" {
					m.Version = "0.9.0"
				}
				if mode == "wrong-target" {
					m.URL = "https://mirror.example/app-1.0.0-wrong-target.tar.gz"
				}
				b, _ := json.Marshal(m)
				os.WriteFile(filepath.Join(dir, "update-"+target+".json"), b, 0600)
			}
			for _, name := range []string{"GZIST-NetKeeper-1.0.0-macos-x64.dmg", "GZIST-NetKeeper-1.0.0-macos-arm64.dmg", "GZIST-NetKeeper-1.0.0-windows-x64-setup.exe", "GZIST-NetKeeper-1.0.0-windows-arm64-setup.exe", "gzist-netkeeper_1.0.0_amd64.deb", "gzist-netkeeper_1.0.0_arm64.deb", "install.sh"} {
				if mode == "missing-installer" && strings.HasSuffix(name, ".dmg") {
					continue
				}
				os.WriteFile(filepath.Join(dir, name), []byte("installer"), 0600)
			}
			err := validateRelease(dir, "1.0.0")
			if (err == nil) != (mode == "valid") {
				t.Fatalf("mode=%s err=%v", mode, err)
			}
		})
	}
}

func TestStageRejectsIncompleteOrTamperedRelease(t *testing.T) {
	for _, mode := range []string{"missing-manifest", "corrupt-archive", "corrupt-delta", "wrong-key", "traversal"} {
		t.Run(mode, func(t *testing.T) {
			dir, key := fixture(t)
			switch mode {
			case "missing-manifest":
				os.Rename(filepath.Join(dir, "update-windows-arm64.json"), filepath.Join(dir, "missing.json"))
			case "corrupt-archive":
				os.WriteFile(filepath.Join(dir, "app.tar.gz"), []byte("tampered!!!!!!"), 0600)
			case "corrupt-delta":
				os.WriteFile(filepath.Join(dir, "app.delta"), []byte("tampered!!!!"), 0600)
			case "wrong-key":
				p, _, _ := ed25519.GenerateKey(rand.Reader)
				key = base64.StdEncoding.EncodeToString(p)
			case "traversal":
				p := filepath.Join(dir, "update-windows-arm64.json")
				b, _ := os.ReadFile(p)
				b = []byte(strings.ReplaceAll(string(b), "app.tar.gz", "%2E%2E%2Fapp.tar.gz"))
				os.WriteFile(p, b, 0600)
			}
			if err := stage(dir, filepath.Join(t.TempDir(), "out"), "https://mirror.example", key); err == nil {
				t.Fatal("accepted bad release")
			}
		})
	}
}
