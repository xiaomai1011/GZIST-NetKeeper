// releasefeed prepares an explicitly trusted, static HTTPS update source.
// It never downloads, deploys, or changes the application's signature verifier.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var targets = []string{"darwin-amd64", "darwin-arm64", "windows-amd64", "windows-arm64", "linux-amd64", "linux-arm64"}

// Matches the manifest schema of the pinned MyGo v0.3.3 SDK.
type asset struct {
	URL       string `json:"url"`
	Size      int64  `json:"size"`
	Signature string `json:"signature"`
	From      string `json:"from,omitempty"`
	Version   string `json:"version,omitempty"`
}
type manifest struct {
	Version string `json:"version"`
	Notes   string `json:"notes,omitempty"`
	Date    string `json:"date,omitempty"`
	asset
	Deltas   []asset `json:"deltas,omitempty"`
	Previous []asset `json:"previous,omitempty"`
}

func baseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") || strings.Contains(u.Path, "\\") {
		return "", errors.New("base URL must be HTTPS without credentials, query or fragment")
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return "", errors.New("base URL must not contain dot segments")
		}
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func configure(config, raw string) error {
	base, err := baseURL(raw)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(config)
	if err != nil {
		return err
	}
	var c map[string]any
	if err = json.Unmarshal(b, &c); err != nil {
		return err
	}
	u, ok := c["updates"].(map[string]any)
	if !ok || u["publicKey"] == nil {
		return errors.New("missing updates.publicKey")
	}
	delete(u, "github")
	u["url"] = base
	b, err = json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(config, append(b, '\n'), 0644)
}

func assetName(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("invalid asset URL")
	}
	name, err := url.PathUnescape(path.Base(u.EscapedPath()))
	if err != nil || !safeName(name) {
		return "", errors.New("unsafe asset filename")
	}
	return name, nil
}
func safeName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\\r\n\x00")
}
func digest(file string) ([]byte, int64, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return h.Sum(nil), n, err
}
func verify(a asset, dir string, key ed25519.PublicKey) (string, error) {
	name, err := assetName(a.URL)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(filepath.Join(dir, name))
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("asset must be a regular file")
	}
	hash, n, err := digest(filepath.Join(dir, name))
	if err != nil {
		return "", err
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil || n != a.Size || n <= 0 || n > 1<<30 || !ed25519.Verify(key, hash, sig) {
		return "", fmt.Errorf("invalid size or signature: %s", name)
	}
	return name, nil
}

// stage requires a new directory: it cannot silently overwrite a live feed.
// All manifests and current payloads are validated before creating output.
func stage(dir, out, raw, keyText string) error {
	base, err := baseURL(raw)
	if err != nil {
		return err
	}
	key, err := base64.StdEncoding.DecodeString(keyText)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("invalid pinned public key")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	files := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".exe") || strings.HasSuffix(name, ".dmg") || strings.HasSuffix(name, ".deb") || strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".delta") || name == "install.sh" {
			info, err := e.Info()
			if err != nil {
				return err
			}
			if !safeName(name) || !info.Mode().IsRegular() {
				return fmt.Errorf("unsafe asset: %s", name)
			}
			files[name] = true
		}
	}
	manifests := map[string][]byte{}
	version := ""
	for _, target := range targets {
		name := "update-" + target + ".json"
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		var m manifest
		if err = json.Unmarshal(b, &m); err != nil {
			return err
		}
		if m.Version == "" || (version != "" && m.Version != version) {
			return errors.New("missing or inconsistent release versions")
		}
		version = m.Version
		rewrite := func(a *asset) error {
			n, err := verify(*a, dir, key)
			if err != nil {
				return err
			}
			if !files[n] {
				return fmt.Errorf("unsupported payload filename: %s", n)
			}
			a.URL = base + "/" + url.PathEscape(n)
			return nil
		}
		if err := rewrite(&m.asset); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		for i := range m.Deltas {
			if err := rewrite(&m.Deltas[i]); err != nil {
				return err
			}
		}
		// Previous is build-time delta history, not required by installed clients.
		// Retain only archives included locally; never leave hidden GitHub fetches.
		previous := make([]asset, 0, len(m.Previous))
		for _, a := range m.Previous {
			n, err := assetName(a.URL)
			if err != nil {
				return err
			}
			if !files[n] {
				continue
			}
			if err := rewrite(&a); err != nil {
				return err
			}
			previous = append(previous, a)
		}
		m.Previous = previous
		b, err = json.MarshalIndent(m, "", "  ")
		if err != nil {
			return err
		}
		manifests[name] = append(b, '\n')
	}
	if err := os.Mkdir(out, 0755); err != nil {
		return err
	}
	var sums, links strings.Builder
	fmt.Fprintf(&links, "<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>GZIST NetKeeper 下载</title><h1>GZIST NetKeeper %s</h1><p>按系统和架构选择安装包：Windows .exe，macOS .dmg，Linux .deb；amd64/x64 表示 Intel/AMD，arm64 表示 ARM。仅信任维护者公布的下载站。</p><ul>", html.EscapeString(version))
	for _, e := range entries { // os.ReadDir returns sorted names.
		name := e.Name()
		if !files[name] {
			continue
		}
		src, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		dst, err := os.OpenFile(filepath.Join(out, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			src.Close()
			return err
		}
		_, copyErr := io.Copy(dst, src)
		src.Close()
		closeErr := dst.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		h, _, err := digest(filepath.Join(out, name))
		if err != nil {
			return err
		}
		fmt.Fprintf(&sums, "%x  %s\n", h, name)
		fmt.Fprintf(&links, "<li><a href=\"%s\">%s</a></li>\n", html.EscapeString(url.PathEscape(name)), html.EscapeString(name))
	}
	for _, target := range targets {
		name := "update-" + target + ".json"
		b := manifests[name]
		if err := os.WriteFile(filepath.Join(out, name), b, 0644); err != nil {
			return err
		}
		fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256(b), name)
	}
	links.WriteString("</ul><p><a href=\"SHA256SUMS\">SHA256SUMS</a>（仅用于完整性检查；同源哈希不能证明来源可信）</p><p>Linux 离线安装：核验来源和哈希后，将 install.sh 和对应架构的 tar.gz 保存到同一目录，执行 <code>sh install.sh ./对应架构.tar.gz</code>，勿直接执行不可信镜像的在线脚本。</p><a href=\"https://github.com/xiaomai1011/GZIST-NetKeeper/releases/latest\">GitHub 原始发布页</a></html>")
	index := []byte(links.String())
	if err := os.WriteFile(filepath.Join(out, "index.html"), index, 0644); err != nil {
		return err
	}
	fmt.Fprintf(&sums, "%x  index.html\n", sha256.Sum256(index))
	return os.WriteFile(filepath.Join(out, "SHA256SUMS"), []byte(sums.String()), 0644)
}

// validateRelease is the CLI/CI inventory gate; stage additionally verifies
// signed payload bytes. Naming checks catch accidental cross-target/stale files,
// not malicious relabeling (SDK signatures do not bind version or target).
func validateRelease(dir, version string) error {
	if version == "" || !safeName(version) {
		return errors.New("missing or invalid configured release version")
	}
	for _, target := range targets {
		b, err := os.ReadFile(filepath.Join(dir, "update-"+target+".json"))
		if err != nil {
			return err
		}
		var m manifest
		if err := json.Unmarshal(b, &m); err != nil {
			return err
		}
		name, err := assetName(m.URL)
		if err != nil || m.Version != version || !strings.HasSuffix(name, "-"+version+"-"+target+".tar.gz") {
			return fmt.Errorf("wrong version or target in update-%s.json (expected %s)", target, version)
		}
	}
	names := []string{"install.sh"}
	for _, arch := range []string{"x64", "arm64"} {
		names = append(names, "GZIST-NetKeeper-"+version+"-macos-"+arch+".dmg", "GZIST-NetKeeper-"+version+"-windows-"+arch+"-setup.exe")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		names = append(names, "gzist-netkeeper_"+version+"_"+arch+".deb")
	}
	for _, name := range names {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("missing or invalid installer: %s", name)
		}
	}
	return nil
}

func main() {
	mode := flag.String("mode", "stage", "configure or stage")
	base := flag.String("base-url", "", "maintainer-controlled HTTPS base URL (required)")
	config := flag.String("config", "mygo.json", "MyGo configuration with pinned public key")
	assets := flag.String("assets", "release-assets", "flat directory containing all six manifests and release assets")
	out := flag.String("out", "release-feed", "new staging directory")
	flag.Parse()
	var err error
	switch *mode {
	case "configure":
		err = configure(*config, *base)
	case "stage":
		var c struct {
			Version string `json:"version"`
			Updates struct {
				PublicKey string `json:"publicKey"`
			} `json:"updates"`
		}
		var b []byte
		b, err = os.ReadFile(*config)
		if err == nil {
			err = json.Unmarshal(b, &c)
		}
		if err == nil {
			err = validateRelease(*assets, c.Version)
		}
		if err == nil {
			err = stage(*assets, *out, *base, c.Updates.PublicKey)
		}
	default:
		err = errors.New("mode must be configure or stage")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
