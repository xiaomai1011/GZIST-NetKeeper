// feedcheck performs read-only checks of a public HTTPS release feed.
// It never publishes, reads credentials, or permits a missing-feed bootstrap.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	manifestLimit  = 1 << 20
	totalTimeout   = 10 * time.Minute
	requestTimeout = 2 * time.Minute
)

type options struct {
	baseURL, dir, mode, version string
	payloadsOnly                bool
}

// Decimal strings avoid integer overflow while comparing strict SemVer cores.
type stableVersion [3]string

func parseVersion(raw string) (stableVersion, error) {
	var version stableVersion
	parts := strings.Split(raw, ".")
	if len(parts) != len(version) {
		return version, errors.New("version must be stable X.Y.Z")
	}
	for i, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return version, errors.New("version must be stable X.Y.Z without leading zeros")
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return version, errors.New("version must be stable X.Y.Z")
			}
		}
		version[i] = part
	}
	return version, nil
}

func compareVersions(a, b stableVersion) int {
	for i := range a {
		if len(a[i]) < len(b[i]) {
			return -1
		}
		if len(a[i]) > len(b[i]) {
			return 1
		}
		if c := strings.Compare(a[i], b[i]); c != 0 {
			return c
		}
	}
	return 0
}

func parseBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") {
		return nil, errors.New("base URL must be HTTPS without credentials, query or fragment")
	}
	// Limit prefixes to unambiguous path segments: reject encoded delimiters,
	// nested escapes, dot paths, controls and backslashes, including after decoding.
	for _, part := range strings.Split(u.Path, "/") {
		if part != "" && !safeName(part) {
			return nil, errors.New("base URL contains an unsafe path segment")
		}
	}
	escaped := strings.ToLower(u.EscapedPath())
	if strings.Contains(escaped, "%2f") || strings.Contains(escaped, "%5c") {
		return nil, errors.New("base URL contains an encoded path separator")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/"
	u.RawPath = ""
	return u, nil
}

// Deliberately conservative, portable names; no hidden files or URL syntax.
func safeName(name string) bool {
	if name == "" || name[0] == '.' || strings.Contains(name, "..") {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == '+') {
			return false
		}
	}
	return true
}

func newHTTPClient(transport http.RoundTripper) *http.Client {
	if transport == nil {
		// No ProxyFromEnvironment, cookie jar, ambient authentication, or transparent
		// decompression. An injected transport is only an internal TLS-test seam.
		transport = &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       30 * time.Second,
			DisableCompression:    true,
		}
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// fetch exposes only public filenames and numeric status codes in errors, never
// a server body or the underlying transport error (which may include a URL).
func fetch(ctx context.Context, client *http.Client, base *url.URL, name string) (io.ReadCloser, error) {
	u := *base
	u.Path += name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%s: cannot create request", displayName(name))
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: HTTPS request failed", displayName(name))
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("%s: HTTP status %d", displayName(name), response.StatusCode)
	}
	if encoding := response.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		response.Body.Close()
		return nil, fmt.Errorf("%s: unexpected content encoding", displayName(name))
	}
	return response.Body, nil
}

func displayName(name string) string {
	if name == "" {
		return "/"
	}
	return name
}

func isPayload(name string) bool {
	for _, suffix := range []string{".exe", ".dmg", ".deb", ".tar.gz", ".delta"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

type stagedFile struct {
	name string
	info os.FileInfo
}

func localDigest(root *os.Root, file stagedFile) ([]byte, int64, error) {
	f, err := root.Open(file.name)
	if err != nil {
		return nil, 0, fmt.Errorf("%s: cannot open staged file", file.name)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, file.info) || info.Size() != file.info.Size() {
		return nil, 0, fmt.Errorf("%s: staged file changed", file.name)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, info.Size()+1))
	if err != nil || n != info.Size() {
		return nil, 0, fmt.Errorf("%s: cannot hash stable staged file", file.name)
	}
	return h.Sum(nil), n, nil
}

func verifyFile(ctx context.Context, client *http.Client, base *url.URL, name string, hash []byte, size int64) error {
	body, err := fetch(ctx, client, base, name)
	if err != nil {
		return err
	}
	defer body.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(body, size+1))
	if err != nil {
		return fmt.Errorf("%s: download failed", displayName(name))
	}
	if n != size || !bytes.Equal(h.Sum(nil), hash) {
		return fmt.Errorf("%s: length or SHA256 mismatch", displayName(name))
	}
	return nil
}

func verify(ctx context.Context, client *http.Client, base *url.URL, dir string, payloadsOnly bool) error {
	// A trailing slash otherwise makes Lstat follow a directory symlink.
	dir = filepath.Clean(dir)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("staging directory must be a real directory, not a symlink")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return errors.New("cannot open staging directory")
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return errors.New("cannot read staging directory")
	}
	entries, err := directory.ReadDir(-1)
	directory.Close()
	if err != nil {
		return errors.New("cannot read staging directory")
	}
	var files []stagedFile
	hasIndex := false
	// Validate ALL entries before any request, even ignored control files.
	for _, entry := range entries {
		name := entry.Name()
		if !safeName(name) {
			return errors.New("unsafe staged filename")
		}
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() == math.MaxInt64 {
			return fmt.Errorf("%s: staged entry must be a regular file", name)
		}
		if name == "index.html" {
			hasIndex = true
		}
		if !payloadsOnly || isPayload(name) {
			files = append(files, stagedFile{name: name, info: info})
		}
	}
	if payloadsOnly && len(files) == 0 {
		return errors.New("no staged payload files")
	}
	if !payloadsOnly && !hasIndex {
		return errors.New("full verification requires index.html")
	}
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return errors.New("verification canceled or timed out")
		}
		hash, size, err := localDigest(root, file)
		if err != nil {
			return err
		}
		if err := verifyFile(ctx, client, base, file.name, hash, size); err != nil {
			return err
		}
		if !payloadsOnly && file.name == "index.html" {
			if err := verifyFile(ctx, client, base, "", hash, size); err != nil {
				return err
			}
		}
	}
	return nil
}

// Only the version matters to the gate, but malformed JSON and ambiguous
// duplicate fields must not be accepted. Unknown manifest fields are allowed.
func manifestVersion(data []byte) (stableVersion, error) {
	invalid := errors.New("invalid current manifest or stable version")
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return stableVersion{}, invalid
	}
	seen := make(map[string]bool)
	var version string
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return stableVersion{}, invalid
		}
		key, ok := token.(string)
		// Go struct decoders accept case-insensitive aliases. Reject them so
		// this gate cannot disagree with an updater about the current version.
		if !ok || seen[key] || (strings.EqualFold(key, "version") && key != "version") {
			return stableVersion{}, invalid
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return stableVersion{}, invalid
		}
		if key == "version" {
			if err := json.Unmarshal(value, &version); err != nil {
				return stableVersion{}, invalid
			}
		}
	}
	if _, err := decoder.Token(); err != nil {
		return stableVersion{}, invalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return stableVersion{}, invalid
	}
	result, err := parseVersion(version)
	if err != nil {
		return stableVersion{}, invalid
	}
	return result, nil
}

func upgrade(ctx context.Context, client *http.Client, base *url.URL, candidate stableVersion) error {
	for _, target := range []string{"darwin-amd64", "darwin-arm64", "windows-amd64", "windows-arm64", "linux-amd64", "linux-arm64"} {
		name := "update-" + target + ".json"
		body, err := fetch(ctx, client, base, name)
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(body, manifestLimit+1))
		body.Close()
		if err != nil || len(data) > manifestLimit {
			return fmt.Errorf("%s: current manifest unreadable or exceeds 1 MiB", name)
		}
		current, err := manifestVersion(data)
		if err != nil {
			return fmt.Errorf("%s: invalid current manifest or stable version", name)
		}
		if compareVersions(candidate, current) <= 0 {
			return fmt.Errorf("%s: candidate must be strictly newer than current version; partial publication requires manual recovery from the exact artifact", name)
		}
	}
	return nil
}

func check(ctx context.Context, opts options, transport http.RoundTripper) error {
	base, err := parseBaseURL(opts.baseURL)
	if err != nil {
		return err
	}
	if opts.mode != "verify" && opts.mode != "upgrade" {
		return errors.New("mode must be verify or upgrade")
	}
	if opts.mode == "upgrade" && opts.payloadsOnly {
		return errors.New("payloads-only is valid only in verify mode")
	}
	var candidate stableVersion
	if opts.mode == "upgrade" {
		candidate, err = parseVersion(opts.version)
		if err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, totalTimeout)
	defer cancel()
	client := newHTTPClient(transport)
	defer client.CloseIdleConnections()
	if opts.mode == "upgrade" {
		return upgrade(ctx, client, base, candidate)
	}
	return verify(ctx, client, base, opts.dir, opts.payloadsOnly)
}

func run(args []string, output io.Writer) error {
	var opts options
	flags := flag.NewFlagSet("feedcheck", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&opts.baseURL, "base-url", "", "public HTTPS feed base URL (required)")
	flags.StringVar(&opts.dir, "dir", "release-feed", "local staged feed directory")
	flags.BoolVar(&opts.payloadsOnly, "payloads-only", false, "verify only payloads, without control files or root")
	flags.StringVar(&opts.mode, "mode", "verify", "verify or upgrade")
	flags.StringVar(&opts.version, "version", "", "candidate stable X.Y.Z (required for upgrade)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if err := check(context.Background(), opts, nil); err != nil {
		return err
	}
	fmt.Fprintf(output, "feedcheck: %s passed\n", opts.mode)
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "feedcheck:", err)
		os.Exit(1)
	}
}
