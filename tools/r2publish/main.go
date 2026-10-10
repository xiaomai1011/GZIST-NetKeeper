// r2publish uploads a complete releasefeed staging directory to an existing R2
// bucket. It never creates buckets, deletes objects, or follows redirects.
package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

var targets = []string{"darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64", "windows-amd64", "windows-arm64"}
var accountPattern = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
var bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

// The endpoint and client fields are internal test seams, not CLI/env options.
type publisher struct {
	endpoint, bucket, accessKey, secretKey string
	client                                 *http.Client
	now                                    func() time.Time
}
type object struct {
	name, path, hash string
	size             int64
	immutable        bool
}

func fromEnv(getenv func(string) string) (*publisher, error) {
	values := make([]string, 4)
	for i, name := range []string{"R2_ACCOUNT_ID", "R2_BUCKET", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY"} {
		values[i] = getenv(name)
		if strings.TrimSpace(values[i]) == "" {
			return nil, fmt.Errorf("missing %s", name)
		}
	}
	if !accountPattern.MatchString(values[0]) {
		return nil, errors.New("invalid R2_ACCOUNT_ID")
	}
	// R2 bucket names are one DNS label (dots and IP addresses are not allowed).
	if !bucketPattern.MatchString(values[1]) {
		return nil, errors.New("invalid R2_BUCKET")
	}
	for _, value := range values[2:] {
		if strings.ContainsAny(value, "\r\n\t ") {
			return nil, errors.New("invalid R2 credentials")
		}
	}
	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout: 30 * time.Second, MaxIdleConns: 2,
	}
	return &publisher{endpoint: "https://" + strings.ToLower(values[0]) + ".r2.cloudflarestorage.com", bucket: values[1], accessKey: values[2], secretKey: values[3], client: &http.Client{Transport: transport, Timeout: 5 * time.Minute, CheckRedirect: noRedirect}, now: time.Now}, nil
}
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
func safeName(name string) bool {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
		return false
	}
	for _, r := range name {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func payload(name string) bool {
	for _, suffix := range []string{".exe", ".dmg", ".deb", ".tar.gz", ".delta"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// openRegular checks both the directory entry and opened descriptor, so a
// symlink replacement cannot silently substitute another preflighted file.
func openRegular(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, errors.New("staged entry is not a readable regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open staged file")
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		f.Close()
		return nil, errors.New("staged file changed while opening")
	}
	return f, nil
}
func fileDigest(f *os.File) (string, int64, error) {
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", 0, errors.New("cannot hash staged file")
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

func preflight(dir string) ([]object, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return nil, errors.New("staging directory must be a non-symlink directory")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, errors.New("cannot read staging directory")
	}
	controls := map[string]bool{"install.sh": true, "SHA256SUMS": true, "index.html": true}
	for _, target := range targets {
		controls["update-"+target+".json"] = true
	}
	objects := map[string]object{}
	for _, entry := range entries {
		name := entry.Name()
		if !safeName(name) || (!controls[name] && !payload(name)) {
			return nil, errors.New("unexpected staged entry")
		}
		path := filepath.Join(dir, name)
		f, err := openRegular(path)
		if err != nil {
			return nil, err
		}
		hash, size, err := fileDigest(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		objects[name] = object{name: name, path: path, hash: hash, size: size, immutable: !controls[name]}
	}
	for name := range controls {
		if _, ok := objects[name]; !ok {
			return nil, errors.New("missing required staged control file")
		}
	}
	sums, err := openRegular(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return nil, err
	}
	defer sums.Close()
	seen := map[string]bool{}
	scanner := bufio.NewScanner(sums)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 67 || line[64:66] != "  " {
			return nil, errors.New("invalid SHA256SUMS record")
		}
		hash, name := line[:64], line[66:]
		decoded, err := hex.DecodeString(hash)
		if err != nil || len(decoded) != 32 || !safeName(name) || name == "SHA256SUMS" || seen[name] {
			return nil, errors.New("invalid SHA256SUMS record")
		}
		obj, ok := objects[name]
		if !ok || obj.hash != strings.ToLower(hash) {
			return nil, errors.New("staged checksum mismatch")
		}
		seen[name] = true
	}
	if scanner.Err() != nil || len(seen) != len(objects)-1 {
		return nil, errors.New("SHA256SUMS must cover every staged file except itself")
	}
	var names []string
	for name, obj := range objects {
		if obj.immutable {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, errors.New("missing staged payloads")
	}
	sort.Strings(names)
	names = append(names, "install.sh")
	for _, target := range targets {
		names = append(names, "update-"+target+".json")
	}
	names = append(names, "SHA256SUMS", "index.html")
	result := make([]object, 0, len(names))
	for _, name := range names {
		result = append(result, objects[name])
	}
	return result, nil
}

func contentType(name string) string {
	switch {
	case strings.HasSuffix(name, ".json"):
		return "application/json"
	case name == "index.html":
		return "text/html; charset=utf-8"
	case name == "install.sh":
		return "text/x-shellscript; charset=utf-8"
	case name == "SHA256SUMS":
		return "text/plain; charset=utf-8"
	case strings.HasSuffix(name, ".tar.gz"):
		return "application/gzip"
	default:
		return "application/octet-stream"
	}
}
func (p *publisher) publish(ctx context.Context, dir string) error {
	return p.publishSelection(ctx, dir, false)
}

// payloadsOnly allows public CDN verification before exposing mutable manifests.
// A subsequent full publication rechecks immutable objects before the controls.
func (p *publisher) publishSelection(ctx context.Context, dir string, payloadsOnly bool) error {
	objects, err := preflight(dir)
	if err != nil {
		return err
	}
	for _, obj := range objects {
		if payloadsOnly && !obj.immutable {
			continue
		}
		if err := ctx.Err(); err != nil {
			return errors.New("publication canceled")
		}
		if obj.immutable {
			exists, err := p.head(ctx, obj)
			if err != nil {
				return err
			}
			if exists {
				continue
			}
		}
		f, err := openRegular(obj.path)
		if err != nil {
			return err
		}
		hash, size, err := fileDigest(f)
		if err != nil || hash != obj.hash || size != obj.size {
			f.Close()
			return errors.New("staged file changed after preflight")
		}
		if _, err = f.Seek(0, io.SeekStart); err != nil {
			f.Close()
			return errors.New("cannot rewind staged file")
		}
		response, err := p.request(ctx, "PUT", obj, f)
		f.Close()
		if err != nil {
			return err
		}
		status := response.StatusCode
		response.Body.Close()
		if status < 200 || status >= 300 {
			return fmt.Errorf("PUT failed: HTTP %d", status)
		}
		exists, err := p.head(ctx, obj)
		if err != nil {
			return err
		}
		if !exists {
			return errors.New("uploaded object missing on read-back")
		}
	}
	return nil
}
func (p *publisher) head(ctx context.Context, obj object) (bool, error) {
	response, err := p.request(ctx, "HEAD", obj, nil)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode == 404 {
		return false, nil
	}
	if response.StatusCode != 200 {
		return false, fmt.Errorf("HEAD failed: HTTP %d", response.StatusCode)
	}
	if response.ContentLength != obj.size || response.Header.Get("x-amz-meta-sha256") != obj.hash {
		return false, errors.New("remote object size or sha256 mismatch; refusing publication")
	}
	return true, nil
}
func (p *publisher) request(ctx context.Context, method string, obj object, body io.Reader) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, method, p.endpoint+"/"+p.bucket+"/"+uriEncode(obj.name), body)
	if err != nil {
		return nil, errors.New("cannot construct object request")
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(nil))
	if method == "PUT" {
		hash = obj.hash
		request.ContentLength = obj.size
		request.Header.Set("x-amz-meta-sha256", hash)
		request.Header.Set("Content-Type", contentType(obj.name))
		cache := "no-cache, max-age=0, must-revalidate, no-transform"
		if obj.immutable {
			cache = "public, max-age=31536000, immutable, no-transform"
			request.Header.Set("If-None-Match", "*")
		}
		request.Header.Set("Cache-Control", cache)
	}
	sign(request, hash, p.accessKey, p.secretKey, p.now())
	client := *p.client
	client.CheckRedirect = noRedirect
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("object request failed (transport or timeout)")
	}
	return response, nil
}

// AWS URI encoding differs from form encoding (spaces are %20, never '+').
func uriEncode(s string) string {
	const digits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_.~/", rune(c)) {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(digits[c>>4])
			b.WriteByte(digits[c&15])
		}
	}
	return b.String()
}
func sign(r *http.Request, hash, access, secret string, now time.Time) {
	stamp := now.UTC().Format("20060102T150405Z")
	date := stamp[:8]
	r.Header.Set("x-amz-date", stamp)
	r.Header.Set("x-amz-content-sha256", hash)
	headers := map[string]string{"host": r.URL.Host}
	for key, values := range r.Header {
		if !strings.EqualFold(key, "Authorization") {
			headers[strings.ToLower(key)] = strings.Join(strings.Fields(strings.Join(values, ",")), " ")
		}
	}
	names := make([]string, 0, len(headers))
	for key := range headers {
		names = append(names, key)
	}
	sort.Strings(names)
	var canonical strings.Builder
	for _, name := range names {
		canonical.WriteString(name + ":" + headers[name] + "\n")
	}
	signed := strings.Join(names, ";")
	canonicalRequest := r.Method + "\n" + uriEncode(r.URL.Path) + "\n" + r.URL.RawQuery + "\n" + canonical.String() + "\n" + signed + "\n" + hash
	scope := date + "/auto/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + fmt.Sprintf("%x", sha256.Sum256([]byte(canonicalRequest)))
	key := []byte("AWS4" + secret)
	for _, part := range []string{date, "auto", "s3", "aws4_request"} {
		key = mac(key, part)
	}
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+access+"/"+scope+", SignedHeaders="+signed+", Signature="+hex.EncodeToString(mac(key, toSign)))
}
func mac(key []byte, text string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(text))
	return h.Sum(nil)
}

func main() {
	dir := flag.String("dir", "release-feed", "staged releasefeed directory")
	payloadsOnly := flag.Bool("payloads-only", false, "upload immutable payloads without changing live controls")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "r2publish: unexpected positional arguments")
		os.Exit(1)
	}
	p, err := fromEnv(os.Getenv)
	if err == nil {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer cancel()
		ctx, timeout := context.WithTimeout(ctx, 30*time.Minute)
		defer timeout()
		err = p.publishSelection(ctx, *dir, *payloadsOnly)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "r2publish:", err)
		os.Exit(1)
	}
	if *payloadsOnly {
		fmt.Println("Immutable payloads uploaded and HEAD-verified; live controls unchanged.")
	} else {
		fmt.Println("Release feed uploaded and HEAD-verified; public byte verification is separate.")
	}
}
