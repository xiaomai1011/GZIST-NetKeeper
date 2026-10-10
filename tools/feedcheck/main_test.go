package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestStableVersions(t *testing.T) {
	for _, value := range []string{"0.0.0", "1.2.3", "999999999999999999999999.0.0"} {
		if _, err := parseVersion(value); err != nil {
			t.Errorf("valid %q: %v", value, err)
		}
	}
	for _, value := range []string{"", "v1.2.3", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.03", "1.2.3-beta", "1.2.3+build", " 1.2.3", "1.2.3\n", "-1.2.3", "1.２.3"} {
		if _, err := parseVersion(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0}, {"1.2.10", "1.2.9", 1}, {"2.0.0", "1.99.99", 1}, {"1.3.0", "1.2.999", 1}, {"0.9.9", "1.0.0", -1}, {"999999999999999999999999.0.0", "999999999999999999999998.9.9", 1},
	} {
		a, _ := parseVersion(tc.a)
		b, _ := parseVersion(tc.b)
		if got := compareVersions(a, b); got != tc.want {
			t.Errorf("compare %s %s = %d", tc.a, tc.b, got)
		}
	}
}

func TestBaseURLValidation(t *testing.T) {
	for _, raw := range []string{"", "http://example.com", "https://user:secret@example.com", "https://example.com?q=x", "https://example.com?", "https://example.com#", "https://example.com#x", "https://example.com/a/../b", "https://example.com/./b", "https://example.com/%2e%2e/b", "https://example.com/a%2f..%2fb", "https://example.com/a%5cb", "https://example.com/%252e%252e/b", "https://example.com/%00", "https:///missing"} {
		if _, err := parseBaseURL(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	for _, raw := range []string{"https://example.com", "https://example.com/feed/v1/", "https://example.com:8443/feed"} {
		if _, err := parseBaseURL(raw); err != nil {
			t.Errorf("rejected %q: %v", raw, err)
		}
	}
}

func stageFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func tlsCheck(t *testing.T, opts options, handler http.HandlerFunc) error {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	opts.baseURL = server.URL + "/releases/v1"
	return check(context.Background(), opts, server.Client().Transport)
}

func TestVerifyFullAndPayloadOnly(t *testing.T) {
	files := map[string]string{"index.html": "index", "install.sh": "installer", "SHA256SUMS": "hashes", "update-linux-amd64.json": "manifest", "app.exe": "windows", "app.dmg": "mac", "app.deb": "deb", "app.tar.gz": "archive", "app.delta": "delta"}
	dir := stageFiles(t, files)
	for _, only := range []bool{false, true} {
		t.Run(fmt.Sprint(only), func(t *testing.T) {
			var paths []string
			err := tlsCheck(t, options{mode: "verify", dir: dir, payloadsOnly: only}, func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("credential sent")
				}
				if r.Header.Get("Accept-Encoding") != "identity" {
					t.Error("must request exact uncompressed bytes")
				}
				name := strings.TrimPrefix(r.URL.Path, "/releases/v1/")
				if name == "" {
					name = "index.html"
				}
				data, ok := files[name]
				if !ok {
					http.NotFound(w, r)
					return
				}
				io.WriteString(w, data)
			})
			if err != nil {
				t.Fatal(err)
			}
			var want []string
			for name := range files {
				if !only || strings.HasSuffix(name, ".exe") || strings.HasSuffix(name, ".dmg") || strings.HasSuffix(name, ".deb") || strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".delta") {
					want = append(want, "/releases/v1/"+name)
				}
			}
			if !only {
				want = append(want, "/releases/v1/")
			}
			sort.Strings(paths)
			sort.Strings(want)
			if !reflect.DeepEqual(paths, want) {
				t.Fatalf("paths %v want %v", paths, want)
			}
		})
	}
}

func TestVerifyRejectsMismatchStatusAndRedirect(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"hash", "abd", 200}, {"short", "ab", 200}, {"long", "abcd", 200}, {"missing", "SERVER-SECRET", 404}, {"redirect", "SERVER-SECRET", 302},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := tlsCheck(t, options{mode: "verify", dir: stageFiles(t, map[string]string{"app.exe": "abc"}), payloadsOnly: true}, func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Location", "/elsewhere")
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			if err == nil {
				t.Fatal("expected failure")
			}
			if calls != 1 {
				t.Errorf("redirect followed: %d", calls)
			}
			if strings.Contains(err.Error(), "SERVER-SECRET") {
				t.Fatal("server body exposed")
			}
		})
	}
}

func TestVerifyRequiresIndexOrPayload(t *testing.T) {
	for _, tc := range []struct {
		files map[string]string
		only  bool
	}{{map[string]string{}, false}, {map[string]string{"app.exe": "x"}, false}, {map[string]string{"index.html": "x"}, true}} {
		err := tlsCheck(t, options{mode: "verify", dir: stageFiles(t, tc.files), payloadsOnly: tc.only}, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid staging must fail before network") })
		if err == nil {
			t.Fatal("accepted incomplete staging")
		}
	}
}

func TestVerifyRejectsUnsafeStaging(t *testing.T) {
	for _, kind := range []string{"symlink", "directory", "unsafe", "root-symlink", "root-symlink-slash"} {
		t.Run(kind, func(t *testing.T) {
			dir := stageFiles(t, map[string]string{"app.exe": "x"})
			switch kind {
			case "symlink":
				if err := os.Symlink(filepath.Join(dir, "app.exe"), filepath.Join(dir, "link.txt")); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(filepath.Join(dir, "nested"), 0700); err != nil {
					t.Fatal(err)
				}
			case "unsafe":
				if err := os.WriteFile(filepath.Join(dir, "bad?name.exe"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			case "root-symlink", "root-symlink-slash":
				link := filepath.Join(t.TempDir(), "feed")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				dir = link
				if kind == "root-symlink-slash" {
					dir += "/"
				}
			}
			err := tlsCheck(t, options{mode: "verify", dir: dir, payloadsOnly: true}, func(w http.ResponseWriter, r *http.Request) { t.Error("unsafe staging reached network") })
			if err == nil {
				t.Fatal("unsafe staging accepted")
			}
		})
	}
}

var expectedTargets = []string{"darwin-amd64", "darwin-arm64", "windows-amd64", "windows-arm64", "linux-amd64", "linux-arm64"}

func TestUpgradeChecksAllSix(t *testing.T) {
	var paths []string
	err := tlsCheck(t, options{mode: "upgrade", version: "2.0.0"}, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		io.WriteString(w, `{"version":"1.9.9","notes":"allowed","url":"https://example.com/file"}`)
	})
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, target := range expectedTargets {
		want = append(want, "/releases/v1/update-"+target+".json")
	}
	sort.Strings(paths)
	sort.Strings(want)
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("got %v want %v", paths, want)
	}
}

func TestUpgradeFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"equal", `{"version":"2.0.0"}`, 200}, {"older", `{"version":"2.0.1"}`, 200}, {"missing", "SERVER-SECRET", 404}, {"malformed", `{"version":`, 200}, {"empty", `{}`, 200}, {"null", `null`, 200}, {"numeric", `{"version":123}`, 200}, {"leading-zero", `{"version":"01.0.0"}`, 200}, {"prerelease", `{"version":"1.0.0-beta"}`, 200}, {"trailing", `{"version":"1.0.0"} {}`, 200}, {"duplicate", `{"version":"9.0.0","version":"1.0.0"}`, 200}, {"case-alias", `{"version":"1.0.0","Version":"9.0.0"}`, 200}, {"oversize", `{"version":"1.0.0","notes":"` + strings.Repeat("x", 1<<20) + `"}`, 200}, {"redirect", ``, 302},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := tlsCheck(t, options{mode: "upgrade", version: "2.0.0"}, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if calls == 1 {
					io.WriteString(w, `{"version":"1.0.0"}`)
					return
				}
				w.Header().Set("Location", "/other")
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			if err == nil {
				t.Fatal("unsafe upgrade accepted")
			}
			if strings.Contains(err.Error(), "SERVER-SECRET") {
				t.Fatal("server body leaked")
			}
		})
	}
	for _, version := range []string{"", "v2.0.0", "2.0.0-rc.1", "2.0.0+build", "02.0.0"} {
		err := tlsCheck(t, options{mode: "upgrade", version: version}, func(w http.ResponseWriter, r *http.Request) { t.Error("invalid candidate reached network") })
		if err == nil {
			t.Errorf("invalid candidate accepted: %q", version)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type countingBody struct{ read int64 }

func (b *countingBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	b.read += int64(len(p))
	return len(p), nil
}
func (b *countingBody) Close() error { return nil }

func TestDownloadBoundsAndNetworkErrors(t *testing.T) {
	for _, mode := range []string{"verify", "upgrade"} {
		body := &countingBody{}
		opts := options{baseURL: "https://example.com", mode: mode, version: "2.0.0", dir: stageFiles(t, map[string]string{"app.exe": "abc"}), payloadsOnly: mode == "verify"}
		err := check(context.Background(), opts, roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: body, Header: make(http.Header)}, nil
		}))
		if err == nil {
			t.Fatal("oversize accepted")
		}
		limit := int64(4)
		if mode == "upgrade" {
			limit = (1 << 20) + 1
		}
		if body.read != limit {
			t.Errorf("read %d bytes want %d", body.read, limit)
		}
		err = check(context.Background(), opts, roundTripFunc(func(r *http.Request) (*http.Response, error) { return nil, fmt.Errorf("NETWORK-SECRET") }))
		if err == nil || strings.Contains(err.Error(), "NETWORK-SECRET") {
			t.Fatalf("unsafe network failure: %v", err)
		}
	}
}

func TestTimeoutAndClientPolicy(t *testing.T) {
	client := newHTTPClient(nil)
	if client.Timeout <= 0 || client.Timeout > 10*time.Minute {
		t.Fatal("missing bounded request timeout")
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr.Proxy != nil || !tr.DisableCompression || client.Jar != nil {
		t.Fatal("environment proxy, cookie or compression enabled")
	}
	if client.CheckRedirect == nil || client.CheckRedirect(&http.Request{}, nil) == nil {
		t.Fatal("redirects enabled")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := check(ctx, options{baseURL: "https://example.com", mode: "upgrade", version: "2.0.0"}, roundTripFunc(func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() }))
	if err == nil {
		t.Fatal("canceled context accepted")
	}
}

func TestCLIValidation(t *testing.T) {
	for _, args := range [][]string{{}, {"-base-url", "http://example.com"}, {"-base-url", "https://example.com", "-mode", "other"}, {"-base-url", "https://example.com", "-mode", "upgrade"}, {"-base-url", "https://example.com", "extra"}, {"-base-url", "https://example.com", "-mode", "upgrade", "-version", "2.0.0", "-payloads-only"}} {
		var output bytes.Buffer
		if err := run(args, &output); err == nil {
			t.Fatalf("accepted args %v", args)
		}
	}
}

func TestVerifyRootMustMatchIndex(t *testing.T) {
	err := tlsCheck(t, options{mode: "verify", dir: stageFiles(t, map[string]string{"index.html": "abc"})}, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			io.WriteString(w, "bad")
		} else {
			io.WriteString(w, "abc")
		}
	})
	if err == nil {
		t.Fatal("root mismatch accepted")
	}
}

func TestVerifyPayloadOnlyNeedsNoIndex(t *testing.T) {
	err := tlsCheck(t, options{mode: "verify", dir: stageFiles(t, map[string]string{"app.exe": "abc"}), payloadsOnly: true}, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "app.exe") {
			t.Errorf("unexpected control request %s", r.URL.Path)
		}
		io.WriteString(w, "abc")
	})
	if err != nil {
		t.Fatal(err)
	}
}
