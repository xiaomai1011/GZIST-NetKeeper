package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

var testTargets = []string{"darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64", "windows-amd64", "windows-arm64"}

func fixture(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	dir := t.TempDir()
	files := map[string][]byte{"app-1.0.0-linux-amd64.tar.gz": []byte("payload"), "installer-1.0.0.exe": []byte("installer"), "install.sh": []byte("#!/bin/sh\n"), "index.html": []byte("<h1>Release</h1>")}
	for _, target := range testTargets {
		files["update-"+target+".json"] = []byte(`{"version":"1.0.0"}`)
	}
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var sums strings.Builder
	for _, name := range names {
		fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256(files[name]), name)
	}
	files["SHA256SUMS"] = []byte(sums.String())
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, files
}

func TestPreflightRejectsBeforeNetwork(t *testing.T) {
	for _, mode := range []string{"tamper", "index-tamper", "symlink", "directory", "unexpected", "extra-manifest", "missing-manifest", "missing-index", "unlisted", "traversal", "duplicate", "self-checksum", "missing-index-hash"} {
		t.Run(mode, func(t *testing.T) {
			dir, files := fixture(t)
			name := "app-1.0.0-linux-amd64.tar.gz"
			write := func(name string, body []byte) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, name), body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			remove := func(name string) {
				t.Helper()
				if err := os.Remove(filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "tamper":
				write(name, []byte("tampered"))
			case "index-tamper":
				write("index.html", []byte("tampered"))
			case "symlink":
				remove(name)
				if err := os.Symlink(filepath.Join(dir, "install.sh"), filepath.Join(dir, name)); err != nil {
					// Windows requires Developer Mode or SeCreateSymbolicLinkPrivilege.
					// Skip only that environmental failure, not arbitrary I/O errors.
					if runtime.GOOS == "windows" && errors.Is(err, syscall.Errno(1314)) {
						t.Skipf("os.Symlink requires Windows privilege: %v", err)
					}
					t.Fatal(err)
				}
			case "directory":
				remove(name)
				if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
					t.Fatal(err)
				}
			case "unexpected":
				write("secret.txt", []byte("do not upload"))
			case "extra-manifest":
				write("update-freebsd-amd64.json", []byte("{}"))
			case "missing-manifest":
				remove("update-linux-arm64.json")
			case "missing-index":
				remove("index.html")
			case "unlisted":
				write("extra-1.0.0.exe", []byte("unlisted"))
			case "traversal":
				write("SHA256SUMS", []byte(strings.ReplaceAll(string(files["SHA256SUMS"]), name, "../"+name)))
			case "duplicate":
				write("SHA256SUMS", append(files["SHA256SUMS"], []byte(fmt.Sprintf("%x  %s\n", sha256.Sum256(files[name]), name))...))
			case "self-checksum":
				write("SHA256SUMS", append(files["SHA256SUMS"], []byte(fmt.Sprintf("%x  SHA256SUMS\n", sha256.Sum256(files["SHA256SUMS"])))...))
			case "missing-index-hash":
				write("SHA256SUMS", []byte(strings.ReplaceAll(string(files["SHA256SUMS"]), fmt.Sprintf("%x  index.html\n", sha256.Sum256(files["index.html"])), "")))
			}
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
			defer server.Close()
			if err := testPublisher(server).publish(context.Background(), dir); err == nil {
				t.Fatal("accepted invalid staged feed")
			}
			if calls != 0 {
				t.Fatalf("network before complete preflight: %d", calls)
			}
		})
	}
}

func TestSigningRepeatable(t *testing.T) {
	r, err := http.NewRequest("GET", "https://example.r2.cloudflarestorage.com/releases/test%20file.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(nil))
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	sign(r, hash, "test-access", "test-secret", now)
	first := r.Header.Get("Authorization")
	// Fixed vector independently calculated with Python hashlib/hmac from the
	// documented SigV4 canonical request and auto/s3 scope (dummy credentials).
	want := "AWS4-HMAC-SHA256 Credential=test-access/20260102/auto/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=1decce94376398584253ed5403a05ecc638297f0dcb73e5a1c4b998d829c7767"
	if first != want {
		t.Fatalf("signature differs from fixed vector: %s", first)
	}
	sign(r, hash, "test-access", "test-secret", now)
	if r.Header.Get("Authorization") != first {
		t.Fatal("signature changes on identical repeated signing")
	}
}

func TestRemoteFailuresStopPublication(t *testing.T) {
	for _, mode := range []string{"overwrite-size", "overwrite-hash", "head-status", "put-status", "readback-size", "readback-hash", "readback-missing", "install-failure"} {
		t.Run(mode, func(t *testing.T) {
			dir, files := fixture(t)
			stored := map[string][]byte{}
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				name := strings.TrimPrefix(r.URL.Path, "/releases/")
				if strings.HasPrefix(name, "update-") || name == "SHA256SUMS" || name == "index.html" {
					t.Errorf("published controls after failure: %s", name)
				}
				if r.Method == "HEAD" {
					if mode == "head-status" {
						w.Header().Set("X-Private", "test-secret")
						w.WriteHeader(403)
						return
					}
					body, ok := stored[name]
					if strings.HasPrefix(mode, "overwrite-") {
						body, ok = files[name], true
					}
					if !ok || mode == "readback-missing" {
						w.WriteHeader(404)
						return
					}
					size := len(body)
					hash := fmt.Sprintf("%x", sha256.Sum256(body))
					if mode == "overwrite-size" || mode == "readback-size" {
						size++
					}
					if mode == "overwrite-hash" || mode == "readback-hash" {
						hash = "different"
					}
					w.Header().Set("Content-Length", fmt.Sprint(size))
					w.Header().Set("x-amz-meta-sha256", hash)
					return
				}
				if strings.HasPrefix(mode, "overwrite-") {
					t.Error("overwrote mismatching immutable object")
				}
				if mode == "put-status" || mode == "install-failure" && name == "install.sh" {
					w.WriteHeader(503)
					fmt.Fprint(w, "test-secret sensitive-response")
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				stored[name] = body
			}))
			defer server.Close()
			err := testPublisher(server).publish(context.Background(), dir)
			if err == nil {
				t.Fatal("accepted remote failure")
			}
			if strings.Contains(err.Error(), "test-secret") || strings.Contains(err.Error(), "sensitive-response") {
				t.Fatal("error leaked sensitive data")
			}
			if mode == "head-status" && !strings.Contains(err.Error(), "HTTP 403") {
				t.Fatalf("missing status: %v", err)
			}
			if mode == "put-status" && !strings.Contains(err.Error(), "HTTP 503") {
				t.Fatalf("missing status: %v", err)
			}
			if strings.HasPrefix(mode, "overwrite-") && calls != 1 {
				t.Fatalf("continued after collision: %d", calls)
			}
		})
	}
}

func TestIdenticalAssetsSkipped(t *testing.T) {
	dir, files := fixture(t)
	puts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/releases/")
		if r.Method == "PUT" {
			puts++
			if strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".exe") {
				t.Error("reuploaded matching immutable asset")
			}
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(files[name])))
		w.Header().Set("x-amz-meta-sha256", fmt.Sprintf("%x", sha256.Sum256(files[name])))
	}))
	defer server.Close()
	if err := testPublisher(server).publish(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	if puts != 9 {
		t.Fatalf("mutable PUT count %d; want 9", puts)
	}
}

func TestNoRedirectAndCancellation(t *testing.T) {
	dir, _ := fixture(t)
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("followed redirect with signed request") }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", destination.URL)
		w.WriteHeader(307)
	}))
	defer source.Close()
	p := testPublisher(source)
	if err := p.publish(context.Background(), dir); err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("redirect result: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.publish(ctx, dir); err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("cancellation result: %v", err)
	}
}

func TestEnvironmentValidation(t *testing.T) {
	valid := map[string]string{"R2_ACCOUNT_ID": strings.Repeat("a", 32), "R2_BUCKET": "release-bucket", "R2_ACCESS_KEY_ID": "test-access", "R2_SECRET_ACCESS_KEY": "test-secret"}
	for key := range valid {
		t.Run("missing-"+key, func(t *testing.T) {
			_, err := fromEnv(func(name string) string {
				if name == key {
					return ""
				}
				return valid[name]
			})
			if err == nil || !strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "test-secret") {
				t.Fatalf("missing env error: %v", err)
			}
		})
	}
	for _, account := range []string{"", strings.Repeat("a", 31), strings.Repeat("g", 32), "https://evil.example", strings.Repeat("a", 32) + "@evil.example"} {
		if _, err := fromEnv(func(name string) string {
			if name == "R2_ACCOUNT_ID" {
				return account
			}
			return valid[name]
		}); err == nil {
			t.Errorf("accepted account %q", account)
		}
	}
	for _, bucket := range []string{"a", "UPPERCASE", "-bucket", "bucket-", "a.b", "192.168.0.1", "bucket/path", strings.Repeat("a", 64)} {
		if _, err := fromEnv(func(name string) string {
			if name == "R2_BUCKET" {
				return bucket
			}
			return valid[name]
		}); err == nil {
			t.Errorf("accepted bucket %q", bucket)
		}
	}
	p, err := fromEnv(func(name string) string {
		if name == "R2_ENDPOINT" {
			return "http://evil.example"
		}
		return valid[name]
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.endpoint != "https://"+strings.Repeat("a", 32)+".r2.cloudflarestorage.com" {
		t.Fatal("unexpected production endpoint")
	}
	transport := p.client.Transport.(*http.Transport)
	if transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MinVersion < 0x0303 || p.client.Timeout <= 0 || transport.TLSHandshakeTimeout <= 0 {
		t.Fatal("unsafe transport configuration")
	}
}

func testPublisher(server *httptest.Server) *publisher {
	return &publisher{endpoint: server.URL, bucket: "releases", accessKey: "test-access", secretKey: "test-secret", client: server.Client(), now: func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }}
}

func TestPublishOrderAndMetadata(t *testing.T) {
	dir, files := fixture(t)
	stored := map[string][]byte{}
	var calls, want []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/releases/")
		calls = append(calls, r.Method+" "+name)
		switch r.Method {
		case "HEAD":
			body, ok := stored[name]
			if !ok {
				w.WriteHeader(404)
				return
			}
			w.Header().Set("Content-Length", fmt.Sprint(len(body)))
			w.Header().Set("x-amz-meta-sha256", fmt.Sprintf("%x", sha256.Sum256(body)))
		case "PUT":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			if !reflect.DeepEqual(body, files[name]) {
				t.Errorf("wrong body: %s", name)
			}
			if r.Header.Get("x-amz-meta-sha256") != fmt.Sprintf("%x", sha256.Sum256(body)) {
				t.Error("missing hash metadata")
			}
			if r.Header.Get("Content-Type") == "" {
				t.Error("missing content type")
			}
			immutable := strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".exe")
			cache := "no-cache, max-age=0, must-revalidate, no-transform"
			if immutable {
				cache = "public, max-age=31536000, immutable, no-transform"
				if r.Header.Get("If-None-Match") != "*" {
					t.Error("missing creation condition")
				}
			}
			if r.Header.Get("Cache-Control") != cache {
				t.Errorf("cache policy: %s", name)
			}
			if !strings.Contains(r.Header.Get("Authorization"), "/auto/s3/aws4_request") {
				t.Error("missing S3 auto signature")
			}
			stored[name] = body
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()
	for _, name := range []string{"app-1.0.0-linux-amd64.tar.gz", "installer-1.0.0.exe"} {
		want = append(want, "HEAD "+name, "PUT "+name, "HEAD "+name)
	}
	want = append(want, "PUT install.sh", "HEAD install.sh")
	for _, target := range testTargets {
		name := "update-" + target + ".json"
		want = append(want, "PUT "+name, "HEAD "+name)
	}
	for _, name := range []string{"SHA256SUMS", "index.html"} {
		want = append(want, "PUT "+name, "HEAD "+name)
	}
	if err := testPublisher(server).publish(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls:\n%v\nwant:\n%v", calls, want)
	}
}

func TestPublishPayloadsOnlyDoesNotExposeControls(t *testing.T) {
	dir, files := fixture(t)
	stored := map[string][]byte{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/releases/")
		if !payload(name) {
			t.Errorf("payload phase accessed control file %s", name)
		}
		if r.Method == "PUT" {
			stored[name], _ = io.ReadAll(r.Body)
			return
		}
		body, ok := stored[name]
		if !ok {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		w.Header().Set("x-amz-meta-sha256", fmt.Sprintf("%x", sha256.Sum256(body)))
	}))
	defer server.Close()
	if err := testPublisher(server).publishSelection(context.Background(), dir, true); err != nil {
		t.Fatal(err)
	}
	for name, data := range files {
		if payload(name) && !reflect.DeepEqual(stored[name], data) {
			t.Errorf("payload not uploaded: %s", name)
		}
	}
}
