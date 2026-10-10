package portal

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
)

// Reproduce a TLS-intolerant peer: reject modern ClientHello with a real
// handshake_failure alert, but accept a certificate-verified TLS 1.2 probe.
func compatibilityServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	modern := &atomic.Int32{}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	s.TLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if slices.Contains(hello.SupportedVersions, tls.VersionTLS13) {
			modern.Add(1)
			cfg := s.TLS.Clone()
			cfg.GetConfigForClient = nil
			cfg.MaxVersion = tls.VersionTLS12
			cfg.CurvePreferences = []tls.CurveID{tls.CurveP521}
			return cfg, nil
		}
		return nil, nil
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	s.Client().Transport.(*http.Transport).TLSClientConfig.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	return s, modern
}

func TestOnlineTLSCompatibilitySkipsLogin(t *testing.T) {
	s, modern := compatibilityServer(t)
	c := New(nil)
	c.Probe, c.ProbeURLs = s.Client(), []string{s.URL}
	c.Preflight = func(context.Context) error { t.Fatal("online client contacted portal"); return nil }
	c.LocalNIC = func() (NIC, error) {
		t.Fatal("online client inspected credentials/network parameters")
		return NIC{}, nil
	}
	original := c.Probe.Transport.(*http.Transport).TLSClientConfig
	r, err := c.Login(context.Background(), "", "")
	if err != nil || !r.OK || !r.AlreadyOnline {
		t.Fatalf("result=%+v err=%v", r, err)
	}
	if modern.Load() == 0 {
		t.Fatal("test did not exercise the incompatible handshake")
	}
	if original.MaxVersion != 0 || original.InsecureSkipVerify {
		t.Fatal("shared TLS settings changed")
	}
}

func TestOnlineCompatibilityStillVerifiesCertificate(t *testing.T) {
	s, modern := compatibilityServer(t)
	c := New(nil) // Deliberately do not trust the test certificate.
	c.ProbeURLs = []string{s.URL}
	err := c.probe(context.Background(), s.URL)
	var certificateError *tls.CertificateVerificationError
	if !errors.As(err, &certificateError) {
		t.Fatalf("compatibility retry must still reject the untrusted certificate: %v", err)
	}
	if modern.Load() == 0 {
		t.Fatal("modern handshake was not exercised")
	}
}

func TestOnlineRejectsHTTPDowngrade(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, plain.URL, http.StatusFound) }))
	defer secure.Close()
	c := New(nil)
	c.Probe, c.ProbeURLs = secure.Client(), []string{secure.URL}
	if c.Online(context.Background()) {
		t.Fatal("same-host HTTP downgrade accepted as verified online")
	}
	c.ProbeURLs = []string{plain.URL}
	if c.Online(context.Background()) {
		t.Fatal("plain HTTP accepted as verified online")
	}
}

func TestOnlineCompatibilityRespectsTLS13Minimum(t *testing.T) {
	s, _ := compatibilityServer(t)
	c := New(nil)
	c.Probe, c.ProbeURLs = s.Client(), []string{s.URL}
	c.Probe.Transport.(*http.Transport).TLSClientConfig.MinVersion = tls.VersionTLS13
	if c.Online(context.Background()) {
		t.Fatal("explicit minimum TLS version weakened")
	}
}

func TestOnlineCompatibilityPreservesCertificatePolicy(t *testing.T) {
	s, _ := compatibilityServer(t)
	c := New(nil)
	c.Probe, c.ProbeURLs = s.Client(), []string{s.URL}
	policyError := errors.New("certificate rejected by custom policy")
	var checked atomic.Int32
	c.Probe.Transport.(*http.Transport).TLSClientConfig.VerifyConnection = func(tls.ConnectionState) error {
		checked.Add(1)
		return policyError
	}
	if err := c.probe(context.Background(), s.URL); !errors.Is(err, policyError) || checked.Load() == 0 {
		t.Fatalf("certificate policy bypassed: checked=%d err=%v", checked.Load(), err)
	}
}

func TestOnlineCancelledProbe(t *testing.T) {
	s, _ := compatibilityServer(t)
	c := New(nil)
	c.Probe, c.ProbeURLs = s.Client(), []string{s.URL}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if c.Online(ctx) {
		t.Fatal("cancelled probe reported online")
	}
}
