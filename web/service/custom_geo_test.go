package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"

	"github.com/op/go-logging"
)

// disableSSRFCheck disables the SSRF guard for the duration of a test,
// allowing httptest servers on localhost. It restores the originals on cleanup.
func disableSSRFCheck(t *testing.T) {
	t.Helper()
	origCheck := checkSSRF
	origBlocked := checkBlockedIP
	origResolve := resolveHostIPs
	checkSSRF = func(_ context.Context, _ string) error { return nil }
	checkBlockedIP = func(net.IP) bool { return false }
	resolveHostIPs = func(ctx context.Context, host string) ([]net.IP, error) {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		ips := make([]net.IP, 0, len(addrs))
		for _, addr := range addrs {
			ips = append(ips, addr.IP)
		}
		return ips, nil
	}
	t.Cleanup(func() {
		checkSSRF = origCheck
		checkBlockedIP = origBlocked
		resolveHostIPs = origResolve
	})
}

func TestNormalizeAliasKey(t *testing.T) {
	if got := NormalizeAliasKey("GeoIP-IR"); got != "geoip_ir" {
		t.Fatalf("got %q", got)
	}
	if got := NormalizeAliasKey("a-b_c"); got != "a_b_c" {
		t.Fatalf("got %q", got)
	}
}

func TestNewCustomGeoService(t *testing.T) {
	s := NewCustomGeoService()
	if err := s.validateAlias("ok_alias-1"); err != nil {
		t.Fatal(err)
	}
}

func TestTriggerUpdateAllAllSuccess(t *testing.T) {
	s := CustomGeoService{}
	s.updateAllGetAll = func() ([]model.CustomGeoResource, error) {
		return []model.CustomGeoResource{
			{Id: 1, Alias: "a"},
			{Id: 2, Alias: "b"},
		}, nil
	}
	s.updateAllApply = func(id int, onStartup bool) (string, error) {
		return fmt.Sprintf("geo_%d.dat", id), nil
	}
	restartCalls := 0
	s.updateAllRestart = func() error {
		restartCalls++
		return nil
	}

	res, err := s.TriggerUpdateAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Succeeded) != 2 || len(res.Failed) != 0 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if restartCalls != 1 {
		t.Fatalf("expected 1 restart, got %d", restartCalls)
	}
}

func TestTriggerUpdateAllPartialSuccess(t *testing.T) {
	s := CustomGeoService{}
	s.updateAllGetAll = func() ([]model.CustomGeoResource, error) {
		return []model.CustomGeoResource{
			{Id: 1, Alias: "ok"},
			{Id: 2, Alias: "bad"},
		}, nil
	}
	s.updateAllApply = func(id int, onStartup bool) (string, error) {
		if id == 2 {
			return "geo_2.dat", ErrCustomGeoDownload
		}
		return "geo_1.dat", nil
	}
	restartCalls := 0
	s.updateAllRestart = func() error {
		restartCalls++
		return nil
	}

	res, err := s.TriggerUpdateAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Succeeded) != 1 || len(res.Failed) != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if restartCalls != 1 {
		t.Fatalf("expected 1 restart, got %d", restartCalls)
	}
}

func TestTriggerUpdateAllAllFailure(t *testing.T) {
	s := CustomGeoService{}
	s.updateAllGetAll = func() ([]model.CustomGeoResource, error) {
		return []model.CustomGeoResource{
			{Id: 1, Alias: "a"},
			{Id: 2, Alias: "b"},
		}, nil
	}
	s.updateAllApply = func(id int, onStartup bool) (string, error) {
		return fmt.Sprintf("geo_%d.dat", id), ErrCustomGeoDownload
	}
	restartCalls := 0
	s.updateAllRestart = func() error {
		restartCalls++
		return nil
	}

	res, err := s.TriggerUpdateAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Succeeded) != 0 || len(res.Failed) != 2 {
		t.Fatalf("unexpected result: %+v", res)
	}
	if restartCalls != 0 {
		t.Fatalf("expected 0 restart, got %d", restartCalls)
	}
}

func TestCustomGeoValidateAlias(t *testing.T) {
	s := CustomGeoService{}
	if err := s.validateAlias(""); !errors.Is(err, ErrCustomGeoAliasRequired) {
		t.Fatal("empty alias")
	}
	if err := s.validateAlias("Bad"); !errors.Is(err, ErrCustomGeoAliasPattern) {
		t.Fatal("uppercase")
	}
	if err := s.validateAlias("a b"); !errors.Is(err, ErrCustomGeoAliasPattern) {
		t.Fatal("space")
	}
	if err := s.validateAlias("ok_alias-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.validateAlias("geoip"); !errors.Is(err, ErrCustomGeoAliasReserved) {
		t.Fatal("reserved")
	}
}

func TestCustomGeoValidateURL(t *testing.T) {
	s := CustomGeoService{}
	if _, err := s.sanitizeURL(""); !errors.Is(err, ErrCustomGeoURLRequired) {
		t.Fatal("empty")
	}
	if _, err := s.sanitizeURL("ftp://x"); !errors.Is(err, ErrCustomGeoURLScheme) {
		t.Fatal("ftp")
	}
	if sanitized, err := s.sanitizeURL("https://example.com/a.dat"); err != nil {
		t.Fatal(err)
	} else if sanitized != "https://example.com/a.dat" {
		t.Fatalf("unexpected sanitized URL: %s", sanitized)
	}
}

func TestCustomGeoValidateType(t *testing.T) {
	s := CustomGeoService{}
	if err := s.validateType("geosite"); err != nil {
		t.Fatal(err)
	}
	if err := s.validateType("x"); !errors.Is(err, ErrCustomGeoInvalidType) {
		t.Fatal("bad type")
	}
}

func TestCustomGeoDownloadToPath(t *testing.T) {
	disableSSRFCheck(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "1")
		if r.Header.Get("If-Modified-Since") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, minDatBytes+1))
	}))
	defer ts.Close()
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	dest := filepath.Join(dir, "geoip_t.dat")
	s := CustomGeoService{}
	skipped, _, err := s.downloadToPath(ts.URL, dest, "")
	if err != nil {
		t.Fatal(err)
	}
	if skipped {
		t.Fatal("expected download")
	}
	st, err := os.Stat(dest)
	if err != nil || st.Size() < minDatBytes {
		t.Fatalf("file %v", err)
	}
	skipped2, _, err2 := s.downloadToPath(ts.URL, dest, "")
	if err2 != nil || !skipped2 {
		t.Fatalf("304 expected skipped=%v err=%v", skipped2, err2)
	}
}

func TestCustomGeoDownloadToPath_missingLocalSendsNoIMSFromDB(t *testing.T) {
	disableSSRFCheck(t)
	lm := "Wed, 21 Oct 2015 07:28:00 GMT"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-Modified-Since") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Last-Modified", lm)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, minDatBytes+1))
	}))
	defer ts.Close()
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	dest := filepath.Join(dir, "geoip_rebuild.dat")
	s := CustomGeoService{}
	skipped, _, err := s.downloadToPath(ts.URL, dest, lm)
	if err != nil {
		t.Fatal(err)
	}
	if skipped {
		t.Fatal("must not treat as not-modified when local file is missing")
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatal("file should exist after container-style rebuild")
	}
}

func TestCustomGeoDownloadToPath_repairSkipsConditional(t *testing.T) {
	disableSSRFCheck(t)
	lm := "Wed, 21 Oct 2015 07:28:00 GMT"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-Modified-Since") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Last-Modified", lm)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, minDatBytes+1))
	}))
	defer ts.Close()
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	dest := filepath.Join(dir, "geoip_bad.dat")
	if err := os.WriteFile(dest, make([]byte, minDatBytes-1), 0o644); err != nil {
		t.Fatal(err)
	}
	s := CustomGeoService{}
	skipped, _, err := s.downloadToPath(ts.URL, dest, lm)
	if err != nil {
		t.Fatal(err)
	}
	if skipped {
		t.Fatal("corrupt local file must be re-downloaded, not 304")
	}
	st, err := os.Stat(dest)
	if err != nil || st.Size() < minDatBytes {
		t.Fatalf("file repaired: %v", err)
	}
}

func TestCustomGeoFileNameFor(t *testing.T) {
	s := CustomGeoService{}
	if s.fileNameFor("geoip", "a") != "geoip_a.dat" {
		t.Fatal("geoip name")
	}
	if s.fileNameFor("geosite", "b") != "geosite_b.dat" {
		t.Fatal("geosite name")
	}
}

func TestLocalDatFileNeedsRepair(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	if !localDatFileNeedsRepair(filepath.Join(dir, "missing.dat")) {
		t.Fatal("missing")
	}
	smallPath := filepath.Join(dir, "small.dat")
	if err := os.WriteFile(smallPath, make([]byte, minDatBytes-1), 0o644); err != nil {
		t.Fatal(err)
	}
	if !localDatFileNeedsRepair(smallPath) {
		t.Fatal("small")
	}
	okPath := filepath.Join(dir, "ok.dat")
	if err := os.WriteFile(okPath, make([]byte, minDatBytes), 0o644); err != nil {
		t.Fatal(err)
	}
	if localDatFileNeedsRepair(okPath) {
		t.Fatal("ok size")
	}
	dirPath := filepath.Join(dir, "isdir.dat")
	if err := os.Mkdir(dirPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if !localDatFileNeedsRepair(dirPath) {
		t.Fatal("dir should need repair")
	}
	if !CustomGeoLocalFileNeedsRepair(dirPath) {
		t.Fatal("exported wrapper dir")
	}
	if CustomGeoLocalFileNeedsRepair(okPath) {
		t.Fatal("exported wrapper ok file")
	}
}

func TestProbeCustomGeoURL_HEADOK(t *testing.T) {
	disableSSRFCheck(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	if err := probeCustomGeoURL(ts.URL); err != nil {
		t.Fatal(err)
	}
}

func TestProbeCustomGeoURL_HEAD405GETRange(t *testing.T) {
	disableSSRFCheck(t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Method == http.MethodGet && r.Header.Get("Range") != "" {
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte{0})
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()
	if err := probeCustomGeoURL(ts.URL); err != nil {
		t.Fatal(err)
	}
}

// --- DNS-rebinding SSRF regression tests (issue 5) ---

// fakeConn is a minimal net.Conn that serves a canned HTTP response and
// discards whatever the client writes. The response is fed only after the
// client writes the request (like a real server): a buffer pre-loaded at
// dial time lets the transport's readLoop peek a byte before the request
// is registered, which kills the connection with a spurious
// readLoopPeekFailLocked error. Read blocks while the buffer is empty
// (until Close), like a real server connection.
type fakeConn struct {
	mu        sync.Mutex
	cond      *sync.Cond
	buf       *bytes.Buffer
	response  string
	responded bool
	closed    bool
	addr      net.Addr
}

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

func newFakeConn(response string, addr string) *fakeConn {
	c := &fakeConn{buf: &bytes.Buffer{}, response: response, addr: fakeAddr(addr)}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *fakeConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.buf.Len() == 0 && !c.closed {
		c.cond.Wait()
	}
	if c.buf.Len() == 0 {
		return 0, io.EOF
	}
	return c.buf.Read(b)
}

func (c *fakeConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if !c.responded {
		// First write carries the request: answer it now.
		c.responded = true
		c.buf.WriteString(c.response)
		c.cond.Broadcast()
	}
	c.mu.Unlock()
	return len(b), nil
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.cond.Broadcast()
	return nil
}
func (c *fakeConn) LocalAddr() net.Addr              { return c.addr }
func (c *fakeConn) RemoteAddr() net.Addr             { return c.addr }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

// recordingDialer records every address the transport dials and answers
// each dial with the next canned HTTP response from responses.
type recordingDialer struct {
	mu        sync.Mutex
	dialed    []string
	responses []string
}

func (d *recordingDialer) dial(_ context.Context, _, addr string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dialed = append(d.dialed, addr)
	body := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
	if len(d.responses) > 0 {
		body = d.responses[0]
		d.responses = d.responses[1:]
	}
	return newFakeConn(body, addr), nil
}

func (d *recordingDialer) dialedAddrs() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := append([]string(nil), d.dialed...)
	return out
}

// installSSRFTestHooks replaces the resolver and dialer for the duration
// of a test and restores them on cleanup.
func installSSRFTestHooks(t *testing.T, resolve func(context.Context, string) ([]net.IP, error), dialer *recordingDialer) {
	t.Helper()
	origResolve := resolveHostIPs
	origDialer := ssrfDialer
	resolveHostIPs = resolve
	ssrfDialer = dialer.dial
	t.Cleanup(func() {
		resolveHostIPs = origResolve
		ssrfDialer = origDialer
	})
}

// TestSSRFTransportRebindingBlocked is the core regression test: the
// resolver answers a public IP on the first lookup and a loopback IP on
// any later lookup (the rebinding attack). The transport must resolve
// exactly once and dial the validated public IP — never the loopback
// address a second resolution would return.
func TestSSRFTransportRebindingBlocked(t *testing.T) {
	resolveCalls := 0
	dialer := &recordingDialer{}
	installSSRFTestHooks(t, func(_ context.Context, host string) ([]net.IP, error) {
		resolveCalls++
		if resolveCalls == 1 {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}, dialer)

	// Disable keep-alives: each request must dial a fresh connection
	// (a reused fakeConn would EOF on the transport's read peek and
	// mask the dial-time check under test).
	tr := ssrfSafeTransport().(*http.Transport)
	tr.DisableKeepAlives = true
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://example.com/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "OK" {
		t.Fatalf("body = %q, want OK", body)
	}
	if resolveCalls != 1 {
		t.Fatalf("resolver called %d times, want exactly 1 (no re-resolution at dial time)", resolveCalls)
	}
	dialed := dialer.dialedAddrs()
	if len(dialed) != 1 || dialed[0] != "93.184.216.34:80" {
		t.Fatalf("dialed %v, want [93.184.216.34:80] — the connection must go to the validated public IP", dialed)
	}
}

// TestSSRFTransportBlocksPrivateIP: a hostname resolving to a private IP
// is rejected before any dial happens.
func TestSSRFTransportBlocksPrivateIP(t *testing.T) {
	dialer := &recordingDialer{}
	installSSRFTestHooks(t, func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.5")}, nil
	}, dialer)

	// Disable keep-alives: each request must dial a fresh connection
	// (a reused fakeConn would EOF on the transport's read peek and
	// mask the dial-time check under test).
	tr := ssrfSafeTransport().(*http.Transport)
	tr.DisableKeepAlives = true
	client := &http.Client{Transport: tr}
	_, err := client.Get("http://internal.example.com/")
	if err == nil {
		t.Fatal("GET to a private IP succeeded, want an SSRF error")
	}
	if !errors.Is(err, ErrCustomGeoSSRFBlocked) {
		t.Fatalf("GET error = %v, want it to wrap %v", err, ErrCustomGeoSSRFBlocked)
	}
	if got := dialer.dialedAddrs(); len(got) != 0 {
		t.Fatalf("dialed %v, want no dial at all", got)
	}
}

// TestSSRFTransportBlocksMixedAnswer: one blocked IP among the candidates
// rejects the whole answer, even if a public IP is also present.
func TestSSRFTransportBlocksMixedAnswer(t *testing.T) {
	dialer := &recordingDialer{}
	installSSRFTestHooks(t, func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("169.254.169.254")}, nil
	}, dialer)

	// Disable keep-alives: each request must dial a fresh connection
	// (a reused fakeConn would EOF on the transport's read peek and
	// mask the dial-time check under test).
	tr := ssrfSafeTransport().(*http.Transport)
	tr.DisableKeepAlives = true
	client := &http.Client{Transport: tr}
	_, err := client.Get("http://example.com/")
	if err == nil {
		t.Fatal("GET with a mixed public/private answer succeeded, want an SSRF error")
	}
	if !errors.Is(err, ErrCustomGeoSSRFBlocked) {
		t.Fatalf("GET error = %v, want it to wrap %v", err, ErrCustomGeoSSRFBlocked)
	}
	if got := dialer.dialedAddrs(); len(got) != 0 {
		t.Fatalf("dialed %v, want no dial at all", got)
	}
}

// TestSSRFTransportIPLiteral: IP-literal hosts are validated as-is and
// never resolved; a public literal is dialled directly.
func TestSSRFTransportIPLiteral(t *testing.T) {
	resolveCalls := 0
	dialer := &recordingDialer{}
	installSSRFTestHooks(t, func(_ context.Context, _ string) ([]net.IP, error) {
		resolveCalls++
		return nil, fmt.Errorf("resolver must not be called for IP literals")
	}, dialer)

	// Disable keep-alives: each request must dial a fresh connection
	// (a reused fakeConn would EOF on the transport's read peek and
	// mask the dial-time check under test).
	tr := ssrfSafeTransport().(*http.Transport)
	tr.DisableKeepAlives = true
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://93.184.216.34/")
	if err != nil {
		t.Fatalf("GET public IP literal: %v", err)
	}
	resp.Body.Close()
	if resolveCalls != 0 {
		t.Fatalf("resolver called %d times for an IP literal, want 0", resolveCalls)
	}
	if got := dialer.dialedAddrs(); len(got) != 1 || got[0] != "93.184.216.34:80" {
		t.Fatalf("dialed %v, want [93.184.216.34:80]", got)
	}

	// A loopback literal is blocked without a dial.
	_, err = client.Get("http://127.0.0.1:1234/")
	if err == nil {
		t.Fatal("GET to a loopback literal succeeded, want an SSRF error")
	}
	if !errors.Is(err, ErrCustomGeoSSRFBlocked) {
		t.Fatalf("GET error = %v, want it to wrap %v", err, ErrCustomGeoSSRFBlocked)
	}
}

// TestSSRFTransportRedirectRevalidated: a redirect to a host that resolves
// to a private IP is blocked; the redirect target goes through the same
// resolve-once-and-dial-validated-IP path as the original URL.
func TestSSRFTransportRedirectRevalidated(t *testing.T) {
	dialer := &recordingDialer{
		responses: []string{
			"HTTP/1.1 302 Found\r\nLocation: http://internal.example.com/\r\nContent-Length: 0\r\n\r\n",
		},
	}
	installSSRFTestHooks(t, func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "example.com":
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		case "internal.example.com":
			return []net.IP{net.ParseIP("10.1.2.3")}, nil
		}
		return nil, fmt.Errorf("unexpected host %s", host)
	}, dialer)

	// Disable keep-alives: each request must dial a fresh connection
	// (a reused fakeConn would EOF on the transport's read peek and
	// mask the dial-time check under test).
	tr := ssrfSafeTransport().(*http.Transport)
	tr.DisableKeepAlives = true
	client := &http.Client{Transport: tr}
	_, err := client.Get("http://example.com/")
	t.Logf("redirect test: dialed=%v err=%v", dialer.dialedAddrs(), err)
	if err == nil {
		t.Fatal("redirect to a private IP succeeded, want an SSRF error")
	}
	if !errors.Is(err, ErrCustomGeoSSRFBlocked) {
		t.Fatalf("GET error = %v, want it to wrap %v", err, ErrCustomGeoSSRFBlocked)
	}
	// Only the first hop was dialled; the redirect target was blocked
	// before its dial.
	if got := dialer.dialedAddrs(); len(got) != 1 || got[0] != "93.184.216.34:80" {
		t.Fatalf("dialed %v, want only [93.184.216.34:80]", got)
	}
}

// TestSSRFTransportIgnoresProxy: with HTTP_PROXY pointing at a dead proxy,
// the download still goes direct — the proxy must not get the hostname
// (and must not bypass validation by resolving it itself).
func TestSSRFTransportIgnoresProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:9")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:9")
	t.Setenv("http_proxy", "http://127.0.0.1:9")
	t.Setenv("https_proxy", "http://127.0.0.1:9")

	dialer := &recordingDialer{}
	installSSRFTestHooks(t, func(_ context.Context, _ string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.216.34")}, nil
	}, dialer)

	// Disable keep-alives: each request must dial a fresh connection
	// (a reused fakeConn would EOF on the transport's read peek and
	// mask the dial-time check under test).
	tr := ssrfSafeTransport().(*http.Transport)
	tr.DisableKeepAlives = true
	client := &http.Client{Transport: tr}
	resp, err := client.Get("http://example.com/")
	if err != nil {
		t.Fatalf("GET with a dead proxy configured: %v (the proxy must be ignored)", err)
	}
	resp.Body.Close()
	if got := dialer.dialedAddrs(); len(got) != 1 || got[0] != "93.184.216.34:80" {
		t.Fatalf("dialed %v, want a direct dial of [93.184.216.34:80]", got)
	}
}

// TestSSRFTransportHTTPSKeepsSNIAndHost: over HTTPS the TLS ServerName and
// the HTTP Host header still carry the original domain, even though the
// TCP connection goes to the validated IP.
func TestSSRFTransportHTTPSKeepsSNIAndHost(t *testing.T) {
	// A self-signed certificate for example.com, trusted by the test client.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	serverCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	var gotSNI, gotHost string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
		_, _ = w.Write([]byte("ok"))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			gotSNI = hi.ServerName
			return &serverCert, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()

	// The server listens on 127.0.0.1:<port>; the URL uses example.com
	// with that port so the dialer resolves example.com to the server.
	serverURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("server URL: %v", err)
	}
	_, port, err := net.SplitHostPort(serverURL.Host)
	if err != nil {
		t.Fatalf("server host: %v", err)
	}
	targetURL := "https://example.com:" + port + "/"

	// Only the resolver is faked here: the TLS handshake needs a real
	// TCP connection to the test server.
	origResolve := resolveHostIPs
	resolveHostIPs = func(_ context.Context, host string) ([]net.IP, error) {
		if host != "example.com" {
			return nil, fmt.Errorf("unexpected host %s", host)
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	t.Cleanup(func() { resolveHostIPs = origResolve })

	// The test resolver returns loopback, so allow it for this test only.
	origBlocked := checkBlockedIP
	checkBlockedIP = func(net.IP) bool { return false }
	t.Cleanup(func() { checkBlockedIP = origBlocked })

	tr := ssrfSafeTransport().(*http.Transport)
	tr.TLSClientConfig = &tls.Config{RootCAs: pool}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("body = %q, want ok", body)
	}
	if gotSNI != "example.com" {
		t.Fatalf("TLS ServerName = %q, want example.com", gotSNI)
	}
	if gotHost != "example.com:"+port {
		t.Fatalf("HTTP Host = %q, want example.com:%s", gotHost, port)
	}
}

// setupGeoMaxSizeTest creates a throw-away database with the Geo download
// limit set to limitMB MiB and returns a service that reads it, plus a
// destination file inside a throw-away bin folder pre-filled with marker
// bytes (the "old file" that must survive a rejected download).
func setupGeoMaxSizeTest(t *testing.T, limitMB int) (*CustomGeoService, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })
	if err := (&SettingService{}).setInt("geoMaxFileSizeMB", limitMB); err != nil {
		t.Fatalf("setInt geoMaxFileSizeMB: %v", err)
	}
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	dest := filepath.Join(dir, "geoip_t.dat")
	if err := os.WriteFile(dest, bytes.Repeat([]byte("A"), 100), 0o644); err != nil {
		t.Fatalf("write old file: %v", err)
	}
	return NewCustomGeoService(), dest
}

func assertGeoOldFileKept(t *testing.T, dest string) {
	t.Helper()
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("old file missing after rejected download: %v", err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte("A"), 100)) {
		t.Fatalf("old file changed after rejected download: %d bytes", len(got))
	}
	if _, err := os.Stat(dest + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temp file left behind: err=%v", err)
	}
}

// TestDownloadToPathRejectsOversizeContentLength: a server declaring a
// Content-Length above the limit is rejected before any byte is written.
func TestDownloadToPathRejectsOversizeContentLength(t *testing.T) {
	disableSSRFCheck(t)
	s, dest := setupGeoMaxSizeTest(t, 1) // 1 MiB limit
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2097152") // 2 MiB
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, 1024))
	}))
	defer ts.Close()

	_, _, err := s.downloadToPath(ts.URL, dest, "")
	if err == nil {
		t.Fatal("oversized Content-Length accepted, want an error")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("error = %v, want it to mention the size limit", err)
	}
	assertGeoOldFileKept(t, dest)
}

// TestDownloadToPathRejectsOversizeStream: a chunked response with no
// Content-Length streaming past the limit is cut off by the hard read
// limit and rejected; the old file survives.
func TestDownloadToPathRejectsOversizeStream(t *testing.T) {
	disableSSRFCheck(t)
	s, dest := setupGeoMaxSizeTest(t, 1) // 1 MiB limit
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Content-Length header: Go serves this chunked.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, (1<<20)+1024)) // 1 MiB + 1 KiB
	}))
	defer ts.Close()

	_, _, err := s.downloadToPath(ts.URL, dest, "")
	if err == nil {
		t.Fatal("oversized stream accepted, want an error")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("error = %v, want it to mention the size limit", err)
	}
	assertGeoOldFileKept(t, dest)
}

// TestDownloadToPathAcceptsUnderLimit: a normal download below the limit
// still replaces the old file.
func TestDownloadToPathAcceptsUnderLimit(t *testing.T) {
	disableSSRFCheck(t)
	s, dest := setupGeoMaxSizeTest(t, 1) // 1 MiB limit
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, 1024))
	}))
	defer ts.Close()

	_, _, err := s.downloadToPath(ts.URL, dest, "")
	if err != nil {
		t.Fatalf("download under the limit failed: %v", err)
	}
	st, err := os.Stat(dest)
	if err != nil || st.Size() != 1024 {
		t.Fatalf("dest size = %v, err = %v, want 1024", st, err)
	}
}

// TestGeoMaxFileSizeBytesFallback: without a setting service, or with a
// missing/invalid setting, the limit falls back to the 100 MiB default
// instead of disabling the cap.
func TestGeoMaxFileSizeBytesFallback(t *testing.T) {
	want := int64(defaultGeoMaxFileSizeMB * 1024 * 1024)
	if got := (&CustomGeoService{}).geoMaxFileSizeBytes(); got != want {
		t.Fatalf("zero-value service limit = %d, want %d", got, want)
	}
	if got := NewCustomGeoService().geoMaxFileSizeBytes(); got != want {
		t.Fatalf("service without a database limit = %d, want %d", got, want)
	}
}

// setupCustomGeoTestDB builds a throw-away panel database and points
// the bin and log folders at temp directories.
func setupCustomGeoTestDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", dir)
	t.Setenv("XUI_LOG_FOLDER", dir)
	logger.InitLogger(logging.ERROR)
	if err := database.InitDB(filepath.Join(dir, "x-ui.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })
}

// TestCustomGeoUpdateDownloadFailureKeepsOldFile: when an update
// changes the local path and the new download fails, the old file and
// the old database record must stay untouched — deleting the old file
// before downloading would leave Xray pointing at a missing .dat.
func TestCustomGeoUpdateDownloadFailureKeepsOldFile(t *testing.T) {
	disableSSRFCheck(t)
	setupCustomGeoTestDB(t)
	s := NewCustomGeoService()

	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, minDatBytes+1))
	}))
	defer good.Close()
	r := &model.CustomGeoResource{Type: "geoip", Alias: "keep", Url: good.URL}
	if err := s.Create(r); err != nil {
		t.Fatalf("Create: %v", err)
	}
	var cur model.CustomGeoResource
	if err := database.GetDB().First(&cur, r.Id).Error; err != nil {
		t.Fatal(err)
	}
	oldContent, err := os.ReadFile(cur.LocalPath)
	if err != nil {
		t.Fatal(err)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer bad.Close()
	// Change the alias (new local path) and point at the failing source.
	upd := &model.CustomGeoResource{Type: "geoip", Alias: "keep2", Url: bad.URL}
	if err := s.Update(cur.Id, upd); err == nil {
		t.Fatal("Update with a failing download should return an error")
	}
	if got, err := os.ReadFile(cur.LocalPath); err != nil || !bytes.Equal(got, oldContent) {
		t.Fatalf("old file lost or changed after failed update: %v", err)
	}
	var after model.CustomGeoResource
	if err := database.GetDB().First(&after, cur.Id).Error; err != nil {
		t.Fatal(err)
	}
	if after.Alias != "keep" || after.Url != good.URL || after.LocalPath != cur.LocalPath {
		t.Fatalf("record changed after failed update: %+v", after)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(cur.LocalPath), s.fileNameFor("geoip", "keep2"))); !os.IsNotExist(err) {
		t.Fatalf("new-path file exists after failed update: %v", err)
	}
}

// TestCustomGeoUpdateURLChangeForcesFullDownload: when the source URL
// changes, the old source's Last-Modified must not be sent to the new
// source — a 304 there would keep the old source's data while the
// record is updated to the new URL.
func TestCustomGeoUpdateURLChangeForcesFullDownload(t *testing.T) {
	disableSSRFCheck(t)
	setupCustomGeoTestDB(t)
	s := NewCustomGeoService()

	oldLM := "Wed, 21 Oct 2015 07:28:00 GMT"
	newLM := "Wed, 21 Oct 2020 07:28:00 GMT"
	contentA := bytes.Repeat([]byte("A"), minDatBytes+1)
	contentB := bytes.Repeat([]byte("B"), minDatBytes+1)
	serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", oldLM)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(contentA)
	}))
	defer serverA.Close()
	serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-Modified-Since") != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Last-Modified", newLM)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(contentB)
	}))
	defer serverB.Close()

	r := &model.CustomGeoResource{Type: "geoip", Alias: "src", Url: serverA.URL}
	if err := s.Create(r); err != nil {
		t.Fatalf("Create: %v", err)
	}
	var cur model.CustomGeoResource
	if err := database.GetDB().First(&cur, r.Id).Error; err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(cur.LocalPath); err != nil || !bytes.Equal(got, contentA) {
		t.Fatalf("initial file is not source A content: %v", err)
	}

	// Same alias (same path), new URL: the update must download
	// source B in full instead of sending source A's Last-Modified.
	upd := &model.CustomGeoResource{Type: "geoip", Alias: "src", Url: serverB.URL}
	if err := s.Update(cur.Id, upd); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got, err := os.ReadFile(cur.LocalPath); err != nil || !bytes.Equal(got, contentB) {
		t.Fatalf("file after URL change is not source B content")
	}
	var after model.CustomGeoResource
	if err := database.GetDB().First(&after, cur.Id).Error; err != nil {
		t.Fatal(err)
	}
	if after.Url != serverB.URL {
		t.Fatalf("record URL %q, want %q", after.Url, serverB.URL)
	}
	if after.LastModified != newLM {
		t.Fatalf("record Last-Modified %q, want %q", after.LastModified, newLM)
	}
}

// TestCustomGeoUpdateDBFailureRestoresOldFile: when the metadata
// update fails after the file was replaced, the old content must
// come back instead of leaving the file and the record inconsistent
// (new content under the old URL and Last-Modified).
func TestCustomGeoUpdateDBFailureRestoresOldFile(t *testing.T) {
	disableSSRFCheck(t)
	setupCustomGeoTestDB(t)
	s := NewCustomGeoService()

	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, minDatBytes+1))
	}))
	defer good.Close()
	r := &model.CustomGeoResource{Type: "geoip", Alias: "keep", Url: good.URL}
	if err := s.Create(r); err != nil {
		t.Fatalf("Create: %v", err)
	}
	var cur model.CustomGeoResource
	if err := database.GetDB().First(&cur, r.Id).Error; err != nil {
		t.Fatal(err)
	}
	oldContent, err := os.ReadFile(cur.LocalPath)
	if err != nil {
		t.Fatal(err)
	}

	// Fail the metadata write only: a trigger that aborts every
	// UPDATE on the resources table. The download still succeeds,
	// so the rollback path is the only thing standing between the
	// new file content and the old record.
	if err := database.GetDB().Exec("CREATE TRIGGER fail_update BEFORE UPDATE ON custom_geo_resources BEGIN SELECT RAISE(ABORT, 'forced db failure'); END").Error; err != nil {
		t.Fatal(err)
	}

	upd := &model.CustomGeoResource{Type: "geoip", Alias: "keep", Url: good.URL}
	if err := s.Update(cur.Id, upd); err == nil {
		t.Fatal("Update should fail when the metadata write fails")
	}
	if got, err := os.ReadFile(cur.LocalPath); err != nil || !bytes.Equal(got, oldContent) {
		t.Fatalf("old file not restored after failed metadata update: %q, %v", got, err)
	}
	var after model.CustomGeoResource
	if err := database.GetDB().First(&after, cur.Id).Error; err != nil {
		t.Fatal(err)
	}
	if after.Url != good.URL || after.LocalPath != cur.LocalPath {
		t.Fatalf("record changed after failed update: %+v", after)
	}
	if _, err := os.Stat(cur.LocalPath + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("backup left behind after rollback: %v", err)
	}
}
