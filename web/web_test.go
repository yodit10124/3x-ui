package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/global"
	"github.com/mhsanaei/3x-ui/v2/web/service"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/op/go-logging"
	"github.com/robfig/cron/v3"
)

// testWebServer is the minimal global.WebServer stub the API controller's
// background status task needs (it registers a cron func at startup).
type testWebServer struct {
	cron *cron.Cron
}

func (w *testWebServer) GetCron() *cron.Cron     { return w.cron }
func (w *testWebServer) GetCtx() context.Context { return context.Background() }
func (w *testWebServer) GetWSHub() any           { return nil }

func TestUseSecureCookie(t *testing.T) {
	cases := []struct {
		name         string
		certFile     string
		keyFile      string
		secureCookie bool
		want         bool
	}{
		{"plain http", "", "", false, false},
		{"direct tls, cert only", "/etc/x-ui/cert.pem", "", false, true},
		{"direct tls, key only", "", "/etc/x-ui/key.pem", false, true},
		{"direct tls, both", "/etc/x-ui/cert.pem", "/etc/x-ui/key.pem", false, true},
		{"proxy tls, explicit setting", "", "", true, true},
		{"proxy tls, setting with no cert", "", "", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := useSecureCookie(tc.certFile, tc.keyFile, tc.secureCookie); got != tc.want {
				t.Fatalf("useSecureCookie(%q, %q, %v) = %v, want %v",
					tc.certFile, tc.keyFile, tc.secureCookie, got, tc.want)
			}
		})
	}
}

// setupSecureCookieEngine builds the real panel router against a throw-away
// database. Settings are written straight to the settings table so the
// test controls exactly what initRouter sees.
func setupSecureCookieEngine(t *testing.T, settings map[string]string) *gin.Engine {
	t.Helper()
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)
	gin.SetMode(gin.TestMode)

	if err := database.InitDB(filepath.Join(t.TempDir(), "x-ui.db")); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })

	// Since the fix for direct binary starts, a fresh database gets a
	// random admin password; set a known one for the login tests.
	if err := (&service.UserService{}).UpdateFirstUser("admin", "admin"); err != nil {
		t.Fatalf("UpdateFirstUser: %v", err)
	}

	for key, value := range settings {
		if err := database.GetDB().Create(&model.Setting{Key: key, Value: value}).Error; err != nil {
			t.Fatalf("set %s: %v", key, err)
		}
	}

	// The API controller starts a background status task against the
	// global web server; give it a stub so initRouter does not panic.
	global.SetWebServer(&testWebServer{cron: cron.New()})
	t.Cleanup(func() { global.SetWebServer(nil) })

	srv := &Server{}
	engine, err := srv.initRouter()
	if err != nil {
		t.Fatalf("initRouter: %v", err)
	}
	return engine
}

// writeSelfSignedCert returns paths to a real self-signed certificate and
// key, so the direct-TLS case exercises the same configuration a real
// deployment has (initRouter only checks that the paths are non-empty,
// but a valid pair keeps the test honest if that ever changes).
func writeSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	certOut.Close()
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("create key file: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		t.Fatalf("write key: %v", err)
	}
	keyOut.Close()
	return certPath, keyPath
}

// loginAsAdmin posts the default admin credentials and returns the
// session cookies from the response.
func loginAsAdmin(t *testing.T, engine *gin.Engine) []*http.Cookie {
	t.Helper()
	body := strings.NewReader(`{"username":"admin","password":"admin"}`)
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status %d, body %s", rec.Code, rec.Body.String())
	}
	resp := rec.Result()
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatalf("login: no Set-Cookie in response, body %s", rec.Body.String())
	}
	return cookies
}

func sessionCookie(t *testing.T, cookies []*http.Cookie) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name == "3x-ui" {
			return c
		}
	}
	t.Fatal("no 3x-ui session cookie in response")
	return nil
}

func TestLoginCookieSecureDirectTLS(t *testing.T) {
	certPath, keyPath := writeSelfSignedCert(t)
	engine := setupSecureCookieEngine(t, map[string]string{
		"webCertFile": certPath,
		"webKeyFile":  keyPath,
	})

	cookie := sessionCookie(t, loginAsAdmin(t, engine))
	if !cookie.Secure {
		t.Fatal("direct HTTPS login: session cookie is missing Secure")
	}
	if !cookie.HttpOnly {
		t.Fatal("direct HTTPS login: session cookie is missing HttpOnly")
	}

	// HSTS is sent on HTTPS deployments.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Fatalf("direct HTTPS: HSTS header = %q, want max-age=31536000", got)
	}
}

func TestLoginCookieSecureProxyTLS(t *testing.T) {
	// No certificate on the panel itself; the reverse proxy terminates TLS
	// and the operator explicitly opted in.
	engine := setupSecureCookieEngine(t, map[string]string{
		"webSecureCookie": "true",
	})

	cookie := sessionCookie(t, loginAsAdmin(t, engine))
	if !cookie.Secure {
		t.Fatal("proxy HTTPS login: session cookie is missing Secure")
	}
	if !cookie.HttpOnly {
		t.Fatal("proxy HTTPS login: session cookie is missing HttpOnly")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if got := rec.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Fatalf("proxy HTTPS: HSTS header = %q, want max-age=31536000", got)
	}
}

func TestLoginCookiePlainHTTP(t *testing.T) {
	engine := setupSecureCookieEngine(t, nil)

	cookie := sessionCookie(t, loginAsAdmin(t, engine))
	if cookie.Secure {
		t.Fatal("plain HTTP login: session cookie must not carry Secure")
	}
	if !cookie.HttpOnly {
		t.Fatal("plain HTTP login: session cookie is missing HttpOnly")
	}

	// No HSTS on an explicit HTTP deployment.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("plain HTTP: HSTS header = %q, want none", got)
	}
}

func TestLoginCookieHSTSDisabled(t *testing.T) {
	certPath, keyPath := writeSelfSignedCert(t)
	engine := setupSecureCookieEngine(t, map[string]string{
		"webCertFile":   certPath,
		"webKeyFile":    keyPath,
		"webHSTSMaxAge": "0",
	})

	// Secure still applies; only the HSTS header is off.
	cookie := sessionCookie(t, loginAsAdmin(t, engine))
	if !cookie.Secure {
		t.Fatal("direct HTTPS login with HSTS disabled: cookie is missing Secure")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("HSTS disabled: header = %q, want none", got)
	}
}

func TestLogoutDeletesSecureCookie(t *testing.T) {
	certPath, keyPath := writeSelfSignedCert(t)
	engine := setupSecureCookieEngine(t, map[string]string{
		"webCertFile": certPath,
		"webKeyFile":  keyPath,
	})

	cookies := loginAsAdmin(t, engine)
	session := sessionCookie(t, cookies)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	// The logout response must delete the cookie with the same Secure
	// attribute, or browsers keep the old session cookie. Deletion is
	// signalled by Max-Age=0 in the raw header (Go's cookie parser maps
	// that to MaxAge -1); the value itself is an encoded empty session
	// payload, which is normal for the cookie store.
	raw := strings.Join(rec.Header().Values("Set-Cookie"), "; ")
	cookie := sessionCookie(t, rec.Result().Cookies())
	if !cookie.Secure {
		t.Fatalf("logout: cookie %+v is missing Secure", cookie)
	}
	if !strings.Contains(raw, "Max-Age=0") {
		t.Fatalf("logout: Set-Cookie %q does not delete the cookie", raw)
	}
}

// Compile-time check that the test certificate is actually usable as a
// TLS pair (guards the fixture in writeSelfSignedCert).
func TestSelfSignedCertFixtureLoads(t *testing.T) {
	certPath, keyPath := writeSelfSignedCert(t)
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("fixture certificate does not load: %v", err)
	}
}

// getServerStatus calls the protected server-status API with the given
// cookies, the way the panel frontend does. Authenticated it answers
// 200; without a valid session checkAPIAuth answers 404 to hide the
// endpoint.
func getServerStatus(t *testing.T, engine *gin.Engine, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/panel/api/server/status", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

// logout posts to /logout with the given cookies and expects the
// 307 redirect to the login page.
func logout(t *testing.T, engine *gin.Engine, cookies []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("logout: status %d, want 307", rec.Code)
	}
}

// TestLogoutRevokesSession is the auditor's scenario: log in, confirm
// the protected API answers, log out, then replay the pre-logout cookie.
// Logout must revoke the session server-side — clearing the browser
// cookie alone cannot stop a stolen copy — so the replay is refused.
func TestLogoutRevokesSession(t *testing.T) {
	engine := setupSecureCookieEngine(t, nil)
	cookies := loginAsAdmin(t, engine)
	if rec := getServerStatus(t, engine, cookies); rec.Code != http.StatusOK {
		t.Fatalf("status before logout: %d, want 200", rec.Code)
	}
	logout(t, engine, cookies)
	if rec := getServerStatus(t, engine, cookies); rec.Code != http.StatusNotFound {
		t.Fatalf("status after logout with replayed cookie: %d, want 404", rec.Code)
	}
}

// TestLogoutKeepsOtherSessions: logout revokes only the current session.
// Product policy: another browser (or tab) logged in as the same user
// keeps working until it logs out itself or the password changes.
func TestLogoutKeepsOtherSessions(t *testing.T) {
	engine := setupSecureCookieEngine(t, nil)
	first := loginAsAdmin(t, engine)
	second := loginAsAdmin(t, engine)
	if sessionCookie(t, first).Value == sessionCookie(t, second).Value {
		t.Fatal("two logins produced identical session cookies, want distinct sessions")
	}
	logout(t, engine, first)
	if rec := getServerStatus(t, engine, first); rec.Code != http.StatusNotFound {
		t.Fatalf("logged-out session still works: status %d, want 404", rec.Code)
	}
	if rec := getServerStatus(t, engine, second); rec.Code != http.StatusOK {
		t.Fatalf("other session after logout: status %d, want 200", rec.Code)
	}
}

// TestPasswordChangeRevokesOtherSessions: changing the password ends
// every other session at once. The browser that changed the password
// gets a fresh session and keeps working.
func TestPasswordChangeRevokesOtherSessions(t *testing.T) {
	engine := setupSecureCookieEngine(t, nil)
	current := loginAsAdmin(t, engine)
	other := loginAsAdmin(t, engine)

	body := strings.NewReader(`{"oldUsername":"admin","oldPassword":"admin","newUsername":"admin","newPassword":"newpass123"}`)
	req := httptest.NewRequest(http.MethodPost, "/panel/setting/updateUser", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	for _, c := range current {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"success":true`) {
		t.Fatalf("updateUser: status %d, body %s", rec.Code, rec.Body.String())
	}
	// The password change refreshes the current browser's session: the
	// response carries a new cookie, which must keep working.
	refreshed := rec.Result().Cookies()
	if len(refreshed) == 0 {
		t.Fatal("updateUser: no Set-Cookie in response")
	}
	if r := getServerStatus(t, engine, refreshed); r.Code != http.StatusOK {
		t.Fatalf("current session after password change: status %d, want 200", r.Code)
	}
	// The other session is revoked.
	if r := getServerStatus(t, engine, other); r.Code != http.StatusNotFound {
		t.Fatalf("other session after password change: status %d, want 404", r.Code)
	}
	// And the new password logs in.
	body = strings.NewReader(`{"username":"admin","password":"newpass123"}`)
	req = httptest.NewRequest(http.MethodPost, "/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	rec = httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login with new password: status %d, body %s", rec.Code, rec.Body.String())
	}
}

// startPanelBehindProxy fronts the real panel router with a reverse proxy
// that preserves the external Host, like a production TLS-terminating
// proxy (nginx proxy_set_header Host $http_host, or ProxyPreserveHost).
// The backend itself serves plain HTTP, so it sees r.TLS == nil while the
// browser's Origin is the external https://panel.example.com.
// preservedHost is the Host value the proxy forwards: "" means it does not
// preserve the external Host at all, and any other value is forwarded
// verbatim — including a port, e.g. "panel.example.com:8443" for the
// $http_host form, or "panel.example.com" for the broken $host form that
// drops the external port.
func startPanelBehindProxy(t *testing.T, settings map[string]string, preservedHost string) string {
	t.Helper()
	engine := setupSecureCookieEngine(t, settings)
	backend := httptest.NewServer(engine)
	t.Cleanup(backend.Close)

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			if preservedHost != "" {
				// Preserve the external Host the browser used; without
				// this the panel sees the backend's own host and both
				// the CSRF check (Origin must match Host) and the
				// WebSocket origin check compare against the wrong name.
				r.Out.Host = preservedHost
			}
		},
	}
	front := httptest.NewServer(proxy)
	t.Cleanup(front.Close)
	return front.URL
}

// loginThroughProxy logs in via the proxy the way the panel frontend
// does: JSON body, X-Requested-With header, and the external Origin.
func loginThroughProxy(t *testing.T, proxyURL, externalOrigin string) []*http.Cookie {
	t.Helper()
	body := strings.NewReader(`{"username":"admin","password":"admin"}`)
	req, err := http.NewRequest(http.MethodPost, proxyURL+"/login", body)
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Origin", externalOrigin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login through proxy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login through proxy: status %d", resp.StatusCode)
	}
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("login through proxy: no Set-Cookie")
	}
	return cookies
}

// loginThroughProxyExpectCSRFRefusal logs in via the proxy and expects the
// CSRF check to refuse it with exactly 403 and the origin-mismatch error,
// not merely a non-200 status (a 404 or 500 from an unrelated failure
// must not pass this test).
func loginThroughProxyExpectCSRFRefusal(t *testing.T, proxyURL, externalOrigin string) {
	t.Helper()
	body := strings.NewReader(`{"username":"admin","password":"admin"}`)
	req, err := http.NewRequest(http.MethodPost, proxyURL+"/login", body)
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Origin", externalOrigin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login through proxy: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("login through proxy: read body: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("login through proxy: status %d, want 403 (body %q)", resp.StatusCode, raw)
	}
	if !strings.Contains(string(raw), "origin mismatch") {
		t.Fatalf("login through proxy: 403 body %q, want the origin mismatch error", raw)
	}
}

func dialWSViaProxy(proxyURL string, cookies []*http.Cookie, externalOrigin string) (*websocket.Conn, *http.Response, error) {
	wsURL := "ws://" + strings.TrimPrefix(proxyURL, "http://") + "/ws"
	header := http.Header{}
	header.Set("Origin", externalOrigin)
	for _, c := range cookies {
		header.Add("Cookie", c.Name+"="+c.Value)
	}
	return (&websocket.Dialer{HandshakeTimeout: 5 * time.Second}).Dial(wsURL, header)
}

// TestWebSocketThroughReverseProxy: the real deployment shape — a
// TLS-terminating reverse proxy in front of the panel. The browser
// reaches the proxy over HTTPS while the proxy talks plain HTTP to the
// panel, preserving the external Host.
//
//   - With wsTrustedOrigins set to the external origin, the WebSocket
//     connects: the panel only sees plain HTTP, so the HTTPS origin
//     matches nothing on its own, but it matches the trusted entry.
//   - Without wsTrustedOrigins, the same connection is refused (403):
//     the HTTPS origin matches neither the panel's own plain-HTTP
//     origin nor any trusted entry.
//   - Without Host preservation, even the login is refused: the CSRF
//     check requires Origin to match the request Host, and the backend
//     would see its own address instead of the external name.
//   - With a non-default external port (https://panel.example.com:8443)
//     the login and the WebSocket both work when the proxy preserves
//     the full Host including the port ($http_host).
//   - With the same :8443 address but a proxy that preserves only the
//     bare host (the nginx $host form, which drops the port), the login
//     is refused: the browser's Origin contains :8443 while the panel
//     sees Host panel.example.com, so the CSRF check rejects it.
func TestWebSocketThroughReverseProxy(t *testing.T) {
	proxyURL := startPanelBehindProxy(t, map[string]string{
		"wsTrustedOrigins": "https://panel.example.com",
		"webSecureCookie":  "true",
	}, "panel.example.com")
	cookies := loginThroughProxy(t, proxyURL, "https://panel.example.com")
	conn, _, err := dialWSViaProxy(proxyURL, cookies, "https://panel.example.com")
	if err != nil {
		t.Fatalf("websocket dial through proxy failed: %v", err)
	}
	conn.Close()

	proxyURL = startPanelBehindProxy(t, nil, "panel.example.com")
	cookies = loginThroughProxy(t, proxyURL, "https://panel.example.com")
	_, resp, err := dialWSViaProxy(proxyURL, cookies, "https://panel.example.com")
	if err == nil {
		t.Fatal("websocket dial without wsTrustedOrigins succeeded, want rejection")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("websocket dial without wsTrustedOrigins: err=%v status=%d, want 403", err, status)
	}

	proxyURL = startPanelBehindProxy(t, map[string]string{
		"wsTrustedOrigins": "https://panel.example.com",
		"webSecureCookie":  "true",
	}, "")
	loginThroughProxyExpectCSRFRefusal(t, proxyURL, "https://panel.example.com")

	// Non-default external port, Host preserved with the port: login
	// and WebSocket both work.
	proxyURL = startPanelBehindProxy(t, map[string]string{
		"wsTrustedOrigins": "https://panel.example.com:8443",
		"webSecureCookie":  "true",
	}, "panel.example.com:8443")
	cookies = loginThroughProxy(t, proxyURL, "https://panel.example.com:8443")
	conn, _, err = dialWSViaProxy(proxyURL, cookies, "https://panel.example.com:8443")
	if err != nil {
		t.Fatalf("websocket dial through proxy on :8443 failed: %v", err)
	}
	conn.Close()

	// Same :8443 address, but the proxy preserves only the bare host
	// (nginx $host, which drops the port): the CSRF check must refuse
	// the login, because Origin https://panel.example.com:8443 does not
	// match Host panel.example.com. This is a proxy misconfiguration,
	// not a reason to relax the CSRF check.
	proxyURL = startPanelBehindProxy(t, map[string]string{
		"wsTrustedOrigins": "https://panel.example.com:8443",
		"webSecureCookie":  "true",
	}, "panel.example.com")
	loginThroughProxyExpectCSRFRefusal(t, proxyURL, "https://panel.example.com:8443")
}
