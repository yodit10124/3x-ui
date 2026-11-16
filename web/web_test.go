package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
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
	"github.com/mhsanaei/3x-ui/v2/web/global"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/session"
	panelws "github.com/mhsanaei/3x-ui/v2/web/websocket"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/websocket"
	"github.com/op/go-logging"
	"github.com/robfig/cron/v3"
)

// testWebServer is the minimal global.WebServer stub the API controller's
// background status task needs (it registers a cron func at startup).
// The hub is the real one initRouter builds, so websocket.GetHub() —
// used by logout/password-change to close live connections — resolves
// to the same hub the engine serves.
type testWebServer struct {
	cron *cron.Cron
	hub  *panelws.Hub
}

func (w *testWebServer) GetCron() *cron.Cron     { return w.cron }
func (w *testWebServer) GetCtx() context.Context { return context.Background() }
func (w *testWebServer) GetWSHub() any           { return w.hub }

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
	stub := &testWebServer{cron: cron.New()}
	global.SetWebServer(stub)
	t.Cleanup(func() { global.SetWebServer(nil) })

	srv := &Server{}
	engine, err := srv.initRouter()
	if err != nil {
		t.Fatalf("initRouter: %v", err)
	}
	// Expose the real hub through the stub so websocket.GetHub()
	// resolves to the hub this engine serves.
	stub.hub = srv.wsHub
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
// TestSessionPasswordHashBackfill: a session row created before the
// password-hash column existed (empty hash) self-heals on its first
// authenticated request, so the WebSocket sweeper does not keep
// dropping its connections after an upgrade.
func TestEmptyPasswordHashSessionRejected(t *testing.T) {
	engine := setupSecureCookieEngine(t, nil)
	cookies := loginAsAdmin(t, engine)

	db := database.GetDB()
	if err := db.Model(&model.LoginSession{}).Where("1 = 1").Update("password_hash", "").Error; err != nil {
		t.Fatalf("clear password_hash: %v", err)
	}
	// A session whose row carries no password hash predates the hash
	// column: it must not be bound to the current password on first
	// access (that would let it survive a password change that
	// happened before that access). It is invalid outright and the
	// row is deleted; the caller logs in again.
	if rec := getServerStatus(t, engine, cookies); rec.Code != http.StatusNotFound {
		t.Fatalf("status with empty-hash session: %d, want 404", rec.Code)
	}
	var rows []model.LoginSession
	if err := db.Find(&rows).Error; err != nil {
		t.Fatalf("read sessions: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("sessions %d after empty-hash rejection, want 0", len(rows))
	}
	// The same cookie cannot open a WebSocket either.
	backend := httptest.NewServer(engine)
	t.Cleanup(backend.Close)
	if _, resp, err := dialWS(t, backend.URL, cookies); err == nil {
		t.Fatal("websocket dial with empty-hash session succeeded, want rejection")
	} else if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("websocket dial with empty-hash session: err=%v status=%d, want 401", err, status)
	}
	// A fresh login still works.
	if rec := getServerStatus(t, engine, loginAsAdmin(t, engine)); rec.Code != http.StatusOK {
		t.Fatalf("status after re-login: %d, want 200", rec.Code)
	}
}

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

// decodeCookiePayload reverses the two base64 layers of a signed (not
// encrypted) gorilla/securecookie value, the way anyone holding the
// cookie can: the outer layer is base64("timestamp|base64(gob)|mac")
// and the inner layer is the raw gob payload. No secret is needed —
// the signature only proves the cookie was not tampered with, it never
// hid its contents.
func decodeCookiePayload(t *testing.T, value string) []byte {
	t.Helper()
	outer, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("decode cookie outer layer: %v", err)
	}
	parts := bytes.SplitN(outer, []byte("|"), 3)
	if len(parts) != 3 {
		t.Fatalf("cookie outer layer has %d parts, want 3", len(parts))
	}
	gob, err := base64.URLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		t.Fatalf("decode cookie gob layer: %v", err)
	}
	return gob
}

// TestLoginCookieHoldsNoPasswordHash: the login cookie must hold only
// the random session ID. Its decodable contents must not contain the
// password, the bcrypt hash, or a user object.
func TestLoginCookieHoldsNoPasswordHash(t *testing.T) {
	engine := setupSecureCookieEngine(t, nil)
	cookies := loginAsAdmin(t, engine)

	var admin model.User
	if err := database.GetDB().Where("username = ?", "admin").First(&admin).Error; err != nil {
		t.Fatalf("read admin: %v", err)
	}
	var payload []byte
	for _, c := range cookies {
		payload = append(payload, decodeCookiePayload(t, c.Value)...)
	}
	if bytes.Contains(payload, []byte(admin.Password)) {
		t.Fatal("login cookie decodes to the bcrypt password hash")
	}
	if bytes.Contains(payload, []byte("LOGIN_USER")) {
		t.Fatal("login cookie decodes to a user object (LOGIN_USER)")
	}
	if bytes.Contains(payload, []byte("Password")) {
		t.Fatal("login cookie decodes to a password field")
	}
	if bytes.Contains(payload, []byte("admin")) {
		t.Fatal("login cookie decodes to the username (no user data belongs in it)")
	}
	if !bytes.Contains(payload, []byte("LOGIN_SESSION_ID")) {
		t.Fatal("login cookie does not decode to a session ID (wrong payload?)")
	}
	// The ID-only cookie must still authenticate.
	if rec := getServerStatus(t, engine, cookies); rec.Code != http.StatusOK {
		t.Fatalf("status with ID-only cookie: %d, want 200", rec.Code)
	}
}

// forgeOldFormatCookie rebuilds a login cookie the old way, signed
// with the panel's own secret: the same session ID plus the full user
// object (including the bcrypt hash).
func forgeOldFormatCookie(t *testing.T, cookies []*http.Cookie) []*http.Cookie {
	t.Helper()
	secret, err := (&service.SettingService{}).GetSecret()
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	var admin model.User
	if err := database.GetDB().Where("username = ?", "admin").First(&admin).Error; err != nil {
		t.Fatalf("read admin: %v", err)
	}
	sc := securecookie.New(secret, nil)
	// The sessions store serializes the session as
	// map[interface{}]interface{}.
	var values map[interface{}]interface{}
	var cookieValue string
	for _, c := range cookies {
		if c.Name != "3x-ui" {
			continue
		}
		cookieValue = c.Value
		if err := sc.Decode("3x-ui", c.Value, &values); err != nil {
			t.Fatalf("decode session cookie: %v", err)
		}
	}
	if cookieValue == "" || values == nil {
		t.Fatal("no 3x-ui cookie from login")
	}
	values["LOGIN_USER"] = admin
	oldValue, err := sc.Encode("3x-ui", values)
	if err != nil {
		t.Fatalf("encode old-format cookie: %v", err)
	}
	return []*http.Cookie{{Name: "3x-ui", Value: oldValue}}
}

// TestOldFormatCookieIsRevoked: a cookie carrying the old format (the
// session ID plus the full user object, including the bcrypt hash) is
// rejected and its server-side session revoked, forcing a fresh login.
func TestOldFormatCookieIsRevoked(t *testing.T) {
	engine := setupSecureCookieEngine(t, nil)
	cookies := loginAsAdmin(t, engine)
	oldCookies := forgeOldFormatCookie(t, cookies)

	// Rejected, and the server-side session is gone: the row is
	// deleted, so the original cookie dies with it.
	if rec := getServerStatus(t, engine, oldCookies); rec.Code != http.StatusNotFound {
		t.Fatalf("status with old-format cookie: %d, want 404", rec.Code)
	}
	var rows []model.LoginSession
	if err := database.GetDB().Find(&rows).Error; err != nil {
		t.Fatalf("read sessions: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("sessions %d after old-format rejection, want 0 (revoked)", len(rows))
	}
	if rec := getServerStatus(t, engine, cookies); rec.Code != http.StatusNotFound {
		t.Fatalf("status with original cookie after revocation: %d, want 404", rec.Code)
	}
	// A fresh login still works and issues the new format.
	cookies = loginAsAdmin(t, engine)
	if rec := getServerStatus(t, engine, cookies); rec.Code != http.StatusOK {
		t.Fatalf("status after re-login: %d, want 200", rec.Code)
	}
}

// TestReloginWithOldCookieDropsUserObject: logging in again while
// carrying an old-format cookie must not keep the user object in the
// new cookie. The session map loaded from the old cookie still holds
// LOGIN_USER (with the bcrypt hash); saving it again would make the
// next request revoke the fresh session on sight — a login loop that
// keeps carrying the hash.
func TestReloginWithOldCookieDropsUserObject(t *testing.T) {
	engine := setupSecureCookieEngine(t, nil)
	cookies := loginAsAdmin(t, engine)
	oldCookies := forgeOldFormatCookie(t, cookies)

	// Re-login carrying the old-format cookie, the way a browser does.
	body := strings.NewReader(`{"username":"admin","password":"admin"}`)
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	for _, c := range oldCookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-login with old cookie: %d, want 200", rec.Code)
	}
	newCookies := rec.Result().Cookies()

	var admin model.User
	if err := database.GetDB().Where("username = ?", "admin").First(&admin).Error; err != nil {
		t.Fatalf("read admin: %v", err)
	}
	var payload []byte
	for _, c := range newCookies {
		payload = append(payload, decodeCookiePayload(t, c.Value)...)
	}
	if bytes.Contains(payload, []byte(admin.Password)) {
		t.Fatal("re-login cookie still decodes to the bcrypt password hash")
	}
	if bytes.Contains(payload, []byte("LOGIN_USER")) {
		t.Fatal("re-login cookie still carries the user object (LOGIN_USER)")
	}
	if !bytes.Contains(payload, []byte("LOGIN_SESSION_ID")) {
		t.Fatal("re-login cookie does not decode to a session ID (wrong payload?)")
	}
	// The new cookie authenticates: no login loop.
	if rec := getServerStatus(t, engine, newCookies); rec.Code != http.StatusOK {
		t.Fatalf("status with re-login cookie: %d, want 200", rec.Code)
	}
	// And again, to prove the loop is really gone.
	if rec := getServerStatus(t, engine, newCookies); rec.Code != http.StatusOK {
		t.Fatalf("second status with re-login cookie: %d, want 200", rec.Code)
	}
}

func assertNoStore(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("%s: Cache-Control %q, want \"no-store\"", what, cc)
	}
}

// TestSensitiveResponsesAreNoStore: login, logout, management pages and
// sensitive APIs must all carry Cache-Control: no-store, while static
// assets keep their own caching.
func TestSensitiveResponsesAreNoStore(t *testing.T) {
	engine := setupSecureCookieEngine(t, nil)

	// Login response.
	body := strings.NewReader(`{"username":"admin","password":"admin"}`)
	req := httptest.NewRequest(http.MethodPost, "/login", body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d, want 200", rec.Code)
	}
	assertNoStore(t, "login", rec)
	cookies := rec.Result().Cookies()

	// Management page (the login page HTML).
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	rec = httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("index page: %d, want 200", rec.Code)
	}
	assertNoStore(t, "index page", rec)

	// Sensitive APIs (authenticated).
	for _, path := range []string{"/panel/api/server/status", "/panel/api/inbounds/list"} {
		req = httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec = httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: %d, want 200", path, rec.Code)
		}
		assertNoStore(t, path, rec)
	}

	// Logout response.
	req = httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("logout: %d, want 307", rec.Code)
	}
	assertNoStore(t, "logout", rec)

	// Static assets keep their own caching: no no-store forced on them.
	req = httptest.NewRequest(http.MethodGet, "/assets/js/axios-init.js", nil)
	rec = httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("asset: %d, want 200", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); strings.Contains(cc, "no-store") {
		t.Fatalf("static asset has Cache-Control %q, want no no-store", cc)
	}
}

// dialWS opens a real WebSocket to the panel backend with the given
// session cookies, the way a browser does (same-origin Origin).
func dialWS(t *testing.T, backendURL string, cookies []*http.Cookie) (*websocket.Conn, *http.Response, error) {
	t.Helper()
	wsURL := "ws://" + strings.TrimPrefix(backendURL, "http://") + "/ws"
	header := http.Header{}
	header.Set("Origin", backendURL)
	for _, c := range cookies {
		header.Add("Cookie", c.Name+"="+c.Value)
	}
	return (&websocket.Dialer{HandshakeTimeout: 5 * time.Second}).Dial(wsURL, header)
}

// readWSUntil reads data messages until one contains marker or the
// deadline passes. Other messages — e.g. the status broadcast the
// server sends every 2s — are skipped.
func readWSUntil(t *testing.T, conn *websocket.Conn, marker string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(deadline)
		_, msg, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("read websocket: %v (want message containing %q)", err, marker)
		}
		if strings.Contains(string(msg), marker) {
			return
		}
	}
	t.Fatalf("timed out waiting for websocket message containing %q", marker)
}

// TestLogoutClosesWebSocket is the auditor's scenario with two
// independent sessions: A and B log in and connect; A logs out; A's
// connection must close promptly and stop receiving pushes, B must keep
// working, and A's old cookie must not reconnect.
func TestLogoutClosesWebSocket(t *testing.T) {
	engine := setupSecureCookieEngine(t, nil)
	backend := httptest.NewServer(engine)
	t.Cleanup(backend.Close)

	aCookies := loginAsAdmin(t, engine)
	bCookies := loginAsAdmin(t, engine)

	aConn, _, err := dialWS(t, backend.URL, aCookies)
	if err != nil {
		t.Fatalf("dial A: %v", err)
	}
	defer aConn.Close()
	bConn, _, err := dialWS(t, backend.URL, bCookies)
	if err != nil {
		t.Fatalf("dial B: %v", err)
	}
	defer bConn.Close()

	// Both connections receive pushes. The dial returns as soon as the
	// 101 handshake completes, which is before the handler registers
	// the client (Register validates the session first), so wait
	// until both clients are actually in the hub before broadcasting
	// the single-shot probe — otherwise it can land before
	// registration and the read times out.
	hub, ok := global.GetWebServer().GetWSHub().(*panelws.Hub)
	if !ok || hub == nil {
		t.Fatal("no hub in test server")
	}
	deadline := time.Now().Add(5 * time.Second)
	for hub.GetClientCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hub.GetClientCount() != 2 {
		t.Fatalf("hub client count %d, want 2", hub.GetClientCount())
	}
	panelws.BroadcastStatus(map[string]any{"probe": "ws-before-logout"})
	readWSUntil(t, aConn, "ws-before-logout", 5*time.Second)
	readWSUntil(t, bConn, "ws-before-logout", 5*time.Second)

	// A logs out: the HTTP session is revoked and A's connection must
	// close promptly (the server sends a close frame when the hub
	// removes the client). A read timeout means the connection is
	// still open — that is the failure the auditor found — while a
	// close frame or EOF means it is dead.
	logout(t, engine, aCookies)
	_ = aConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := aConn.ReadMessage(); err == nil {
		t.Fatal("A's websocket stayed open after logout, want it closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("A's websocket still open after logout (read timed out): %v", err)
	}

	// B is untouched: still connected and still receiving pushes.
	panelws.BroadcastStatus(map[string]any{"probe": "ws-after-logout"})
	readWSUntil(t, bConn, "ws-after-logout", 5*time.Second)

	// A's old cookie cannot reconnect: its session row is gone.
	if _, resp, err := dialWS(t, backend.URL, aCookies); err == nil {
		t.Fatal("websocket dial with logged-out cookie succeeded, want rejection")
	} else if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("websocket dial with logged-out cookie: err=%v status=%d, want 401", err, status)
	}
}

// TestLogoutDuringWebSocketHandshake: the logout lands while a
// WebSocket is still handshaking — authenticated, upgraded, but not
// yet registered. Register re-validates the session at registration
// time, so the connection is refused instead of joining the hub and
// living until the next sweep. The ordering is controlled with a
// blocking validator (no sleeps): the dial blocks inside validation
// until the test logs out and releases it.
func TestLogoutDuringWebSocketHandshake(t *testing.T) {
	engine := setupSecureCookieEngine(t, nil)
	backend := httptest.NewServer(engine)
	t.Cleanup(backend.Close)

	cookies := loginAsAdmin(t, engine)

	hub, ok := global.GetWebServer().GetWSHub().(*panelws.Hub)
	if !ok || hub == nil {
		t.Fatal("no hub in test server")
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	hub.SetSessionValidator(func(sessionID string, userID int) bool {
		once.Do(func() { close(entered) })
		<-release
		// The real check: after the logout below the row is gone.
		return session.ValidateSessionID(sessionID, userID)
	})

	type dialResult struct {
		conn *websocket.Conn
		resp *http.Response
		err  error
	}
	res := make(chan dialResult, 1)
	go func() {
		wsURL := "ws://" + strings.TrimPrefix(backend.URL, "http://") + "/ws"
		header := http.Header{}
		header.Set("Origin", backend.URL)
		for _, c := range cookies {
			header.Add("Cookie", c.Name+"="+c.Value)
		}
		conn, resp, err := (&websocket.Dialer{HandshakeTimeout: 5 * time.Second}).Dial(wsURL, header)
		res <- dialResult{conn, resp, err}
	}()

	// Wait until the handler is blocked inside Register's validation.
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("hub Register never started validation")
	}
	if n := hub.GetClientCount(); n != 0 {
		t.Fatalf("client registered before validation finished: %d", n)
	}

	// The logout lands while the handshake is in flight.
	logout(t, engine, cookies)
	close(release)

	d := <-res
	if d.err != nil {
		t.Fatalf("websocket dial failed: %v", d.err)
	}
	defer d.conn.Close()
	_ = d.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := d.conn.ReadMessage(); err == nil {
		t.Fatal("websocket stayed open after logout during handshake, want it closed")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("websocket still open after logout during handshake (read timed out): %v", err)
	}
	if n := hub.GetClientCount(); n != 0 {
		t.Fatalf("hub still holds %d clients after refused registration", n)
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
