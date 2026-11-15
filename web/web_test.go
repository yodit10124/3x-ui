package web

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
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
