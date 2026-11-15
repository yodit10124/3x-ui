package controller

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/web/websocket"
)

func TestCheckOriginAllowed(t *testing.T) {
	cases := []struct {
		name    string
		origin  string
		reqHost string
		reqTLS  bool
		trusted []string
		want    bool
	}{
		// Legitimate panel pages.
		{"same origin http", "http://panel.example.com", "panel.example.com", false, nil, true},
		{"same origin https", "https://panel.example.com", "panel.example.com", true, nil, true},
		{"same origin with explicit port", "http://panel.example.com:2053", "panel.example.com:2053", false, nil, true},
		{"same origin explicit default port", "http://panel.example.com:80", "panel.example.com", false, nil, true},
		{"same origin https explicit default port", "https://panel.example.com:443", "panel.example.com", true, nil, true},
		{"same origin host case-insensitive", "HTTP://PANEL.EXAMPLE.COM", "panel.example.com", false, nil, true},
		{"same origin ipv6", "http://[::1]:2053", "[::1]:2053", false, nil, true},
		{"same origin ipv6 no port", "http://[::1]", "[::1]", false, nil, true},

		// The attacks the old hostname-only check let through.
		{"same host different port", "http://panel.example.com:8080", "panel.example.com", false, nil, false},
		{"same host different port, request has port", "http://panel.example.com:8080", "panel.example.com:2053", false, nil, false},
		{"different scheme, https origin on http panel", "https://panel.example.com", "panel.example.com", false, nil, false},
		{"different scheme, http origin on https panel", "http://panel.example.com", "panel.example.com", true, nil, false},
		{"other domain", "http://evil.example.com", "panel.example.com", false, nil, false},
		{"subdomain is another origin", "http://sub.panel.example.com", "panel.example.com", false, nil, false},
		{"ipv6 different port", "http://[::1]:9999", "[::1]:2053", false, nil, false},

		// Missing Origin: non-browser clients. Allowed by design; the
		// login check in HandleWebSocket still applies.
		{"no origin", "", "panel.example.com", false, nil, true},
		{"no origin https", "", "panel.example.com", true, nil, true},

		// Malformed origins.
		{"not a url", "not a url", "panel.example.com", false, nil, false},
		{"no scheme", "panel.example.com", "panel.example.com", false, nil, false},
		{"unknown scheme", "ftp://panel.example.com", "panel.example.com", false, nil, false},
		{"empty host", "http://", "panel.example.com", false, nil, false},
		{"origin with userinfo", "http://user@panel.example.com", "panel.example.com", false, nil, false},
		{"origin with bad port", "http://panel.example.com:abc", "panel.example.com", false, nil, false},
		{"origin with out-of-range port", "http://panel.example.com:70000", "panel.example.com", false, nil, false},

		// Trusted external origins (reverse-proxy deployments).
		{"trusted proxy origin", "https://public.example.com", "127.0.0.1:2053", false, []string{"https://public.example.com"}, true},
		{"trusted proxy origin with port", "https://public.example.com:8443", "127.0.0.1:2053", false, []string{"https://public.example.com:8443"}, true},
		{"trusted entry without port does not cover another port", "https://public.example.com:8443", "127.0.0.1:2053", false, []string{"https://public.example.com"}, false},
		{"trusted entry with port does not cover default port", "https://public.example.com", "127.0.0.1:2053", false, []string{"https://public.example.com:8443"}, false},
		{"trusted entry different scheme", "http://public.example.com", "127.0.0.1:2053", false, []string{"https://public.example.com"}, false},
		{"trusted entry other domain", "https://other.example.com", "127.0.0.1:2053", false, []string{"https://public.example.com"}, false},
		{"trusted list with malformed entry ignored", "https://public.example.com", "127.0.0.1:2053", false, []string{"not an origin", "https://public.example.com"}, true},
		{"trusted list empty", "https://public.example.com", "127.0.0.1:2053", false, []string{}, false},
		{"same origin still works with a trusted list set", "http://127.0.0.1:2053", "127.0.0.1:2053", false, []string{"https://public.example.com"}, true},

		// Malformed request Host: reject rather than guess.
		{"request host empty", "http://panel.example.com", "", false, nil, false},
		{"request host bad port", "http://panel.example.com:2053", "panel.example.com:abc", false, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkOriginAllowed(tc.origin, tc.reqHost, tc.reqTLS, tc.trusted); got != tc.want {
				t.Fatalf("checkOriginAllowed(%q, %q, tls=%v, %v) = %v, want %v",
					tc.origin, tc.reqHost, tc.reqTLS, tc.trusted, got, tc.want)
			}
		})
	}
}

func TestParseOriginTriple(t *testing.T) {
	cases := []struct {
		raw   string
		want  originTriple
		valid bool
	}{
		{"http://example.com", originTriple{"http", "example.com", 80}, true},
		{"https://example.com", originTriple{"https", "example.com", 443}, true},
		{"https://example.com:8443", originTriple{"https", "example.com", 8443}, true},
		{"http://[::1]:2053", originTriple{"http", "::1", 2053}, true},
		{"HTTPS://EXAMPLE.COM", originTriple{"https", "example.com", 443}, true},
		{"example.com", originTriple{}, false},
		{"ftp://example.com", originTriple{}, false},
		{"http://", originTriple{}, false},
		{"http://user@example.com", originTriple{}, false},
		{"http://example.com:0", originTriple{}, false},
		{"http://example.com:65536", originTriple{}, false},
		{"http://example.com:abc", originTriple{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got, ok := parseOriginTriple(tc.raw)
			if ok != tc.valid {
				t.Fatalf("parseOriginTriple(%q) valid = %v, want %v", tc.raw, ok, tc.valid)
			}
			if tc.valid && !got.equals(tc.want) {
				t.Fatalf("parseOriginTriple(%q) = %+v, want %+v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestWebSocketControllerCheckOrigin exercises the wiring: the controller
// reads its trusted origins from the injected func on every upgrade.
func TestWebSocketControllerCheckOrigin(t *testing.T) {
	hub := websocket.NewHub()
	ctrl := NewWebSocketController(hub, func() []string {
		return []string{"https://public.example.com"}
	})

	allowed := func(origin, host string, useTLS bool) bool {
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:2053/ws", nil)
		req.Host = host
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if useTLS {
			req.TLS = &tls.ConnectionState{}
		}
		return ctrl.checkOrigin(req)
	}

	if !allowed("https://public.example.com", "127.0.0.1:2053", false) {
		t.Fatal("trusted proxy origin rejected")
	}
	if allowed("http://public.example.com", "127.0.0.1:2053", false) {
		t.Fatal("trusted origin with a different scheme accepted")
	}
	if allowed("https://public.example.com:8443", "127.0.0.1:2053", false) {
		t.Fatal("trusted origin on an unlisted port accepted")
	}
	if !allowed("http://127.0.0.1:2053", "127.0.0.1:2053", false) {
		t.Fatal("same-origin request rejected")
	}

	// Nil trusted-origins func: same-origin only.
	ctrl2 := NewWebSocketController(hub, nil)
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:2053/ws", nil)
	req.Host = "127.0.0.1:2053"
	req.Header.Set("Origin", "https://public.example.com")
	if ctrl2.checkOrigin(req) {
		t.Fatal("external origin accepted with no trusted list")
	}
}
