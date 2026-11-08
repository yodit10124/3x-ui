package controller

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestGetRemoteIp covers H-1: forwarding headers must be ignored unless
// the direct peer is a trusted reverse proxy (XUI_TRUSTED_PROXIES).
func TestGetRemoteIp(t *testing.T) {
	gin.SetMode(gin.TestMode)

	makeCtx := func(remoteAddr string, headers map[string]string) *gin.Context {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remoteAddr
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = req
		return c
	}

	tests := []struct {
		name       string
		trustedEnv string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "direct access ignores X-Forwarded-For",
			trustedEnv: "",
			remoteAddr: "203.0.113.10:12345",
			headers:    map[string]string{"X-Forwarded-For": "9.9.9.9"},
			want:       "203.0.113.10",
		},
		{
			name:       "direct access ignores X-Real-IP",
			trustedEnv: "",
			remoteAddr: "203.0.113.10:12345",
			headers:    map[string]string{"X-Real-IP": "9.9.9.9"},
			want:       "203.0.113.10",
		},
		{
			name:       "direct access returns RemoteAddr without headers",
			trustedEnv: "",
			remoteAddr: "203.0.113.10:12345",
			want:       "203.0.113.10",
		},
		{
			name:       "trusted proxy honours X-Forwarded-For",
			trustedEnv: "127.0.0.1",
			remoteAddr: "127.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.7"},
			want:       "198.51.100.7",
		},
		{
			name:       "trusted proxy honours X-Real-IP without XFF",
			trustedEnv: "127.0.0.1",
			remoteAddr: "127.0.0.1:54321",
			headers:    map[string]string{"X-Real-IP": "198.51.100.7"},
			want:       "198.51.100.7",
		},
		{
			name:       "trusted proxy chain returns first untrusted entry from the right",
			trustedEnv: "127.0.0.1, 10.0.0.0/8",
			remoteAddr: "127.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.7, 10.0.0.5"},
			want:       "198.51.100.7",
		},
		{
			name:       "trusted proxy chain all trusted returns leftmost client",
			trustedEnv: "127.0.0.1, 10.0.0.0/8",
			remoteAddr: "127.0.0.1:54321",
			headers:    map[string]string{"X-Forwarded-For": "10.0.0.9, 10.0.0.5"},
			want:       "10.0.0.9",
		},
		{
			name:       "untrusted peer in CIDR range is not trusted",
			trustedEnv: "10.0.0.0/8",
			remoteAddr: "192.0.2.1:12345",
			headers:    map[string]string{"X-Forwarded-For": "9.9.9.9"},
			want:       "192.0.2.1",
		},
		{
			name:       "unparseable RemoteAddr returns unknown",
			trustedEnv: "",
			remoteAddr: "not-an-ip",
			want:       "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("XUI_TRUSTED_PROXIES", tt.trustedEnv)
			if got := getRemoteIp(makeCtx(tt.remoteAddr, tt.headers)); got != tt.want {
				t.Errorf("getRemoteIp() = %q, want %q", got, tt.want)
			}
		})
	}
}
