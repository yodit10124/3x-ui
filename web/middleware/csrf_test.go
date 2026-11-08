package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestCSRFMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(CSRFMiddleware())
	// Stand-in handlers: any request that passes the middleware gets 200.
	engine.POST("/panel/setting/all", func(c *gin.Context) { c.Status(http.StatusOK) })
	engine.POST("/panel/xray/update", func(c *gin.Context) { c.Status(http.StatusOK) })
	engine.POST("/panel/api/inbounds/add", func(c *gin.Context) { c.Status(http.StatusOK) })
	engine.GET("/panel/setting/all", func(c *gin.Context) { c.Status(http.StatusOK) })
	engine.POST("/logout", func(c *gin.Context) { c.Status(http.StatusOK) })
	engine.POST("/login", func(c *gin.Context) { c.Status(http.StatusOK) })

	cases := []struct {
		name       string
		method     string
		path       string
		headers    map[string]string
		wantStatus int
	}{
		{"panel setting POST without header", http.MethodPost, "/panel/setting/all", nil, http.StatusForbidden},
		{"panel setting POST with header", http.MethodPost, "/panel/setting/all", map[string]string{"X-Requested-With": "XMLHttpRequest"}, http.StatusOK},
		{"panel xray POST without header", http.MethodPost, "/panel/xray/update", nil, http.StatusForbidden},
		{"panel api POST without header is 404 not 403", http.MethodPost, "/panel/api/inbounds/add", nil, http.StatusNotFound},
		{"panel api POST with header", http.MethodPost, "/panel/api/inbounds/add", map[string]string{"X-Requested-With": "XMLHttpRequest"}, http.StatusOK},
		{"panel GET is not checked", http.MethodGet, "/panel/setting/all", nil, http.StatusOK},
		{"logout POST without header", http.MethodPost, "/logout", nil, http.StatusForbidden},
		{"logout POST with header", http.MethodPost, "/logout", map[string]string{"X-Requested-With": "XMLHttpRequest"}, http.StatusOK},
		{"login POST without header", http.MethodPost, "/login", nil, http.StatusForbidden},
		{"login POST with header", http.MethodPost, "/login", map[string]string{"X-Requested-With": "XMLHttpRequest"}, http.StatusOK},
		{"cross-origin Origin rejected", http.MethodPost, "/panel/setting/all", map[string]string{"X-Requested-With": "XMLHttpRequest", "Origin": "http://evil.example"}, http.StatusForbidden},
		{"same-origin Origin accepted", http.MethodPost, "/panel/setting/all", map[string]string{"X-Requested-With": "XMLHttpRequest", "Origin": "http://example.com"}, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Errorf("%s %s: got status %d, want %d", tc.method, tc.path, w.Code, tc.wantStatus)
			}
		})
	}
}
