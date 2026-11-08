package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// SecurityHeadersMiddleware adds defence-in-depth response headers (L3):
// a restrictive Content-Security-Policy, X-Frame-Options, X-Content-Type-Options
// and a Referrer-Policy. CSP is deliberately conservative: the panel's own
// inline scripts/styles are served with 'unsafe-inline' because the bundled
// frontend relies on them; the header still blocks external origins, object
// embeds and form actions to other origins.
//
// 'unsafe-eval' is REQUIRED, not optional: Vue 2.7's template compiler
// compiles the in-DOM templates (new Vue({el: '#app'}), plus components
// with string templates) via `new Function(...)` (vue.min.js, createFunction).
// Without 'unsafe-eval' the browser refuses to evaluate the compiled render
// functions, Vue never mounts, #app stays hidden behind v-cloak and the
// login/panel page is a blank white screen. That is what happened with the
// first build of this fix (2026-11-07): HTML and APIs all returned 200,
// but the page was white in a real browser.
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; form-action 'self'; base-uri 'self'; object-src 'none'")
		c.Header("X-Frame-Options", "SAMEORIGIN")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "same-origin")
		c.Next()
	}
}

// CSRFMiddleware (H3) protects state-changing panel calls against
// cross-site request forgery. Browsers cannot set a custom header from a
// plain cross-site form or <img> request, and the panel frontend (axios,
// web/assets/js/axios-init.js) sends X-Requested-With: XMLHttpRequest on
// every request, so requiring that header on state-changing requests is a
// reliable, low-friction check. In addition, when an Origin or Referer
// header is present it must match the request Host.
//
// Scope: every state-changing request under /panel/ (POST/PUT/DELETE/PATCH),
// which covers /panel/api/*, /panel/setting/* (update, updateUser,
// restartPanel, all, ...) and /panel/xray/* (update, warp/:action,
// nord/*, testOutbound, resetOutboundsTraffic, ...). GET requests are
// read-only, except for /panel/api/backuptotgbot which triggers a Telegram
// backup (a state-changing side effect), so that endpoint is protected too.
// The sensitive GET /panel/api/server/getDb was changed to POST (see
// web/controller/server.go). Two routes outside /panel/ are covered
// explicitly: POST /logout (L-3, logout is POST-only since the GET route
// was removed) and POST /login (login CSRF would log the victim into the
// attacker's account; the login page posts through axios, which always
// sends X-Requested-With, so this does not break login).
//
// 404 instead of 403 under /panel/api/*: this middleware runs before the
// session middleware (web/web.go registers sessions after it) and before
// the per-controller auth (checkAPIAuth / checkLogin), so it cannot tell
// whether the caller is logged in, and it must NOT be moved after auth
// (the global registration order cannot express per-controller auth).
// /panel/api/* is designed to answer 404 to unauthenticated callers
// (checkAPIAuth in web/controller/api.go) to hide endpoint existence, and
// a 403 JSON here would leak it. So every CSRF failure under /panel/api/*
// is answered with a bare 404, logged-in or not. In practice a logged-in
// browser never trips this: axios always sends X-Requested-With with a
// same-origin Origin, so the only cost is a less specific frontend error
// toast ("Request failed" instead of the CSRF message) if a legitimate
// client ever omits the header. /panel/setting/* and /panel/xray/* keep
// the 403 JSON: their auth (checkLogin) answers 401/redirect, not 404,
// so there is no existence-hiding contract to preserve, and the JSON
// message keeps the frontend error toast informative.
func CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		method := c.Request.Method

		needsCheck := false
		switch {
		case strings.Contains(path, "/panel/"):
			needsCheck = method == http.MethodPost || method == http.MethodPut ||
				method == http.MethodDelete || method == http.MethodPatch ||
				strings.HasSuffix(path, "/backuptotgbot")
		case strings.HasSuffix(path, "/logout"):
			// L-3: logout is a state-changing POST; the GET route no
			// longer exists, so only POST needs the check here.
			needsCheck = method == http.MethodPost
		case strings.HasSuffix(path, "/login"):
			needsCheck = method == http.MethodPost
		}
		if !needsCheck {
			c.Next()
			return
		}
		if c.GetHeader("X-Requested-With") != "XMLHttpRequest" {
			abortCSRF(c, path, "missing X-Requested-With header")
			return
		}
		if origin := c.GetHeader("Origin"); origin != "" {
			if u, err := url.Parse(origin); err != nil || u.Host != c.Request.Host {
				abortCSRF(c, path, "origin mismatch")
				return
			}
		} else if referer := c.GetHeader("Referer"); referer != "" {
			if u, err := url.Parse(referer); err != nil || u.Host != c.Request.Host {
				abortCSRF(c, path, "referer mismatch")
				return
			}
		}
		c.Next()
	}
}

// abortCSRF rejects a request that failed the CSRF checks. Under
// /panel/api/* it answers a bare 404 (see the CSRFMiddleware comment:
// checkAPIAuth hides endpoint existence from unauthenticated callers
// with 404, and a 403 JSON here would leak it); everywhere else it
// answers 403 with a JSON message so the frontend can show it.
func abortCSRF(c *gin.Context, path, msg string) {
	if strings.Contains(path, "/panel/api/") {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"success": false, "msg": msg})
}
