package middleware

import (
	"github.com/gin-gonic/gin"
)

// NoStoreMiddleware marks responses as non-cacheable. It is applied to
// the panel's base path group, which covers the login and logout
// responses, the management pages and every sensitive API — nothing
// under it is safe for a browser or an intermediate proxy to retain.
// Static assets are served outside that group (engine-level StaticFS)
// and keep their own caching. no-store (not no-cache) is deliberate:
// no-cache would still allow storing the response as long as it is
// revalidated, which is not good enough for credentials and panel data.
func NoStoreMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Next()
	}
}
