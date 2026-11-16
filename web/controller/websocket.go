package controller

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/web/session"
	"github.com/mhsanaei/3x-ui/v2/web/websocket"

	"github.com/gin-gonic/gin"
	ws "github.com/gorilla/websocket"
)

const (
	writeWait       = 10 * time.Second
	pongWait        = 60 * time.Second
	pingPeriod      = (pongWait * 9) / 10
	clientReadLimit = 512
)

var defaultUpgrader = ws.Upgrader{
	ReadBufferSize:    32768,
	WriteBufferSize:   32768,
	EnableCompression: true,
}

// originTriple is a parsed origin: scheme, host and effective port.
// WebSocket origins are compared as this full triple — matching only the
// hostname, as the old check did, lets a page on another port (or served
// over plain HTTP while the panel is on HTTPS) open a socket with the
// admin's session.
type originTriple struct {
	scheme string
	host   string
	port   int
}

func (t originTriple) equals(o originTriple) bool {
	return t.scheme == o.scheme && strings.EqualFold(t.host, o.host) && t.port == o.port
}

func defaultPort(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

// parseOriginTriple parses a full origin (scheme://host[:port]). The scheme
// must be http or https, the host non-empty; a missing port resolves to
// the scheme default. Anything else (user info, a bare host, an unknown
// scheme, a bad port) is not an origin.
func parseOriginTriple(raw string) (originTriple, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil {
		return originTriple{}, false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return originTriple{}, false
	}
	host := u.Hostname()
	if host == "" {
		return originTriple{}, false
	}
	port := defaultPort(scheme)
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return originTriple{}, false
		}
		port = n
	}
	return originTriple{scheme: scheme, host: host, port: port}, true
}

// splitHostPort splits a Host header value (host, host:port, [ipv6] or
// [ipv6]:port) into host and effective port for the given scheme.
// Malformed values are rejected.
func splitHostPort(hostport, scheme string) (string, int, bool) {
	if hostport == "" {
		return "", 0, false
	}
	defPort := defaultPort(scheme)
	// Bracketed IPv6 literal, with or without a port.
	if strings.HasPrefix(hostport, "[") {
		i := strings.LastIndex(hostport, "]")
		if i < 0 {
			return "", 0, false
		}
		host := hostport[1:i]
		rest := hostport[i+1:]
		if rest == "" {
			return host, defPort, true
		}
		if !strings.HasPrefix(rest, ":") {
			return "", 0, false
		}
		p, err := strconv.Atoi(rest[1:])
		if err != nil || p <= 0 || p > 65535 {
			return "", 0, false
		}
		return host, p, true
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err == nil {
		if portStr == "" {
			return host, defPort, true
		}
		p, err := strconv.Atoi(portStr)
		if err != nil || p <= 0 || p > 65535 {
			return "", 0, false
		}
		return host, p, true
	}
	// No port: the whole value is the host — unless it contains a colon,
	// which means a malformed port (or an unbracketed IPv6 literal).
	if strings.Contains(hostport, ":") {
		return "", 0, false
	}
	return hostport, defPort, true
}

// checkOriginAllowed decides whether the Origin header value may open a
// WebSocket to a request whose Host is reqHost and whose scheme is https
// when reqTLS is set. trusted holds the configured external origins.
//
// Rules:
//   - No Origin header: allowed. That is a non-browser client (curl, a
//     native app) or an old browser; the login check in HandleWebSocket
//     still applies, so this is not an authentication bypass.
//   - Otherwise the Origin must parse as a full origin and match the
//     request's own origin triple (scheme, host, effective port), or one
//     of the trusted origins, exactly. Same host on a different port, a
//     different scheme, or another domain is rejected — and a trusted
//     entry never matches a different port than the one listed.
func checkOriginAllowed(origin, reqHost string, reqTLS bool, trusted []string) bool {
	if origin == "" {
		return true
	}
	o, ok := parseOriginTriple(origin)
	if !ok {
		return false
	}
	scheme := "http"
	if reqTLS {
		scheme = "https"
	}
	reqHostName, reqPort, ok := splitHostPort(reqHost, scheme)
	if !ok {
		return false
	}
	if o.equals(originTriple{scheme: scheme, host: reqHostName, port: reqPort}) {
		return true
	}
	for _, raw := range trusted {
		if t, ok := parseOriginTriple(raw); ok && o.equals(t) {
			return true
		}
	}
	return false
}

// WebSocketController handles WebSocket connections for real-time updates.
type WebSocketController struct {
	BaseController
	hub *websocket.Hub
	// trustedOrigins supplies the configured external origins allowed in
	// addition to the panel's own origin. It is read on every upgrade, so
	// a settings change takes effect without a restart. Nil means
	// same-origin only.
	trustedOrigins func() []string
	upgrader       ws.Upgrader
}

// NewWebSocketController creates a new WebSocket controller.
func NewWebSocketController(hub *websocket.Hub, trustedOrigins func() []string) *WebSocketController {
	w := &WebSocketController{hub: hub, trustedOrigins: trustedOrigins}
	w.upgrader = defaultUpgrader
	w.upgrader.CheckOrigin = w.checkOrigin
	return w
}

// checkOrigin enforces the full-origin rule for an upgrade request.
func (w *WebSocketController) checkOrigin(r *http.Request) bool {
	var trusted []string
	if w.trustedOrigins != nil {
		trusted = w.trustedOrigins()
	}
	return checkOriginAllowed(r.Header.Get("Origin"), r.Host, r.TLS != nil, trusted)
}

// HandleWebSocket upgrades the HTTP connection and starts the read/write pumps.
func (w *WebSocketController) HandleWebSocket(c *gin.Context) {
	user := session.GetLoginUser(c)
	if user == nil {
		logger.Warningf("Unauthorized WebSocket connection attempt from %s", getRemoteIp(c))
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	conn, err := w.upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		logger.Error("Failed to upgrade WebSocket connection:", err)
		return
	}

	// Bind the connection to the login session that established it:
	// when that session is revoked (logout, password change, expiry)
	// the hub can close exactly this connection. A logged-out cookie
	// fails GetLoginUser above, so it cannot reconnect either.
	// Register re-validates the session and reports failure: a
	// logout that landed during the handshake, or a hub that stopped
	// while the upgrade was in flight, must not start pumps for a
	// connection nobody will ever close.
	client := websocket.NewClient(uuid.New().String(), session.GetSessionID(c), user.Id)
	if !w.hub.Register(client) {
		logger.Debugf("WebSocket client %s registration refused from %s (session revoked or hub stopped)", client.ID, getRemoteIp(c))
		conn.Close()
		return
	}
	logger.Debugf("WebSocket client %s registered from %s", client.ID, getRemoteIp(c))

	go w.writePump(client, conn)
	go w.readPump(client, conn)
}

// readPump consumes inbound frames so the gorilla deadline/pong machinery keeps
// running. Clients send no commands today; frames are discarded.
func (w *WebSocketController) readPump(client *websocket.Client, conn *ws.Conn) {
	defer func() {
		if r := common.Recover("WebSocket readPump panic"); r != nil {
			logger.Error("WebSocket readPump panic recovered:", r)
		}
		w.hub.Unregister(client)
		conn.Close()
	}()

	conn.SetReadLimit(clientReadLimit)
	conn.SetReadDeadline(time.Now().Add(pongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(pongWait))
	})

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			if ws.IsUnexpectedCloseError(err, ws.CloseGoingAway, ws.CloseAbnormalClosure) {
				logger.Debugf("WebSocket read error for client %s: %v", client.ID, err)
			}
			return
		}
	}
}

// writePump pushes hub messages to the connection and emits keepalive pings.
func (w *WebSocketController) writePump(client *websocket.Client, conn *ws.Conn) {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		if r := common.Recover("WebSocket writePump panic"); r != nil {
			logger.Error("WebSocket writePump panic recovered:", r)
		}
		ticker.Stop()
		conn.Close()
	}()

	for {
		select {
		case msg, ok := <-client.Send:
			conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				conn.WriteMessage(ws.CloseMessage, []byte{})
				return
			}
			if err := conn.WriteMessage(ws.TextMessage, msg); err != nil {
				logger.Debugf("WebSocket write error for client %s: %v", client.ID, err)
				return
			}

		case <-ticker.C:
			conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := conn.WriteMessage(ws.PingMessage, nil); err != nil {
				logger.Debugf("WebSocket ping error for client %s: %v", client.ID, err)
				return
			}
		}
	}
}
