// Package websocket provides a WebSocket hub for real-time updates and notifications.
package websocket

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mhsanaei/3x-ui/v2/logger"
)

// MessageType identifies the kind of WebSocket message.
type MessageType string

const (
	MessageTypeStatus       MessageType = "status"
	MessageTypeTraffic      MessageType = "traffic"
	MessageTypeInbounds     MessageType = "inbounds"
	MessageTypeOutbounds    MessageType = "outbounds"
	MessageTypeNotification MessageType = "notification"
	MessageTypeXrayState    MessageType = "xray_state"
	// MessageTypeClientStats carries absolute traffic counters for the clients
	// that had activity in the latest collection window. Frontend applies these
	// in-place — far smaller than re-broadcasting the full inbound list and
	// scales to 10k+ clients without falling back to REST.
	MessageTypeClientStats MessageType = "client_stats"
	MessageTypeInvalidate  MessageType = "invalidate" // Tells frontend to re-fetch via REST (last-resort).

	// maxMessageSize caps the WebSocket payload. Beyond this the hub sends a
	// lightweight invalidate signal and the frontend re-fetches via REST.
	// 10MB lets typical 2k–8k-client deployments push directly via WS (low
	// latency); larger installs fall back to invalidate.
	maxMessageSize = 10 * 1024 * 1024 // 10MB

	enqueueTimeout    = 100 * time.Millisecond
	clientSendQueue   = 512  // ~50s of buffering for a momentarily slow browser.
	hubBroadcastQueue = 2048 // Headroom for cron-storm + admin-mutation bursts.

	// minBroadcastInterval throttles per-type broadcasts so cron storms or
	// rapid mutations cannot drown the hub. Bursts within the interval are
	// dropped (not coalesced); the next broadcast outside the window delivers
	// the latest state. Only message types in throttledMessageTypes are gated —
	// heartbeat and real-time signals (status, traffic, client_stats,
	// notification, xray_state, invalidate) bypass this so they are never delayed.
	minBroadcastInterval = 250 * time.Millisecond

	// defaultSessionSweepInterval is how often the hub re-validates live
	// connections against their server-side sessions. A connection must
	// not outlive its login session (expiry), a password change or a user
	// deletion by more than this. Logout closes its connections
	// immediately (see CloseSessionClients); the sweep is the backstop
	// for the paths without an explicit close call.
	defaultSessionSweepInterval = 30 * time.Second

	// hubRestartAttempts caps panic-recovery restarts. After this many
	// consecutive failures we stop trying and log; the panel keeps running
	// (frontend falls back to REST polling) and the operator can investigate.
	hubRestartAttempts = 3
)

// NewClient builds a Client ready for hub registration. sessionID/userID
// bind the connection to the login session that established it, so the
// session's revocation (logout, password change, expiry) can close
// exactly this connection without touching the user's other sessions.
func NewClient(id, sessionID string, userID int) *Client {
	return &Client{
		ID:        id,
		SessionID: sessionID,
		UserID:    userID,
		Send:      make(chan []byte, clientSendQueue),
	}
}

// Message is the wire format sent to clients.
type Message struct {
	Type    MessageType `json:"type"`
	Payload any         `json:"payload"`
	Time    int64       `json:"time"`
}

// Client represents a single WebSocket connection.
type Client struct {
	ID string
	// SessionID/UserID bind the connection to the login session that
	// established it (see NewClient). Empty SessionID means the
	// connection predates session binding and is swept as invalid.
	SessionID string
	UserID    int
	Send      chan []byte
	closeOnce sync.Once
}

// Hub fan-outs messages to all connected clients.
//
// Registration is synchronous: Register inserts the client into the
// map under the hub lock and reports success, Unregister removes it
// the same way. The old design queued both through separate channels
// and the hub loop consumed them in select order, which left three
// holes: an unregister processed before its register left a dead
// client in the registry; a logout missed a connection still queued
// for registration; and Stop closed only registered clients while a
// queued registration was never processed and its goroutines lingered
// after an internal restart. Synchronous registration closes all
// three: the last operation wins deterministically, Register
// re-validates the session at registration time (so a logout that
// lands during the handshake is refused), and Stop refuses new
// registrations and waits for the loop to finish shutting down.
//
// Validation and insertion are one atomic decision with respect to
// revocations. A revocation that lands between Register's validation
// and its insert would otherwise miss the not-yet-registered
// connection, which would then receive broadcasts until the next
// sweep. Every revocation (CloseSessionClients, CloseUserClients,
// sweeper closes) bumps revEpoch under the hub lock — even when it
// matches no registered client, because the revocation itself, not
// the number of clients it closed, is what a concurrent registration
// must observe. Register records the epoch before validating and
// re-checks it under the lock at insert: a changed epoch means the
// validation is stale and must be redone against the revoked
// session. Either the revocation's scan sees the new client (and
// closes it) or the registration sees the revocation (and is
// refused) — there is no ordering in which a revoked session's
// connection joins the broadcast set. Merely re-validating once
// before the insert would leave the same window open.
type Hub struct {
	clients   map[*Client]struct{}
	broadcast chan []byte
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc

	// revEpoch counts revocation events, guarded by mu. See the Hub
	// comment above: Register re-validates when it changed.
	revEpoch uint64
	// pumpClosed is set by Stop under mu, after the event loop
	// exits, and read by StartPumps under the same lock. Its write
	// is the barrier that orders Stop's pump wait after every
	// reservation made before it: a StartPumps that acquired the
	// lock first has already counted its pumps, and one that
	// acquires it later sees pumpClosed and is refused.
	pumpClosed bool
	// pumps counts the read/write pump goroutines of registered
	// clients; Stop waits for it, so no TCP connection or goroutine
	// outlives the shutdown.
	pumps sync.WaitGroup

	// stopped is set by Stop and refuses every later Register. It is
	// checked before validation and again under the lock at insert,
	// so a stop that lands while a registration is being validated
	// still wins.
	stopped atomic.Bool
	// started reports whether Run has begun; Stop waits for the loop
	// to exit only when it has, so stopping a never-started hub
	// cannot hang.
	started atomic.Bool
	// done closes when Run returns, i.e. after the loop has shut down
	// and closed every registered client.
	done     chan struct{}
	doneOnce sync.Once

	throttleMu    sync.Mutex
	lastBroadcast map[MessageType]time.Time

	// sessionValidator reports whether a (sessionID, userID) pair is
	// still valid. Injected by the web server (it is the same
	// server-side session check HTTP auth uses); nil disables sweeping.
	// Kept behind a mutex because it is set once at startup while the
	// hub loop reads it on every sweep.
	validatorMu      sync.RWMutex
	sessionValidator func(sessionID string, userID int) bool
	// sweepIntervalNs is the session-sweep period in nanoseconds
	// (atomic: set at startup or by tests, read by the hub loop).
	sweepIntervalNs atomic.Int64
}

// NewHub creates a hub. Call Run in a goroutine to start its event loop.
func NewHub() *Hub {
	ctx, cancel := context.WithCancel(context.Background())
	h := &Hub{
		clients:       make(map[*Client]struct{}),
		broadcast:     make(chan []byte, hubBroadcastQueue),
		ctx:           ctx,
		cancel:        cancel,
		done:          make(chan struct{}),
		lastBroadcast: make(map[MessageType]time.Time),
	}
	h.sweepIntervalNs.Store(int64(defaultSessionSweepInterval))
	return h
}

// SetSessionValidator injects the function the hub sweeper uses to decide
// whether a connection's login session is still valid. Called once by
// the web server at startup; nil disables sweeping.
func (h *Hub) SetSessionValidator(fn func(sessionID string, userID int) bool) {
	if h == nil {
		return
	}
	h.validatorMu.Lock()
	h.sessionValidator = fn
	h.validatorMu.Unlock()
}

// SetSessionSweepInterval overrides the session-sweep period (tests use
// a short interval so the sweep fires promptly). Non-positive values
// restore the default.
func (h *Hub) SetSessionSweepInterval(d time.Duration) {
	if h == nil {
		return
	}
	if d <= 0 {
		d = defaultSessionSweepInterval
	}
	h.sweepIntervalNs.Store(int64(d))
}

func (h *Hub) getSessionValidator() func(sessionID string, userID int) bool {
	if h == nil {
		return nil
	}
	h.validatorMu.RLock()
	defer h.validatorMu.RUnlock()
	return h.sessionValidator
}

func (h *Hub) getSweepInterval() time.Duration {
	if h == nil {
		return defaultSessionSweepInterval
	}
	d := time.Duration(h.sweepIntervalNs.Load())
	if d <= 0 {
		return defaultSessionSweepInterval
	}
	return d
}

// revocationEpoch reads the current revocation count.
func (h *Hub) revocationEpoch() uint64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.revEpoch
}

// bumpRevocationEpoch records one revocation event. Callers bump
// before scanning for clients to close: a registration racing the
// revocation must observe it even when no client is registered yet,
// because the scan would miss a connection still being validated.
func (h *Hub) bumpRevocationEpoch() {
	h.mu.Lock()
	h.revEpoch++
	h.mu.Unlock()
}

// CloseSessionClients closes every connection bound to one login
// session, e.g. on logout. The hub removes each client (closing its
// Send channel makes the write pump send a close frame and drop the
// TCP connection), so no further broadcasts reach it. Other sessions —
// including other sessions of the same user — are untouched.
func (h *Hub) CloseSessionClients(sessionID string) {
	if h == nil || sessionID == "" {
		return
	}
	h.bumpRevocationEpoch()
	h.mu.RLock()
	var targets []*Client
	for c := range h.clients {
		if c.SessionID == sessionID {
			targets = append(targets, c)
		}
	}
	h.mu.RUnlock()
	for _, c := range targets {
		h.removeClient(c)
	}
}

// CloseUserClients closes every connection of one user, e.g. on a
// password change, when all of the user's sessions are revoked at once.
func (h *Hub) CloseUserClients(userID int) {
	if h == nil || userID == 0 {
		return
	}
	h.bumpRevocationEpoch()
	h.mu.RLock()
	var targets []*Client
	for c := range h.clients {
		if c.UserID == userID {
			targets = append(targets, c)
		}
	}
	h.mu.RUnlock()
	for _, c := range targets {
		h.removeClient(c)
	}
}

// CloseAllClients closes every connection, e.g. on a database import
// that invalidates all sessions at once. Like the other revocation
// calls it bumps the revocation epoch first, so a registration racing
// the close re-validates instead of joining.
func (h *Hub) CloseAllClients() {
	if h == nil {
		return
	}
	h.bumpRevocationEpoch()
	h.mu.RLock()
	clients := make([]*Client, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.RUnlock()
	for _, c := range clients {
		h.removeClient(c)
	}
}

// sweepSessions re-validates every live connection against its login
// session and closes the ones whose session is gone: expired, revoked
// by a password change, or belonging to a deleted user. It runs on the
// sweep ticker; logout closes its connections immediately instead, so
// the sweep is only the backstop for paths without an explicit close.
// Validation happens without holding the hub lock, so a slow check
// cannot stall broadcasts.
func (h *Hub) sweepSessions() {
	validate := h.getSessionValidator()
	if validate == nil {
		return
	}
	h.mu.RLock()
	clients := make([]*Client, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.RUnlock()
	closedAny := false
	for _, c := range clients {
		if !validate(c.SessionID, c.UserID) {
			h.removeClient(c)
			closedAny = true
			logger.Debugf("WebSocket client %s closed: session no longer valid", c.ID)
		}
	}
	if closedAny {
		h.bumpRevocationEpoch()
	}
}

// throttledMessageTypes is the explicit allow-list of message types subject to
// the per-type rate limit. Everything else (status, traffic, client_stats,
// notification, xray_state, invalidate) is heartbeat- or signal-class and must
// not be delayed. Keeping the set explicit (vs. an exclusion list) makes the
// intent obvious when new message types are added — by default they bypass.
var throttledMessageTypes = map[MessageType]struct{}{
	MessageTypeInbounds:  {},
	MessageTypeOutbounds: {},
}

// shouldThrottle returns true if a broadcast of msgType is rate-limited and
// happened within minBroadcastInterval of the previous one. Only message types
// in throttledMessageTypes are gated.
func (h *Hub) shouldThrottle(msgType MessageType) bool {
	if _, gated := throttledMessageTypes[msgType]; !gated {
		return false
	}
	h.throttleMu.Lock()
	defer h.throttleMu.Unlock()
	now := time.Now()
	if last, ok := h.lastBroadcast[msgType]; ok && now.Sub(last) < minBroadcastInterval {
		return true
	}
	h.lastBroadcast[msgType] = now
	return false
}

// Start launches the event loop in a goroutine. It marks the hub
// started synchronously, before the goroutine exists, so Stop can
// reliably wait for the loop to exit: setting the flag inside Run
// would race with a Stop that lands before the goroutine is first
// scheduled. Callers must use Start, not `go h.Run()`.
func (h *Hub) Start() {
	h.started.Store(true)
	go h.Run()
}

// Run drives the hub. The inner loop is wrapped in a panic-recovery harness
// that retries up to hubRestartAttempts times with backoff so a transient
// panic doesn't permanently kill real-time updates for commercial deployments.
// After the cap, the hub stays down and the frontend falls back to REST polling.
// Run returns once the hub has stopped (see Stop); done closes then, so
// Stop can wait for the shutdown to complete. A Hub runs at most once —
// the web server creates a fresh Hub on every (re)start.
func (h *Hub) Run() {
	h.started.Store(true)
	defer func() {
		h.started.Store(false)
		h.doneOnce.Do(func() { close(h.done) })
	}()
	for attempt := 0; attempt < hubRestartAttempts; attempt++ {
		stopped := h.runOnce()
		if stopped {
			return
		}
		if attempt < hubRestartAttempts-1 {
			wait := time.Duration(1<<attempt) * time.Second // 1s, 2s, 4s
			logger.Errorf("WebSocket hub crashed, restarting in %s (%d/%d)", wait, attempt+1, hubRestartAttempts-1)
			select {
			case <-time.After(wait):
			case <-h.ctx.Done():
				return
			}
		}
	}
	logger.Error("WebSocket hub stopped after exhausting restart attempts")
}

// runOnce drives the event loop once and returns true if the hub stopped
// cleanly (context cancelled). On panic, recover logs and returns false so
// Run can decide whether to retry.
func (h *Hub) runOnce() (stopped bool) {
	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("WebSocket hub panic recovered: %v", r)
			stopped = false
		}
	}()

	sweepTicker := time.NewTicker(h.getSweepInterval())
	defer sweepTicker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			h.shutdown()
			return true

		case <-sweepTicker.C:
			h.sweepSessions()

		case msg := <-h.broadcast:
			h.fanout(msg)
		}
	}
}

// shutdown closes all client send channels and clears the registry.
func (h *Hub) shutdown() {
	h.mu.Lock()
	for c := range h.clients {
		c.closeOnce.Do(func() { close(c.Send) })
	}
	h.clients = make(map[*Client]struct{})
	h.mu.Unlock()
	logger.Info("WebSocket hub stopped")
}

// removeClient deletes a client and closes its send channel exactly once.
func (h *Hub) removeClient(c *Client) {
	h.mu.Lock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		c.closeOnce.Do(func() { close(c.Send) })
	}
	n := len(h.clients)
	h.mu.Unlock()
	logger.Debugf("WebSocket client disconnected: %s (total: %d)", c.ID, n)
}

// fanout delivers msg to every client. Each send is non-blocking — a client
// whose buffer is full is collected for direct removal at the end.
func (h *Hub) fanout(msg []byte) {
	if msg == nil {
		return
	}
	h.mu.RLock()
	if len(h.clients) == 0 {
		h.mu.RUnlock()
		return
	}
	targets := make([]*Client, 0, len(h.clients))
	for c := range h.clients {
		targets = append(targets, c)
	}
	h.mu.RUnlock()

	var dead []*Client
	for _, c := range targets {
		if !trySend(c, msg) {
			dead = append(dead, c)
		}
	}

	if len(dead) == 0 {
		return
	}
	h.mu.Lock()
	for _, c := range dead {
		if _, ok := h.clients[c]; ok {
			delete(h.clients, c)
			c.closeOnce.Do(func() { close(c.Send) })
			logger.Debugf("WebSocket client %s send buffer full, disconnected", c.ID)
		}
	}
	h.mu.Unlock()
}

// trySend performs a non-blocking write to the client's Send channel.
// Returns false if the client should be evicted (full buffer or closed channel).
// A defer-recover guards against the rare race where the channel was closed
// concurrently — sending on a closed channel always panics, even with select+default.
func trySend(c *Client, msg []byte) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()
	select {
	case c.Send <- msg:
		return true
	default:
		return false
	}
}

// Broadcast serializes payload and queues it for delivery to all clients.
// If the serialized message exceeds maxMessageSize, an invalidate signal is
// queued instead so the frontend re-fetches via REST. Broadcasts of throttled
// message types (see throttledMessageTypes) within minBroadcastInterval of
// the previous one are dropped — the next legitimate mutation will push the
// fresh state.
func (h *Hub) Broadcast(messageType MessageType, payload any) {
	if h == nil || payload == nil || h.GetClientCount() == 0 {
		return
	}
	if h.shouldThrottle(messageType) {
		return
	}
	data, err := json.Marshal(Message{
		Type:    messageType,
		Payload: payload,
		Time:    time.Now().UnixMilli(),
	})
	if err != nil {
		logger.Error("WebSocket marshal failed:", err)
		return
	}
	if len(data) > maxMessageSize {
		logger.Debugf("WebSocket payload %d bytes exceeds limit, sending invalidate for %s", len(data), messageType)
		h.broadcastInvalidate(messageType)
		return
	}
	h.enqueue(data)
}

// broadcastInvalidate queues a lightweight signal telling clients to re-fetch
// the named data type via REST.
func (h *Hub) broadcastInvalidate(originalType MessageType) {
	data, err := json.Marshal(Message{
		Type:    MessageTypeInvalidate,
		Payload: map[string]string{"type": string(originalType)},
		Time:    time.Now().UnixMilli(),
	})
	if err != nil {
		logger.Error("WebSocket invalidate marshal failed:", err)
		return
	}
	h.enqueue(data)
}

// enqueue submits raw bytes to the broadcast channel. Dropped on backpressure
// (channel full for >100ms) or shutdown.
func (h *Hub) enqueue(data []byte) {
	select {
	case h.broadcast <- data:
	case <-time.After(enqueueTimeout):
		logger.Warning("WebSocket broadcast channel full, dropping message")
	case <-h.ctx.Done():
	}
}

// GetClientCount returns the number of connected clients.
func (h *Hub) GetClientCount() int {
	if h == nil {
		return 0
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// Register adds a client to the hub and reports whether it was accepted.
// Registration is synchronous (the client is in the map when Register
// returns), so a disconnect immediately afterwards cannot be processed
// before the registration, and a logout or stop cannot miss a
// connection that is still "on its way in".
//
// Registration is refused — and the client's Send channel closed so its
// pumps exit — when the hub is stopped, or when the injected session
// validator says the login session is no longer valid. The validation
// runs before the insert (without holding the hub lock, so a slow
// check cannot stall broadcasts); the stopped flag is re-checked
// under the lock at insert, so a stop landing mid-validation still
// wins. A client with no session ID is accepted without validation
// (the sweeper treats it as invalid and closes it); the validator is
// skipped entirely when none is set, e.g. in unit tests.
//
// The validation and the insert are one atomic decision with respect
// to revocations (see the Hub comment): Register records the
// revocation epoch before validating and re-checks it under the lock
// at insert. A changed epoch means a logout or password change
// landed mid-validation, so the validation is stale and Register
// loops to re-validate against the revoked session instead of
// inserting a connection the revocation's scan could not see.
func (h *Hub) Register(c *Client) bool {
	if h == nil || c == nil {
		return false
	}
	if h.stopped.Load() {
		c.closeOnce.Do(func() { close(c.Send) })
		return false
	}
	for {
		epoch := h.revocationEpoch()
		if validate := h.getSessionValidator(); validate != nil && c.SessionID != "" {
			if !validate(c.SessionID, c.UserID) {
				c.closeOnce.Do(func() { close(c.Send) })
				return false
			}
		}
		h.mu.Lock()
		if h.stopped.Load() {
			h.mu.Unlock()
			c.closeOnce.Do(func() { close(c.Send) })
			return false
		}
		if h.revEpoch != epoch {
			h.mu.Unlock()
			continue
		}
		h.clients[c] = struct{}{}
		logger.Debugf("WebSocket client connected: %s (total: %d)", c.ID, len(h.clients))
		h.mu.Unlock()
		return true
	}
}

// StartPumps reserves n pump goroutines for a registered client and
// reports whether the reservation was accepted. The controller calls
// it right after Register and starts the pumps only on success, so a
// stop landing between Register and the pump start refuses the
// reservation instead of leaving pumps running after Stop returned.
// The reservation and the stopped/pumpClosed checks happen under the
// hub lock, and Stop sets pumpClosed under the same lock before
// waiting for the pumps, so a pump can neither start after Stop
// returned nor be missed by Stop's wait.
func (h *Hub) StartPumps(n int) bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.stopped.Load() || h.pumpClosed {
		return false
	}
	h.pumps.Add(n)
	return true
}

// PumpDone marks one pump goroutine finished. The controller defers
// it in each pump it started through StartPumps.
func (h *Hub) PumpDone() {
	if h == nil {
		return
	}
	h.pumps.Done()
}

// Unregister removes a client from the hub. Synchronous like Register,
// so the last operation wins deterministically: a disconnect right
// after registration leaves no record behind.
func (h *Hub) Unregister(c *Client) {
	if h == nil || c == nil {
		return
	}
	h.removeClient(c)
}

// Stop signals the hub to shut down, closes all client connections,
// and waits for the event loop and every pump goroutine to finish —
// so no connection or goroutine is left behind when the panel stops
// or restarts in-process. Stopping a hub whose loop never started
// returns at once. A stopped hub refuses every later Register.
//
// Setting pumpClosed under the lock is the barrier for the pump
// wait: StartPumps reserves under the same lock, so any reservation
// made before it is counted by the wait, and any made after it sees
// pumpClosed and is refused. Without it a pump could start between
// the loop exit and the wait and outlive Stop.
func (h *Hub) Stop() {
	if h == nil {
		return
	}
	h.stopped.Store(true)
	if h.cancel != nil {
		h.cancel()
	}
	if h.started.Load() {
		<-h.done
	}
	h.mu.Lock()
	h.pumpClosed = true
	h.mu.Unlock()
	h.pumps.Wait()
}
