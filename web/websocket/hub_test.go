package websocket

import (
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/logger"

	"github.com/op/go-logging"
)

// initTestLogger starts the panel logger (the hub logs connects and
// disconnects); without it the underlying go-logging Logger is nil and
// the hub panics on the first register.
func initTestLogger(t *testing.T) {
	t.Helper()
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)
}

// waitForCount polls the hub until it holds n clients or the deadline passes.
func waitForCount(t *testing.T, h *Hub, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if h.GetClientCount() == n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("client count %d, want %d after %s", h.GetClientCount(), n, timeout)
}

// sendClosed reports whether the client's Send channel is already closed.
// No messages are broadcast in these tests, so a non-empty channel would
// only mean the client is still alive.
func sendClosed(c *Client) bool {
	select {
	case _, ok := <-c.Send:
		return !ok
	default:
		return false
	}
}

func TestHubCloseSessionClients(t *testing.T) {
	initTestLogger(t)
	h := NewHub()
	go h.Run()
	defer h.Stop()

	a1 := NewClient("a1", "session-a", 1)
	a2 := NewClient("a2", "session-a", 1)
	b := NewClient("b", "session-b", 1)
	h.Register(a1)
	h.Register(a2)
	h.Register(b)
	waitForCount(t, h, 3, 5*time.Second)

	// Closing one session must close exactly its connections.
	h.CloseSessionClients("session-a")
	waitForCount(t, h, 1, 5*time.Second)
	if !sendClosed(a1) || !sendClosed(a2) {
		t.Fatal("session-a clients not closed")
	}
	if sendClosed(b) {
		t.Fatal("session-b client closed, want it alive")
	}
	if h.GetClientCount() != 1 {
		t.Fatalf("client count %d, want 1", h.GetClientCount())
	}
}

func TestHubCloseUserClients(t *testing.T) {
	initTestLogger(t)
	h := NewHub()
	go h.Run()
	defer h.Stop()

	u1 := NewClient("u1", "session-1", 1)
	u2 := NewClient("u2", "session-2", 1)
	other := NewClient("other", "session-3", 2)
	h.Register(u1)
	h.Register(u2)
	h.Register(other)
	waitForCount(t, h, 3, 5*time.Second)

	// A password change revokes every session of the user at once.
	h.CloseUserClients(1)
	waitForCount(t, h, 1, 5*time.Second)
	if !sendClosed(u1) || !sendClosed(u2) {
		t.Fatal("user 1 clients not closed")
	}
	if sendClosed(other) {
		t.Fatal("user 2 client closed, want it alive")
	}
}

func TestHubSessionSweeper(t *testing.T) {
	initTestLogger(t)
	h := NewHub()
	h.SetSessionValidator(func(sessionID string, userID int) bool {
		// Only the "live" session is still valid; "dead" expired.
		return sessionID == "live"
	})
	h.SetSessionSweepInterval(50 * time.Millisecond)
	go h.Run()
	defer h.Stop()

	dead := NewClient("dead", "dead", 1)
	live := NewClient("live", "live", 1)
	h.Register(dead)
	h.Register(live)
	waitForCount(t, h, 2, 5*time.Second)

	// The sweep must close the dead session's connection and leave the
	// live one alone, within a few sweep intervals.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if sendClosed(dead) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sendClosed(dead) {
		t.Fatal("dead session client not closed by sweeper")
	}
	if sendClosed(live) {
		t.Fatal("live session client closed by sweeper, want it alive")
	}
	if h.GetClientCount() != 1 {
		t.Fatalf("client count %d, want 1", h.GetClientCount())
	}
}
