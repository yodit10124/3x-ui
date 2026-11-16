package websocket

import (
	"sync"
	"sync/atomic"
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
	h.Start()
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
	h.Start()
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
	h.SetSessionSweepInterval(50 * time.Millisecond)
	h.Start()
	defer h.Stop()

	dead := NewClient("dead", "dead", 1)
	live := NewClient("live", "live", 1)
	// Register first, then install the validator: Register validates
	// at registration time, so a client that is already invalid
	// would be refused outright and never reach the sweeper.
	h.Register(dead)
	h.Register(live)
	waitForCount(t, h, 2, 5*time.Second)
	h.SetSessionValidator(func(sessionID string, userID int) bool {
		// Only the "live" session is still valid; "dead" expired.
		return sessionID == "live"
	})

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

// TestHubRegisterRefusedAfterStop: once the hub is stopped, Register
// refuses and closes the client's Send channel instead of leaving a
// connection nobody will ever close.
func TestHubRegisterRefusedAfterStop(t *testing.T) {
	initTestLogger(t)
	h := NewHub()
	h.Start()
	h.Stop()

	c := NewClient("late", "session-x", 1)
	if h.Register(c) {
		t.Fatal("Register after Stop accepted, want refused")
	}
	if !sendClosed(c) {
		t.Fatal("refused client Send not closed")
	}
	if h.GetClientCount() != 0 {
		t.Fatalf("client count %d, want 0", h.GetClientCount())
	}
}

// TestHubRegisterValidatesSession: Register re-validates the login
// session at registration time, so a session revoked during the
// handshake is refused instead of living until the next sweep.
func TestHubRegisterValidatesSession(t *testing.T) {
	initTestLogger(t)
	h := NewHub()
	h.SetSessionValidator(func(sessionID string, userID int) bool {
		return sessionID == "live"
	})
	h.Start()
	defer h.Stop()

	dead := NewClient("dead", "dead", 1)
	if h.Register(dead) {
		t.Fatal("Register with revoked session accepted, want refused")
	}
	if !sendClosed(dead) {
		t.Fatal("refused client Send not closed")
	}
	live := NewClient("live", "live", 1)
	if !h.Register(live) {
		t.Fatal("Register with valid session refused, want accepted")
	}
	if h.GetClientCount() != 1 {
		t.Fatalf("client count %d, want 1", h.GetClientCount())
	}
}

// blockingValidator blocks inside the validation until release is
// closed, then answers with valid.Load(). entered closes on the first
// call, so the test can perform the revocation (or stop) while the
// registration is still in flight — deterministic ordering, no sleeps.
func blockingValidator(t *testing.T, valid *atomic.Bool) (func(string, int) bool, chan struct{}, chan struct{}) {
	t.Helper()
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	validate := func(sessionID string, userID int) bool {
		once.Do(func() { close(entered) })
		<-release
		return valid.Load()
	}
	return validate, entered, release
}

func waitEntered(t *testing.T, entered chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Register never entered validation")
	}
}

// TestHubRegisterRefusedWhenSessionRevokedDuringHandshake: the
// handshake is in flight (Register blocked in validation) when the
// session is revoked; validation then answers false and the
// registration is refused.
func TestHubRegisterRefusedWhenSessionRevokedDuringHandshake(t *testing.T) {
	initTestLogger(t)
	h := NewHub()
	valid := &atomic.Bool{}
	valid.Store(true)
	validate, entered, release := blockingValidator(t, valid)
	h.SetSessionValidator(validate)
	h.Start()
	defer h.Stop()

	c := NewClient("hs", "session-hs", 1)
	done := make(chan bool, 1)
	go func() { done <- h.Register(c) }()
	waitEntered(t, entered)
	// The logout lands while the handshake is in flight.
	valid.Store(false)
	close(release)
	select {
	case ok := <-done:
		if ok {
			t.Fatal("Register accepted a session revoked during the handshake")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Register did not return after validation released")
	}
	if !sendClosed(c) {
		t.Fatal("refused client Send not closed")
	}
	if h.GetClientCount() != 0 {
		t.Fatalf("client count %d, want 0", h.GetClientCount())
	}
}

// TestHubRegisterRefusedWhenStoppedDuringHandshake: the hub stops
// while a registration is being validated; the stopped flag is
// re-checked under the lock at insert, so the registration is
// refused even though the session is still valid.
func TestHubRegisterRefusedWhenStoppedDuringHandshake(t *testing.T) {
	initTestLogger(t)
	h := NewHub()
	valid := &atomic.Bool{}
	valid.Store(true)
	validate, entered, release := blockingValidator(t, valid)
	h.SetSessionValidator(validate)
	h.Start()
	defer h.Stop()

	c := NewClient("hs", "session-hs", 1)
	done := make(chan bool, 1)
	go func() { done <- h.Register(c) }()
	waitEntered(t, entered)
	h.Stop() // waits for the loop to exit; Register is still blocked
	close(release)
	select {
	case ok := <-done:
		if ok {
			t.Fatal("Register accepted after the hub stopped")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Register did not return after validation released")
	}
	if !sendClosed(c) {
		t.Fatal("refused client Send not closed")
	}
	if h.GetClientCount() != 0 {
		t.Fatalf("client count %d, want 0", h.GetClientCount())
	}
}

// TestHubRegisterThenUnregisterImmediately: registration and
// unregistration are both synchronous, so a disconnect right after
// registration leaves no record behind.
// TestHubRegisterRefusedWhenRevokedBetweenValidationAndInsert: the
// session is still valid when validation answers, but the revocation
// (logout or password change) and its scan complete before the
// registration is inserted. The revocation bumps the revocation
// epoch, so the registration re-validates against the now-revoked
// session and is refused — the connection never joins the broadcast
// set and receives no further broadcasts. The ordering is controlled
// with a blocking validator; no sleeps.
func TestHubRegisterRefusedWhenRevokedBetweenValidationAndInsert(t *testing.T) {
	revocations := map[string]func(h *Hub){
		"logout":          func(h *Hub) { h.CloseSessionClients("session-race") },
		"password-change": func(h *Hub) { h.CloseUserClients(1) },
	}
	for name, revoke := range revocations {
		t.Run(name, func(t *testing.T) {
			initTestLogger(t)
			h := NewHub()
			var calls atomic.Int32
			entered := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			h.SetSessionValidator(func(sessionID string, userID int) bool {
				if calls.Add(1) == 1 {
					once.Do(func() { close(entered) })
					<-release
					return true // valid at validation time
				}
				return false // revoked by the time of the re-validation
			})
			h.Start()
			defer h.Stop()

			c := NewClient("race", "session-race", 1)
			done := make(chan bool, 1)
			go func() { done <- h.Register(c) }()
			waitEntered(t, entered)
			// The revocation lands while the handshake is in flight:
			// its scan finds nothing (the connection is not
			// registered yet), but it bumps the revocation epoch.
			revoke(h)
			close(release)
			select {
			case ok := <-done:
				if ok {
					t.Fatal("Register accepted a session revoked between validation and insert")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Register did not return after validation released")
			}
			if n := calls.Load(); n != 2 {
				t.Fatalf("validator called %d times, want 2 (validation + re-validation)", n)
			}
			if !sendClosed(c) {
				t.Fatal("refused client Send not closed")
			}
			if h.GetClientCount() != 0 {
				t.Fatalf("client count %d, want 0", h.GetClientCount())
			}
			// A broadcast afterwards must not reach the refused
			// connection: it never joined the broadcast set.
			h.Broadcast(MessageTypeStatus, map[string]string{"ping": "pong"})
			select {
			case msg, ok := <-c.Send:
				if ok {
					t.Fatalf("refused client received a broadcast: %s", msg)
				}
			default:
			}
		})
	}
}

// TestHubStopWaitsForPumps: Stop does not return while pump
// goroutines reserved through StartPumps are still running, and
// returns once the last one finishes.
func TestHubStopWaitsForPumps(t *testing.T) {
	initTestLogger(t)
	h := NewHub()
	h.Start()

	if !h.StartPumps(2) {
		t.Fatal("StartPumps refused on a running hub")
	}
	stopped := make(chan struct{})
	go func() {
		h.Stop()
		close(stopped)
	}()
	// Stop must still be waiting while both pumps run.
	select {
	case <-stopped:
		t.Fatal("Stop returned while pumps were still running")
	case <-time.After(200 * time.Millisecond):
	}
	h.PumpDone()
	// ... and while one pump still runs.
	select {
	case <-stopped:
		t.Fatal("Stop returned with one pump still running")
	case <-time.After(200 * time.Millisecond):
	}
	h.PumpDone()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return after all pumps finished")
	}
	// A reservation after Stop is refused.
	if h.StartPumps(1) {
		t.Fatal("StartPumps accepted after Stop")
	}
}

// TestHubCloseAllClients: CloseAllClients closes every connection
// at once, e.g. on a database import that invalidates all sessions.
func TestHubCloseAllClients(t *testing.T) {
	initTestLogger(t)
	h := NewHub()
	h.Start()
	defer h.Stop()

	a := NewClient("a", "session-a", 1)
	b := NewClient("b", "session-b", 2)
	h.Register(a)
	h.Register(b)
	waitForCount(t, h, 2, 5*time.Second)

	h.CloseAllClients()
	waitForCount(t, h, 0, 5*time.Second)
	if !sendClosed(a) || !sendClosed(b) {
		t.Fatal("clients not closed by CloseAllClients")
	}
}

func TestHubRegisterThenUnregisterImmediately(t *testing.T) {
	initTestLogger(t)
	h := NewHub()
	h.Start()
	defer h.Stop()

	c := NewClient("fast", "session-fast", 1)
	if !h.Register(c) {
		t.Fatal("Register refused, want accepted")
	}
	h.Unregister(c)
	if h.GetClientCount() != 0 {
		t.Fatalf("client count %d, want 0", h.GetClientCount())
	}
	if !sendClosed(c) {
		t.Fatal("unregistered client Send not closed")
	}
	// A broadcast afterwards must not resurrect or panic on the record.
	h.Broadcast(MessageTypeStatus, map[string]string{"ping": "pong"})
	if h.GetClientCount() != 0 {
		t.Fatalf("client count %d after broadcast, want 0", h.GetClientCount())
	}
}

// TestHubStopClosesClientsAndWaits: Stop closes every registered
// client and waits for the event loop to finish, so when Stop returns
// the shutdown has already happened — no connection or goroutine is
// left behind for an in-process restart.
func TestHubStopClosesClientsAndWaits(t *testing.T) {
	initTestLogger(t)
	h := NewHub()
	h.Start()

	c := NewClient("stop", "session-stop", 1)
	if !h.Register(c) {
		t.Fatal("Register refused, want accepted")
	}
	h.Stop()
	// Stop waited for the loop to exit, so the shutdown already ran:
	// no polling, the client must be gone right now.
	if h.GetClientCount() != 0 {
		t.Fatalf("client count %d right after Stop, want 0", h.GetClientCount())
	}
	if !sendClosed(c) {
		t.Fatal("client Send not closed right after Stop")
	}
}
