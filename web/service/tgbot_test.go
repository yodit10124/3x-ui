package service

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/global"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"github.com/google/uuid"
	"github.com/mymmrac/telego"
	"github.com/op/go-logging"
)

const (
	tgbotTestAdminID = int64(111)
	tgbotTestUserID  = int64(999)
	tgbotTestChatID  = int64(555)
)

// setupTgbotTestDB creates a throw-away database with one VLESS inbound
// holding a single client, plus a traffic row for that client. It returns
// the inbound id. The global bot state is left stopped (isRunning=false,
// bot=nil) so every Telegram send is a no-op.
func setupTgbotTestDB(t *testing.T) int {
	t.Helper()
	// Point the logger at a throw-away folder so InitLogger never touches
	// the panel's real log directory.
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)

	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })

	hashStorage = global.NewHashStorage(20 * time.Minute)
	t.Cleanup(func() { hashStorage = nil })

	addClientSessionsMu.Lock()
	addClientSessions = make(map[addClientSessionKey]*addClientSession)
	addClientSessionsMu.Unlock()

	inbound := &model.Inbound{
		Remark:   "test",
		Enable:   true,
		Port:     12345,
		Protocol: model.VLESS,
		Settings: `{"clients":[{"id":"11111111-1111-1111-1111-111111111111","flow":"","email":"victim@example.com","limitIp":0,"totalGB":0,"expiryTime":0,"enable":true,"tgId":0,"comment":"","reset":0}],"decryption":"none"}`,
		Tag:      "test-inbound",
	}
	if err := database.GetDB().Create(inbound).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	if err := database.GetDB().Create(&xray.ClientTraffic{
		InboundId: inbound.Id,
		Email:     "victim@example.com",
		Up:        1000,
		Down:      2000,
		Enable:    true,
	}).Error; err != nil {
		t.Fatalf("create traffic: %v", err)
	}
	return inbound.Id
}

func tgbotTestTraffic(t *testing.T) (int64, int64) {
	t.Helper()
	var ct xray.ClientTraffic
	if err := database.GetDB().Where("email = ?", "victim@example.com").First(&ct).Error; err != nil {
		t.Fatalf("read traffic: %v", err)
	}
	return ct.Up, ct.Down
}

func tgbotTestCallbackQuery(userID int64, data string) *telego.CallbackQuery {
	return &telego.CallbackQuery{
		ID:   "test-query",
		From: telego.User{ID: userID},
		Message: &telego.Message{
			Chat:      telego.Chat{ID: tgbotTestChatID},
			MessageID: 7,
		},
		Data: data,
	}
}

// TestIsPersonalBotCallback: only the two personal queries are open to
// non-admins; every management callback must be refused for them.
func TestIsPersonalBotCallback(t *testing.T) {
	allowed := []string{"client_traffic", "client_commands"}
	for _, data := range allowed {
		if !isPersonalBotCallback(data) {
			t.Fatalf("isPersonalBotCallback(%q) = false, want true", data)
		}
	}
	denied := []string{
		"", "get_usage", "usage_refresh", "inbounds", "deplete_soon",
		"get_backup", "get_banlogs", "onlines", "onlines_refresh", "commands",
		"add_client", "add_client_to", "add_client_ch_default_email",
		"add_client_default_info", "add_client_cancel",
		"add_client_submit_enable", "add_client_submit_disable",
		"reset_all_traffics", "reset_all_traffics_c", "reset_all_traffics_cancel",
		"get_sorted_traffic_usage_report", "get_inbounds",
		"client_traffic ", " client_traffic", "CLIENT_TRAFFIC",
		"client_get_usage victim@example.com",
	}
	for _, data := range denied {
		if isPersonalBotCallback(data) {
			t.Fatalf("isPersonalBotCallback(%q) = true, want false", data)
		}
	}
}

// TestAnswerCallbackNonAdminDenied: a non-admin submitting management
// callbacks must not change the database or receive management data.
// The same callbacks from an admin must keep working.
func TestAnswerCallbackNonAdminDenied(t *testing.T) {
	setupTgbotTestDB(t)
	tb := (&Tgbot{}).NewTgbot()

	denied := []string{"reset_all_traffics_c", "get_banlogs", "add_client_submit_enable"}
	for _, data := range denied {
		tb.answerCallback(tgbotTestCallbackQuery(tgbotTestUserID, data), false)
		if up, down := tgbotTestTraffic(t); up != 1000 || down != 2000 {
			t.Fatalf("non-admin %q changed traffic: up=%d down=%d", data, up, down)
		}
	}

	// The admin path still works: resetting all traffics zeroes the counters.
	tb.answerCallback(tgbotTestCallbackQuery(tgbotTestAdminID, "reset_all_traffics_c"), true)
	if up, down := tgbotTestTraffic(t); up != 0 || down != 0 {
		t.Fatalf("admin reset_all_traffics_c did not reset: up=%d down=%d", up, down)
	}
}

// TestAnswerCallbackAdminSubmitRequiresSession: an admin submit without a
// live add-client session is refused at the session check (no panic, no
// database change); a non-admin submit is refused earlier, at the gate.
func TestAnswerCallbackAdminSubmitRequiresSession(t *testing.T) {
	inboundID := setupTgbotTestDB(t)
	tb := (&Tgbot{}).NewTgbot()

	// Non-admin: denied by the authorization gate.
	tb.answerCallback(tgbotTestCallbackQuery(tgbotTestUserID, "add_client_submit_enable"), false)

	// Admin without a session: refused by the session check.
	tb.answerCallback(tgbotTestCallbackQuery(tgbotTestAdminID, "add_client_submit_enable"), true)

	inbound, err := tb.inboundService.GetInbound(inboundID)
	if err != nil {
		t.Fatalf("GetInbound: %v", err)
	}
	if got := inbound.Settings; got != `{"clients":[{"id":"11111111-1111-1111-1111-111111111111","flow":"","email":"victim@example.com","limitIp":0,"totalGB":0,"expiryTime":0,"enable":true,"tgId":0,"comment":"","reset":0}],"decryption":"none"}` {
		t.Fatalf("inbound settings changed unexpectedly: %s", got)
	}
}

// TestAnswerCallbackAdminSubmitReachesService: an admin with a live session
// passes the gate and the session check and reaches the submit logic. The
// session points at a missing inbound here, so the submit fails cleanly
// inside the service (no Xray runs in tests); the point is that the admin
// is not stopped by the authorization or session checks, while a non-admin
// never gets that far. A full submit-to-database run needs a live Xray API.
func TestAnswerCallbackAdminSubmitReachesService(t *testing.T) {
	setupTgbotTestDB(t)
	tb := (&Tgbot{}).NewTgbot()

	addClientSessionsMu.Lock()
	sess := tb.newAddClientSession(tgbotTestChatID, tgbotTestAdminID, 999999)
	sess.email = "newclient@example.com"
	sess.id = uuid.New().String()
	addClientSessionsMu.Unlock()

	// Must not panic: the submit fails inside the service (unknown inbound).
	tb.answerCallback(tgbotTestCallbackQuery(tgbotTestAdminID, "add_client_submit_enable"), true)

	// The failed submit keeps the session (the admin can retry or cancel).
	addClientSessionsMu.Lock()
	if got := getAddClientSession(tgbotTestChatID, tgbotTestAdminID); got == nil {
		t.Fatal("failed submit dropped the session; the admin could no longer retry")
	}
	addClientSessionsMu.Unlock()
}

// TestAddClientSessionIsolation: sessions are isolated by (chat, user);
// another member of the same chat cannot read or hijack the flow, and
// expired sessions disappear.
func TestAddClientSessionIsolation(t *testing.T) {
	setupTgbotTestDB(t)
	tb := (&Tgbot{}).NewTgbot()

	addClientSessionsMu.Lock()
	sessA := tb.newAddClientSession(1, tgbotTestAdminID, 10)
	sessA.email = "admin-a@example.com"
	sessB := tb.newAddClientSession(1, int64(222), 20)
	sessB.email = "admin-b@example.com"
	addClientSessionsMu.Unlock()

	// Same chat, different user: no access to A's session.
	addClientSessionsMu.Lock()
	if got := getAddClientSession(1, tgbotTestUserID); got != nil {
		t.Fatalf("stranger got a session: %+v", got)
	}
	// Each admin reads only their own session.
	if got := getAddClientSession(1, tgbotTestAdminID); got == nil || got.email != "admin-a@example.com" {
		t.Fatalf("admin A session wrong: %+v", got)
	}
	if got := getAddClientSession(1, 222); got == nil || got.email != "admin-b@example.com" {
		t.Fatalf("admin B session wrong: %+v", got)
	}
	// Same user, different chat: separate session.
	if got := getAddClientSession(2, tgbotTestAdminID); got != nil {
		t.Fatalf("session leaked across chats: %+v", got)
	}
	addClientSessionsMu.Unlock()

	// Cancel removes only that session.
	addClientSessionsMu.Lock()
	deleteAddClientSession(1, tgbotTestAdminID)
	if got := getAddClientSession(1, tgbotTestAdminID); got != nil {
		t.Fatal("cancelled session still present")
	}
	if got := getAddClientSession(1, 222); got == nil {
		t.Fatal("cancelling one session removed the other admin's session")
	}
	addClientSessionsMu.Unlock()

	// Expired sessions are dropped on access.
	addClientSessionsMu.Lock()
	sessC := tb.newAddClientSession(3, tgbotTestAdminID, 30)
	sessC.lastActive = time.Now().Add(-31 * time.Minute)
	if got := getAddClientSession(3, tgbotTestAdminID); got != nil {
		t.Fatal("expired session was returned")
	}
	addClientSessionsMu.Unlock()
}

// TestAddClientSessionConcurrent hammers the session store from many
// goroutines: two admins creating different clients at the same time must
// never see each other's data. Run with -race.
func TestAddClientSessionConcurrent(t *testing.T) {
	setupTgbotTestDB(t)
	tb := (&Tgbot{}).NewTgbot()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			chatID := int64(100 + n%4)
			userID := int64(1000 + n)
			for j := 0; j < 50; j++ {
				addClientSessionsMu.Lock()
				sess := tb.newAddClientSession(chatID, userID, n)
				sess.email = "user-" + string(rune('a'+n)) + "@example.com"
				sess.state = "awaiting_email"
				got := getAddClientSession(chatID, userID)
				if got == nil || got.email != sess.email {
					t.Errorf("session mismatch for chat %d user %d", chatID, userID)
				}
				if j%2 == 0 {
					// Clear only the input step (the mutex is already held
					// here, so do not call clearAddClientInputState).
					sess.state = ""
				}
				if j == 49 {
					deleteAddClientSession(chatID, userID)
				}
				addClientSessionsMu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	addClientSessionsMu.Lock()
	defer addClientSessionsMu.Unlock()
	if len(addClientSessions) != 0 {
		t.Fatalf("expected all sessions cleaned up, got %d", len(addClientSessions))
	}
}

// TestHandleAddClientInput: only the session owner can feed input into the
// flow; another member of the same chat is ignored.
func TestHandleAddClientInput(t *testing.T) {
	inboundID := setupTgbotTestDB(t)
	tb := (&Tgbot{}).NewTgbot()

	addClientSessionsMu.Lock()
	sess := tb.newAddClientSession(tgbotTestChatID, tgbotTestAdminID, inboundID)
	sess.state = "awaiting_email"
	sess.email = "default@example.com"
	addClientSessionsMu.Unlock()

	hijack := &telego.Message{
		Chat: telego.Chat{ID: tgbotTestChatID},
		From: &telego.User{ID: tgbotTestUserID},
		Text: "hijack@example.com",
	}
	tb.handleAddClientInput(hijack)
	addClientSessionsMu.Lock()
	if sess.email != "default@example.com" {
		t.Fatalf("stranger overwrote the email: %q", sess.email)
	}
	if sess.state != "awaiting_email" {
		t.Fatalf("stranger changed the state: %q", sess.state)
	}
	addClientSessionsMu.Unlock()

	owner := &telego.Message{
		Chat: telego.Chat{ID: tgbotTestChatID},
		From: &telego.User{ID: tgbotTestAdminID},
		Text: "owner@example.com",
	}
	tb.handleAddClientInput(owner)
	addClientSessionsMu.Lock()
	defer addClientSessionsMu.Unlock()
	if sess.email != "owner@example.com" {
		t.Fatalf("owner input not applied: %q", sess.email)
	}
	if sess.state != "" {
		t.Fatalf("input step not cleared: %q", sess.state)
	}
}

// TestHandleAddClientInputNoSession: input without a live session is ignored.
func TestHandleAddClientInputNoSession(t *testing.T) {
	setupTgbotTestDB(t)
	tb := (&Tgbot{}).NewTgbot()
	tb.handleAddClientInput(&telego.Message{
		Chat: telego.Chat{ID: tgbotTestChatID},
		From: &telego.User{ID: tgbotTestUserID},
		Text: "anything",
	})
}

// TestBuildJSONForProtocolUsesSession: the client JSON is built from the
// session's own data, not from shared state.
func TestBuildJSONForProtocolUsesSession(t *testing.T) {
	setupTgbotTestDB(t)
	tb := (&Tgbot{}).NewTgbot()

	addClientSessionsMu.Lock()
	sess := tb.newAddClientSession(tgbotTestChatID, tgbotTestAdminID, 1)
	sess.id = "22222222-2222-2222-2222-222222222222"
	sess.email = "json@example.com"
	sess.flow = "xtls-rprx-vision"
	addClientSessionsMu.Unlock()

	got, err := tb.BuildJSONForProtocol(sess, model.VLESS)
	if err != nil {
		t.Fatalf("BuildJSONForProtocol: %v", err)
	}
	for _, want := range []string{
		"22222222-2222-2222-2222-222222222222",
		"json@example.com",
		"xtls-rprx-vision",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("JSON missing %q: %s", want, got)
		}
	}
}
