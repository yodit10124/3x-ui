package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/global"
	"github.com/mhsanaei/3x-ui/v2/web/locale"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"github.com/google/uuid"
	"github.com/mymmrac/telego"
	th "github.com/mymmrac/telego/telegohandler"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/op/go-logging"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/text/language"
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

// fakeTelegramAPI answers Bot API calls against a local test server so the
// bot's send/delete paths can run without Telegram. It records how many
// messages were sent and deleted, assigns each sent message a distinct
// increasing ID, and records the ID of every deleted message, so a test can
// wait for the delete of one specific message.
type fakeTelegramAPI struct {
	mu      sync.Mutex
	sends   int
	nextID  int
	deleted []int
}

func (f *fakeTelegramAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	method := path.Base(r.URL.Path)
	f.mu.Lock()
	id := 0
	switch method {
	case "sendMessage", "editMessageText", "editMessageReplyMarkup":
		f.sends++
		if f.nextID == 0 {
			f.nextID = 100
		}
		id = f.nextID
		f.nextID++
	case "deleteMessage":
		var req struct {
			MessageID int `json:"message_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.MessageID != 0 {
			f.deleted = append(f.deleted, req.MessageID)
		}
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch method {
	case "sendMessage", "editMessageText", "editMessageReplyMarkup":
		fmt.Fprintf(w, `{"ok":true,"result":{"message_id":%d,"date":1700000000,"chat":{"id":%d,"type":"private"}}}`, id, tgbotTestChatID)
	default:
		fmt.Fprint(w, `{"ok":true,"result":true}`)
	}
}

func (f *fakeTelegramAPI) sendCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sends
}

// lastSentID returns the ID assigned to the most recently sent message, or
// 0 if nothing was sent yet.
func (f *fakeTelegramAPI) lastSentID() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nextID == 0 {
		return 0
	}
	return f.nextID - 1
}

// deletedMessageIDs returns the IDs of the messages deleted so far, in
// order.
func (f *fakeTelegramAPI) deletedMessageIDs() []int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]int, len(f.deleted))
	copy(out, f.deleted)
	return out
}

// setupFakeTgbot installs a bot backed by the fake API server and marks it
// running, so sends and deletes actually execute. The previous bot state is
// restored when the test ends.
func setupFakeTgbot(t *testing.T) *fakeTelegramAPI {
	t.Helper()
	api := &fakeTelegramAPI{}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	fakeBot, err := telego.NewBot("123456:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		telego.WithAPIServer(srv.URL), telego.WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("NewBot: %v", err)
	}
	oldBot := bot
	oldRunning := isRunning.Load()
	bot = fakeBot
	isRunning.Store(true)
	t.Cleanup(func() {
		bot = oldBot
		isRunning.Store(oldRunning)
	})
	return api
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
	// Input handling re-checks the admin status on every message, so
	// the test must load the admin list the way Start() does.
	setAdminIds([]int64{tgbotTestAdminID})
	t.Cleanup(func() { setAdminIds(nil) })

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

// TestHandleAddClientInputRevokedAdmin covers the audit scenario
// "start input -> revoked -> keep sending text": an admin enters the
// add-client flow, is removed from the admin list (and the bot reloaded),
// then keeps sending text before the session expires. The revoked user
// must not be able to keep editing the draft or trigger reads and echoes
// of inbound data.
//
// Two layers are exercised:
//   - an admin-list update deletes the sessions of revoked users at once;
//   - even if such a session still exists (the revocation raced the
//     input), handling the input re-checks the admin status, deletes the
//     session and refuses without sending anything.
func TestHandleAddClientInputRevokedAdmin(t *testing.T) {
	setupTgbotTestDB(t)
	api := setupFakeTgbot(t)
	tb := (&Tgbot{}).NewTgbot()

	setAdminIds([]int64{tgbotTestAdminID})
	t.Cleanup(func() { setAdminIds(nil) })

	// The admin starts an add-client flow and reaches the email step.
	addClientSessionsMu.Lock()
	sess := tb.newAddClientSession(tgbotTestChatID, tgbotTestAdminID, 1)
	sess.state = "awaiting_email"
	addClientSessionsMu.Unlock()

	// Revocation via an admin-list update must drop the session at once.
	setAdminIds([]int64{222})
	addClientSessionsMu.Lock()
	if got := getAddClientSession(tgbotTestChatID, tgbotTestAdminID); got != nil {
		addClientSessionsMu.Unlock()
		t.Fatal("revoked admin's session survived the admin-list update")
	}
	addClientSessionsMu.Unlock()

	// A further text message must not recreate or use the flow, and must
	// not echo any management information.
	tb.handleAddClientInput(&telego.Message{
		Chat: telego.Chat{ID: tgbotTestChatID},
		From: &telego.User{ID: tgbotTestAdminID},
		Text: "attacker@example.com",
	})
	if got := api.sendCount(); got != 0 {
		t.Fatalf("revoked admin input produced %d sends, want 0", got)
	}

	// Second layer: a session that still exists for a user who is not an
	// admin (revocation raced the input) must be deleted on the next
	// input, again without reading or echoing inbound data.
	addClientSessionsMu.Lock()
	sess = tb.newAddClientSession(tgbotTestChatID, tgbotTestUserID, 1)
	sess.state = "awaiting_email"
	addClientSessionsMu.Unlock()
	tb.handleAddClientInput(&telego.Message{
		Chat: telego.Chat{ID: tgbotTestChatID},
		From: &telego.User{ID: tgbotTestUserID},
		Text: "attacker@example.com",
	})
	addClientSessionsMu.Lock()
	if got := getAddClientSession(tgbotTestChatID, tgbotTestUserID); got != nil {
		addClientSessionsMu.Unlock()
		t.Fatal("non-admin session survived input handling")
	}
	addClientSessionsMu.Unlock()
	if got := api.sendCount(); got != 0 {
		t.Fatalf("non-admin input produced %d sends, want 0", got)
	}
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

// TestSendMsgToTgbotDeleteAfterKeepsNewInputState: the audit scenario — the
// admin fills in the email, then, while the "received email" prompt is
// still alive, clicks "change ID". The old prompt's timer must not clear
// the new awaiting_id step when it fires; the timer only deletes its own
// message. On the old code (the timer cleared the input state) this test
// fails with state "".
func TestSendMsgToTgbotDeleteAfterKeepsNewInputState(t *testing.T) {
	setupTgbotTestDB(t)
	api := setupFakeTgbot(t)
	tb := (&Tgbot{}).NewTgbot()

	addClientSessionsMu.Lock()
	tb.newAddClientSession(tgbotTestChatID, tgbotTestAdminID, 1)
	addClientSessionsMu.Unlock()

	// Arm the timer of an earlier prompt (1s here instead of the
	// production 3s, same code path). Each sent message gets a distinct
	// ID from the fake API, so the armed message can be told apart from
	// the prompt the callback sends next.
	tb.SendMsgToTgbotDeleteAfter(tgbotTestChatID, "received_email", 1)
	armedID := api.lastSentID()

	// Before the timer fires, the admin moves on to the next step via the
	// "change ID" button, which sets awaiting_id synchronously.
	tb.answerCallback(tgbotTestCallbackQuery(tgbotTestAdminID, "add_client_ch_default_id"), true)

	addClientSessionsMu.Lock()
	sess := getAddClientSession(tgbotTestChatID, tgbotTestAdminID)
	state := ""
	if sess != nil {
		state = sess.state
	}
	addClientSessionsMu.Unlock()
	if state != "awaiting_id" {
		t.Fatalf("state after moving to next step = %q, want awaiting_id", state)
	}

	// Wait for the old prompt's own delete event, not a fixed sleep: the
	// wait is synchronised with the timer actually firing. The callback
	// above deletes its own message (id 7), so a bare delete count would
	// not prove the timer ran.
	deadline := time.Now().Add(5 * time.Second)
	for {
		deleted := false
		for _, id := range api.deletedMessageIDs() {
			if id == armedID {
				deleted = true
				break
			}
		}
		if deleted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("old prompt message %d was never deleted, timer did not fire", armedID)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The old timer ran, and the new step must have survived it.
	addClientSessionsMu.Lock()
	sess = getAddClientSession(tgbotTestChatID, tgbotTestAdminID)
	state = ""
	if sess != nil {
		state = sess.state
	}
	addClientSessionsMu.Unlock()
	if state != "awaiting_id" {
		t.Fatalf("old prompt timer cleared the new step: state = %q, want awaiting_id", state)
	}
}

// TestAdminIdsConcurrentReload: a bot reload swapping the admin list while
// messages are being handled must not trip the race detector, and any
// single snapshot a reader observes must be one complete generation —
// never a mix of two. On the old code (plain slice, writes locked but
// reads unlocked) this test fails under -race.
func TestAdminIdsConcurrentReload(t *testing.T) {
	setupTgbotTestDB(t)
	setupFakeTgbot(t)
	tb := (&Tgbot{}).NewTgbot()

	setA := []int64{111, 222}
	setB := []int64{333, 444}
	setAdminIds(setA)
	t.Cleanup(func() { setAdminIds(nil) })

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Reload loop: swap the snapshot between two disjoint generations.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				setAdminIds(setA)
				setAdminIds(setB)
			}
		}
	}()
	// Reader loops: each iteration loads ONE snapshot and checks it is a
	// single complete generation, then exercises the permission check.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					ids := getAdminIds()
					seenA, seenB := false, false
					for _, id := range ids {
						if id == 111 || id == 222 {
							seenA = true
						}
						if id == 333 || id == 444 {
							seenB = true
						}
					}
					if seenA && seenB {
						t.Errorf("single admin snapshot mixes two generations: %v", ids)
						return
					}
					if len(ids) != 2 {
						t.Errorf("admin snapshot has %d entries, want 2: %v", len(ids), ids)
						return
					}
					// Permission checks run concurrently with the reload.
					_ = checkAdmin(111)
					_ = checkAdmin(333)
					_ = checkAdmin(999)
				}
			}
		}()
	}
	// Broadcast loop: iterate the snapshot and send via the fake bot.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				tb.SendMsgToTgbotAdmins("ping")
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Deterministic tail: a final known snapshot reads back exactly.
	setAdminIds(setA)
	if !checkAdmin(111) || !checkAdmin(222) || checkAdmin(333) {
		t.Fatalf("final snapshot mismatch: 111=%v 222=%v 333=%v",
			checkAdmin(111), checkAdmin(222), checkAdmin(333))
	}
	setAdminIds(nil)
	if checkAdmin(111) {
		t.Fatalf("cleared admin list still reports 111 as admin")
	}
}

// H-2: with Xray never started, the package-global process pointer p is
// nil. The three Telegram paths that used to touch p directly must not
// panic, and the client must be reported offline. On the old code each
// of these calls panics (the test binary crashes).
func TestTgbotNilXrayProcess(t *testing.T) {
	setupTgbotTestDB(t)
	tb := (&Tgbot{}).NewTgbot()

	// Pin p to nil: other tests in this package start a fake Xray and
	// leave p set. Restore it afterwards.
	oldP := p
	p = nil
	t.Cleanup(func() { p = oldP })

	// Force the uncached path in prepareServerUsageInfo: a warm cache
	// would return early without touching the process pointer.
	statusCache.mutex.Lock()
	statusCache.data = nil
	statusCache.mutex.Unlock()
	serverStatsCache.mutex.Lock()
	serverStatsCache.data = ""
	serverStatsCache.mutex.Unlock()

	var ct xray.ClientTraffic
	if err := database.GetDB().Where("email = ?", "victim@example.com").First(&ct).Error; err != nil {
		t.Fatalf("read traffic: %v", err)
	}

	// clientInfoMsg: must not panic and must produce output. Whether the
	// client is reported offline is decided by IsXrayRunning, asserted
	// below; the rendered status text itself is not observable here
	// because the locale bundle is not loaded in tests.
	msg := tb.clientInfoMsg(&ct, true, true, true, true, true, false)
	if msg == "" {
		t.Fatal("clientInfoMsg with nil Xray process returned empty info")
	}
	if tb.xrayService.IsXrayRunning() {
		t.Fatal("IsXrayRunning with nil Xray process returned true")
	}
	if onlines := tb.xrayService.GetOnlineClients(); onlines != nil {
		t.Fatalf("GetOnlineClients with nil Xray process returned %v, want nil", onlines)
	}

	// prepareServerUsageInfo: must not panic and must produce output.
	if info := tb.prepareServerUsageInfo(); info == "" {
		t.Fatal("prepareServerUsageInfo with nil Xray process returned empty info")
	}

	// onlineClients: must not panic and must send nothing.
	tb.onlineClients(tgbotTestChatID)
}

// H-2: the PanicRecovery middleware registered by newBotHandler must
// keep the update loop alive after a handler panics. The panicking
// update is a callback query without a message, which matches none of
// the production routes (they all need a message or a command) and
// therefore reaches the panicking handler registered last. Without the
// middleware the panic crashes the test binary; with it, the following
// close-keyboard message is still answered.
func TestTgbotPanicRecoveryMiddleware(t *testing.T) {
	setupTgbotTestDB(t)
	api := setupFakeTgbot(t)
	tb := (&Tgbot{}).NewTgbot()

	updates := make(chan telego.Update, 4)
	h, err := tb.newBotHandler(bot, updates)
	if err != nil {
		t.Fatalf("newBotHandler: %v", err)
	}
	// Registered last, but matched first for a message-less callback:
	// the production callback route requires a message.
	h.HandleCallbackQuery(func(ctx *th.Context, query telego.CallbackQuery) error {
		panic("boom")
	}, th.AnyCallbackQuery())

	go func() { _ = h.Start() }()
	t.Cleanup(func() { _ = h.Stop() })

	// Update 1: panics inside a handler.
	updates <- telego.Update{UpdateID: 1, CallbackQuery: &telego.CallbackQuery{
		ID:   "q1",
		From: telego.User{ID: tgbotTestAdminID},
	}}

	// Update 2: the close-keyboard button must still be answered. If
	// the panic had killed the handler loop, no send would ever arrive.
	closeText := tb.I18nBot("tgbot.buttons.closeKeyboard")
	updates <- telego.Update{UpdateID: 2, Message: &telego.Message{
		MessageID: 2,
		From:      &telego.User{ID: tgbotTestAdminID},
		Chat:      telego.Chat{ID: tgbotTestChatID},
		Text:      closeText,
	}}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if api.sendCount() >= 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("handler loop died after the panicking update: no answer to the second update")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// H-2 (end to end): the admin get_usage callback with Xray never started
// must be answered, not crash the panel. It runs through the real
// dispatch path: newBotHandler -> AnyCallbackQueryWithMessage -> worker
// goroutine -> answerCallback -> getServerUsage -> prepareServerUsageInfo.
// On the old code the goroutine panics on the nil process pointer and
// the test binary crashes; with the guards removed but the recover kept
// the process would survive yet never answer, so the send assertion
// pins the guards, not just the recover.
func TestTgbotGetUsageWithNilXrayProcess(t *testing.T) {
	setupTgbotTestDB(t)
	api := setupFakeTgbot(t)
	tb := (&Tgbot{}).NewTgbot()
	setAdminIds([]int64{tgbotTestAdminID})
	t.Cleanup(func() { setAdminIds(nil) })

	oldP := p
	p = nil
	t.Cleanup(func() { p = oldP })
	statusCache.mutex.Lock()
	statusCache.data = nil
	statusCache.mutex.Unlock()
	serverStatsCache.mutex.Lock()
	serverStatsCache.data = ""
	serverStatsCache.mutex.Unlock()

	// The worker pool is created by Start() in production; tests never
	// call Start(), so a nil pool would block the dispatch goroutine
	// forever before answerCallback runs.
	oldPool := messageWorkerPool
	messageWorkerPool = make(chan struct{}, 10)
	t.Cleanup(func() {
		// Wait for the in-flight dispatch worker to release its slot
		// before restoring the global pool. The worker holds a token
		// from the moment it is dispatched until its deferred release
		// runs, so a non-empty pool means it is still running; restoring
		// the global while it runs would race with its release. (N-8)
		deadline := time.Now().Add(5 * time.Second)
		for len(messageWorkerPool) > 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		messageWorkerPool = oldPool
	})

	updates := make(chan telego.Update, 4)
	h, err := tb.newBotHandler(bot, updates)
	if err != nil {
		t.Fatalf("newBotHandler: %v", err)
	}
	go func() { _ = h.Start() }()
	t.Cleanup(func() { _ = h.Stop() })

	updates <- telego.Update{UpdateID: 1, CallbackQuery: &telego.CallbackQuery{
		ID:   "q-usage",
		From: telego.User{ID: tgbotTestAdminID},
		Message: &telego.Message{
			Chat:      telego.Chat{ID: tgbotTestChatID},
			MessageID: 7,
		},
		Data: "get_usage",
	}}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if api.sendCount() >= 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("get_usage callback with nil Xray process was never answered")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// setupTgbotTestLocale loads the real English bot translations into
// the global bot localizer for one test, restoring the previous
// localizer afterwards. Tests run sequentially in this package, so
// the global swap is safe.
func setupTgbotTestLocale(t *testing.T) {
	t.Helper()
	bundle := i18n.NewBundle(language.MustParse("en-US"))
	bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)
	data, err := os.ReadFile("../translation/translate.en_US.toml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.ParseMessageFileBytes(data, "translate.en_US.toml"); err != nil {
		t.Fatal(err)
	}
	old := locale.LocalizerBot
	locale.LocalizerBot = i18n.NewLocalizer(bundle, "en-US")
	t.Cleanup(func() { locale.LocalizerBot = old })
}

// TestEscapeI18nBotParams (M-6): template parameter values are
// HTML-escaped, keys are not, and parameters without the separator
// pass through unchanged.
func TestEscapeI18nBotParams(t *testing.T) {
	got := escapeI18nBotParams([]string{
		`ClientComment==<a href="https://evil.example/phish">click</a>`,
		`Email==a@b.com`,
		`NoSeparator`,
	})
	if want := `ClientComment==&lt;a href=&#34;https://evil.example/phish&#34;&gt;click&lt;/a&gt;`; got[0] != want {
		t.Fatalf("got %q, want %q", got[0], want)
	}
	if got[1] != `Email==a@b.com` {
		t.Fatalf("plain value changed: %q", got[1])
	}
	if got[2] != `NoSeparator` {
		t.Fatalf("separator-less parameter changed: %q", got[2])
	}
}

// TestBuildInboundClientDataMessageEscapesHTML (M-6): a phishing
// anchor planted in a client comment must reach the Telegram
// message escaped, not as a live link. The audit's PoC comment was
// `<a href="https://evil.example/phish">点击领取流量</a>`.
func TestBuildInboundClientDataMessageEscapesHTML(t *testing.T) {
	setupTgbotTestLocale(t)
	tb := (&Tgbot{}).NewTgbot()
	sess := &addClientSession{
		id:         "11111111-1111-1111-1111-111111111111",
		email:      "victim@example.com",
		comment:    `<a href="https://evil.example/phish">click here for free traffic</a>`,
		totalGB:    0,
		expiryTime: 0,
		enable:     true,
	}
	msg, err := tb.BuildInboundClientDataMessage(sess, "vless-in", model.VLESS)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msg, `<a href="https://evil.example/phish">`) {
		t.Fatalf("message contains a live phishing anchor: %q", msg)
	}
	if !strings.Contains(msg, "&lt;a href=") {
		t.Fatalf("comment was not HTML-escaped in the message: %q", msg)
	}
	if !strings.Contains(msg, "victim@example.com") {
		t.Fatalf("email missing from the message: %q", msg)
	}
}

// TestI18nBotEscapesErrorMessage (M-6): an error string echoed into
// the error_add_client template is escaped too, so a crafted error
// cannot inject markup either.
func TestI18nBotEscapesErrorMessage(t *testing.T) {
	setupTgbotTestLocale(t)
	tb := (&Tgbot{}).NewTgbot()
	msg := tb.I18nBot("tgbot.messages.error_add_client", "error=="+`<b>boom</b>`)
	if strings.Contains(msg, "<b>boom</b>") {
		t.Fatalf("error text not escaped: %q", msg)
	}
	if !strings.Contains(msg, "&lt;b&gt;boom&lt;/b&gt;") {
		t.Fatalf("escaped error text missing: %q", msg)
	}
}

// TestBuildJSONForProtocolInjectionBlocked (M-7): the audit's PoC
// email `a@b.com","id":"99999999-...","flow":"xtls-rprx-vision`
// used to override the client's id and flow through Sprintf. It must
// now be rejected by the email check, and even a quote-bearing value
// in an unvalidated field (comment) must survive only as data.
func TestBuildJSONForProtocolInjectionBlocked(t *testing.T) {
	tb := (&Tgbot{}).NewTgbot()
	base := &addClientSession{
		id:         "11111111-1111-1111-1111-111111111111",
		flow:       "xtls-rprx-vision",
		email:      "victim@example.com",
		limitIP:    0,
		totalGB:    0,
		expiryTime: 0,
		enable:     true,
		tgID:       "123",
		comment:    "plain",
		reset:      0,
		security:   "auto",
	}

	// The audit's PoC email is rejected outright.
	poc := *base
	poc.email = `a@b.com","id":"99999999-9999-9999-9999-999999999999","flow":"xtls-rprx-vision`
	if _, err := tb.BuildJSONForProtocol(&poc, model.VLESS); err == nil {
		t.Fatal("PoC email was accepted, want it rejected")
	}

	// A non-UUID id is rejected for VMESS/VLESS.
	badID := *base
	badID.id = "not-a-uuid"
	if _, err := tb.BuildJSONForProtocol(&badID, model.VLESS); err == nil {
		t.Fatal("non-UUID id was accepted, want it rejected")
	}

	// The default email is an 8-character random token, not an
	// address; it must still be accepted.
	tokenEmail := *base
	tokenEmail.email = "a1b2c3d4"
	if _, err := tb.BuildJSONForProtocol(&tokenEmail, model.VLESS); err != nil {
		t.Fatalf("default-style token email rejected: %v", err)
	}

	// A quote-bearing comment must round-trip as data: parsing the
	// output JSON must yield the original id, flow, tgId, and the
	// comment verbatim, with no injected fields.
	inject := *base
	inject.comment = `x","id":"99999999-9999-9999-9999-999999999999","flow":"none","tgId":"666`
	out, err := tb.BuildJSONForProtocol(&inject, model.VLESS)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Clients []struct {
			ID      string `json:"id"`
			Flow    string `json:"flow"`
			Email   string `json:"email"`
			TgID    int64  `json:"tgId"`
			Comment string `json:"comment"`
		} `json:"clients"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if len(parsed.Clients) != 1 {
		t.Fatalf("want exactly one client, got %d: %s", len(parsed.Clients), out)
	}
	got := parsed.Clients[0]
	// L-16: tgId is a JSON number now, and the injected "666" inside
	// the comment must not override it.
	if got.ID != base.id || got.Flow != base.flow || got.TgID != 123 {
		t.Fatalf("injected fields leaked through: %+v", got)
	}
	if got.Comment != inject.comment {
		t.Fatalf("comment mismatch: got %q, want %q", got.Comment, inject.comment)
	}
}

// TestBuildJSONForProtocolShapes (M-7): each protocol emits exactly
// its old field set, with the same JSON types, so AddInboundClient
// keeps parsing the settings the same way.
func TestBuildJSONForProtocolShapes(t *testing.T) {
	tb := (&Tgbot{}).NewTgbot()
	sess := &addClientSession{
		id:         "11111111-1111-1111-1111-111111111111",
		flow:       "xtls-rprx-vision",
		email:      "victim@example.com",
		limitIP:    2,
		totalGB:    1073741824,
		expiryTime: 1735689600000,
		enable:     true,
		tgID:       "123",
		comment:    `quote " backslash \ newline` + "\n",
		reset:      0,
		security:   "auto",
		trPassword: `p"ass`,
		shPassword: `s"pass`,
		method:     "aes-256-gcm",
	}
	cases := []struct {
		protocol model.Protocol
		fields   []string
		absent   []string
	}{
		{model.VMESS, []string{`"id"`, `"security"`, `"email"`}, []string{`"flow"`, `"password"`, `"method"`}},
		{model.VLESS, []string{`"id"`, `"flow"`, `"email"`}, []string{`"security"`, `"password"`, `"method"`}},
		{model.Trojan, []string{`"password"`, `"email"`}, []string{`"id"`, `"flow"`, `"security"`, `"method"`}},
		{model.Shadowsocks, []string{`"method"`, `"password"`, `"email"`}, []string{`"id"`, `"flow"`, `"security"`}},
	}
	for _, tc := range cases {
		out, err := tb.BuildJSONForProtocol(sess, tc.protocol)
		if err != nil {
			t.Fatalf("%s: %v", tc.protocol, err)
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(out), &parsed); err != nil {
			t.Fatalf("%s: output is not valid JSON: %v\n%s", tc.protocol, err, out)
		}
		clients, ok := parsed["clients"].([]any)
		if !ok || len(clients) != 1 {
			t.Fatalf("%s: want one client: %s", tc.protocol, out)
		}
		client, ok := clients[0].(map[string]any)
		if !ok {
			t.Fatalf("%s: client is not an object: %s", tc.protocol, out)
		}
		for _, f := range tc.fields {
			if _, ok := client[strings.Trim(f, `"`)]; !ok {
				t.Fatalf("%s: missing field %s: %s", tc.protocol, f, out)
			}
		}
		for _, f := range tc.absent {
			if _, ok := client[strings.Trim(f, `"`)]; ok {
				t.Fatalf("%s: unexpected field %s: %s", tc.protocol, f, out)
			}
		}
		// Numeric and boolean types must stay JSON numbers/bools.
		if _, ok := client["limitIp"].(float64); !ok {
			t.Fatalf("%s: limitIp is not a number: %s", tc.protocol, out)
		}
		if _, ok := client["enable"].(bool); !ok {
			t.Fatalf("%s: enable is not a bool: %s", tc.protocol, out)
		}
	}
}

// TestTgbotRateLimiter (M-8): a per-(chat, user) token bucket
// allows the burst, then denies until it refills, and tracks users
// independently.
func TestTgbotRateLimiter(t *testing.T) {
	lim := newTgbotRateLimiter(3, 50*time.Millisecond)
	for i := 0; i < 3; i++ {
		if !lim.Allow(1, 100) {
			t.Fatalf("allow %d: want true", i)
		}
	}
	if lim.Allow(1, 100) {
		t.Fatal("4th call in the burst was allowed, want denied")
	}
	// Another user and another chat are unaffected.
	if !lim.Allow(1, 200) {
		t.Fatal("different user was denied, want allowed")
	}
	if !lim.Allow(2, 100) {
		t.Fatal("different chat was denied, want allowed")
	}
	time.Sleep(120 * time.Millisecond)
	if !lim.Allow(1, 100) {
		t.Fatal("call after refill was denied, want allowed")
	}
}

// TestTgbotRateLimiterDropsFlood (M-8): firing 15 /id commands at
// once from one user must produce exactly the burst (10) of answers;
// the rest are dropped before any worker goroutine is spawned.
func TestTgbotRateLimiterDropsFlood(t *testing.T) {
	setupTgbotTestDB(t)
	api := setupFakeTgbot(t)

	// Disable the refill for this test: the handler loop can take
	// over a second to dispatch the flood, and a refilled token
	// would legitimately admit an 11th command. Set before NewTgbot
	// so the new limiter picks it up.
	origRefill := tgbotRateLimitRefill
	tgbotRateLimitRefill = time.Hour
	t.Cleanup(func() { tgbotRateLimitRefill = origRefill })
	tb := (&Tgbot{}).NewTgbot()

	// The worker pool is normally created by Start(); the handler
	// test drives newBotHandler directly, so create it here.
	oldPool := messageWorkerPool
	messageWorkerPool = make(chan struct{}, 10)
	t.Cleanup(func() { messageWorkerPool = oldPool })

	updates := make(chan telego.Update, 32)
	h, err := tb.newBotHandler(bot, updates)
	if err != nil {
		t.Fatalf("newBotHandler: %v", err)
	}
	go func() { _ = h.Start() }()
	t.Cleanup(func() { _ = h.Stop() })

	for i := 0; i < 15; i++ {
		updates <- telego.Update{UpdateID: i + 1, Message: &telego.Message{
			MessageID: i + 1,
			From:      &telego.User{ID: tgbotTestUserID},
			Chat:      telego.Chat{ID: tgbotTestChatID},
			Text:      "/id",
		}}
	}

	// Under -race the whole path (DB setup, handler dispatch, fake
	// API round-trips) runs several times slower, so the deadline
	// is generous; the assertion below is still exact.
	deadline := time.Now().Add(15 * time.Second)
	for {
		if api.sendCount() >= tgbotRateLimitBurst {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d answers arrived, want %d", api.sendCount(), tgbotRateLimitBurst)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Let any straggler finish, then the count must be exactly the
	// burst: the 5 over-limit commands were dropped, not queued.
	time.Sleep(2 * time.Second)
	if got := api.sendCount(); got != tgbotRateLimitBurst {
		t.Fatalf("sendCount = %d, want exactly the burst of %d", got, tgbotRateLimitBurst)
	}
}

// TestUserLoginNotifyDedup (M-8): three identical failed-login
// notifications in a row produce a single Telegram message; a
// different IP is a different key and does notify.
func TestUserLoginNotifyDedup(t *testing.T) {
	setupTgbotTestDB(t)
	api := setupFakeTgbot(t)
	setAdminIds([]int64{tgbotTestAdminID})
	t.Cleanup(func() { setAdminIds(nil) })
	tb := (&Tgbot{}).NewTgbot()

	// The setting defaults to true in the test database.
	if enabled, err := tb.settingService.GetTgBotLoginNotify(); err != nil || !enabled {
		t.Fatalf("login notify not enabled in test DB: %v %v", enabled, err)
	}

	waitForSends := func(want int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if api.sendCount() >= want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("sendCount = %d, want at least %d", api.sendCount(), want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	username := "flood-user-m8"
	tb.UserLoginNotify(username, "***", "203.0.113.9", "2026-11-25 17:00:00", LoginFail)
	tb.UserLoginNotify(username, "***", "203.0.113.9", "2026-11-25 17:00:01", LoginFail)
	tb.UserLoginNotify(username, "***", "203.0.113.9", "2026-11-25 17:00:02", LoginFail)
	waitForSends(1)
	time.Sleep(500 * time.Millisecond)
	if got := api.sendCount(); got != 1 {
		t.Fatalf("sendCount = %d after three identical notifies, want 1", got)
	}

	tb.UserLoginNotify(username, "***", "198.51.100.7", "2026-11-25 17:00:03", LoginFail)
	waitForSends(2)
}

// TestTgbotRetryAfter (M-8): a 429 error yields the requested delay
// (capped), other errors are not rate limits.
func TestTgbotRetryAfter(t *testing.T) {
	if d, ok := tgbotRetryAfter(fmt.Errorf("telegram: 429 Too Many Requests: retry after 35")); !ok || d != 35*time.Second {
		t.Fatalf("429 with retry after 35: got (%v, %v), want (35s, true)", d, ok)
	}
	if d, ok := tgbotRetryAfter(fmt.Errorf("telegram: 429 Too Many Requests: retry after 600")); !ok || d != 60*time.Second {
		t.Fatalf("429 with retry after 600: got (%v, %v), want (60s, true)", d, ok)
	}
	if _, ok := tgbotRetryAfter(fmt.Errorf("connection reset by peer")); ok {
		t.Fatal("connection error reported as a rate limit")
	}
}

// TestSendBackupAndBanLogsNilBot (M-9): with the bot stopped (bot
// nil), sendBackup and sendBanLogs must return without panicking.
// Real files are planted at the paths they open, so without the
// guard the calls would reach bot.SendDocument on the nil bot.
func TestSendBackupAndBanLogsNilBot(t *testing.T) {
	setupTgbotTestDB(t)
	// No setupFakeTgbot: bot stays nil and isRunning stays false.
	setAdminIds([]int64{tgbotTestAdminID})
	t.Cleanup(func() { setAdminIds(nil) })
	if bot != nil || isRunning.Load() {
		t.Fatal("test setup: bot must be nil and stopped")
	}

	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	t.Setenv("XUI_BIN_FOLDER", dir)
	t.Setenv("XUI_LOG_FOLDER", dir)
	plant := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	plant(config.GetDBPath(), "fake-db")
	plant(xray.GetConfigPath(), "{}")
	plant(xray.GetIPLimitBannedLogPath(), "banned log line\n")
	plant(xray.GetIPLimitBannedPrevLogPath(), "previous banned log line\n")

	tb := (&Tgbot{}).NewTgbot()
	// Must return, not panic on the nil bot.
	tb.sendBackup(tgbotTestAdminID)
	tb.sendBanLogs(tgbotTestAdminID, true)
	tb.sendBanLogs(tgbotTestAdminID, false)
}

// resetUserShareRequests clears the pending "select user" registry
// for one test. Tests run sequentially in this package.
func resetUserShareRequests(t *testing.T) {
	t.Helper()
	userShareMu.Lock()
	userShareRequests = map[int32]pendingUserShare{}
	userShareMu.Unlock()
}

// TestUserShareRequestRegistry (M-10): an issued request id is
// consumable once, by its own admin in its own chat only; anything
// else is refused, and issued ids are random, not sequential.
func TestUserShareRequestRegistry(t *testing.T) {
	resetUserShareRequests(t)

	id := issueUserShareRequest(tgbotTestChatID, tgbotTestAdminID, 7)
	if id == 0 {
		t.Fatal("issued a zero request id")
	}
	if _, ok := consumeUserShareRequest(id, tgbotTestChatID+1, tgbotTestAdminID); ok {
		t.Fatal("request consumed from a different chat")
	}
	id2 := issueUserShareRequest(tgbotTestChatID, tgbotTestAdminID, 7)
	if _, ok := consumeUserShareRequest(id2, tgbotTestChatID, tgbotTestAdminID+1); ok {
		t.Fatal("request consumed by a different admin")
	}
	id3 := issueUserShareRequest(tgbotTestChatID, tgbotTestAdminID, 7)
	if trafficID, ok := consumeUserShareRequest(id3, tgbotTestChatID, tgbotTestAdminID); !ok || trafficID != 7 {
		t.Fatalf("legit consume failed: (%d, %v)", trafficID, ok)
	}
	if _, ok := consumeUserShareRequest(id3, tgbotTestChatID, tgbotTestAdminID); ok {
		t.Fatal("replayed request id was accepted")
	}
	if _, ok := consumeUserShareRequest(123456789, tgbotTestChatID, tgbotTestAdminID); ok {
		t.Fatal("unknown request id was accepted")
	}
	a := issueUserShareRequest(tgbotTestChatID, tgbotTestAdminID, 1)
	b := issueUserShareRequest(tgbotTestChatID, tgbotTestAdminID, 2)
	if a == b {
		t.Fatal("two issued request ids collide")
	}
}

// TestHandleUsersSharedRequiresIssuedRequest (M-10): the audit's
// attack — another admin answers with the predictable traffic row id
// — must not bind anything; only the admin the keyboard was issued
// to, with the issued random id, may bind.
func TestHandleUsersSharedRequiresIssuedRequest(t *testing.T) {
	setupTgbotTestDB(t)
	setupFakeTgbot(t)
	setAdminIds([]int64{tgbotTestAdminID, 222})
	t.Cleanup(func() { setAdminIds(nil) })
	tb := (&Tgbot{}).NewTgbot()
	resetUserShareRequests(t)

	// The legit bind reaches UpdateInboundClient, which calls
	// p.GetAPIPort(): start a fake Xray process (a sleeping script,
	// as the import tests do) so p is non-nil. API calls against it
	// fail harmlessly and only set needRestart.
	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XUI_BIN_FOLDER", binDir)
	script := "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo \"Xray 99.0-test (test)\"; exit 0; fi\nexec sleep 60\n"
	if err := os.WriteFile(filepath.Join(binDir, xray.GetBinaryName()), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = (&XrayService{}).StopXray() })
	if err := (&XrayService{}).RestartXray(true); err != nil {
		t.Fatalf("RestartXray: %v", err)
	}

	traffic, _, err := tb.inboundService.GetClientByEmail("victim@example.com")
	if err != nil {
		t.Fatal(err)
	}
	trafficID := int(traffic.Id)

	tgIDOf := func() int64 {
		t.Helper()
		_, client, err := tb.inboundService.GetClientByEmail("victim@example.com")
		if err != nil {
			t.Fatal(err)
		}
		return client.TgID
	}
	if got := tgIDOf(); got != 0 {
		t.Fatalf("initial tgId = %d, want 0", got)
	}

	share := func(fromID int64, requestID int, sharedUserID int64) {
		t.Helper()
		tb.handleAddClientInput(&telego.Message{
			MessageID: 1,
			From:      &telego.User{ID: fromID},
			Chat:      telego.Chat{ID: tgbotTestChatID},
			UsersShared: &telego.UsersShared{
				RequestID: requestID,
				Users:     []telego.SharedUser{{UserID: sharedUserID}},
			},
		})
	}

	// (a) The old attack: admin 222 answers with the predictable
	// traffic row id, no keyboard ever issued.
	share(222, trafficID, 777)
	if got := tgIDOf(); got != 0 {
		t.Fatalf("tgId = %d after unissued request, want 0 (unbound)", got)
	}

	// (b) A keyboard issued to admin 111, answered by admin 222.
	issued := issueUserShareRequest(tgbotTestChatID, tgbotTestAdminID, trafficID)
	share(222, int(issued), 777)
	if got := tgIDOf(); got != 0 {
		t.Fatalf("tgId = %d after another admin answered, want 0 (unbound)", got)
	}

	// (c) The same keyboard answered by its owner binds the user.
	issued2 := issueUserShareRequest(tgbotTestChatID, tgbotTestAdminID, trafficID)
	share(tgbotTestAdminID, int(issued2), 777)
	if got := tgIDOf(); got != 777 {
		t.Fatalf("tgId = %d after the owner's answer, want 777", got)
	}

	// (d) Replaying the same request id does not re-bind (here to a
	// different user).
	share(tgbotTestAdminID, int(issued2), 888)
	if got := tgIDOf(); got != 777 {
		t.Fatalf("tgId = %d after replay, want 777 (unchanged)", got)
	}
}

// TestValidateTgbotURLs (L-15): the proxy must be a socks5 URL with a
// host, the API server an http(s) URL with a host. The old prefix-only
// checks accepted "httpfoo://..." and host-less URLs.
func TestValidateTgbotURLs(t *testing.T) {
	// The validators log on the invalid path, so the logger must be
	// initialised first (as in setupTgbotTestDB).
	t.Setenv("XUI_LOG_FOLDER", t.TempDir())
	logger.InitLogger(logging.ERROR)
	for _, good := range []string{"socks5://127.0.0.1:1080", "socks5://user:pass@proxy.example.com:1080"} {
		if got := validateTgbotProxyURL(good); got != good {
			t.Fatalf("validateTgbotProxyURL(%q) = %q, want it kept", good, got)
		}
	}
	for _, bad := range []string{"http://127.0.0.1:1080", "https://proxy.example.com", "socks5://", "socks5:/x", "://bad", "socks4://127.0.0.1:1080"} {
		if got := validateTgbotProxyURL(bad); got != "" {
			t.Fatalf("validateTgbotProxyURL(%q) = %q, want empty", bad, got)
		}
	}
	for _, good := range []string{"https://api.example.com", "http://127.0.0.1:8080", "https://api.example.com/bot"} {
		if got := validateTgbotAPIServerURL(good); got != good {
			t.Fatalf("validateTgbotAPIServerURL(%q) = %q, want it kept", good, got)
		}
	}
	for _, bad := range []string{"httpfoo://api.example.com", "ftp://api.example.com", "https://", "https:/x", "://bad", "api.example.com"} {
		if got := validateTgbotAPIServerURL(bad); got != "" {
			t.Fatalf("validateTgbotAPIServerURL(%q) = %q, want empty", bad, got)
		}
	}
	if got := validateTgbotProxyURL(""); got != "" {
		t.Fatalf("validateTgbotProxyURL(\"\") = %q, want empty", got)
	}
	if got := validateTgbotAPIServerURL(""); got != "" {
		t.Fatalf("validateTgbotAPIServerURL(\"\") = %q, want empty", got)
	}
}

// TestAddClientKeepsLiveDraft (L-16): tapping "add client" again, or
// picking an inbound, must not silently discard a draft in progress.
func TestAddClientKeepsLiveDraft(t *testing.T) {
	inboundID := setupTgbotTestDB(t)
	setupFakeTgbot(t)
	tb := (&Tgbot{}).NewTgbot()

	addClientSessionsMu.Lock()
	sess := tb.newAddClientSession(tgbotTestChatID, tgbotTestAdminID, inboundID)
	sess.email = "draft@example.com"
	origID := sess.id
	addClientSessionsMu.Unlock()

	tb.answerCallback(tgbotTestCallbackQuery(tgbotTestAdminID, "add_client"), true)
	addClientSessionsMu.Lock()
	kept := getAddClientSession(tgbotTestChatID, tgbotTestAdminID)
	if kept == nil || kept.email != "draft@example.com" || kept.id != origID {
		t.Fatalf("add_client discarded the live draft: %+v", kept)
	}
	addClientSessionsMu.Unlock()

	tb.answerCallback(tgbotTestCallbackQuery(tgbotTestAdminID, fmt.Sprintf("add_client_to %d", inboundID)), true)
	addClientSessionsMu.Lock()
	kept = getAddClientSession(tgbotTestChatID, tgbotTestAdminID)
	if kept == nil || kept.email != "draft@example.com" || kept.id != origID || kept.inboundID != inboundID {
		t.Fatalf("add_client_to discarded the live draft: %+v", kept)
	}
	addClientSessionsMu.Unlock()
}

// TestBuildJSONForProtocolTgIDNumber (L-16): the stored client JSON
// must carry tgId as a number, so model.Client parses it.
func TestBuildJSONForProtocolTgIDNumber(t *testing.T) {
	tb := (&Tgbot{}).NewTgbot()
	sess := &addClientSession{
		id: "11111111-1111-1111-1111-111111111111", email: "victim@example.com",
		enable: true, tgID: "123",
	}
	out, err := tb.BuildJSONForProtocol(sess, model.VLESS)
	if err != nil {
		t.Fatalf("BuildJSONForProtocol: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	client := parsed["clients"].([]any)[0].(map[string]any)
	if _, ok := client["tgId"].(float64); !ok {
		t.Fatalf("tgId is not a JSON number: %s", out)
	}
	if client["tgId"].(float64) != 123 {
		t.Fatalf("tgId = %v, want 123", client["tgId"])
	}

	// An unset Telegram id stores 0, not an empty string.
	sess.tgID = ""
	out, err = tb.BuildJSONForProtocol(sess, model.VLESS)
	if err != nil {
		t.Fatalf("BuildJSONForProtocol: %v", err)
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	client = parsed["clients"].([]any)[0].(map[string]any)
	if _, ok := client["tgId"].(float64); !ok {
		t.Fatalf("tgId is not a JSON number: %s", out)
	}
	if client["tgId"].(float64) != 0 {
		t.Fatalf("tgId = %v, want 0", client["tgId"])
	}
}

// TestBulkSenderCapsMessages (L-16): one bulk callback may not fan
// out to unbounded Telegram sends.
func TestBulkSenderCapsMessages(t *testing.T) {
	api := setupFakeTgbot(t)
	tb := (&Tgbot{}).NewTgbot()
	sender := newBulkSender(tb, tgbotTestChatID)
	for i := 0; i < maxTgbotBulkMessages+5; i++ {
		sender.send(fmt.Sprintf("item %d", i))
	}
	sender.finish()
	if got := api.sendCount(); got != maxTgbotBulkMessages+1 {
		t.Fatalf("bulk sender sent %d messages, want %d (cap) + 1 summary", got, maxTgbotBulkMessages)
	}
	if sender.total != maxTgbotBulkMessages+5 || !sender.truncated {
		t.Fatalf("bulk sender total=%d truncated=%v, want %d/true", sender.total, sender.truncated, maxTgbotBulkMessages+5)
	}

	// Under the cap nothing is truncated and no summary is sent.
	api2 := setupFakeTgbot(t)
	sender2 := newBulkSender(tb, tgbotTestChatID)
	sender2.send("only one")
	sender2.finish()
	if got := api2.sendCount(); got != 1 {
		t.Fatalf("bulk sender under the cap sent %d messages, want 1", got)
	}
}

// TestResetAllTrafficsCapsMessages (L-16): resetting traffic for many
// clients still resets every one of them, but reports at most the cap
// plus a summary and the finish message.
func TestResetAllTrafficsCapsMessages(t *testing.T) {
	inboundID := setupTgbotTestDB(t)
	api := setupFakeTgbot(t)
	tb := (&Tgbot{}).NewTgbot()

	origCap := maxTgbotBulkMessages
	maxTgbotBulkMessages = 2
	t.Cleanup(func() { maxTgbotBulkMessages = origCap })

	db := database.GetDB()
	var inbound model.Inbound
	if err := db.First(&inbound, inboundID).Error; err != nil {
		t.Fatalf("read inbound: %v", err)
	}
	clients := make([]string, 0, 5)
	settings := `{"clients":[`
	for i := 1; i <= 5; i++ {
		email := fmt.Sprintf("reset-%d@example.com", i)
		clients = append(clients, email)
		if i > 1 {
			settings += ","
		}
		settings += fmt.Sprintf(`{"id":"11111111-1111-1111-1111-11111111111%d","email":%q,"tgId":0,"enable":true}`, i, email)
		if err := db.Create(&xray.ClientTraffic{
			InboundId: inboundID, Email: email, Up: 500, Down: 600, Enable: true,
		}).Error; err != nil {
			t.Fatalf("create traffic: %v", err)
		}
	}
	settings += `]}`
	inbound.Settings = settings
	if err := db.Save(&inbound).Error; err != nil {
		t.Fatalf("save inbound: %v", err)
	}

	tb.answerCallback(tgbotTestCallbackQuery(tgbotTestAdminID, "reset_all_traffics_c"), true)

	// 2 per-client reports + 1 summary + 1 finish message.
	if got := api.sendCount(); got != 4 {
		t.Fatalf("reset_all_traffics_c sent %d messages, want 4", got)
	}
	// ...but every client's traffic was still reset.
	for _, email := range clients {
		var ct xray.ClientTraffic
		if err := db.Where("email = ?", email).First(&ct).Error; err != nil {
			t.Fatalf("read traffic for %s: %v", email, err)
		}
		if ct.Up != 0 || ct.Down != 0 {
			t.Fatalf("traffic for %s not reset: up=%d down=%d", email, ct.Up, ct.Down)
		}
	}
}
