package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
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
