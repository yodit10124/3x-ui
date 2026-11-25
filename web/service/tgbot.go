package service

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"math/big"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/web/global"
	"github.com/mhsanaei/3x-ui/v2/web/locale"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"github.com/google/uuid"
	"github.com/mymmrac/telego"
	th "github.com/mymmrac/telego/telegohandler"
	tu "github.com/mymmrac/telego/telegoutil"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

var (
	bot *telego.Bot

	// botCancel stores the function to cancel the context, stopping Long Polling gracefully.
	botCancel context.CancelFunc
	// tgBotMutex protects concurrent access to botCancel variable
	tgBotMutex sync.Mutex
	// botWG waits for the OnReceive Long Polling goroutine to finish.
	botWG sync.WaitGroup

	botHandler *th.BotHandler
	// adminIds holds the Telegram admin IDs as an immutable snapshot,
	// replaced atomically on (re)start and cleared on stop. Message and
	// callback handling reads it on every permission check, concurrently
	// with a bot reload, so a plain slice guarded by a mutex on the
	// write side only is not enough: readers would race the reload.
	// The snapshot is never mutated after it is stored; a reload builds
	// a fresh slice and swaps the pointer.
	adminIds atomic.Pointer[[]int64]
	// isRunning is read by every send helper (unlocked, on the message
	// handling path) and written by OnReceive/StopBot, so it is atomic
	// rather than guarded by tgBotMutex.
	isRunning   atomic.Bool
	hostname    string
	hashStorage *global.HashStorage

	// Performance improvements
	messageWorkerPool chan struct{} // Semaphore for limiting concurrent message processing

	// Simple cache for frequently accessed data
	statusCache struct {
		data      *Status
		timestamp time.Time
		mutex     sync.RWMutex
	}

	serverStatsCache struct {
		data      string
		timestamp time.Time
		mutex     sync.RWMutex
	}
)

// addClientSessionTTL bounds how long an unfinished add-client flow stays
// alive. Expired sessions are dropped on next access.
const addClientSessionTTL = 30 * time.Minute

// addClientSession holds the in-progress data of one add-client flow,
// owned by a single Telegram user in a single chat. Two admins working in
// parallel (or two chats) each get their own session, so their inputs can
// never overwrite each other.
type addClientSession struct {
	userID     int64
	chatID     int64
	inboundID  int
	state      string // awaiting_* step; "" when not waiting for text input
	id         string
	flow       string
	email      string
	limitIP    int
	totalGB    int64
	expiryTime int64
	enable     bool
	tgID       string
	comment    string
	reset      int
	security   string
	shPassword string
	trPassword string
	method     string
	lastActive time.Time
}

// addClientSessionKey isolates sessions by chat and by the user who started
// the flow. A group member who did not start the flow cannot read or
// modify it, and two admins in the same group keep separate sessions.
type addClientSessionKey struct {
	chatID int64
	userID int64
}

var (
	// addClientSessionsMu guards every read, write and delete of the
	// session map and of the sessions inside it. It is held for the
	// duration of one callback/input step (including the Telegram sends
	// inside it): add-client flows are rare interactive operations, so
	// the serialization cost is negligible, and a single lock keeps the
	// discipline deadlock-free.
	addClientSessionsMu sync.Mutex
	addClientSessions   = make(map[addClientSessionKey]*addClientSession)
)

// newAddClientSession creates a session owned by (chatID, userID) with the
// default client values. Callers must hold addClientSessionsMu.
func (t *Tgbot) newAddClientSession(chatID, userID int64, inboundID int) *addClientSession {
	sess := &addClientSession{
		userID:     userID,
		chatID:     chatID,
		inboundID:  inboundID,
		id:         uuid.New().String(),
		flow:       "",
		email:      t.randomLowerAndNum(8),
		limitIP:    0,
		totalGB:    0,
		expiryTime: 0,
		enable:     true,
		tgID:       "",
		comment:    "",
		reset:      0,
		security:   "auto",
		shPassword: t.randomShadowSocksPassword(),
		trPassword: t.randomLowerAndNum(10),
		method:     "",
		lastActive: time.Now(),
	}
	addClientSessions[addClientSessionKey{chatID: chatID, userID: userID}] = sess
	return sess
}

// getAddClientSession returns the live session for (chatID, userID), or nil
// when there is none or it expired. Expired sessions are removed.
// Callers must hold addClientSessionsMu.
func getAddClientSession(chatID, userID int64) *addClientSession {
	key := addClientSessionKey{chatID: chatID, userID: userID}
	sess, ok := addClientSessions[key]
	if !ok {
		return nil
	}
	if time.Since(sess.lastActive) > addClientSessionTTL {
		delete(addClientSessions, key)
		return nil
	}
	sess.lastActive = time.Now()
	return sess
}

// deleteAddClientSession removes the session for (chatID, userID), if any.
// Callers must hold addClientSessionsMu.
func deleteAddClientSession(chatID, userID int64) {
	delete(addClientSessions, addClientSessionKey{chatID: chatID, userID: userID})
}

// userShareRequestTTL bounds how long an issued "select a Telegram
// user" keyboard stays answerable (M-10).
const userShareRequestTTL = 30 * time.Minute

// pendingUserShare records one outstanding "select a Telegram user"
// keyboard: which admin, in which chat, may answer it, and for which
// client (M-10).
type pendingUserShare struct {
	chatID    int64
	userID    int64
	trafficID int
	expiresAt time.Time
}

var (
	userShareMu       sync.Mutex
	userShareRequests = map[int32]pendingUserShare{}
)

// issueUserShareRequest mints a random, unguessable RequestID for a
// "select TG user" keyboard and records who may answer it (M-10).
// The RequestID used to be the sequential traffic row id, and the
// handler only checked that the sender was an admin, so any admin in
// a group chat could answer another admin's keyboard and bind any
// Telegram user to any client.
func issueUserShareRequest(chatID, userID int64, trafficID int) int32 {
	for {
		n, err := rand.Int(rand.Reader, big.NewInt(1<<31-1))
		if err != nil {
			continue
		}
		id := int32(n.Int64()) + 1 // never 0
		userShareMu.Lock()
		if _, taken := userShareRequests[id]; !taken {
			if len(userShareRequests) >= 512 {
				now := time.Now()
				for oldID, old := range userShareRequests {
					if now.After(old.expiresAt) {
						delete(userShareRequests, oldID)
					}
				}
			}
			userShareRequests[id] = pendingUserShare{
				chatID:    chatID,
				userID:    userID,
				trafficID: trafficID,
				expiresAt: time.Now().Add(userShareRequestTTL),
			}
			userShareMu.Unlock()
			return id
		}
		userShareMu.Unlock()
	}
}

// consumeUserShareRequest validates an echoed UsersShared RequestID:
// it must have been issued for this chat and this admin, and must
// not be expired (M-10). A valid entry is consumed (one-shot) and
// its traffic ID is returned; anything else is refused.
func consumeUserShareRequest(requestID int32, chatID, userID int64) (int, bool) {
	userShareMu.Lock()
	defer userShareMu.Unlock()
	entry, ok := userShareRequests[requestID]
	if !ok {
		return 0, false
	}
	delete(userShareRequests, requestID)
	if time.Now().After(entry.expiresAt) {
		return 0, false
	}
	if entry.chatID != chatID || entry.userID != userID {
		return 0, false
	}
	return entry.trafficID, true
}

// clearAddClientInputState clears the awaiting-input step of the session
// for (chatID, userID), keeping the collected client data. It is used when
// a command, a button press or the close-keyboard action cancels text
// input without cancelling the flow itself.
func clearAddClientInputState(chatID, userID int64) {
	addClientSessionsMu.Lock()
	defer addClientSessionsMu.Unlock()
	if sess := getAddClientSession(chatID, userID); sess != nil {
		sess.state = ""
	}
}

// requireAddClientSession returns the live session for the callback's
// sender, answering the callback with an error when the flow is gone
// (expired, cancelled, or never started). Callers must hold
// addClientSessionsMu.
func (t *Tgbot) requireAddClientSession(callbackQuery *telego.CallbackQuery) *addClientSession {
	sess := getAddClientSession(callbackQuery.Message.GetChat().ID, callbackQuery.From.ID)
	if sess == nil {
		t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.noQuery"))
		return nil
	}
	return sess
}

// personalBotCallbacks are the only callbacks a non-admin Telegram user may
// invoke. client_traffic answers with the caller's own usage (looked up by
// their Telegram user ID) and client_commands is static help text, so
// neither leaks another user's data.
var personalBotCallbacks = map[string]bool{
	"client_traffic":  true,
	"client_commands": true,
}

// isPersonalBotCallback reports whether a callback is a personal query any
// user may invoke for their own data.
func isPersonalBotCallback(data string) bool {
	return personalBotCallbacks[data]
}

// LoginStatus represents the result of a login attempt.
type LoginStatus byte

// Login status constants
const (
	LoginSuccess        LoginStatus = 1        // Login was successful
	LoginFail           LoginStatus = 0        // Login failed
	EmptyTelegramUserID             = int64(0) // Default value for empty Telegram user ID
)

// Tgbot provides business logic for Telegram bot integration.
// It handles bot commands, user interactions, and status reporting via Telegram.
type Tgbot struct {
	inboundService InboundService
	settingService SettingService
	serverService  ServerService
	xrayService    XrayService
	lastStatus     *Status
	// limiter caps how fast one (chat, user) can drive the bot (M-8).
	// Nil on a zero-value Tgbot falls back to the shared default.
	limiter *tgbotRateLimiter
}

// NewTgbot creates a new Tgbot instance.
func (t *Tgbot) NewTgbot() *Tgbot {
	return &Tgbot{limiter: newTgbotRateLimiter(tgbotRateLimitBurst, tgbotRateLimitRefill)}
}

// tgbotRateLimitBurst is how many commands/callbacks one (chat, user)
// may fire at once; tgbotRateLimitRefill is how fast the bucket
// refills afterwards (M-8). A human admin never notices the cap; a
// flooder is held to about one command per second. They are vars so
// tests can disable the refill.
var (
	tgbotRateLimitBurst  = 10
	tgbotRateLimitRefill = time.Second
)

// tgbotRateLimiter is a per-(chat, user) token bucket (M-8). Without
// it, any Telegram user who knows the bot's username can flood it
// with /usage or client_traffic commands, each triggering DB scans
// and Telegram sends, and the worker-pool goroutines pile up
// unbounded behind the semaphore.
type tgbotRateLimiter struct {
	mu      sync.Mutex
	buckets map[tgbotRateLimitKey]*tgbotTokenBucket
	burst   int
	refill  time.Duration
}

type tgbotRateLimitKey struct {
	chatID int64
	userID int64
}

type tgbotTokenBucket struct {
	tokens   float64
	lastSeen time.Time
}

func newTgbotRateLimiter(burst int, refill time.Duration) *tgbotRateLimiter {
	return &tgbotRateLimiter{
		buckets: map[tgbotRateLimitKey]*tgbotTokenBucket{},
		burst:   burst,
		refill:  refill,
	}
}

// Allow consumes one token for (chatID, userID) and reports whether
// the command may run. Buckets idle for over 10 minutes are dropped
// when the map grows, so the table cannot grow without bound.
func (l *tgbotRateLimiter) Allow(chatID, userID int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	key := tgbotRateLimitKey{chatID: chatID, userID: userID}
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= 512 {
			for k, old := range l.buckets {
				if now.Sub(old.lastSeen) > 10*time.Minute {
					delete(l.buckets, k)
				}
			}
		}
		b = &tgbotTokenBucket{tokens: float64(l.burst), lastSeen: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.lastSeen).Seconds() / l.refill.Seconds()
	if b.tokens > float64(l.burst) {
		b.tokens = float64(l.burst)
	}
	b.lastSeen = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// defaultTgbotLimiter backs zero-value Tgbot instances, which carry
// a nil limiter.
var defaultTgbotLimiter = newTgbotRateLimiter(tgbotRateLimitBurst, tgbotRateLimitRefill)

// tgbotRetryAfterPattern extracts the delay from a Telegram 429
// error ("Too Many Requests: retry after 35").
var tgbotRetryAfterPattern = regexp.MustCompile(`(?i)retry after (\d+)`)

// tgbotRetryAfter reports the delay Telegram asks for after a 429
// (M-8), or false when the error is not a rate limit. A missing
// number falls back to 2s; a requested delay is capped at 60s so a
// bogus value cannot stall the sender for long.
func tgbotRetryAfter(err error) (time.Duration, bool) {
	lower := strings.ToLower(err.Error())
	if !strings.Contains(lower, "429") && !strings.Contains(lower, "too many requests") && !strings.Contains(lower, "retry after") {
		return 0, false
	}
	if m := tgbotRetryAfterPattern.FindStringSubmatch(err.Error()); len(m) == 2 {
		if secs, convErr := strconv.Atoi(m[1]); convErr == nil && secs > 0 {
			if secs > 60 {
				secs = 60
			}
			return time.Duration(secs) * time.Second, true
		}
	}
	return 2 * time.Second, true
}

// allowTgbotCommand reports whether one command/callback/message from
// (chatID, userID) may run now (M-8). Over-limit input is dropped
// silently: answering it would itself be a Telegram send, which is
// what the limit exists to prevent.
func (t *Tgbot) allowTgbotCommand(chatID, userID int64) bool {
	lim := t.limiter
	if lim == nil {
		lim = defaultTgbotLimiter
	}
	return lim.Allow(chatID, userID)
}

// I18nBot retrieves a localized message for the bot interface.
// All template parameter values are HTML-escaped before
// substitution (M-6): bot messages are sent with ParseMode HTML, so
// a user-controlled value such as a client comment, email, or
// inbound remark could otherwise inject markup (e.g. a phishing
// link) into a message read by another admin or client. The
// template text itself keeps its own <b>/<code> formatting; only
// interpolated values are escaped.
func (t *Tgbot) I18nBot(name string, params ...string) string {
	return locale.I18n(locale.Bot, name, escapeI18nBotParams(params)...)
}

// escapeI18nBotParams HTML-escapes the value part of each
// "Key==value" template parameter, leaving the key untouched.
// Parameters without the separator pass through unchanged.
func escapeI18nBotParams(params []string) []string {
	escaped := make([]string, len(params))
	for i, param := range params {
		if key, value, ok := strings.Cut(param, "=="); ok {
			escaped[i] = key + "==" + html.EscapeString(value)
		} else {
			escaped[i] = param
		}
	}
	return escaped
}

// GetHashStorage returns the hash storage instance for callback queries.
func (t *Tgbot) GetHashStorage() *global.HashStorage {
	return hashStorage
}

// getCachedStatus returns cached server status if it's fresh enough (less than 5 seconds old)
func (t *Tgbot) getCachedStatus() (*Status, bool) {
	statusCache.mutex.RLock()
	defer statusCache.mutex.RUnlock()

	if statusCache.data != nil && time.Since(statusCache.timestamp) < 5*time.Second {
		return statusCache.data, true
	}
	return nil, false
}

// setCachedStatus updates the status cache
func (t *Tgbot) setCachedStatus(status *Status) {
	statusCache.mutex.Lock()
	defer statusCache.mutex.Unlock()

	statusCache.data = status
	statusCache.timestamp = time.Now()
}

// getCachedServerStats returns cached server stats if it's fresh enough (less than 10 seconds old)
func (t *Tgbot) getCachedServerStats() (string, bool) {
	serverStatsCache.mutex.RLock()
	defer serverStatsCache.mutex.RUnlock()

	if serverStatsCache.data != "" && time.Since(serverStatsCache.timestamp) < 10*time.Second {
		return serverStatsCache.data, true
	}
	return "", false
}

// setCachedServerStats updates the server stats cache
func (t *Tgbot) setCachedServerStats(stats string) {
	serverStatsCache.mutex.Lock()
	defer serverStatsCache.mutex.Unlock()

	serverStatsCache.data = stats
	serverStatsCache.timestamp = time.Now()
}

// Start initializes and starts the Telegram bot with the provided translation files.
func (t *Tgbot) Start(i18nFS embed.FS) error {
	// Initialize localizer
	err := locale.InitLocalizer(i18nFS, &t.settingService)
	if err != nil {
		return err
	}

	// If Start is called again (e.g. during reload), ensure any previous long-polling
	// loop is stopped before creating a new bot / receiver.
	StopBot()

	// Initialize hash storage to store callback queries
	hashStorage = global.NewHashStorage(20 * time.Minute)

	// Initialize worker pool for concurrent message processing (max 10 concurrent handlers)
	messageWorkerPool = make(chan struct{}, 10)

	t.SetHostname()

	// Get Telegram bot token
	tgBotToken, err := t.settingService.GetTgBotToken()
	if err != nil || tgBotToken == "" {
		logger.Warning("Failed to get Telegram bot token:", err)
		return err
	}

	// Get Telegram bot chat ID(s)
	tgBotID, err := t.settingService.GetTgBotChatId()
	if err != nil {
		logger.Warning("Failed to get Telegram bot chat ID:", err)
		return err
	}

	parsedAdminIds := make([]int64, 0)
	// Parse admin IDs from comma-separated string
	if tgBotID != "" {
		for _, adminID := range strings.Split(tgBotID, ",") {
			id, err := strconv.ParseInt(adminID, 10, 64)
			if err != nil {
				logger.Warning("Failed to parse admin ID from Telegram bot chat ID:", err)
				return err
			}
			parsedAdminIds = append(parsedAdminIds, int64(id))
		}
	}
	setAdminIds(parsedAdminIds)

	// Get Telegram bot proxy URL
	tgBotProxy, err := t.settingService.GetTgBotProxy()
	if err != nil {
		logger.Warning("Failed to get Telegram bot proxy URL:", err)
	}

	// Get Telegram bot API server URL
	tgBotAPIServer, err := t.settingService.GetTgBotAPIServer()
	if err != nil {
		logger.Warning("Failed to get Telegram bot API server URL:", err)
	}

	// Create new Telegram bot instance
	bot, err = t.NewBot(tgBotToken, tgBotProxy, tgBotAPIServer)
	if err != nil {
		logger.Error("Failed to initialize Telegram bot API:", err)
		return err
	}

	t.trySetBotCommands(bot)

	// Start receiving Telegram bot messages
	tgBotMutex.Lock()
	alreadyRunning := isRunning.Load() || botCancel != nil
	tgBotMutex.Unlock()
	if !alreadyRunning {
		logger.Info("Telegram bot receiver started")
		go t.OnReceive()
	}

	return nil
}

func (t *Tgbot) trySetBotCommands(bot *telego.Bot) {
	defer func() {
		if r := recover(); r != nil {
			logger.Warning("Failed to register bot commands (Telegram may be rate-limiting); bot will continue without them:", r)
		}
	}()

	err := bot.SetMyCommands(context.Background(), &telego.SetMyCommandsParams{
		Commands: []telego.BotCommand{
			{Command: "start", Description: t.I18nBot("tgbot.commands.startDesc")},
			{Command: "help", Description: t.I18nBot("tgbot.commands.helpDesc")},
			{Command: "status", Description: t.I18nBot("tgbot.commands.statusDesc")},
			{Command: "id", Description: t.I18nBot("tgbot.commands.idDesc")},
		},
	})
	if err != nil {
		logger.Warning("Failed to set bot commands:", err)
	}
}

// createRobustFastHTTPClient creates a fasthttp.Client with proper connection handling
func (t *Tgbot) createRobustFastHTTPClient(proxyUrl string) *fasthttp.Client {
	client := &fasthttp.Client{
		// Connection timeouts
		ReadTimeout:                   30 * time.Second,
		WriteTimeout:                  30 * time.Second,
		MaxIdleConnDuration:           60 * time.Second,
		MaxConnDuration:               0, // unlimited, but controlled by MaxIdleConnDuration
		MaxIdemponentCallAttempts:     3,
		ReadBufferSize:                4096,
		WriteBufferSize:               4096,
		MaxConnsPerHost:               100,
		MaxConnWaitTimeout:            10 * time.Second,
		DisableHeaderNamesNormalizing: false,
		DisablePathNormalizing:        false,
		// Retry on connection errors (RetryIf is deprecated in
		// fasthttp v1.70.0; RetryIfErr takes the same request
		// predicate plus the attempt count and the error, and
		// returns whether to reset the timeout and whether to retry)
		RetryIfErr: func(request *fasthttp.Request, attempts int, err error) (bool, bool) {
			// Retry on connection errors for GET and POST requests
			method := string(request.Header.Method())
			return false, method == "GET" || method == "POST"
		},
	}

	// Set proxy if provided
	if proxyUrl != "" {
		client.Dial = fasthttpproxy.FasthttpSocksDialer(proxyUrl)
	}

	return client
}

// NewBot creates a new Telegram bot instance with optional proxy and API server settings.
func (t *Tgbot) NewBot(token string, proxyUrl string, apiServerUrl string) (*telego.Bot, error) {
	// Validate proxy URL if provided
	if proxyUrl != "" {
		if !strings.HasPrefix(proxyUrl, "socks5://") {
			logger.Warning("Invalid socks5 URL, ignoring proxy")
			proxyUrl = "" // Clear invalid proxy
		} else {
			_, err := url.Parse(proxyUrl)
			if err != nil {
				logger.Warningf("Can't parse proxy URL, ignoring proxy: %v", err)
				proxyUrl = ""
			}
		}
	}

	// Validate API server URL if provided
	if apiServerUrl != "" {
		if !strings.HasPrefix(apiServerUrl, "http") {
			logger.Warning("Invalid http(s) URL for API server, using default")
			apiServerUrl = ""
		} else {
			_, err := url.Parse(apiServerUrl)
			if err != nil {
				logger.Warningf("Can't parse API server URL, using default: %v", err)
				apiServerUrl = ""
			}
		}
	}

	// Create robust fasthttp client
	client := t.createRobustFastHTTPClient(proxyUrl)

	// Build bot options
	var options []telego.BotOption
	options = append(options, telego.WithFastHTTPClient(client))

	if apiServerUrl != "" {
		options = append(options, telego.WithAPIServer(apiServerUrl))
	}

	return telego.NewBot(token, options...)
}

// IsRunning checks if the Telegram bot is currently running.
func (t *Tgbot) IsRunning() bool {
	return isRunning.Load()
}

// SetHostname sets the hostname for the bot.
func (t *Tgbot) SetHostname() {
	host, err := os.Hostname()
	if err != nil {
		logger.Error("get hostname error:", err)
		hostname = ""
		return
	}
	hostname = host
}

// Stop safely stops the Telegram bot's Long Polling operation.
// This method now calls the global StopBot function and cleans up other resources.
func (t *Tgbot) Stop() {
	StopBot()
	logger.Info("Stop Telegram receiver ...")
	setAdminIds(nil)
}

// StopBot safely stops the Telegram bot's Long Polling operation by cancelling its context.
// This is the global function called from main.go's signal handler and t.Stop().
func StopBot() {
	// Don't hold the mutex while cancelling/waiting.
	tgBotMutex.Lock()
	cancel := botCancel
	botCancel = nil
	handler := botHandler
	botHandler = nil
	isRunning.Store(false)
	tgBotMutex.Unlock()

	if handler != nil {
		handler.Stop()
	}

	if cancel != nil {
		logger.Info("Sending cancellation signal to Telegram bot...")
		// Cancels the context passed to UpdatesViaLongPolling; this closes updates channel
		// and lets botHandler.Start() exit cleanly.
		cancel()
		botWG.Wait()
		logger.Info("Telegram bot successfully stopped.")
	}
}

// encodeQuery encodes the query string if it's longer than 64 characters.
func (t *Tgbot) encodeQuery(query string) string {
	// NOTE: we only need to hash for more than 64 chars
	if len(query) <= 64 {
		return query
	}

	return hashStorage.SaveHash(query)
}

// decodeQuery decodes a hashed query string back to its original form.
func (t *Tgbot) decodeQuery(query string) (string, error) {
	if !hashStorage.IsMD5(query) {
		return query, nil
	}

	decoded, exists := hashStorage.GetValue(query)
	if !exists {
		return "", common.NewError("hash not found in storage!")
	}

	return decoded, nil
}

// OnReceive starts the message receiving loop for the Telegram bot.
func (t *Tgbot) OnReceive() {
	params := telego.GetUpdatesParams{
		Timeout: 20, // Reduced timeout to detect connection issues faster
	}
	// Strict singleton: never start a second long-polling loop.
	tgBotMutex.Lock()
	if botCancel != nil || isRunning.Load() {
		tgBotMutex.Unlock()
		logger.Warning("TgBot OnReceive called while already running; ignoring.")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	botCancel = cancel
	isRunning.Store(true)
	// Add to WaitGroup before releasing the lock so StopBot() can't return
	// before this receiver goroutine is accounted for.
	botWG.Add(1)
	tgBotMutex.Unlock()

	// Get updates channel using the context with shorter timeout for better error recovery
	updates, _ := bot.UpdatesViaLongPolling(ctx, &params)
	go func() {
		defer botWG.Done()
		// N-4: this goroutine is outside the handler middleware's
		// reach; a panic in NewBotHandler/h.Start() must not kill the
		// whole panel process.
		defer func() {
			if r := recover(); r != nil {
				logger.Error("TgBot receiver panic recovered: ", r)
			}
		}()
		h, err := t.newBotHandler(bot, updates)
		if err != nil {
			logger.Error("TgBot failed to create update handler: ", err)
			return
		}
		tgBotMutex.Lock()
		botHandler = h
		tgBotMutex.Unlock()

		h.Start()
	}()
}

// newBotHandler builds the Telegram update handler with all message and
// callback routes. It is split out of OnReceive so tests can drive it
// with a fake bot and a synthetic updates channel.
func (t *Tgbot) newBotHandler(bot *telego.Bot, updates <-chan telego.Update) (*th.BotHandler, error) {
	h, err := th.NewBotHandler(bot, updates)
	if err != nil {
		return nil, err
	}

	// Defense in depth (H-2): a panic in any handler must not kill the
	// whole panel process. The middleware only covers the synchronous
	// handler itself, so the worker goroutines below carry their own
	// recover as well. A recovered panic is logged, never swallowed
	// silently.
	h.Use(th.PanicRecoveryHandler(func(recovered any) error {
		logger.Error("TgBot handler panic recovered: ", recovered)
		return nil
	}))

	h.HandleMessage(func(ctx *th.Context, message telego.Message) error {
		clearAddClientInputState(message.Chat.ID, message.From.ID)
		t.SendMsgToTgbot(message.Chat.ID, t.I18nBot("tgbot.keyboardClosed"), tu.ReplyKeyboardRemove())
		return nil
	}, th.TextEqual(t.I18nBot("tgbot.buttons.closeKeyboard")))

	h.HandleMessage(func(ctx *th.Context, message telego.Message) error {
		// M-8: drop over-limit commands before spawning a worker
		// goroutine for them; otherwise a flooder piles up
		// unbounded goroutines behind the worker pool.
		if !t.allowTgbotCommand(message.Chat.ID, message.From.ID) {
			return nil
		}
		// Use goroutine with worker pool for concurrent command processing
		go func() {
			// The handler middleware cannot see into this goroutine:
			// recover here so a panic in answerCommand never kills
			// the panel process.
			defer func() {
				if r := recover(); r != nil {
					logger.Error("TgBot command handler panic recovered: ", r)
				}
			}()
			// Capture the pool channel locally: Start() may replace the
			// global pool on bot reload, and a worker releasing into the
			// new pool (which it never acquired from) would block
			// forever on the empty channel and corrupt its count. (N-8)
			pool := messageWorkerPool
			pool <- struct{}{}        // Acquire worker
			defer func() { <-pool }() // Release worker

			clearAddClientInputState(message.Chat.ID, message.From.ID)
			t.answerCommand(&message, message.Chat.ID, checkAdmin(message.From.ID))
		}()
		return nil
	}, th.AnyCommand())

	h.HandleCallbackQuery(func(ctx *th.Context, query telego.CallbackQuery) error {
		// M-8: same per-(chat, user) limit as commands.
		if !t.allowTgbotCommand(query.Message.GetChat().ID, query.From.ID) {
			return nil
		}
		// Use goroutine with worker pool for concurrent callback processing
		go func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Error("TgBot callback handler panic recovered: ", r)
				}
			}()
			// Same local capture as the command worker above (N-8):
			// never release into a pool replaced by a later Start().
			pool := messageWorkerPool
			pool <- struct{}{}        // Acquire worker
			defer func() { <-pool }() // Release worker

			clearAddClientInputState(query.Message.GetChat().ID, query.From.ID)
			t.answerCallback(&query, checkAdmin(query.From.ID))
		}()
		return nil
	}, th.AnyCallbackQueryWithMessage())

	h.HandleMessage(func(ctx *th.Context, message telego.Message) error {
		t.handleAddClientInput(&message)
		return nil
	}, th.AnyMessage())

	return h, nil
}

// handleAddClientInput consumes one text message as the next value of an
// in-progress add-client flow. The session is keyed by both the chat and
// the user who started the flow: in a group chat, another member's message
// can neither read nor overwrite the admin's in-progress client.
func (t *Tgbot) handleAddClientInput(message *telego.Message) {
	addClientSessionsMu.Lock()
	defer addClientSessionsMu.Unlock()

	chatId := message.Chat.ID
	var userID int64
	if message.From != nil {
		userID = message.From.ID
	}
	// M-8: plain messages share the per-(chat, user) bucket with
	// commands and callbacks.
	if !t.allowTgbotCommand(chatId, userID) {
		return
	}
	sess := getAddClientSession(chatId, userID)
	if sess == nil || sess.state == "" {
		if message.UsersShared != nil {
			if checkAdmin(userID) {
				// M-10: the echoed RequestID must be one this bot
				// issued to this admin in this chat, for one client.
				// An unknown, expired, or another admin's request is
				// refused instead of binding whatever traffic id it names.
				trafficID, ok := consumeUserShareRequest(int32(message.UsersShared.RequestID), chatId, userID)
				if !ok {
					t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.messages.selectUserFailed"), tu.ReplyKeyboardRemove())
					return
				}
				for _, sharedUser := range message.UsersShared.Users {
					userID := sharedUser.UserID
					needRestart, err := t.inboundService.SetClientTelegramUserID(trafficID, userID)
					if needRestart {
						t.xrayService.SetToNeedRestart()
					}
					output := ""
					if err != nil {
						output += t.I18nBot("tgbot.messages.selectUserFailed")
					} else {
						output += t.I18nBot("tgbot.messages.userSaved")
					}
					t.SendMsgToTgbot(chatId, output, tu.ReplyKeyboardRemove())
				}
			} else {
				t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.noResult"), tu.ReplyKeyboardRemove())
			}
		}
		return
	}

	// The session was created by an admin, but the admin list can change
	// while a flow is in progress (revocation, then a bot reload). The
	// sender's admin status is therefore re-checked on every input: a
	// revoked user must not keep editing the draft or trigger reads and
	// echoes of inbound data. The final client creation stays protected
	// by the admin callback check, but nothing before it may leak
	// management information. setAdminIds deletes the sessions of
	// revoked users as well; this check covers the race window between
	// the revocation and that cleanup.
	if !checkAdmin(userID) {
		deleteAddClientSession(chatId, userID)
		return
	}

	switch sess.state {
	case "awaiting_id":
		if sess.id == strings.TrimSpace(message.Text) {
			t.SendMsgToTgbotDeleteAfter(chatId, t.I18nBot("tgbot.messages.using_default_value"), 3, tu.ReplyKeyboardRemove())
			sess.state = ""
			inbound, _ := t.inboundService.GetInbound(sess.inboundID)
			message_text, _ := t.BuildInboundClientDataMessage(sess, inbound.Remark, inbound.Protocol)
			t.addClient(sess, chatId, message_text)
			return
		}

		sess.id = strings.TrimSpace(message.Text)
		if t.isSingleWord(sess.id) {
			sess.state = "awaiting_id"

			cancel_btn_markup := tu.InlineKeyboard(
				tu.InlineKeyboardRow(
					tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.use_default")).WithCallbackData("add_client_default_info"),
				),
			)

			t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.messages.incorrect_input"), cancel_btn_markup)
		} else {
			t.SendMsgToTgbotDeleteAfter(chatId, t.I18nBot("tgbot.messages.received_id"), 3, tu.ReplyKeyboardRemove())
			sess.state = ""
			inbound, _ := t.inboundService.GetInbound(sess.inboundID)
			message_text, _ := t.BuildInboundClientDataMessage(sess, inbound.Remark, inbound.Protocol)
			t.addClient(sess, chatId, message_text)
		}
	case "awaiting_password_tr":
		if sess.trPassword == strings.TrimSpace(message.Text) {
			t.SendMsgToTgbotDeleteAfter(chatId, t.I18nBot("tgbot.messages.using_default_value"), 3, tu.ReplyKeyboardRemove())
			sess.state = ""
			return
		}

		sess.trPassword = strings.TrimSpace(message.Text)
		if t.isSingleWord(sess.trPassword) {
			sess.state = "awaiting_password_tr"

			cancel_btn_markup := tu.InlineKeyboard(
				tu.InlineKeyboardRow(
					tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.use_default")).WithCallbackData("add_client_default_info"),
				),
			)

			t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.messages.incorrect_input"), cancel_btn_markup)
		} else {
			t.SendMsgToTgbotDeleteAfter(chatId, t.I18nBot("tgbot.messages.received_password"), 3, tu.ReplyKeyboardRemove())
			sess.state = ""
			inbound, _ := t.inboundService.GetInbound(sess.inboundID)
			message_text, _ := t.BuildInboundClientDataMessage(sess, inbound.Remark, inbound.Protocol)
			t.addClient(sess, chatId, message_text)
		}
	case "awaiting_password_sh":
		if sess.shPassword == strings.TrimSpace(message.Text) {
			t.SendMsgToTgbotDeleteAfter(chatId, t.I18nBot("tgbot.messages.using_default_value"), 3, tu.ReplyKeyboardRemove())
			sess.state = ""
			return
		}

		sess.shPassword = strings.TrimSpace(message.Text)
		if t.isSingleWord(sess.shPassword) {
			sess.state = "awaiting_password_sh"

			cancel_btn_markup := tu.InlineKeyboard(
				tu.InlineKeyboardRow(
					tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.use_default")).WithCallbackData("add_client_default_info"),
				),
			)

			t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.messages.incorrect_input"), cancel_btn_markup)
		} else {
			t.SendMsgToTgbotDeleteAfter(chatId, t.I18nBot("tgbot.messages.received_password"), 3, tu.ReplyKeyboardRemove())
			sess.state = ""
			inbound, _ := t.inboundService.GetInbound(sess.inboundID)
			message_text, _ := t.BuildInboundClientDataMessage(sess, inbound.Remark, inbound.Protocol)
			t.addClient(sess, chatId, message_text)
		}
	case "awaiting_email":
		if sess.email == strings.TrimSpace(message.Text) {
			t.SendMsgToTgbotDeleteAfter(chatId, t.I18nBot("tgbot.messages.using_default_value"), 3, tu.ReplyKeyboardRemove())
			sess.state = ""
			return
		}

		sess.email = strings.TrimSpace(message.Text)
		if t.isSingleWord(sess.email) {
			sess.state = "awaiting_email"

			cancel_btn_markup := tu.InlineKeyboard(
				tu.InlineKeyboardRow(
					tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.use_default")).WithCallbackData("add_client_default_info"),
				),
			)

			t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.messages.incorrect_input"), cancel_btn_markup)
		} else {
			t.SendMsgToTgbotDeleteAfter(chatId, t.I18nBot("tgbot.messages.received_email"), 3, tu.ReplyKeyboardRemove())
			sess.state = ""
			inbound, _ := t.inboundService.GetInbound(sess.inboundID)
			message_text, _ := t.BuildInboundClientDataMessage(sess, inbound.Remark, inbound.Protocol)
			t.addClient(sess, chatId, message_text)
		}
	case "awaiting_comment":
		if sess.comment == strings.TrimSpace(message.Text) {
			t.SendMsgToTgbotDeleteAfter(chatId, t.I18nBot("tgbot.messages.using_default_value"), 3, tu.ReplyKeyboardRemove())
			sess.state = ""
			return
		}

		sess.comment = strings.TrimSpace(message.Text)
		t.SendMsgToTgbotDeleteAfter(chatId, t.I18nBot("tgbot.messages.received_comment"), 3, tu.ReplyKeyboardRemove())
		sess.state = ""
		inbound, _ := t.inboundService.GetInbound(sess.inboundID)
		message_text, _ := t.BuildInboundClientDataMessage(sess, inbound.Remark, inbound.Protocol)
		t.addClient(sess, chatId, message_text)
	}
}

// answerCommand processes incoming command messages from Telegram users.
func (t *Tgbot) answerCommand(message *telego.Message, chatId int64, isAdmin bool) {
	msg, onlyMessage := "", false

	command, _, commandArgs := tu.ParseCommand(message.Text)

	// Helper function to handle unknown commands.
	handleUnknownCommand := func() {
		msg += t.I18nBot("tgbot.commands.unknown")
	}

	// Handle the command.
	switch command {
	case "help":
		msg += t.I18nBot("tgbot.commands.help")
		msg += t.I18nBot("tgbot.commands.pleaseChoose")
	case "start":
		msg += t.I18nBot("tgbot.commands.start", "Firstname=="+message.From.FirstName)
		if isAdmin {
			msg += t.I18nBot("tgbot.commands.welcome", "Hostname=="+hostname)
		}
		msg += "\n\n" + t.I18nBot("tgbot.commands.pleaseChoose")
	case "status":
		onlyMessage = true
		msg += t.I18nBot("tgbot.commands.status")
	case "id":
		onlyMessage = true
		msg += t.I18nBot("tgbot.commands.getID", "ID=="+strconv.FormatInt(message.From.ID, 10))
	case "usage":
		onlyMessage = true
		if len(commandArgs) > 0 {
			if isAdmin {
				t.searchClient(chatId, commandArgs[0])
			} else {
				t.getClientUsage(chatId, int64(message.From.ID), commandArgs[0])
			}
		} else {
			msg += t.I18nBot("tgbot.commands.usage")
		}
	case "inbound":
		onlyMessage = true
		if isAdmin && len(commandArgs) > 0 {
			t.searchInbound(chatId, commandArgs[0])
		} else {
			handleUnknownCommand()
		}
	case "restart":
		onlyMessage = true
		if isAdmin {
			if len(commandArgs) == 0 {
				if t.xrayService.IsXrayRunning() {
					err := t.xrayService.RestartXray(true)
					if err != nil {
						msg += t.I18nBot("tgbot.commands.restartFailed", "Error=="+err.Error())
					} else {
						msg += t.I18nBot("tgbot.commands.restartSuccess")
					}
				} else {
					msg += t.I18nBot("tgbot.commands.xrayNotRunning")
				}
			} else {
				handleUnknownCommand()
				msg += t.I18nBot("tgbot.commands.restartUsage")
			}
		} else {
			handleUnknownCommand()
		}
	default:
		handleUnknownCommand()
	}

	if msg != "" {
		t.sendResponse(chatId, msg, onlyMessage, isAdmin)
	}
}

// sendResponse sends the response message based on the onlyMessage flag.
func (t *Tgbot) sendResponse(chatId int64, msg string, onlyMessage, isAdmin bool) {
	if onlyMessage {
		t.SendMsgToTgbot(chatId, msg)
	} else {
		t.SendAnswer(chatId, msg, isAdmin)
	}
}

// randomLowerAndNum generates a random string of lowercase letters and numbers.
func (t *Tgbot) randomLowerAndNum(length int) string {
	charset := "abcdefghijklmnopqrstuvwxyz0123456789"
	bytes := make([]byte, length)
	for i := range bytes {
		randomIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		bytes[i] = charset[randomIndex.Int64()]
	}
	return string(bytes)
}

// randomShadowSocksPassword generates a random password for Shadowsocks.
func (t *Tgbot) randomShadowSocksPassword() string {
	array := make([]byte, 32)
	_, err := rand.Read(array)
	if err != nil {
		return t.randomLowerAndNum(32)
	}
	return base64.StdEncoding.EncodeToString(array)
}

// answerCallback processes callback queries from inline keyboards.
func (t *Tgbot) answerCallback(callbackQuery *telego.CallbackQuery, isAdmin bool) {
	chatId := callbackQuery.Message.GetChat().ID

	if isAdmin {
		// get query from hash storage
		decodedQuery, err := t.decodeQuery(callbackQuery.Data)
		if err != nil {
			t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.noQuery"))
			return
		}
		dataArray := strings.Split(decodedQuery, " ")

		if len(dataArray) >= 2 && len(dataArray[1]) > 0 {
			email := dataArray[1]
			switch dataArray[0] {
			case "client_get_usage":
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.messages.email", "Email=="+email))
				t.searchClient(chatId, email)
			case "client_refresh":
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.clientRefreshSuccess", "Email=="+email))
				t.searchClient(chatId, email, callbackQuery.Message.GetMessageID())
			case "client_cancel":
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.canceled", "Email=="+email))
				t.searchClient(chatId, email, callbackQuery.Message.GetMessageID())
			case "ips_refresh":
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.IpRefreshSuccess", "Email=="+email))
				t.searchClientIps(chatId, email, callbackQuery.Message.GetMessageID())
			case "ips_cancel":
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.canceled", "Email=="+email))
				t.searchClientIps(chatId, email, callbackQuery.Message.GetMessageID())
			case "tgid_refresh":
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.TGIdRefreshSuccess", "Email=="+email))
				t.clientTelegramUserInfo(chatId, email, 0, callbackQuery.Message.GetMessageID())
			case "tgid_cancel":
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.canceled", "Email=="+email))
				t.clientTelegramUserInfo(chatId, email, 0, callbackQuery.Message.GetMessageID())
			case "reset_traffic":
				inlineKeyboard := tu.InlineKeyboard(
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancelReset")).WithCallbackData(t.encodeQuery("client_cancel "+email)),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.confirmResetTraffic")).WithCallbackData(t.encodeQuery("reset_traffic_c "+email)),
					),
				)
				t.editMessageCallbackTgBot(chatId, callbackQuery.Message.GetMessageID(), inlineKeyboard)
			case "reset_traffic_c":
				err := t.inboundService.ResetClientTrafficByEmail(email)
				if err == nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.resetTrafficSuccess", "Email=="+email))
					t.searchClient(chatId, email, callbackQuery.Message.GetMessageID())
				} else {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
				}
			case "limit_traffic":
				inlineKeyboard := tu.InlineKeyboard(
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancel")).WithCallbackData(t.encodeQuery("client_cancel "+email)),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.unlimited")).WithCallbackData(t.encodeQuery("limit_traffic_c "+email+" 0")),
						tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.custom")).WithCallbackData(t.encodeQuery("limit_traffic_in "+email+" 0")),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton("1 GB").WithCallbackData(t.encodeQuery("limit_traffic_c "+email+" 1")),
						tu.InlineKeyboardButton("5 GB").WithCallbackData(t.encodeQuery("limit_traffic_c "+email+" 5")),
						tu.InlineKeyboardButton("10 GB").WithCallbackData(t.encodeQuery("limit_traffic_c "+email+" 10")),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton("20 GB").WithCallbackData(t.encodeQuery("limit_traffic_c "+email+" 20")),
						tu.InlineKeyboardButton("30 GB").WithCallbackData(t.encodeQuery("limit_traffic_c "+email+" 30")),
						tu.InlineKeyboardButton("40 GB").WithCallbackData(t.encodeQuery("limit_traffic_c "+email+" 40")),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton("50 GB").WithCallbackData(t.encodeQuery("limit_traffic_c "+email+" 50")),
						tu.InlineKeyboardButton("60 GB").WithCallbackData(t.encodeQuery("limit_traffic_c "+email+" 60")),
						tu.InlineKeyboardButton("80 GB").WithCallbackData(t.encodeQuery("limit_traffic_c "+email+" 80")),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton("100 GB").WithCallbackData(t.encodeQuery("limit_traffic_c "+email+" 100")),
						tu.InlineKeyboardButton("150 GB").WithCallbackData(t.encodeQuery("limit_traffic_c "+email+" 150")),
						tu.InlineKeyboardButton("200 GB").WithCallbackData(t.encodeQuery("limit_traffic_c "+email+" 200")),
					),
				)
				t.editMessageCallbackTgBot(chatId, callbackQuery.Message.GetMessageID(), inlineKeyboard)
			case "limit_traffic_c":
				if len(dataArray) == 3 {
					limitTraffic, err := strconv.Atoi(dataArray[2])
					if err == nil {
						needRestart, err := t.inboundService.ResetClientTrafficLimitByEmail(email, limitTraffic)
						if needRestart {
							t.xrayService.SetToNeedRestart()
						}
						if err == nil {
							t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.setTrafficLimitSuccess", "Email=="+email))
							t.searchClient(chatId, email, callbackQuery.Message.GetMessageID())
							return
						}
					}
				}
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
				t.searchClient(chatId, email, callbackQuery.Message.GetMessageID())
			case "limit_traffic_in":
				if len(dataArray) >= 3 {
					oldInputNumber, err := strconv.Atoi(dataArray[2])
					inputNumber := oldInputNumber
					if err == nil {
						if len(dataArray) == 4 {
							num, err := strconv.Atoi(dataArray[3])
							if err == nil {
								switch num {
								case -2:
									inputNumber = 0
								case -1:
									if inputNumber > 0 {
										inputNumber = (inputNumber / 10)
									}
								default:
									inputNumber = (inputNumber * 10) + num
								}
							}
							if inputNumber == oldInputNumber {
								t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.successfulOperation"))
								return
							}
							if inputNumber >= 999999 {
								t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
								return
							}
						}
						inlineKeyboard := tu.InlineKeyboard(
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancel")).WithCallbackData(t.encodeQuery("client_cancel "+email)),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.confirmNumberAdd", "Num=="+strconv.Itoa(inputNumber))).WithCallbackData(t.encodeQuery("limit_traffic_c "+email+" "+strconv.Itoa(inputNumber))),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("1").WithCallbackData(t.encodeQuery("limit_traffic_in "+email+" "+strconv.Itoa(inputNumber)+" 1")),
								tu.InlineKeyboardButton("2").WithCallbackData(t.encodeQuery("limit_traffic_in "+email+" "+strconv.Itoa(inputNumber)+" 2")),
								tu.InlineKeyboardButton("3").WithCallbackData(t.encodeQuery("limit_traffic_in "+email+" "+strconv.Itoa(inputNumber)+" 3")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("4").WithCallbackData(t.encodeQuery("limit_traffic_in "+email+" "+strconv.Itoa(inputNumber)+" 4")),
								tu.InlineKeyboardButton("5").WithCallbackData(t.encodeQuery("limit_traffic_in "+email+" "+strconv.Itoa(inputNumber)+" 5")),
								tu.InlineKeyboardButton("6").WithCallbackData(t.encodeQuery("limit_traffic_in "+email+" "+strconv.Itoa(inputNumber)+" 6")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("7").WithCallbackData(t.encodeQuery("limit_traffic_in "+email+" "+strconv.Itoa(inputNumber)+" 7")),
								tu.InlineKeyboardButton("8").WithCallbackData(t.encodeQuery("limit_traffic_in "+email+" "+strconv.Itoa(inputNumber)+" 8")),
								tu.InlineKeyboardButton("9").WithCallbackData(t.encodeQuery("limit_traffic_in "+email+" "+strconv.Itoa(inputNumber)+" 9")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("🔄").WithCallbackData(t.encodeQuery("limit_traffic_in "+email+" "+strconv.Itoa(inputNumber)+" -2")),
								tu.InlineKeyboardButton("0").WithCallbackData(t.encodeQuery("limit_traffic_in "+email+" "+strconv.Itoa(inputNumber)+" 0")),
								tu.InlineKeyboardButton("⬅️").WithCallbackData(t.encodeQuery("limit_traffic_in "+email+" "+strconv.Itoa(inputNumber)+" -1")),
							),
						)
						t.editMessageCallbackTgBot(chatId, callbackQuery.Message.GetMessageID(), inlineKeyboard)
						return
					}
				}
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
				t.searchClient(chatId, email, callbackQuery.Message.GetMessageID())
			case "add_client_limit_traffic_c":
				addClientSessionsMu.Lock()
				defer addClientSessionsMu.Unlock()
				sess := t.requireAddClientSession(callbackQuery)
				if sess == nil {
					return
				}
				limitTraffic, _ := strconv.ParseInt(dataArray[1], 10, 64)
				sess.totalGB = limitTraffic * 1024 * 1024 * 1024
				messageId := callbackQuery.Message.GetMessageID()
				inbound, err := t.inboundService.GetInbound(sess.inboundID)
				if err != nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
					return
				}
				message_text, err := t.BuildInboundClientDataMessage(sess, inbound.Remark, inbound.Protocol)
				if err != nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
					return
				}

				t.addClient(sess, callbackQuery.Message.GetChat().ID, message_text, messageId)
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.successfulOperation"))
			case "add_client_limit_traffic_in":
				addClientSessionsMu.Lock()
				defer addClientSessionsMu.Unlock()
				sess := t.requireAddClientSession(callbackQuery)
				if sess == nil {
					return
				}
				if len(dataArray) >= 2 {
					oldInputNumber, err := strconv.Atoi(dataArray[1])
					inputNumber := oldInputNumber
					if err == nil {
						if len(dataArray) == 3 {
							num, err := strconv.Atoi(dataArray[2])
							if err == nil {
								switch num {
								case -2:
									inputNumber = 0
								case -1:
									if inputNumber > 0 {
										inputNumber = (inputNumber / 10)
									}
								default:
									inputNumber = (inputNumber * 10) + num
								}
							}
							if inputNumber == oldInputNumber {
								t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.successfulOperation"))
								return
							}
							if inputNumber >= 999999 {
								t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
								return
							}
						}
						inlineKeyboard := tu.InlineKeyboard(
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancel")).WithCallbackData(t.encodeQuery("add_client_default_traffic_exp")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.confirmNumberAdd", "Num=="+strconv.Itoa(inputNumber))).WithCallbackData(t.encodeQuery("add_client_limit_traffic_c "+strconv.Itoa(inputNumber))),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("1").WithCallbackData(t.encodeQuery("add_client_limit_traffic_in "+strconv.Itoa(inputNumber)+" 1")),
								tu.InlineKeyboardButton("2").WithCallbackData(t.encodeQuery("add_client_limit_traffic_in "+strconv.Itoa(inputNumber)+" 2")),
								tu.InlineKeyboardButton("3").WithCallbackData(t.encodeQuery("add_client_limit_traffic_in "+strconv.Itoa(inputNumber)+" 3")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("4").WithCallbackData(t.encodeQuery("add_client_limit_traffic_in "+strconv.Itoa(inputNumber)+" 4")),
								tu.InlineKeyboardButton("5").WithCallbackData(t.encodeQuery("add_client_limit_traffic_in "+strconv.Itoa(inputNumber)+" 5")),
								tu.InlineKeyboardButton("6").WithCallbackData(t.encodeQuery("add_client_limit_traffic_in "+strconv.Itoa(inputNumber)+" 6")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("7").WithCallbackData(t.encodeQuery("add_client_limit_traffic_in "+strconv.Itoa(inputNumber)+" 7")),
								tu.InlineKeyboardButton("8").WithCallbackData(t.encodeQuery("add_client_limit_traffic_in "+strconv.Itoa(inputNumber)+" 8")),
								tu.InlineKeyboardButton("9").WithCallbackData(t.encodeQuery("add_client_limit_traffic_in "+strconv.Itoa(inputNumber)+" 9")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("🔄").WithCallbackData(t.encodeQuery("add_client_limit_traffic_in "+strconv.Itoa(inputNumber)+" -2")),
								tu.InlineKeyboardButton("0").WithCallbackData(t.encodeQuery("add_client_limit_traffic_in "+strconv.Itoa(inputNumber)+" 0")),
								tu.InlineKeyboardButton("⬅️").WithCallbackData(t.encodeQuery("add_client_limit_traffic_in "+strconv.Itoa(inputNumber)+" -1")),
							),
						)
						t.editMessageCallbackTgBot(chatId, callbackQuery.Message.GetMessageID(), inlineKeyboard)
						return
					}
				}
			case "reset_exp":
				inlineKeyboard := tu.InlineKeyboard(
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancelReset")).WithCallbackData(t.encodeQuery("client_cancel "+email)),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.unlimited")).WithCallbackData(t.encodeQuery("reset_exp_c "+email+" 0")),
						tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.custom")).WithCallbackData(t.encodeQuery("reset_exp_in "+email+" 0")),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.add")+" 7 "+t.I18nBot("tgbot.days")).WithCallbackData(t.encodeQuery("reset_exp_c "+email+" 7")),
						tu.InlineKeyboardButton(t.I18nBot("tgbot.add")+" 10 "+t.I18nBot("tgbot.days")).WithCallbackData(t.encodeQuery("reset_exp_c "+email+" 10")),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.add")+" 14 "+t.I18nBot("tgbot.days")).WithCallbackData(t.encodeQuery("reset_exp_c "+email+" 14")),
						tu.InlineKeyboardButton(t.I18nBot("tgbot.add")+" 20 "+t.I18nBot("tgbot.days")).WithCallbackData(t.encodeQuery("reset_exp_c "+email+" 20")),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.add")+" 1 "+t.I18nBot("tgbot.month")).WithCallbackData(t.encodeQuery("reset_exp_c "+email+" 30")),
						tu.InlineKeyboardButton(t.I18nBot("tgbot.add")+" 3 "+t.I18nBot("tgbot.months")).WithCallbackData(t.encodeQuery("reset_exp_c "+email+" 90")),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.add")+" 6 "+t.I18nBot("tgbot.months")).WithCallbackData(t.encodeQuery("reset_exp_c "+email+" 180")),
						tu.InlineKeyboardButton(t.I18nBot("tgbot.add")+" 12 "+t.I18nBot("tgbot.months")).WithCallbackData(t.encodeQuery("reset_exp_c "+email+" 365")),
					),
				)
				t.editMessageCallbackTgBot(chatId, callbackQuery.Message.GetMessageID(), inlineKeyboard)
			case "reset_exp_c":
				if len(dataArray) == 3 {
					days, err := strconv.ParseInt(dataArray[2], 10, 64)
					if err == nil {
						var date int64
						if days > 0 {
							traffic, err := t.inboundService.GetClientTrafficByEmail(email)
							if err != nil {
								logger.Warning(err)
								msg := t.I18nBot("tgbot.wentWrong")
								t.SendMsgToTgbot(chatId, msg)
								return
							}
							if traffic == nil {
								msg := t.I18nBot("tgbot.noResult")
								t.SendMsgToTgbot(chatId, msg)
								return
							}

							if traffic.ExpiryTime > 0 {
								if traffic.ExpiryTime-time.Now().Unix()*1000 < 0 {
									date = -int64(days * 24 * 60 * 60000)
								} else {
									date = traffic.ExpiryTime + int64(days*24*60*60000)
								}
							} else {
								date = traffic.ExpiryTime - int64(days*24*60*60000)
							}

						}
						needRestart, err := t.inboundService.ResetClientExpiryTimeByEmail(email, date)
						if needRestart {
							t.xrayService.SetToNeedRestart()
						}
						if err == nil {
							t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.expireResetSuccess", "Email=="+email))
							t.searchClient(chatId, email, callbackQuery.Message.GetMessageID())
							return
						}
					}
				}
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
				t.searchClient(chatId, email, callbackQuery.Message.GetMessageID())
			case "reset_exp_in":
				if len(dataArray) >= 3 {
					oldInputNumber, err := strconv.Atoi(dataArray[2])
					inputNumber := oldInputNumber
					if err == nil {
						if len(dataArray) == 4 {
							num, err := strconv.Atoi(dataArray[3])
							if err == nil {
								switch num {
								case -2:
									inputNumber = 0
								case -1:
									if inputNumber > 0 {
										inputNumber = (inputNumber / 10)
									}
								default:
									inputNumber = (inputNumber * 10) + num
								}
							}
							if inputNumber == oldInputNumber {
								t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.successfulOperation"))
								return
							}
							if inputNumber >= 999999 {
								t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
								return
							}
						}
						inlineKeyboard := tu.InlineKeyboard(
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancel")).WithCallbackData(t.encodeQuery("client_cancel "+email)),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.confirmNumber", "Num=="+strconv.Itoa(inputNumber))).WithCallbackData(t.encodeQuery("reset_exp_c "+email+" "+strconv.Itoa(inputNumber))),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("1").WithCallbackData(t.encodeQuery("reset_exp_in "+email+" "+strconv.Itoa(inputNumber)+" 1")),
								tu.InlineKeyboardButton("2").WithCallbackData(t.encodeQuery("reset_exp_in "+email+" "+strconv.Itoa(inputNumber)+" 2")),
								tu.InlineKeyboardButton("3").WithCallbackData(t.encodeQuery("reset_exp_in "+email+" "+strconv.Itoa(inputNumber)+" 3")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("4").WithCallbackData(t.encodeQuery("reset_exp_in "+email+" "+strconv.Itoa(inputNumber)+" 4")),
								tu.InlineKeyboardButton("5").WithCallbackData(t.encodeQuery("reset_exp_in "+email+" "+strconv.Itoa(inputNumber)+" 5")),
								tu.InlineKeyboardButton("6").WithCallbackData(t.encodeQuery("reset_exp_in "+email+" "+strconv.Itoa(inputNumber)+" 6")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("7").WithCallbackData(t.encodeQuery("reset_exp_in "+email+" "+strconv.Itoa(inputNumber)+" 7")),
								tu.InlineKeyboardButton("8").WithCallbackData(t.encodeQuery("reset_exp_in "+email+" "+strconv.Itoa(inputNumber)+" 8")),
								tu.InlineKeyboardButton("9").WithCallbackData(t.encodeQuery("reset_exp_in "+email+" "+strconv.Itoa(inputNumber)+" 9")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("🔄").WithCallbackData(t.encodeQuery("reset_exp_in "+email+" "+strconv.Itoa(inputNumber)+" -2")),
								tu.InlineKeyboardButton("0").WithCallbackData(t.encodeQuery("reset_exp_in "+email+" "+strconv.Itoa(inputNumber)+" 0")),
								tu.InlineKeyboardButton("⬅️").WithCallbackData(t.encodeQuery("reset_exp_in "+email+" "+strconv.Itoa(inputNumber)+" -1")),
							),
						)
						t.editMessageCallbackTgBot(chatId, callbackQuery.Message.GetMessageID(), inlineKeyboard)
						return
					}
				}
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
				t.searchClient(chatId, email, callbackQuery.Message.GetMessageID())
			case "add_client_reset_exp_c":
				addClientSessionsMu.Lock()
				defer addClientSessionsMu.Unlock()
				sess := t.requireAddClientSession(callbackQuery)
				if sess == nil {
					return
				}
				sess.expiryTime = 0
				days, _ := strconv.ParseInt(dataArray[1], 10, 64)
				var date int64
				if sess.expiryTime > 0 {
					if sess.expiryTime-time.Now().Unix()*1000 < 0 {
						date = -int64(days * 24 * 60 * 60000)
					} else {
						date = sess.expiryTime + int64(days*24*60*60000)
					}
				} else {
					date = sess.expiryTime - int64(days*24*60*60000)
				}
				sess.expiryTime = date

				messageId := callbackQuery.Message.GetMessageID()
				inbound, err := t.inboundService.GetInbound(sess.inboundID)
				if err != nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
					return
				}
				message_text, err := t.BuildInboundClientDataMessage(sess, inbound.Remark, inbound.Protocol)
				if err != nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
					return
				}

				t.addClient(sess, callbackQuery.Message.GetChat().ID, message_text, messageId)
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.successfulOperation"))
			case "add_client_reset_exp_in":
				addClientSessionsMu.Lock()
				defer addClientSessionsMu.Unlock()
				sess := t.requireAddClientSession(callbackQuery)
				if sess == nil {
					return
				}
				if len(dataArray) >= 2 {
					oldInputNumber, err := strconv.Atoi(dataArray[1])
					inputNumber := oldInputNumber
					if err == nil {
						if len(dataArray) == 3 {
							num, err := strconv.Atoi(dataArray[2])
							if err == nil {
								switch num {
								case -2:
									inputNumber = 0
								case -1:
									if inputNumber > 0 {
										inputNumber = (inputNumber / 10)
									}
								default:
									inputNumber = (inputNumber * 10) + num
								}
							}
							if inputNumber == oldInputNumber {
								t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.successfulOperation"))
								return
							}
							if inputNumber >= 999999 {
								t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
								return
							}
						}
						inlineKeyboard := tu.InlineKeyboard(
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancel")).WithCallbackData(t.encodeQuery("add_client_default_traffic_exp")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.confirmNumberAdd", "Num=="+strconv.Itoa(inputNumber))).WithCallbackData(t.encodeQuery("add_client_reset_exp_c "+strconv.Itoa(inputNumber))),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("1").WithCallbackData(t.encodeQuery("add_client_reset_exp_in "+strconv.Itoa(inputNumber)+" 1")),
								tu.InlineKeyboardButton("2").WithCallbackData(t.encodeQuery("add_client_reset_exp_in "+strconv.Itoa(inputNumber)+" 2")),
								tu.InlineKeyboardButton("3").WithCallbackData(t.encodeQuery("add_client_reset_exp_in "+strconv.Itoa(inputNumber)+" 3")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("4").WithCallbackData(t.encodeQuery("add_client_reset_exp_in "+strconv.Itoa(inputNumber)+" 4")),
								tu.InlineKeyboardButton("5").WithCallbackData(t.encodeQuery("add_client_reset_exp_in "+strconv.Itoa(inputNumber)+" 5")),
								tu.InlineKeyboardButton("6").WithCallbackData(t.encodeQuery("add_client_reset_exp_in "+strconv.Itoa(inputNumber)+" 6")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("7").WithCallbackData(t.encodeQuery("add_client_reset_exp_in "+strconv.Itoa(inputNumber)+" 7")),
								tu.InlineKeyboardButton("8").WithCallbackData(t.encodeQuery("add_client_reset_exp_in "+strconv.Itoa(inputNumber)+" 8")),
								tu.InlineKeyboardButton("9").WithCallbackData(t.encodeQuery("add_client_reset_exp_in "+strconv.Itoa(inputNumber)+" 9")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("🔄").WithCallbackData(t.encodeQuery("add_client_reset_exp_in "+strconv.Itoa(inputNumber)+" -2")),
								tu.InlineKeyboardButton("0").WithCallbackData(t.encodeQuery("add_client_reset_exp_in "+strconv.Itoa(inputNumber)+" 0")),
								tu.InlineKeyboardButton("⬅️").WithCallbackData(t.encodeQuery("add_client_reset_exp_in "+strconv.Itoa(inputNumber)+" -1")),
							),
						)
						t.editMessageCallbackTgBot(chatId, callbackQuery.Message.GetMessageID(), inlineKeyboard)
						return
					}
				}
			case "ip_limit":
				inlineKeyboard := tu.InlineKeyboard(
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancelIpLimit")).WithCallbackData(t.encodeQuery("client_cancel "+email)),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.unlimited")).WithCallbackData(t.encodeQuery("ip_limit_c "+email+" 0")),
						tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.custom")).WithCallbackData(t.encodeQuery("ip_limit_in "+email+" 0")),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton("1").WithCallbackData(t.encodeQuery("ip_limit_c "+email+" 1")),
						tu.InlineKeyboardButton("2").WithCallbackData(t.encodeQuery("ip_limit_c "+email+" 2")),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton("3").WithCallbackData(t.encodeQuery("ip_limit_c "+email+" 3")),
						tu.InlineKeyboardButton("4").WithCallbackData(t.encodeQuery("ip_limit_c "+email+" 4")),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton("5").WithCallbackData(t.encodeQuery("ip_limit_c "+email+" 5")),
						tu.InlineKeyboardButton("6").WithCallbackData(t.encodeQuery("ip_limit_c "+email+" 6")),
						tu.InlineKeyboardButton("7").WithCallbackData(t.encodeQuery("ip_limit_c "+email+" 7")),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton("8").WithCallbackData(t.encodeQuery("ip_limit_c "+email+" 8")),
						tu.InlineKeyboardButton("9").WithCallbackData(t.encodeQuery("ip_limit_c "+email+" 9")),
						tu.InlineKeyboardButton("10").WithCallbackData(t.encodeQuery("ip_limit_c "+email+" 10")),
					),
				)
				t.editMessageCallbackTgBot(chatId, callbackQuery.Message.GetMessageID(), inlineKeyboard)
			case "ip_limit_c":
				if len(dataArray) == 3 {
					count, err := strconv.Atoi(dataArray[2])
					if err == nil {
						needRestart, err := t.inboundService.ResetClientIpLimitByEmail(email, count)
						if needRestart {
							t.xrayService.SetToNeedRestart()
						}
						if err == nil {
							t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.resetIpSuccess", "Email=="+email, "Count=="+strconv.Itoa(count)))
							t.searchClient(chatId, email, callbackQuery.Message.GetMessageID())
							return
						}
					}
				}
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
				t.searchClient(chatId, email, callbackQuery.Message.GetMessageID())
			case "ip_limit_in":
				if len(dataArray) >= 3 {
					oldInputNumber, err := strconv.Atoi(dataArray[2])
					inputNumber := oldInputNumber
					if err == nil {
						if len(dataArray) == 4 {
							num, err := strconv.Atoi(dataArray[3])
							if err == nil {
								switch num {
								case -2:
									inputNumber = 0
								case -1:
									if inputNumber > 0 {
										inputNumber = (inputNumber / 10)
									}
								default:
									inputNumber = (inputNumber * 10) + num
								}
							}
							if inputNumber == oldInputNumber {
								t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.successfulOperation"))
								return
							}
							if inputNumber >= 999999 {
								t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
								return
							}
						}
						inlineKeyboard := tu.InlineKeyboard(
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancel")).WithCallbackData(t.encodeQuery("client_cancel "+email)),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.confirmNumber", "Num=="+strconv.Itoa(inputNumber))).WithCallbackData(t.encodeQuery("ip_limit_c "+email+" "+strconv.Itoa(inputNumber))),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("1").WithCallbackData(t.encodeQuery("ip_limit_in "+email+" "+strconv.Itoa(inputNumber)+" 1")),
								tu.InlineKeyboardButton("2").WithCallbackData(t.encodeQuery("ip_limit_in "+email+" "+strconv.Itoa(inputNumber)+" 2")),
								tu.InlineKeyboardButton("3").WithCallbackData(t.encodeQuery("ip_limit_in "+email+" "+strconv.Itoa(inputNumber)+" 3")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("4").WithCallbackData(t.encodeQuery("ip_limit_in "+email+" "+strconv.Itoa(inputNumber)+" 4")),
								tu.InlineKeyboardButton("5").WithCallbackData(t.encodeQuery("ip_limit_in "+email+" "+strconv.Itoa(inputNumber)+" 5")),
								tu.InlineKeyboardButton("6").WithCallbackData(t.encodeQuery("ip_limit_in "+email+" "+strconv.Itoa(inputNumber)+" 6")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("7").WithCallbackData(t.encodeQuery("ip_limit_in "+email+" "+strconv.Itoa(inputNumber)+" 7")),
								tu.InlineKeyboardButton("8").WithCallbackData(t.encodeQuery("ip_limit_in "+email+" "+strconv.Itoa(inputNumber)+" 8")),
								tu.InlineKeyboardButton("9").WithCallbackData(t.encodeQuery("ip_limit_in "+email+" "+strconv.Itoa(inputNumber)+" 9")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("🔄").WithCallbackData(t.encodeQuery("ip_limit_in "+email+" "+strconv.Itoa(inputNumber)+" -2")),
								tu.InlineKeyboardButton("0").WithCallbackData(t.encodeQuery("ip_limit_in "+email+" "+strconv.Itoa(inputNumber)+" 0")),
								tu.InlineKeyboardButton("⬅️").WithCallbackData(t.encodeQuery("ip_limit_in "+email+" "+strconv.Itoa(inputNumber)+" -1")),
							),
						)
						t.editMessageCallbackTgBot(chatId, callbackQuery.Message.GetMessageID(), inlineKeyboard)
						return
					}
				}
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
				t.searchClient(chatId, email, callbackQuery.Message.GetMessageID())
			case "add_client_ip_limit_c":
				addClientSessionsMu.Lock()
				defer addClientSessionsMu.Unlock()
				sess := t.requireAddClientSession(callbackQuery)
				if sess == nil {
					return
				}
				if len(dataArray) == 2 {
					count, _ := strconv.Atoi(dataArray[1])
					sess.limitIP = count
				}

				messageId := callbackQuery.Message.GetMessageID()
				inbound, err := t.inboundService.GetInbound(sess.inboundID)
				if err != nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
					return
				}
				message_text, err := t.BuildInboundClientDataMessage(sess, inbound.Remark, inbound.Protocol)
				if err != nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
					return
				}

				t.addClient(sess, callbackQuery.Message.GetChat().ID, message_text, messageId)
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.successfulOperation"))
			case "add_client_ip_limit_in":
				addClientSessionsMu.Lock()
				defer addClientSessionsMu.Unlock()
				sess := t.requireAddClientSession(callbackQuery)
				if sess == nil {
					return
				}
				if len(dataArray) >= 2 {
					oldInputNumber, err := strconv.Atoi(dataArray[1])
					inputNumber := oldInputNumber
					if err == nil {
						if len(dataArray) == 3 {
							num, err := strconv.Atoi(dataArray[2])
							if err == nil {
								switch num {
								case -2:
									inputNumber = 0
								case -1:
									if inputNumber > 0 {
										inputNumber = (inputNumber / 10)
									}
								default:
									inputNumber = (inputNumber * 10) + num
								}
							}
							if inputNumber == oldInputNumber {
								t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.successfulOperation"))
								return
							}
							if inputNumber >= 999999 {
								t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
								return
							}
						}
						inlineKeyboard := tu.InlineKeyboard(
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancel")).WithCallbackData(t.encodeQuery("add_client_default_ip_limit")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.confirmNumber", "Num=="+strconv.Itoa(inputNumber))).WithCallbackData(t.encodeQuery("add_client_ip_limit_c "+strconv.Itoa(inputNumber))),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("1").WithCallbackData(t.encodeQuery("add_client_ip_limit_in "+strconv.Itoa(inputNumber)+" 1")),
								tu.InlineKeyboardButton("2").WithCallbackData(t.encodeQuery("add_client_ip_limit_in "+strconv.Itoa(inputNumber)+" 2")),
								tu.InlineKeyboardButton("3").WithCallbackData(t.encodeQuery("add_client_ip_limit_in "+strconv.Itoa(inputNumber)+" 3")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("4").WithCallbackData(t.encodeQuery("add_client_ip_limit_in "+strconv.Itoa(inputNumber)+" 4")),
								tu.InlineKeyboardButton("5").WithCallbackData(t.encodeQuery("add_client_ip_limit_in "+strconv.Itoa(inputNumber)+" 5")),
								tu.InlineKeyboardButton("6").WithCallbackData(t.encodeQuery("add_client_ip_limit_in "+strconv.Itoa(inputNumber)+" 6")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("7").WithCallbackData(t.encodeQuery("add_client_ip_limit_in "+strconv.Itoa(inputNumber)+" 7")),
								tu.InlineKeyboardButton("8").WithCallbackData(t.encodeQuery("add_client_ip_limit_in "+strconv.Itoa(inputNumber)+" 8")),
								tu.InlineKeyboardButton("9").WithCallbackData(t.encodeQuery("add_client_ip_limit_in "+strconv.Itoa(inputNumber)+" 9")),
							),
							tu.InlineKeyboardRow(
								tu.InlineKeyboardButton("🔄").WithCallbackData(t.encodeQuery("add_client_ip_limit_in "+strconv.Itoa(inputNumber)+" -2")),
								tu.InlineKeyboardButton("0").WithCallbackData(t.encodeQuery("add_client_ip_limit_in "+strconv.Itoa(inputNumber)+" 0")),
								tu.InlineKeyboardButton("⬅️").WithCallbackData(t.encodeQuery("add_client_ip_limit_in "+strconv.Itoa(inputNumber)+" -1")),
							),
						)
						t.editMessageCallbackTgBot(chatId, callbackQuery.Message.GetMessageID(), inlineKeyboard)
						return
					}
				}
			case "clear_ips":
				inlineKeyboard := tu.InlineKeyboard(
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancel")).WithCallbackData(t.encodeQuery("ips_cancel "+email)),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.confirmClearIps")).WithCallbackData(t.encodeQuery("clear_ips_c "+email)),
					),
				)
				t.editMessageCallbackTgBot(chatId, callbackQuery.Message.GetMessageID(), inlineKeyboard)
			case "clear_ips_c":
				err := t.inboundService.ClearClientIps(email)
				if err == nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.clearIpSuccess", "Email=="+email))
					t.searchClientIps(chatId, email, callbackQuery.Message.GetMessageID())
				} else {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
				}
			case "ip_log":
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.getIpLog", "Email=="+email))
				t.searchClientIps(chatId, email)
			case "tg_user":
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.getUserInfo", "Email=="+email))
				t.clientTelegramUserInfo(chatId, email, callbackQuery.From.ID)
			case "tgid_remove":
				inlineKeyboard := tu.InlineKeyboard(
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancel")).WithCallbackData(t.encodeQuery("tgid_cancel "+email)),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.confirmRemoveTGUser")).WithCallbackData(t.encodeQuery("tgid_remove_c "+email)),
					),
				)
				t.editMessageCallbackTgBot(chatId, callbackQuery.Message.GetMessageID(), inlineKeyboard)
			case "tgid_remove_c":
				traffic, err := t.inboundService.GetClientTrafficByEmail(email)
				if err != nil || traffic == nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
					return
				}
				needRestart, err := t.inboundService.SetClientTelegramUserID(traffic.Id, EmptyTelegramUserID)
				if needRestart {
					t.xrayService.SetToNeedRestart()
				}
				if err == nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.removedTGUserSuccess", "Email=="+email))
					t.clientTelegramUserInfo(chatId, email, 0, callbackQuery.Message.GetMessageID())
				} else {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
				}
			case "toggle_enable":
				inlineKeyboard := tu.InlineKeyboard(
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancel")).WithCallbackData(t.encodeQuery("client_cancel "+email)),
					),
					tu.InlineKeyboardRow(
						tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.confirmToggle")).WithCallbackData(t.encodeQuery("toggle_enable_c "+email)),
					),
				)
				t.editMessageCallbackTgBot(chatId, callbackQuery.Message.GetMessageID(), inlineKeyboard)
			case "toggle_enable_c":
				enabled, needRestart, err := t.inboundService.ToggleClientEnableByEmail(email)
				if needRestart {
					t.xrayService.SetToNeedRestart()
				}
				if err == nil {
					if enabled {
						t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.enableSuccess", "Email=="+email))
					} else {
						t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.disableSuccess", "Email=="+email))
					}
					t.searchClient(chatId, email, callbackQuery.Message.GetMessageID())
				} else {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.errorOperation"))
				}
			case "get_clients":
				inboundId := dataArray[1]
				inboundIdInt, err := strconv.Atoi(inboundId)
				if err != nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
					return
				}
				inbound, err := t.inboundService.GetInbound(inboundIdInt)
				if err != nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
					return
				}
				clients, err := t.getInboundClients(inboundIdInt)
				if err != nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
					return
				}
				t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.answers.chooseClient", "Inbound=="+inbound.Remark), clients)
			case "add_client_to":
				addClientSessionsMu.Lock()
				defer addClientSessionsMu.Unlock()

				inboundId := dataArray[1]
				inboundIdInt, err := strconv.Atoi(inboundId)
				if err != nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
					return
				}
				sess := t.newAddClientSession(chatId, callbackQuery.From.ID, inboundIdInt)
				inbound, err := t.inboundService.GetInbound(inboundIdInt)
				if err != nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
					return
				}

				message_text, err := t.BuildInboundClientDataMessage(sess, inbound.Remark, inbound.Protocol)
				if err != nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
					return
				}

				t.addClient(sess, callbackQuery.Message.GetChat().ID, message_text)
			}
			return
		} else {
			switch callbackQuery.Data {
			case "get_inbounds":
				inbounds, err := t.getInbounds()
				if err != nil {
					t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
					return

				}
				t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.buttons.allClients"))
				t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.answers.chooseInbound"), inbounds)
			}

		}
	}

	// The management callbacks below are admin-only. Non-admins may only
	// invoke their own personal queries (client_traffic, client_commands);
	// everything else is refused here. Never rely on which buttons the
	// client shows, and never on the callback encoding: any chat member
	// can press a button the bot posted in a group, or replay callback
	// data.
	if !isAdmin && !isPersonalBotCallback(callbackQuery.Data) {
		t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.notAllowed"))
		return
	}

	switch callbackQuery.Data {
	case "get_usage":
		t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.buttons.serverUsage"))
		t.getServerUsage(chatId)
	case "usage_refresh":
		t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.successfulOperation"))
		t.getServerUsage(chatId, callbackQuery.Message.GetMessageID())
	case "inbounds":
		t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.buttons.getInbounds"))
		t.SendMsgToTgbot(chatId, t.getInboundUsages())
	case "deplete_soon":
		t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.buttons.depleteSoon"))
		t.getExhausted(chatId)
	case "get_backup":
		t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.buttons.dbBackup"))
		t.sendBackup(chatId)
	case "get_banlogs":
		t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.buttons.getBanLogs"))
		t.sendBanLogs(chatId, true)
	case "client_traffic":
		tgUserID := callbackQuery.From.ID
		t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.buttons.clientUsage"))
		t.getClientUsage(chatId, tgUserID)
	case "client_commands":
		t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.buttons.commands"))
		t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.commands.helpClientCommands"))
	case "onlines":
		t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.buttons.onlines"))
		t.onlineClients(chatId)
	case "onlines_refresh":
		t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.successfulOperation"))
		t.onlineClients(chatId, callbackQuery.Message.GetMessageID())
	case "commands":
		t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.buttons.commands"))
		t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.commands.helpAdminCommands"))
	case "add_client":
		addClientSessionsMu.Lock()
		defer addClientSessionsMu.Unlock()
		t.newAddClientSession(chatId, callbackQuery.From.ID, 0)

		inbounds, err := t.getInboundsAddClient()
		if err != nil {
			t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
			return
		}
		t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.buttons.addClient"))
		t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.answers.chooseInbound"), inbounds)
	case "add_client_ch_default_email":
		addClientSessionsMu.Lock()
		defer addClientSessionsMu.Unlock()
		sess := t.requireAddClientSession(callbackQuery)
		if sess == nil {
			return
		}
		t.deleteMessageTgBot(chatId, callbackQuery.Message.GetMessageID())
		sess.state = "awaiting_email"
		cancel_btn_markup := tu.InlineKeyboard(
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.use_default")).WithCallbackData("add_client_default_info"),
			),
		)
		prompt_message := t.I18nBot("tgbot.messages.email_prompt", "ClientEmail=="+sess.email)
		t.SendMsgToTgbot(chatId, prompt_message, cancel_btn_markup)
	case "add_client_ch_default_id":
		addClientSessionsMu.Lock()
		defer addClientSessionsMu.Unlock()
		sess := t.requireAddClientSession(callbackQuery)
		if sess == nil {
			return
		}
		t.deleteMessageTgBot(chatId, callbackQuery.Message.GetMessageID())
		sess.state = "awaiting_id"
		cancel_btn_markup := tu.InlineKeyboard(
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.use_default")).WithCallbackData("add_client_default_info"),
			),
		)
		prompt_message := t.I18nBot("tgbot.messages.id_prompt", "ClientId=="+sess.id)
		t.SendMsgToTgbot(chatId, prompt_message, cancel_btn_markup)
	case "add_client_ch_default_pass_tr":
		addClientSessionsMu.Lock()
		defer addClientSessionsMu.Unlock()
		sess := t.requireAddClientSession(callbackQuery)
		if sess == nil {
			return
		}
		t.deleteMessageTgBot(chatId, callbackQuery.Message.GetMessageID())
		sess.state = "awaiting_password_tr"
		cancel_btn_markup := tu.InlineKeyboard(
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.use_default")).WithCallbackData("add_client_default_info"),
			),
		)
		prompt_message := t.I18nBot("tgbot.messages.pass_prompt", "ClientPassword=="+sess.trPassword)
		t.SendMsgToTgbot(chatId, prompt_message, cancel_btn_markup)
	case "add_client_ch_default_pass_sh":
		addClientSessionsMu.Lock()
		defer addClientSessionsMu.Unlock()
		sess := t.requireAddClientSession(callbackQuery)
		if sess == nil {
			return
		}
		t.deleteMessageTgBot(chatId, callbackQuery.Message.GetMessageID())
		sess.state = "awaiting_password_sh"
		cancel_btn_markup := tu.InlineKeyboard(
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.use_default")).WithCallbackData("add_client_default_info"),
			),
		)
		prompt_message := t.I18nBot("tgbot.messages.pass_prompt", "ClientPassword=="+sess.shPassword)
		t.SendMsgToTgbot(chatId, prompt_message, cancel_btn_markup)
	case "add_client_ch_default_comment":
		addClientSessionsMu.Lock()
		defer addClientSessionsMu.Unlock()
		sess := t.requireAddClientSession(callbackQuery)
		if sess == nil {
			return
		}
		t.deleteMessageTgBot(chatId, callbackQuery.Message.GetMessageID())
		sess.state = "awaiting_comment"
		cancel_btn_markup := tu.InlineKeyboard(
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.use_default")).WithCallbackData("add_client_default_info"),
			),
		)
		prompt_message := t.I18nBot("tgbot.messages.comment_prompt", "ClientComment=="+sess.comment)
		t.SendMsgToTgbot(chatId, prompt_message, cancel_btn_markup)
	case "add_client_ch_default_traffic":
		addClientSessionsMu.Lock()
		defer addClientSessionsMu.Unlock()
		if t.requireAddClientSession(callbackQuery) == nil {
			return
		}
		inlineKeyboard := tu.InlineKeyboard(
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancel")).WithCallbackData(t.encodeQuery("add_client_default_traffic_exp")),
			),
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.unlimited")).WithCallbackData(t.encodeQuery("add_client_limit_traffic_c 0")),
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.custom")).WithCallbackData(t.encodeQuery("add_client_limit_traffic_in 0")),
			),
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton("1 GB").WithCallbackData(t.encodeQuery("add_client_limit_traffic_c 1")),
				tu.InlineKeyboardButton("5 GB").WithCallbackData(t.encodeQuery("add_client_limit_traffic_c 5")),
				tu.InlineKeyboardButton("10 GB").WithCallbackData(t.encodeQuery("add_client_limit_traffic_c 10")),
			),
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton("20 GB").WithCallbackData(t.encodeQuery("add_client_limit_traffic_c 20")),
				tu.InlineKeyboardButton("30 GB").WithCallbackData(t.encodeQuery("add_client_limit_traffic_c 30")),
				tu.InlineKeyboardButton("40 GB").WithCallbackData(t.encodeQuery("add_client_limit_traffic_c 40")),
			),
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton("50 GB").WithCallbackData(t.encodeQuery("add_client_limit_traffic_c 50")),
				tu.InlineKeyboardButton("60 GB").WithCallbackData(t.encodeQuery("add_client_limit_traffic_c 60")),
				tu.InlineKeyboardButton("80 GB").WithCallbackData(t.encodeQuery("add_client_limit_traffic_c 80")),
			),
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton("100 GB").WithCallbackData(t.encodeQuery("add_client_limit_traffic_c 100")),
				tu.InlineKeyboardButton("150 GB").WithCallbackData(t.encodeQuery("add_client_limit_traffic_c 150")),
				tu.InlineKeyboardButton("200 GB").WithCallbackData(t.encodeQuery("add_client_limit_traffic_c 200")),
			),
		)
		t.editMessageCallbackTgBot(chatId, callbackQuery.Message.GetMessageID(), inlineKeyboard)
	case "add_client_ch_default_exp":
		addClientSessionsMu.Lock()
		defer addClientSessionsMu.Unlock()
		if t.requireAddClientSession(callbackQuery) == nil {
			return
		}
		inlineKeyboard := tu.InlineKeyboard(
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancel")).WithCallbackData(t.encodeQuery("add_client_default_traffic_exp")),
			),
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.unlimited")).WithCallbackData(t.encodeQuery("add_client_reset_exp_c 0")),
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.custom")).WithCallbackData(t.encodeQuery("add_client_reset_exp_in 0")),
			),
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.add")+" 7 "+t.I18nBot("tgbot.days")).WithCallbackData(t.encodeQuery("add_client_reset_exp_c 7")),
				tu.InlineKeyboardButton(t.I18nBot("tgbot.add")+" 10 "+t.I18nBot("tgbot.days")).WithCallbackData(t.encodeQuery("add_client_reset_exp_c 10")),
			),
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.add")+" 14 "+t.I18nBot("tgbot.days")).WithCallbackData(t.encodeQuery("add_client_reset_exp_c 14")),
				tu.InlineKeyboardButton(t.I18nBot("tgbot.add")+" 20 "+t.I18nBot("tgbot.days")).WithCallbackData(t.encodeQuery("add_client_reset_exp_c 20")),
			),
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.add")+" 1 "+t.I18nBot("tgbot.month")).WithCallbackData(t.encodeQuery("add_client_reset_exp_c 30")),
				tu.InlineKeyboardButton(t.I18nBot("tgbot.add")+" 3 "+t.I18nBot("tgbot.months")).WithCallbackData(t.encodeQuery("add_client_reset_exp_c 90")),
			),
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.add")+" 6 "+t.I18nBot("tgbot.months")).WithCallbackData(t.encodeQuery("add_client_reset_exp_c 180")),
				tu.InlineKeyboardButton(t.I18nBot("tgbot.add")+" 12 "+t.I18nBot("tgbot.months")).WithCallbackData(t.encodeQuery("add_client_reset_exp_c 365")),
			),
		)
		t.editMessageCallbackTgBot(chatId, callbackQuery.Message.GetMessageID(), inlineKeyboard)
	case "add_client_ch_default_ip_limit":
		addClientSessionsMu.Lock()
		defer addClientSessionsMu.Unlock()
		if t.requireAddClientSession(callbackQuery) == nil {
			return
		}
		inlineKeyboard := tu.InlineKeyboard(
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancel")).WithCallbackData(t.encodeQuery("add_client_default_ip_limit")),
			),
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.unlimited")).WithCallbackData(t.encodeQuery("add_client_ip_limit_c 0")),
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.custom")).WithCallbackData(t.encodeQuery("add_client_ip_limit_in 0")),
			),
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton("1").WithCallbackData(t.encodeQuery("add_client_ip_limit_c 1")),
				tu.InlineKeyboardButton("2").WithCallbackData(t.encodeQuery("add_client_ip_limit_c 2")),
			),
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton("3").WithCallbackData(t.encodeQuery("add_client_ip_limit_c 3")),
				tu.InlineKeyboardButton("4").WithCallbackData(t.encodeQuery("add_client_ip_limit_c 4")),
			),
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton("5").WithCallbackData(t.encodeQuery("add_client_ip_limit_c 5")),
				tu.InlineKeyboardButton("6").WithCallbackData(t.encodeQuery("add_client_ip_limit_c 6")),
				tu.InlineKeyboardButton("7").WithCallbackData(t.encodeQuery("add_client_ip_limit_c 7")),
			),
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton("8").WithCallbackData(t.encodeQuery("add_client_ip_limit_c 8")),
				tu.InlineKeyboardButton("9").WithCallbackData(t.encodeQuery("add_client_ip_limit_c 9")),
				tu.InlineKeyboardButton("10").WithCallbackData(t.encodeQuery("add_client_ip_limit_c 10")),
			),
		)
		t.editMessageCallbackTgBot(chatId, callbackQuery.Message.GetMessageID(), inlineKeyboard)
	case "add_client_default_info":
		addClientSessionsMu.Lock()
		defer addClientSessionsMu.Unlock()
		sess := t.requireAddClientSession(callbackQuery)
		if sess == nil {
			return
		}
		t.deleteMessageTgBot(chatId, callbackQuery.Message.GetMessageID())
		t.SendMsgToTgbotDeleteAfter(chatId, t.I18nBot("tgbot.messages.using_default_value"), 3, tu.ReplyKeyboardRemove())
		sess.state = ""
		inbound, _ := t.inboundService.GetInbound(sess.inboundID)
		message_text, _ := t.BuildInboundClientDataMessage(sess, inbound.Remark, inbound.Protocol)
		t.addClient(sess, chatId, message_text)
	case "add_client_cancel":
		addClientSessionsMu.Lock()
		defer addClientSessionsMu.Unlock()
		deleteAddClientSession(chatId, callbackQuery.From.ID)
		t.deleteMessageTgBot(chatId, callbackQuery.Message.GetMessageID())
		t.SendMsgToTgbotDeleteAfter(chatId, t.I18nBot("tgbot.messages.cancel"), 3, tu.ReplyKeyboardRemove())
	case "add_client_default_traffic_exp":
		addClientSessionsMu.Lock()
		defer addClientSessionsMu.Unlock()
		sess := t.requireAddClientSession(callbackQuery)
		if sess == nil {
			return
		}
		messageId := callbackQuery.Message.GetMessageID()
		inbound, err := t.inboundService.GetInbound(sess.inboundID)
		if err != nil {
			t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
			return
		}
		message_text, err := t.BuildInboundClientDataMessage(sess, inbound.Remark, inbound.Protocol)
		if err != nil {
			t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
			return
		}
		t.addClient(sess, chatId, message_text, messageId)
		t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.canceled", "Email=="+sess.email))
	case "add_client_default_ip_limit":
		addClientSessionsMu.Lock()
		defer addClientSessionsMu.Unlock()
		sess := t.requireAddClientSession(callbackQuery)
		if sess == nil {
			return
		}
		messageId := callbackQuery.Message.GetMessageID()
		inbound, err := t.inboundService.GetInbound(sess.inboundID)
		if err != nil {
			t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
			return
		}
		message_text, err := t.BuildInboundClientDataMessage(sess, inbound.Remark, inbound.Protocol)
		if err != nil {
			t.sendCallbackAnswerTgBot(callbackQuery.ID, err.Error())
			return
		}
		t.addClient(sess, chatId, message_text, messageId)
		t.sendCallbackAnswerTgBot(callbackQuery.ID, t.I18nBot("tgbot.answers.canceled", "Email=="+sess.email))
	case "add_client_submit_disable":
		addClientSessionsMu.Lock()
		defer addClientSessionsMu.Unlock()
		sess := t.requireAddClientSession(callbackQuery)
		if sess == nil {
			return
		}
		sess.enable = false
		_, err := t.SubmitAddClient(sess)
		if err != nil {
			errorMessage := fmt.Sprintf("%v", err)
			t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.messages.error_add_client", "error=="+errorMessage), tu.ReplyKeyboardRemove())
		} else {
			t.deleteMessageTgBot(chatId, callbackQuery.Message.GetMessageID())
			t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.answers.successfulOperation"), tu.ReplyKeyboardRemove())
			deleteAddClientSession(chatId, callbackQuery.From.ID)
		}
	case "add_client_submit_enable":
		addClientSessionsMu.Lock()
		defer addClientSessionsMu.Unlock()
		sess := t.requireAddClientSession(callbackQuery)
		if sess == nil {
			return
		}
		sess.enable = true
		_, err := t.SubmitAddClient(sess)
		if err != nil {
			errorMessage := fmt.Sprintf("%v", err)
			t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.messages.error_add_client", "error=="+errorMessage), tu.ReplyKeyboardRemove())
		} else {
			t.deleteMessageTgBot(chatId, callbackQuery.Message.GetMessageID())
			t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.answers.successfulOperation"), tu.ReplyKeyboardRemove())
			deleteAddClientSession(chatId, callbackQuery.From.ID)
		}
	case "reset_all_traffics_cancel":
		t.deleteMessageTgBot(chatId, callbackQuery.Message.GetMessageID())
		t.SendMsgToTgbotDeleteAfter(chatId, t.I18nBot("tgbot.messages.cancel"), 1, tu.ReplyKeyboardRemove())
	case "reset_all_traffics":
		inlineKeyboard := tu.InlineKeyboard(
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancelReset")).WithCallbackData(t.encodeQuery("reset_all_traffics_cancel")),
			),
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.confirmResetTraffic")).WithCallbackData(t.encodeQuery("reset_all_traffics_c")),
			),
		)
		t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.messages.AreYouSure"), inlineKeyboard)
	case "reset_all_traffics_c":
		t.deleteMessageTgBot(chatId, callbackQuery.Message.GetMessageID())
		emails, err := t.inboundService.getAllEmails()
		if err != nil {
			t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.answers.errorOperation"), tu.ReplyKeyboardRemove())
			return
		}

		for _, email := range emails {
			err := t.inboundService.ResetClientTrafficByEmail(email)
			if err == nil {
				msg := t.I18nBot("tgbot.messages.SuccessResetTraffic", "ClientEmail=="+email)
				t.SendMsgToTgbot(chatId, msg, tu.ReplyKeyboardRemove())
			} else {
				msg := t.I18nBot("tgbot.messages.FailedResetTraffic", "ClientEmail=="+email, "ErrorMessage=="+err.Error())
				t.SendMsgToTgbot(chatId, msg, tu.ReplyKeyboardRemove())
			}
		}

		t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.messages.FinishProcess"), tu.ReplyKeyboardRemove())
	case "get_sorted_traffic_usage_report":
		t.deleteMessageTgBot(chatId, callbackQuery.Message.GetMessageID())
		emails, err := t.inboundService.getAllEmails()

		if err != nil {
			t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.answers.errorOperation"), tu.ReplyKeyboardRemove())
			return
		}
		valid_emails, extra_emails, err := t.inboundService.FilterAndSortClientEmails(emails)
		if err != nil {
			t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.answers.errorOperation"), tu.ReplyKeyboardRemove())
			return
		}

		for _, valid_emails := range valid_emails {
			traffic, err := t.inboundService.GetClientTrafficByEmail(valid_emails)
			if err != nil {
				logger.Warning(err)
				msg := t.I18nBot("tgbot.wentWrong")
				t.SendMsgToTgbot(chatId, msg)
				continue
			}
			if traffic == nil {
				msg := t.I18nBot("tgbot.noResult")
				t.SendMsgToTgbot(chatId, msg)
				continue
			}

			output := t.clientInfoMsg(traffic, false, false, false, false, true, false)
			t.SendMsgToTgbot(chatId, output, tu.ReplyKeyboardRemove())
		}
		for _, extra_emails := range extra_emails {
			msg := fmt.Sprintf("📧 %s\n%s", extra_emails, t.I18nBot("tgbot.noResult"))
			t.SendMsgToTgbot(chatId, msg, tu.ReplyKeyboardRemove())

		}
	}
}

// BuildInboundClientDataMessage builds a message with client data for the given inbound and protocol.
func (t *Tgbot) BuildInboundClientDataMessage(sess *addClientSession, inbound_remark string, protocol model.Protocol) (string, error) {
	var message string

	currentTime := time.Now()
	timestampMillis := currentTime.UnixNano() / int64(time.Millisecond)

	expiryTime := ""
	diff := sess.expiryTime/1000 - timestampMillis
	if sess.expiryTime == 0 {
		expiryTime = t.I18nBot("tgbot.unlimited")
	} else if diff > 172800 {
		expiryTime = time.Unix((sess.expiryTime / 1000), 0).Format("2006-01-02 15:04:05")
	} else if sess.expiryTime < 0 {
		expiryTime = fmt.Sprintf("%d %s", sess.expiryTime/-86400000, t.I18nBot("tgbot.days"))
	} else {
		expiryTime = fmt.Sprintf("%d %s", diff/3600, t.I18nBot("tgbot.hours"))
	}

	traffic_value := ""
	if sess.totalGB == 0 {
		traffic_value = "♾️ Unlimited(Reset)"
	} else {
		traffic_value = common.FormatTraffic(sess.totalGB)
	}

	ip_limit := ""
	if sess.limitIP == 0 {
		ip_limit = "♾️ Unlimited(Reset)"
	} else {
		ip_limit = fmt.Sprint(sess.limitIP)
	}

	switch protocol {
	case model.VMESS, model.VLESS:
		message = t.I18nBot("tgbot.messages.inbound_client_data_id", "InboundRemark=="+inbound_remark, "ClientId=="+sess.id, "ClientEmail=="+sess.email, "ClientTraffic=="+traffic_value, "ClientExp=="+expiryTime, "IpLimit=="+ip_limit, "ClientComment=="+sess.comment)

	case model.Trojan:
		message = t.I18nBot("tgbot.messages.inbound_client_data_pass", "InboundRemark=="+inbound_remark, "ClientPass=="+sess.trPassword, "ClientEmail=="+sess.email, "ClientTraffic=="+traffic_value, "ClientExp=="+expiryTime, "IpLimit=="+ip_limit, "ClientComment=="+sess.comment)

	case model.Shadowsocks:
		message = t.I18nBot("tgbot.messages.inbound_client_data_pass", "InboundRemark=="+inbound_remark, "ClientPass=="+sess.shPassword, "ClientEmail=="+sess.email, "ClientTraffic=="+traffic_value, "ClientExp=="+expiryTime, "IpLimit=="+ip_limit, "ClientComment=="+sess.comment)

	default:
		return "", errors.New("unknown protocol")
	}

	return message, nil
}

// tgbotClientJSON is the per-protocol client object emitted by
// BuildJSONForProtocol. It is marshaled with encoding/json (M-7):
// building the JSON with Sprintf let a quote in an admin-supplied
// value break out of its field and override later fields (notably
// id/flow/tgId). Fields absent for a protocol are omitted, so the
// emitted object keeps exactly the old per-protocol field set.
type tgbotClientJSON struct {
	ID         string `json:"id,omitempty"`
	Security   string `json:"security,omitempty"`
	Flow       string `json:"flow,omitempty"`
	Password   string `json:"password,omitempty"`
	Method     string `json:"method,omitempty"`
	Email      string `json:"email"`
	LimitIP    int    `json:"limitIp"`
	TotalGB    int64  `json:"totalGB"`
	ExpiryTime int64  `json:"expiryTime"`
	Enable     bool   `json:"enable"`
	TgID       string `json:"tgId"`
	Comment    string `json:"comment"`
	Reset      int    `json:"reset"`
}

// tgbotClientSettings wraps one client the way AddInboundClient
// expects it: {"clients": [...]}.
type tgbotClientSettings struct {
	Clients []tgbotClientJSON `json:"clients"`
}

// tgbotEmailPattern accepts either a plain email address or a plain
// token label (the add-client flow's default email is an 8-character
// random token, not an address). It rejects quotes, commas, colons,
// whitespace, and control characters, so a value can never smuggle
// extra JSON fields even before marshaling.
var tgbotEmailPattern = regexp.MustCompile(`^(?:[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}|[A-Za-z0-9._\-]+)$`)

// BuildJSONForProtocol builds a JSON string for the given protocol with client data.
func (t *Tgbot) BuildJSONForProtocol(sess *addClientSession, protocol model.Protocol) (string, error) {
	// M-7: the client id must be a real UUID and the email a plain
	// address or token label; a crafted value used to break out of
	// its JSON string and override later fields.
	if protocol == model.VMESS || protocol == model.VLESS {
		if _, err := uuid.Parse(sess.id); err != nil {
			return "", fmt.Errorf("invalid client id %q: not a UUID", sess.id)
		}
	}
	if !tgbotEmailPattern.MatchString(sess.email) {
		return "", fmt.Errorf("invalid client email %q", sess.email)
	}

	client := tgbotClientJSON{
		Email:      sess.email,
		LimitIP:    sess.limitIP,
		TotalGB:    sess.totalGB,
		ExpiryTime: sess.expiryTime,
		Enable:     sess.enable,
		TgID:       sess.tgID,
		Comment:    sess.comment,
		Reset:      sess.reset,
	}
	switch protocol {
	case model.VMESS:
		client.ID = sess.id
		client.Security = sess.security
	case model.VLESS:
		client.ID = sess.id
		client.Flow = sess.flow
	case model.Trojan:
		client.Password = sess.trPassword
	case model.Shadowsocks:
		client.Method = sess.method
		client.Password = sess.shPassword
	default:
		return "", errors.New("unknown protocol")
	}

	out, err := json.Marshal(tgbotClientSettings{Clients: []tgbotClientJSON{client}})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// SubmitAddClient submits the client addition request to the inbound service.
func (t *Tgbot) SubmitAddClient(sess *addClientSession) (bool, error) {

	inbound, err := t.inboundService.GetInbound(sess.inboundID)
	if err != nil {
		logger.Warning("getIboundClients run failed:", err)
		return false, errors.New(t.I18nBot("tgbot.answers.getInboundsFailed"))
	}

	jsonString, err := t.BuildJSONForProtocol(sess, inbound.Protocol)
	if err != nil {
		logger.Warning("BuildJSONForProtocol run failed:", err)
		return false, errors.New("failed to build JSON for protocol")
	}

	newInbound := &model.Inbound{
		Id:       sess.inboundID,
		Settings: jsonString,
	}

	return t.inboundService.AddInboundClient(newInbound)
}

// setAdminIds replaces the admin list snapshot with a fresh copy. The
// stored slice is never mutated afterwards, so readers can iterate the
// snapshot without holding any lock. A nil list clears the admins.
func setAdminIds(ids []int64) {
	if ids == nil {
		ids = []int64{}
	}
	cp := make([]int64, len(ids))
	copy(cp, ids)
	adminIds.Store(&cp)
	// Revocation must take effect at once: drop the in-progress
	// add-client sessions of users who are no longer admins, so a
	// revoked admin cannot keep editing a draft they started while
	// they were an admin. handleAddClientInput re-checks on every
	// input as a second layer, for the race window.
	purgeRevokedSessions(cp)
}

// purgeRevokedSessions deletes the add-client sessions of every user not
// present in the current admin list. Callers must not hold
// addClientSessionsMu.
func purgeRevokedSessions(admins []int64) {
	keep := make(map[int64]bool, len(admins))
	for _, id := range admins {
		keep[id] = true
	}
	addClientSessionsMu.Lock()
	defer addClientSessionsMu.Unlock()
	for key := range addClientSessions {
		if !keep[key.userID] {
			delete(addClientSessions, key)
		}
	}
}

// getAdminIds returns the current admin list snapshot. The returned slice
// must not be modified.
func getAdminIds() []int64 {
	if ids := adminIds.Load(); ids != nil {
		return *ids
	}
	return nil
}

// checkAdmin checks if the given Telegram ID is an admin.
func checkAdmin(tgId int64) bool {
	for _, adminId := range getAdminIds() {
		if adminId == tgId {
			return true
		}
	}
	return false
}

// SendAnswer sends a response message with an inline keyboard to the specified chat.
func (t *Tgbot) SendAnswer(chatId int64, msg string, isAdmin bool) {
	numericKeyboard := tu.InlineKeyboard(
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.SortedTrafficUsageReport")).WithCallbackData(t.encodeQuery("get_sorted_traffic_usage_report")),
		),
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.serverUsage")).WithCallbackData(t.encodeQuery("get_usage")),
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.ResetAllTraffics")).WithCallbackData(t.encodeQuery("reset_all_traffics")),
		),
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.dbBackup")).WithCallbackData(t.encodeQuery("get_backup")),
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.getBanLogs")).WithCallbackData(t.encodeQuery("get_banlogs")),
		),
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.getInbounds")).WithCallbackData(t.encodeQuery("inbounds")),
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.depleteSoon")).WithCallbackData(t.encodeQuery("deplete_soon")),
		),
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.commands")).WithCallbackData(t.encodeQuery("commands")),
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.onlines")).WithCallbackData(t.encodeQuery("onlines")),
		),
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.allClients")).WithCallbackData(t.encodeQuery("get_inbounds")),
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.addClient")).WithCallbackData(t.encodeQuery("add_client")),
		),
		// TODOOOOOOOOOOOOOO: Add restart button here.
	)
	numericKeyboardClient := tu.InlineKeyboard(
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.clientUsage")).WithCallbackData(t.encodeQuery("client_traffic")),
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.commands")).WithCallbackData(t.encodeQuery("client_commands")),
		),
	)

	var ReplyMarkup telego.ReplyMarkup
	if isAdmin {
		ReplyMarkup = numericKeyboard
	} else {
		ReplyMarkup = numericKeyboardClient
	}
	t.SendMsgToTgbot(chatId, msg, ReplyMarkup)
}

// SendMsgToTgbot sends a message to the Telegram bot with optional reply markup.
func (t *Tgbot) SendMsgToTgbot(chatId int64, msg string, replyMarkup ...telego.ReplyMarkup) {
	if bot == nil || !isRunning.Load() {
		return
	}

	if msg == "" {
		logger.Info("[tgbot] message is empty!")
		return
	}

	var allMessages []string
	limit := 2000

	// paging message if it is big
	if len(msg) > limit {
		messages := strings.Split(msg, "\r\n\r\n")
		lastIndex := -1

		for _, message := range messages {
			if (len(allMessages) == 0) || (len(allMessages[lastIndex])+len(message) > limit) {
				allMessages = append(allMessages, message)
				lastIndex++
			} else {
				allMessages[lastIndex] += "\r\n\r\n" + message
			}
		}
		if strings.TrimSpace(allMessages[len(allMessages)-1]) == "" {
			allMessages = allMessages[:len(allMessages)-1]
		}
	} else {
		allMessages = append(allMessages, msg)
	}
	for n, message := range allMessages {
		params := telego.SendMessageParams{
			ChatID:    tu.ID(chatId),
			Text:      message,
			ParseMode: "HTML",
		}
		// only add replyMarkup to last message
		if len(replyMarkup) > 0 && n == (len(allMessages)-1) {
			params.ReplyMarkup = replyMarkup[0]
		}

		// Retry logic with exponential backoff for connection errors
		maxRetries := 3
		for attempt := range maxRetries {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			_, err := bot.SendMessage(ctx, &params)
			cancel()

			if err == nil {
				break // Success
			}

			// Check if error is a connection error
			errStr := err.Error()

			// M-8: a 429 is Telegram telling us to slow down, not a
			// connection error to burn retries on: honor the
			// requested delay (capped) and retry.
			if delay, ok := tgbotRetryAfter(err); ok && attempt < maxRetries-1 {
				logger.Warningf("Telegram rate limit sending message (attempt %d/%d), retrying in %v: %v",
					attempt+1, maxRetries, delay, err)
				time.Sleep(delay)
				continue
			}

			isConnectionError := strings.Contains(errStr, "connection") ||
				strings.Contains(errStr, "timeout") ||
				strings.Contains(errStr, "closed")

			if isConnectionError && attempt < maxRetries-1 {
				// Exponential backoff: 1s, 2s, 4s
				backoff := time.Duration(1<<uint(attempt)) * time.Second
				logger.Warningf("Connection error sending telegram message (attempt %d/%d), retrying in %v: %v",
					attempt+1, maxRetries, backoff, err)
				time.Sleep(backoff)
			} else {
				logger.Warning("Error sending telegram message:", err)
				break
			}
		}

		// Reduced delay to improve performance (only needed for rate limiting)
		if n < len(allMessages)-1 { // Only delay between messages, not after the last one
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func (t *Tgbot) SendMsgToTgbotAdmins(msg string, replyMarkup ...telego.ReplyMarkup) {
	if len(replyMarkup) > 0 {
		for _, adminId := range getAdminIds() {
			t.SendMsgToTgbot(adminId, msg, replyMarkup[0])
		}
	} else {
		for _, adminId := range getAdminIds() {
			t.SendMsgToTgbot(adminId, msg)
		}
	}
}

// SendReport sends a periodic report to admin chats.
func (t *Tgbot) SendReport() {
	runTime, err := t.settingService.GetTgbotRuntime()
	if err == nil && len(runTime) > 0 {
		msg := ""
		msg += t.I18nBot("tgbot.messages.report", "RunTime=="+runTime)
		msg += t.I18nBot("tgbot.messages.datetime", "DateTime=="+time.Now().Format("2006-01-02 15:04:05"))
		t.SendMsgToTgbotAdmins(msg)
	}

	info := t.sendServerUsage()
	t.SendMsgToTgbotAdmins(info)

	t.sendExhaustedToAdmins()
	t.notifyExhausted()

	backupEnable, err := t.settingService.GetTgBotBackup()
	if err == nil && backupEnable {
		t.SendBackupToAdmins()
	}
}

// SendBackupToAdmins sends a database backup to admin chats.
func (t *Tgbot) SendBackupToAdmins() {
	if !t.IsRunning() {
		return
	}
	ids := getAdminIds()
	for i, adminId := range ids {
		t.sendBackup(int64(adminId))
		// Add delay between sends to avoid Telegram rate limits
		if i < len(ids)-1 {
			time.Sleep(1 * time.Second)
		}
	}
}

// sendExhaustedToAdmins sends notifications about exhausted clients to admins.
func (t *Tgbot) sendExhaustedToAdmins() {
	if !t.IsRunning() {
		return
	}
	for _, adminId := range getAdminIds() {
		t.getExhausted(int64(adminId))
	}
}

// getServerUsage retrieves and formats server usage information.
func (t *Tgbot) getServerUsage(chatId int64, messageID ...int) string {
	info := t.prepareServerUsageInfo()

	keyboard := tu.InlineKeyboard(tu.InlineKeyboardRow(
		tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.refresh")).WithCallbackData(t.encodeQuery("usage_refresh"))))

	if len(messageID) > 0 {
		t.editMessageTgBot(chatId, messageID[0], info, keyboard)
	} else {
		t.SendMsgToTgbot(chatId, info, keyboard)
	}

	return info
}

// Send server usage without an inline keyboard
func (t *Tgbot) sendServerUsage() string {
	info := t.prepareServerUsageInfo()
	return info
}

// prepareServerUsageInfo prepares the server usage information string.
func (t *Tgbot) prepareServerUsageInfo() string {
	// Check if we have cached data first
	if cachedStats, found := t.getCachedServerStats(); found {
		return cachedStats
	}

	info, ipv4, ipv6 := "", "", ""

	// get latest status of server with caching
	if cachedStatus, found := t.getCachedStatus(); found {
		t.lastStatus = cachedStatus
	} else {
		t.lastStatus = t.serverService.GetStatus(t.lastStatus)
		t.setCachedStatus(t.lastStatus)
	}
	onlines := t.xrayService.GetOnlineClients()

	info += t.I18nBot("tgbot.messages.hostname", "Hostname=="+hostname)
	info += t.I18nBot("tgbot.messages.version", "Version=="+config.GetVersion())
	info += t.I18nBot("tgbot.messages.xrayVersion", "XrayVersion=="+fmt.Sprint(t.lastStatus.Xray.Version))

	// get ip address
	netInterfaces, err := net.Interfaces()
	if err != nil {
		logger.Error("net.Interfaces failed, err: ", err.Error())
		info += t.I18nBot("tgbot.messages.ip", "IP=="+t.I18nBot("tgbot.unknown"))
		info += "\r\n"
	} else {
		for i := range netInterfaces {
			if (netInterfaces[i].Flags & net.FlagUp) != 0 {
				addrs, _ := netInterfaces[i].Addrs()

				for _, address := range addrs {
					if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
						if ipnet.IP.To4() != nil {
							ipv4 += ipnet.IP.String() + " "
						} else if ipnet.IP.To16() != nil && !ipnet.IP.IsLinkLocalUnicast() {
							ipv6 += ipnet.IP.String() + " "
						}
					}
				}
			}
		}

		info += t.I18nBot("tgbot.messages.ipv4", "IPv4=="+ipv4)
		info += t.I18nBot("tgbot.messages.ipv6", "IPv6=="+ipv6)
	}

	info += t.I18nBot("tgbot.messages.serverUpTime", "UpTime=="+strconv.FormatUint(t.lastStatus.Uptime/86400, 10), "Unit=="+t.I18nBot("tgbot.days"))
	info += t.I18nBot("tgbot.messages.serverLoad", "Load1=="+strconv.FormatFloat(t.lastStatus.Loads[0], 'f', 2, 64), "Load2=="+strconv.FormatFloat(t.lastStatus.Loads[1], 'f', 2, 64), "Load3=="+strconv.FormatFloat(t.lastStatus.Loads[2], 'f', 2, 64))
	info += t.I18nBot("tgbot.messages.serverMemory", "Current=="+common.FormatTraffic(int64(t.lastStatus.Mem.Current)), "Total=="+common.FormatTraffic(int64(t.lastStatus.Mem.Total)))
	info += t.I18nBot("tgbot.messages.onlinesCount", "Count=="+fmt.Sprint(len(onlines)))
	info += t.I18nBot("tgbot.messages.tcpCount", "Count=="+strconv.Itoa(t.lastStatus.TcpCount))
	info += t.I18nBot("tgbot.messages.udpCount", "Count=="+strconv.Itoa(t.lastStatus.UdpCount))
	info += t.I18nBot("tgbot.messages.traffic", "Total=="+common.FormatTraffic(int64(t.lastStatus.NetTraffic.Sent+t.lastStatus.NetTraffic.Recv)), "Upload=="+common.FormatTraffic(int64(t.lastStatus.NetTraffic.Sent)), "Download=="+common.FormatTraffic(int64(t.lastStatus.NetTraffic.Recv)))
	info += t.I18nBot("tgbot.messages.xrayStatus", "State=="+fmt.Sprint(t.lastStatus.Xray.State))

	// Cache the complete server stats
	t.setCachedServerStats(info)

	return info
}

// loginNotifyDedupWindow coalesces repeat login notifications for
// the same (username, IP, status) (M-8). Without it, every failed
// login — an attacker can force one per request — becomes a Telegram
// message to the admins.
const loginNotifyDedupWindow = time.Minute

type loginNotifyKey struct {
	username string
	ip       string
	status   LoginStatus
}

var (
	loginNotifyMu      sync.Mutex
	loginNotifyEntries = map[loginNotifyKey]time.Time{}
)

// UserLoginNotify sends a notification about user login attempts to admins.
//
// M-8: the send runs in its own goroutine, so a slow or hanging
// Telegram API never holds the login request (the call site is the
// login handler). Repeat notifications for the same (username, IP,
// status) inside loginNotifyDedupWindow are coalesced to one: the
// first sends, the rest are dropped.
func (t *Tgbot) UserLoginNotify(username string, password string, ip string, timeStr string, status LoginStatus) {
	if !t.IsRunning() {
		return
	}

	if username == "" || ip == "" || timeStr == "" {
		logger.Warning("UserLoginNotify failed, invalid info!")
		return
	}

	loginNotifyEnabled, err := t.settingService.GetTgBotLoginNotify()
	if err != nil || !loginNotifyEnabled {
		return
	}

	loginNotifyMu.Lock()
	key := loginNotifyKey{username: username, ip: ip, status: status}
	if last, ok := loginNotifyEntries[key]; ok && time.Since(last) < loginNotifyDedupWindow {
		loginNotifyMu.Unlock()
		return
	}
	loginNotifyEntries[key] = time.Now()
	loginNotifyMu.Unlock()

	go t.sendLoginNotify(username, password, ip, timeStr, status)
}

// sendLoginNotify builds and sends one login notification. It runs in
// its own goroutine; see UserLoginNotify.
func (t *Tgbot) sendLoginNotify(username string, password string, ip string, timeStr string, status LoginStatus) {
	msg := ""
	switch status {
	case LoginSuccess:
		msg += t.I18nBot("tgbot.messages.loginSuccess")
		msg += t.I18nBot("tgbot.messages.hostname", "Hostname=="+hostname)
	case LoginFail:
		msg += t.I18nBot("tgbot.messages.loginFailed")
		msg += t.I18nBot("tgbot.messages.hostname", "Hostname=="+hostname)
		// H5: the password argument is accepted for API compatibility but
		// never included in the notification - it must not leave the panel.
		_ = password
		msg += t.I18nBot("tgbot.messages.password", "Password==<redacted>")
	}
	msg += t.I18nBot("tgbot.messages.username", "Username=="+username)
	msg += t.I18nBot("tgbot.messages.ip", "IP=="+ip)
	msg += t.I18nBot("tgbot.messages.time", "Time=="+timeStr)
	t.SendMsgToTgbotAdmins(msg)
}

// getInboundUsages retrieves and formats inbound usage information.
func (t *Tgbot) getInboundUsages() string {
	var info strings.Builder
	// get traffic
	inbounds, err := t.inboundService.GetAllInbounds()
	if err != nil {
		logger.Warning("GetAllInbounds run failed:", err)
		info.WriteString(t.I18nBot("tgbot.answers.getInboundsFailed"))
	} else {
		// NOTE:If there no any sessions here,need to notify here
		// TODO:Sub-node push, automatic conversion format
		for _, inbound := range inbounds {
			info.WriteString(t.I18nBot("tgbot.messages.inbound", "Remark=="+inbound.Remark))
			info.WriteString(t.I18nBot("tgbot.messages.port", "Port=="+strconv.Itoa(inbound.Port)))
			info.WriteString(t.I18nBot("tgbot.messages.traffic", "Total=="+common.FormatTraffic((inbound.Up+inbound.Down)), "Upload=="+common.FormatTraffic(inbound.Up), "Download=="+common.FormatTraffic(inbound.Down)))

			if inbound.ExpiryTime == 0 {
				info.WriteString(t.I18nBot("tgbot.messages.expire", "Time=="+t.I18nBot("tgbot.unlimited")))
			} else {
				info.WriteString(t.I18nBot("tgbot.messages.expire", "Time=="+time.Unix((inbound.ExpiryTime/1000), 0).Format("2006-01-02 15:04:05")))
			}
			info.WriteString("\r\n")
		}
	}
	return info.String()
}

// getInbounds creates an inline keyboard with all inbounds.
func (t *Tgbot) getInbounds() (*telego.InlineKeyboardMarkup, error) {
	inbounds, err := t.inboundService.GetAllInbounds()
	if err != nil {
		logger.Warning("GetAllInbounds run failed:", err)
		return nil, errors.New(t.I18nBot("tgbot.answers.getInboundsFailed"))
	}

	if len(inbounds) == 0 {
		logger.Warning("No inbounds found")
		return nil, errors.New(t.I18nBot("tgbot.answers.getInboundsFailed"))
	}

	var buttons []telego.InlineKeyboardButton
	for _, inbound := range inbounds {
		status := "❌"
		if inbound.Enable {
			status = "✅"
		}
		callbackData := t.encodeQuery(fmt.Sprintf("%s %d", "get_clients", inbound.Id))
		buttons = append(buttons, tu.InlineKeyboardButton(fmt.Sprintf("%v - %v", inbound.Remark, status)).WithCallbackData(callbackData))
	}

	cols := 1
	if len(buttons) >= 6 {
		cols = 2
	}

	keyboard := tu.InlineKeyboardGrid(tu.InlineKeyboardCols(cols, buttons...))
	return keyboard, nil
}

// getInboundsAddClient creates an inline keyboard for adding clients to inbounds.
func (t *Tgbot) getInboundsAddClient() (*telego.InlineKeyboardMarkup, error) {
	inbounds, err := t.inboundService.GetAllInbounds()
	if err != nil {
		logger.Warning("GetAllInbounds run failed:", err)
		return nil, errors.New(t.I18nBot("tgbot.answers.getInboundsFailed"))
	}

	if len(inbounds) == 0 {
		logger.Warning("No inbounds found")
		return nil, errors.New(t.I18nBot("tgbot.answers.getInboundsFailed"))
	}

	excludedProtocols := map[model.Protocol]bool{
		model.Tunnel:    true,
		model.Mixed:     true,
		model.WireGuard: true,
		model.HTTP:      true,
	}

	var buttons []telego.InlineKeyboardButton
	for _, inbound := range inbounds {
		if excludedProtocols[inbound.Protocol] {
			continue
		}

		status := "❌"
		if inbound.Enable {
			status = "✅"
		}
		callbackData := t.encodeQuery(fmt.Sprintf("%s %d", "add_client_to", inbound.Id))
		buttons = append(buttons, tu.InlineKeyboardButton(fmt.Sprintf("%v - %v", inbound.Remark, status)).WithCallbackData(callbackData))
	}

	cols := 1
	if len(buttons) >= 6 {
		cols = 2
	}

	keyboard := tu.InlineKeyboardGrid(tu.InlineKeyboardCols(cols, buttons...))
	return keyboard, nil
}

// getInboundClients creates an inline keyboard with clients of a specific inbound.
func (t *Tgbot) getInboundClients(id int) (*telego.InlineKeyboardMarkup, error) {
	inbound, err := t.inboundService.GetInbound(id)
	if err != nil {
		logger.Warning("getIboundClients run failed:", err)
		return nil, errors.New(t.I18nBot("tgbot.answers.getInboundsFailed"))
	}
	clients, err := t.inboundService.GetClients(inbound)
	var buttons []telego.InlineKeyboardButton

	if err != nil {
		logger.Warning("GetInboundClients run failed:", err)
		return nil, errors.New(t.I18nBot("tgbot.answers.getInboundsFailed"))
	} else {
		if len(clients) > 0 {
			for _, client := range clients {
				buttons = append(buttons, tu.InlineKeyboardButton(client.Email).WithCallbackData(t.encodeQuery("client_get_usage "+client.Email)))
			}

		} else {
			return nil, errors.New(t.I18nBot("tgbot.answers.getClientsFailed"))
		}

	}
	cols := 0
	if len(buttons) < 6 {
		cols = 3
	} else {
		cols = 2
	}
	keyboard := tu.InlineKeyboardGrid(tu.InlineKeyboardCols(cols, buttons...))

	return keyboard, nil
}

// clientInfoMsg formats client information message based on traffic and flags.
func (t *Tgbot) clientInfoMsg(
	traffic *xray.ClientTraffic,
	printEnabled bool,
	printOnline bool,
	printActive bool,
	printDate bool,
	printTraffic bool,
	printRefreshed bool,
) string {
	now := time.Now().Unix()
	expiryTime := ""
	flag := false
	diff := traffic.ExpiryTime/1000 - now
	if traffic.ExpiryTime == 0 {
		expiryTime = t.I18nBot("tgbot.unlimited")
	} else if diff > 172800 || !traffic.Enable {
		expiryTime = time.Unix((traffic.ExpiryTime / 1000), 0).Format("2006-01-02 15:04:05")
		if diff > 0 {
			days := diff / 86400
			hours := (diff % 86400) / 3600
			minutes := (diff % 3600) / 60
			remainingTime := ""
			if days > 0 {
				remainingTime += fmt.Sprintf("%d %s ", days, t.I18nBot("tgbot.days"))
			}
			if hours > 0 {
				remainingTime += fmt.Sprintf("%d %s ", hours, t.I18nBot("tgbot.hours"))
			}
			if minutes > 0 {
				remainingTime += fmt.Sprintf("%d %s", minutes, t.I18nBot("tgbot.minutes"))
			}
			expiryTime += fmt.Sprintf(" (%s)", remainingTime)
		}
	} else if traffic.ExpiryTime < 0 {
		expiryTime = fmt.Sprintf("%d %s", traffic.ExpiryTime/-86400000, t.I18nBot("tgbot.days"))
		flag = true
	} else {
		expiryTime = fmt.Sprintf("%d %s", diff/3600, t.I18nBot("tgbot.hours"))
		flag = true
	}

	total := ""
	if traffic.Total == 0 {
		total = t.I18nBot("tgbot.unlimited")
	} else {
		total = common.FormatTraffic((traffic.Total))
	}

	enabled := ""
	isEnabled, err := t.inboundService.checkIsEnabledByEmail(traffic.Email)
	if err != nil {
		logger.Warning(err)
		enabled = t.I18nBot("tgbot.wentWrong")
	} else if isEnabled {
		enabled = t.I18nBot("tgbot.messages.yes")
	} else {
		enabled = t.I18nBot("tgbot.messages.no")
	}

	active := ""
	if traffic.Enable {
		active = t.I18nBot("tgbot.messages.yes")
	} else {
		active = t.I18nBot("tgbot.messages.no")
	}

	status := t.I18nBot("tgbot.offline")
	isOnline := false
	if t.xrayService.IsXrayRunning() {
		if slices.Contains(t.xrayService.GetOnlineClients(), traffic.Email) {
			status = t.I18nBot("tgbot.online")
			isOnline = true
		}
	}

	output := ""
	output += t.I18nBot("tgbot.messages.email", "Email=="+traffic.Email)
	if printEnabled {
		output += t.I18nBot("tgbot.messages.enabled", "Enable=="+enabled)
	}
	if printOnline {
		output += t.I18nBot("tgbot.messages.online", "Status=="+status)
		if !isOnline && traffic.LastOnline > 0 {
			output += t.I18nBot("tgbot.messages.lastOnline", "Time=="+time.UnixMilli(traffic.LastOnline).Format("2006-01-02 15:04:05"))
		}
	}
	if printActive {
		output += t.I18nBot("tgbot.messages.active", "Enable=="+active)
	}
	if printDate {
		if flag {
			output += t.I18nBot("tgbot.messages.expireIn", "Time=="+expiryTime)
		} else {
			output += t.I18nBot("tgbot.messages.expire", "Time=="+expiryTime)
		}
	}
	if printTraffic {
		output += t.I18nBot("tgbot.messages.upload", "Upload=="+common.FormatTraffic(traffic.Up))
		output += t.I18nBot("tgbot.messages.download", "Download=="+common.FormatTraffic(traffic.Down))
		output += t.I18nBot("tgbot.messages.total", "UpDown=="+common.FormatTraffic((traffic.Up+traffic.Down)), "Total=="+total)
	}
	if printRefreshed {
		output += t.I18nBot("tgbot.messages.refreshedOn", "Time=="+time.Now().Format("2006-01-02 15:04:05"))
	}

	return output
}

// getClientUsage retrieves and sends client usage information to the chat.
func (t *Tgbot) getClientUsage(chatId int64, tgUserID int64, email ...string) {
	traffics, err := t.inboundService.GetClientTrafficTgBot(tgUserID)
	if err != nil {
		logger.Warning(err)
		msg := t.I18nBot("tgbot.wentWrong")
		t.SendMsgToTgbot(chatId, msg)
		return
	}

	if len(traffics) == 0 {
		t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.answers.askToAddUserId", "TgUserID=="+strconv.FormatInt(tgUserID, 10)))
		return
	}

	output := ""

	if len(traffics) > 0 {
		if len(email) > 0 {
			for _, traffic := range traffics {
				if traffic.Email == email[0] {
					output := t.clientInfoMsg(traffic, true, true, true, true, true, true)
					t.SendMsgToTgbot(chatId, output)
					return
				}
			}
			msg := t.I18nBot("tgbot.noResult")
			t.SendMsgToTgbot(chatId, msg)
			return
		} else {
			for _, traffic := range traffics {
				output += t.clientInfoMsg(traffic, true, true, true, true, true, false)
				output += "\r\n"
			}
		}
	}

	output += t.I18nBot("tgbot.messages.refreshedOn", "Time=="+time.Now().Format("2006-01-02 15:04:05"))
	t.SendMsgToTgbot(chatId, output)
	output = t.I18nBot("tgbot.commands.pleaseChoose")
	t.SendAnswer(chatId, output, false)
}

// searchClientIps searches and sends client IP addresses for the given email.
func (t *Tgbot) searchClientIps(chatId int64, email string, messageID ...int) {
	ips, err := t.inboundService.GetInboundClientIps(email)
	if err != nil || len(ips) == 0 {
		ips = t.I18nBot("tgbot.noIpRecord")
	}

	formattedIps := ips
	if err == nil && len(ips) > 0 {
		type ipWithTimestamp struct {
			IP        string `json:"ip"`
			Timestamp int64  `json:"timestamp"`
		}

		var ipsWithTime []ipWithTimestamp
		if json.Unmarshal([]byte(ips), &ipsWithTime) == nil && len(ipsWithTime) > 0 {
			lines := make([]string, 0, len(ipsWithTime))
			for _, item := range ipsWithTime {
				if item.IP == "" {
					continue
				}
				if item.Timestamp > 0 {
					ts := time.Unix(item.Timestamp, 0).Format("2006-01-02 15:04:05")
					lines = append(lines, fmt.Sprintf("%s (%s)", item.IP, ts))
					continue
				}
				lines = append(lines, item.IP)
			}
			if len(lines) > 0 {
				formattedIps = strings.Join(lines, "\n")
			}
		} else {
			var oldIps []string
			if json.Unmarshal([]byte(ips), &oldIps) == nil && len(oldIps) > 0 {
				formattedIps = strings.Join(oldIps, "\n")
			}
		}
	}

	output := ""
	output += t.I18nBot("tgbot.messages.email", "Email=="+email)
	output += t.I18nBot("tgbot.messages.ips", "IPs=="+formattedIps)
	output += t.I18nBot("tgbot.messages.refreshedOn", "Time=="+time.Now().Format("2006-01-02 15:04:05"))

	inlineKeyboard := tu.InlineKeyboard(
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.refresh")).WithCallbackData(t.encodeQuery("ips_refresh "+email)),
		),
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.clearIPs")).WithCallbackData(t.encodeQuery("clear_ips "+email)),
		),
	)

	if len(messageID) > 0 {
		t.editMessageTgBot(chatId, messageID[0], output, inlineKeyboard)
	} else {
		t.SendMsgToTgbot(chatId, output, inlineKeyboard)
	}
}

// clientTelegramUserInfo retrieves and sends Telegram user info for the client.
// requesterID is the admin who opened this view; it is recorded with
// the issued "select TG user" keyboard (M-10) so only that admin in
// this chat may answer it. Callers on the edit path (messageID set)
// pass 0: no keyboard is issued there.
func (t *Tgbot) clientTelegramUserInfo(chatId int64, email string, requesterID int64, messageID ...int) {
	traffic, client, err := t.inboundService.GetClientByEmail(email)
	if err != nil {
		logger.Warning(err)
		msg := t.I18nBot("tgbot.wentWrong")
		t.SendMsgToTgbot(chatId, msg)
		return
	}
	if client == nil {
		msg := t.I18nBot("tgbot.noResult")
		t.SendMsgToTgbot(chatId, msg)
		return
	}
	tgId := "None"
	if client.TgID != 0 {
		tgId = strconv.FormatInt(client.TgID, 10)
	}

	output := ""
	output += t.I18nBot("tgbot.messages.email", "Email=="+email)
	output += t.I18nBot("tgbot.messages.TGUser", "TelegramID=="+tgId)
	output += t.I18nBot("tgbot.messages.refreshedOn", "Time=="+time.Now().Format("2006-01-02 15:04:05"))

	inlineKeyboard := tu.InlineKeyboard(
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.refresh")).WithCallbackData(t.encodeQuery("tgid_refresh "+email)),
		),
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.removeTGUser")).WithCallbackData(t.encodeQuery("tgid_remove "+email)),
		),
	)

	if len(messageID) > 0 {
		t.editMessageTgBot(chatId, messageID[0], output, inlineKeyboard)
	} else {
		t.SendMsgToTgbot(chatId, output, inlineKeyboard)
		// M-10: the keyboard's RequestID is a random value bound to
		// this admin, chat, and client — never the sequential
		// traffic row id.
		requestUser := telego.KeyboardButtonRequestUsers{
			RequestID: issueUserShareRequest(chatId, requesterID, traffic.Id),
			UserIsBot: new(bool),
		}
		keyboard := tu.Keyboard(
			tu.KeyboardRow(
				tu.KeyboardButton(t.I18nBot("tgbot.buttons.selectTGUser")).WithRequestUsers(&requestUser),
			),
			tu.KeyboardRow(
				tu.KeyboardButton(t.I18nBot("tgbot.buttons.closeKeyboard")),
			),
		).WithIsPersistent().WithResizeKeyboard()
		t.SendMsgToTgbot(chatId, t.I18nBot("tgbot.buttons.selectOneTGUser"), keyboard)
	}
}

// searchClient searches for a client by email and sends the information.
func (t *Tgbot) searchClient(chatId int64, email string, messageID ...int) {
	traffic, err := t.inboundService.GetClientTrafficByEmail(email)
	if err != nil {
		logger.Warning(err)
		msg := t.I18nBot("tgbot.wentWrong")
		t.SendMsgToTgbot(chatId, msg)
		return
	}
	if traffic == nil {
		msg := t.I18nBot("tgbot.noResult")
		t.SendMsgToTgbot(chatId, msg)
		return
	}

	output := t.clientInfoMsg(traffic, true, true, true, true, true, true)

	inlineKeyboard := tu.InlineKeyboard(
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.refresh")).WithCallbackData(t.encodeQuery("client_refresh "+email)),
		),
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.resetTraffic")).WithCallbackData(t.encodeQuery("reset_traffic "+email)),
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.limitTraffic")).WithCallbackData(t.encodeQuery("limit_traffic "+email)),
		),
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.resetExpire")).WithCallbackData(t.encodeQuery("reset_exp "+email)),
		),
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.ipLog")).WithCallbackData(t.encodeQuery("ip_log "+email)),
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.ipLimit")).WithCallbackData(t.encodeQuery("ip_limit "+email)),
		),
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.setTGUser")).WithCallbackData(t.encodeQuery("tg_user "+email)),
		),
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.toggle")).WithCallbackData(t.encodeQuery("toggle_enable "+email)),
		),
	)
	if len(messageID) > 0 {
		t.editMessageTgBot(chatId, messageID[0], output, inlineKeyboard)
	} else {
		t.SendMsgToTgbot(chatId, output, inlineKeyboard)
	}
}

// getCommonClientButtons returns the shared inline keyboard rows for client configuration
func (t *Tgbot) getCommonClientButtons() [][]telego.InlineKeyboardButton {
	return [][]telego.InlineKeyboardButton{
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.limitTraffic")).WithCallbackData("add_client_ch_default_traffic"),
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.resetExpire")).WithCallbackData("add_client_ch_default_exp"),
		),
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.change_comment")).WithCallbackData("add_client_ch_default_comment"),
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.ipLimit")).WithCallbackData("add_client_ch_default_ip_limit"),
		),
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.submitDisable")).WithCallbackData("add_client_submit_disable"),
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.submitEnable")).WithCallbackData("add_client_submit_enable"),
		),
		tu.InlineKeyboardRow(
			tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.cancel")).WithCallbackData("add_client_cancel"),
		),
	}
}

// addClient handles the process of adding a new client to an inbound.
func (t *Tgbot) addClient(sess *addClientSession, chatId int64, msg string, messageID ...int) {
	inbound, err := t.inboundService.GetInbound(sess.inboundID)
	if err != nil {
		t.SendMsgToTgbot(chatId, err.Error())
		return
	}

	protocol := inbound.Protocol

	var protocolRows [][]telego.InlineKeyboardButton
	switch protocol {
	case model.VMESS, model.VLESS:
		protocolRows = [][]telego.InlineKeyboardButton{
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.change_email")).WithCallbackData("add_client_ch_default_email"),
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.change_id")).WithCallbackData("add_client_ch_default_id"),
			),
		}
	case model.Trojan:
		protocolRows = [][]telego.InlineKeyboardButton{
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.change_email")).WithCallbackData("add_client_ch_default_email"),
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.change_password")).WithCallbackData("add_client_ch_default_pass_tr"),
			),
		}
	case model.Shadowsocks:
		protocolRows = [][]telego.InlineKeyboardButton{
			tu.InlineKeyboardRow(
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.change_email")).WithCallbackData("add_client_ch_default_email"),
				tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.change_password")).WithCallbackData("add_client_ch_default_pass_sh"),
			),
		}
	}

	commonRows := t.getCommonClientButtons()
	inlineKeyboard := tu.InlineKeyboard(append(protocolRows, commonRows...)...)

	if len(messageID) > 0 {
		t.editMessageTgBot(chatId, messageID[0], msg, inlineKeyboard)
	} else {
		t.SendMsgToTgbot(chatId, msg, inlineKeyboard)
	}

}

// searchInbound searches for inbounds by remark and sends the results.
func (t *Tgbot) searchInbound(chatId int64, remark string) {
	inbounds, err := t.inboundService.SearchInbounds(remark)
	if err != nil {
		logger.Warning(err)
		msg := t.I18nBot("tgbot.wentWrong")
		t.SendMsgToTgbot(chatId, msg)
		return
	}
	if len(inbounds) == 0 {
		msg := t.I18nBot("tgbot.noInbounds")
		t.SendMsgToTgbot(chatId, msg)
		return
	}

	for _, inbound := range inbounds {
		info := ""
		info += t.I18nBot("tgbot.messages.inbound", "Remark=="+inbound.Remark)
		info += t.I18nBot("tgbot.messages.port", "Port=="+strconv.Itoa(inbound.Port))
		info += t.I18nBot("tgbot.messages.traffic", "Total=="+common.FormatTraffic((inbound.Up+inbound.Down)), "Upload=="+common.FormatTraffic(inbound.Up), "Download=="+common.FormatTraffic(inbound.Down))

		if inbound.ExpiryTime == 0 {
			info += t.I18nBot("tgbot.messages.expire", "Time=="+t.I18nBot("tgbot.unlimited"))
		} else {
			info += t.I18nBot("tgbot.messages.expire", "Time=="+time.Unix((inbound.ExpiryTime/1000), 0).Format("2006-01-02 15:04:05"))
		}
		t.SendMsgToTgbot(chatId, info)

		if len(inbound.ClientStats) > 0 {
			var output strings.Builder
			for _, traffic := range inbound.ClientStats {
				output.WriteString(t.clientInfoMsg(&traffic, true, true, true, true, true, true))
			}
			t.SendMsgToTgbot(chatId, output.String())
		}
	}
}

// getExhausted retrieves and sends information about exhausted clients.
func (t *Tgbot) getExhausted(chatId int64) {
	trDiff := int64(0)
	exDiff := int64(0)
	now := time.Now().Unix() * 1000
	var exhaustedInbounds []model.Inbound
	var exhaustedClients []xray.ClientTraffic
	var disabledInbounds []model.Inbound
	var disabledClients []xray.ClientTraffic

	TrafficThreshold, err := t.settingService.GetTrafficDiff()
	if err == nil && TrafficThreshold > 0 {
		trDiff = int64(TrafficThreshold) * 1073741824
	}
	ExpireThreshold, err := t.settingService.GetExpireDiff()
	if err == nil && ExpireThreshold > 0 {
		exDiff = int64(ExpireThreshold) * 86400000
	}
	inbounds, err := t.inboundService.GetAllInbounds()
	if err != nil {
		logger.Warning("Unable to load Inbounds", err)
	}

	for _, inbound := range inbounds {
		if inbound.Enable {
			if (inbound.ExpiryTime > 0 && (inbound.ExpiryTime-now < exDiff)) ||
				(inbound.Total > 0 && (inbound.Total-(inbound.Up+inbound.Down) < trDiff)) {
				exhaustedInbounds = append(exhaustedInbounds, *inbound)
			}
			if len(inbound.ClientStats) > 0 {
				for _, client := range inbound.ClientStats {
					if client.Enable {
						if (client.ExpiryTime > 0 && (client.ExpiryTime-now < exDiff)) ||
							(client.Total > 0 && (client.Total-(client.Up+client.Down) < trDiff)) {
							exhaustedClients = append(exhaustedClients, client)
						}
					} else {
						disabledClients = append(disabledClients, client)
					}
				}
			}
		} else {
			disabledInbounds = append(disabledInbounds, *inbound)
		}
	}

	// Inbounds
	output := ""
	output += t.I18nBot("tgbot.messages.exhaustedCount", "Type=="+t.I18nBot("tgbot.inbounds"))
	output += t.I18nBot("tgbot.messages.disabled", "Disabled=="+strconv.Itoa(len(disabledInbounds)))
	output += t.I18nBot("tgbot.messages.depleteSoon", "Deplete=="+strconv.Itoa(len(exhaustedInbounds)))

	if len(exhaustedInbounds) > 0 {
		output += t.I18nBot("tgbot.messages.depleteSoon", "Deplete=="+t.I18nBot("tgbot.inbounds"))

		for _, inbound := range exhaustedInbounds {
			output += t.I18nBot("tgbot.messages.inbound", "Remark=="+inbound.Remark)
			output += t.I18nBot("tgbot.messages.port", "Port=="+strconv.Itoa(inbound.Port))
			output += t.I18nBot("tgbot.messages.traffic", "Total=="+common.FormatTraffic((inbound.Up+inbound.Down)), "Upload=="+common.FormatTraffic(inbound.Up), "Download=="+common.FormatTraffic(inbound.Down))
			if inbound.ExpiryTime == 0 {
				output += t.I18nBot("tgbot.messages.expire", "Time=="+t.I18nBot("tgbot.unlimited"))
			} else {
				output += t.I18nBot("tgbot.messages.expire", "Time=="+time.Unix((inbound.ExpiryTime/1000), 0).Format("2006-01-02 15:04:05"))
			}
			output += "\r\n"
		}
	}

	// Clients
	exhaustedCC := len(exhaustedClients)
	output += t.I18nBot("tgbot.messages.exhaustedCount", "Type=="+t.I18nBot("tgbot.clients"))
	output += t.I18nBot("tgbot.messages.disabled", "Disabled=="+strconv.Itoa(len(disabledClients)))
	output += t.I18nBot("tgbot.messages.depleteSoon", "Deplete=="+strconv.Itoa(exhaustedCC))

	if exhaustedCC > 0 {
		output += t.I18nBot("tgbot.messages.depleteSoon", "Deplete=="+t.I18nBot("tgbot.clients"))
		var buttons []telego.InlineKeyboardButton
		for _, traffic := range exhaustedClients {
			output += t.clientInfoMsg(&traffic, true, false, false, true, true, false)
			output += "\r\n"
			buttons = append(buttons, tu.InlineKeyboardButton(traffic.Email).WithCallbackData(t.encodeQuery("client_get_usage "+traffic.Email)))
		}
		cols := 0
		if exhaustedCC < 11 {
			cols = 1
		} else {
			cols = 2
		}
		output += t.I18nBot("tgbot.messages.refreshedOn", "Time=="+time.Now().Format("2006-01-02 15:04:05"))
		keyboard := tu.InlineKeyboardGrid(tu.InlineKeyboardCols(cols, buttons...))
		t.SendMsgToTgbot(chatId, output, keyboard)
	} else {
		output += t.I18nBot("tgbot.messages.refreshedOn", "Time=="+time.Now().Format("2006-01-02 15:04:05"))
		t.SendMsgToTgbot(chatId, output)
	}
}

// notifyExhausted sends notifications for exhausted clients.
func (t *Tgbot) notifyExhausted() {
	trDiff := int64(0)
	exDiff := int64(0)
	now := time.Now().Unix() * 1000

	TrafficThreshold, err := t.settingService.GetTrafficDiff()
	if err == nil && TrafficThreshold > 0 {
		trDiff = int64(TrafficThreshold) * 1073741824
	}
	ExpireThreshold, err := t.settingService.GetExpireDiff()
	if err == nil && ExpireThreshold > 0 {
		exDiff = int64(ExpireThreshold) * 86400000
	}
	inbounds, err := t.inboundService.GetAllInbounds()
	if err != nil {
		logger.Warning("Unable to load Inbounds", err)
	}

	var chatIDsDone []int64
	for _, inbound := range inbounds {
		if inbound.Enable {
			if len(inbound.ClientStats) > 0 {
				clients, err := t.inboundService.GetClients(inbound)
				if err == nil {
					for _, client := range clients {
						if client.TgID != 0 {
							chatID := client.TgID
							if !int64Contains(chatIDsDone, chatID) && !checkAdmin(chatID) {
								var disabledClients []xray.ClientTraffic
								var exhaustedClients []xray.ClientTraffic
								traffics, err := t.inboundService.GetClientTrafficTgBot(client.TgID)
								if err == nil && len(traffics) > 0 {
									output := t.I18nBot("tgbot.messages.exhaustedCount", "Type=="+t.I18nBot("tgbot.clients"))
									for _, traffic := range traffics {
										if traffic.Enable {
											if (traffic.ExpiryTime > 0 && (traffic.ExpiryTime-now < exDiff)) ||
												(traffic.Total > 0 && (traffic.Total-(traffic.Up+traffic.Down) < trDiff)) {
												exhaustedClients = append(exhaustedClients, *traffic)
											}
										} else {
											disabledClients = append(disabledClients, *traffic)
										}
									}
									if len(exhaustedClients) > 0 {
										output += t.I18nBot("tgbot.messages.disabled", "Disabled=="+strconv.Itoa(len(disabledClients)))
										if len(disabledClients) > 0 {
											output += t.I18nBot("tgbot.clients") + ":\r\n"
											for _, traffic := range disabledClients {
												output += " " + traffic.Email
											}
											output += "\r\n"
										}
										output += "\r\n"
										output += t.I18nBot("tgbot.messages.depleteSoon", "Deplete=="+strconv.Itoa(len(exhaustedClients)))
										for _, traffic := range exhaustedClients {
											output += t.clientInfoMsg(&traffic, true, false, false, true, true, false)
											output += "\r\n"
										}
										t.SendMsgToTgbot(chatID, output)
									}
									chatIDsDone = append(chatIDsDone, chatID)
								}
							}
						}
					}
				}
			}
		}
	}
}

// int64Contains checks if an int64 slice contains a specific item.
func int64Contains(slice []int64, item int64) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// onlineClients retrieves and sends information about online clients.
func (t *Tgbot) onlineClients(chatId int64, messageID ...int) {
	if !t.xrayService.IsXrayRunning() {
		return
	}

	onlines := t.xrayService.GetOnlineClients()
	onlinesCount := len(onlines)
	output := t.I18nBot("tgbot.messages.onlinesCount", "Count=="+fmt.Sprint(onlinesCount))
	keyboard := tu.InlineKeyboard(tu.InlineKeyboardRow(
		tu.InlineKeyboardButton(t.I18nBot("tgbot.buttons.refresh")).WithCallbackData(t.encodeQuery("onlines_refresh"))))

	if onlinesCount > 0 {
		var buttons []telego.InlineKeyboardButton
		for _, online := range onlines {
			buttons = append(buttons, tu.InlineKeyboardButton(online).WithCallbackData(t.encodeQuery("client_get_usage "+online)))
		}
		cols := 0
		if onlinesCount < 21 {
			cols = 2
		} else if onlinesCount < 61 {
			cols = 3
		} else {
			cols = 4
		}
		keyboard.InlineKeyboard = append(keyboard.InlineKeyboard, tu.InlineKeyboardCols(cols, buttons...)...)
	}

	if len(messageID) > 0 {
		t.editMessageTgBot(chatId, messageID[0], output, keyboard)
	} else {
		t.SendMsgToTgbot(chatId, output, keyboard)
	}
}

// sendBackup sends a backup of the database and configuration files.
func (t *Tgbot) sendBackup(chatId int64) {
	// M-9: like every other direct bot.Send* helper, refuse to run
	// when the bot is not up; without this a nil bot panics.
	if bot == nil || !isRunning.Load() {
		return
	}
	// The backup contains the full database and config: only send it to an
	// admin chat. In a private chat the chat ID equals the admin user ID,
	// so this also refuses to post a backup into a group chat.
	if !checkAdmin(chatId) {
		logger.Warning("sendBackup called for non-admin chat, refusing: ", chatId)
		return
	}

	output := t.I18nBot("tgbot.messages.backupTime", "Time=="+time.Now().Format("2006-01-02 15:04:05"))
	t.SendMsgToTgbot(chatId, output)

	// Update by manually trigger a checkpoint operation
	err := database.Checkpoint()
	if err != nil {
		logger.Error("Error in trigger a checkpoint operation: ", err)
	}

	// Send database backup
	file, err := os.Open(config.GetDBPath())
	if err == nil {
		defer file.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		document := tu.Document(
			tu.ID(chatId),
			tu.File(file),
		)
		_, err = bot.SendDocument(ctx, document)
		if err != nil {
			logger.Error("Error in uploading backup: ", err)
		}
	} else {
		logger.Error("Error in opening db file for backup: ", err)
	}

	// Small delay between file sends
	time.Sleep(500 * time.Millisecond)

	// Send config.json backup
	file, err = os.Open(xray.GetConfigPath())
	if err == nil {
		defer file.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		document := tu.Document(
			tu.ID(chatId),
			tu.File(file),
		)
		_, err = bot.SendDocument(ctx, document)
		if err != nil {
			logger.Error("Error in uploading config.json: ", err)
		}
	} else {
		logger.Error("Error in opening config.json file for backup: ", err)
	}
}

// sendBanLogs sends the ban logs to the specified chat.
func (t *Tgbot) sendBanLogs(chatId int64, dt bool) {
	// M-9: same nil-bot guard as sendBackup.
	if bot == nil || !isRunning.Load() {
		return
	}
	if dt {
		output := t.I18nBot("tgbot.messages.datetime", "DateTime=="+time.Now().Format("2006-01-02 15:04:05"))
		t.SendMsgToTgbot(chatId, output)
	}

	file, err := os.Open(xray.GetIPLimitBannedPrevLogPath())
	if err == nil {
		// Check if the file is non-empty before attempting to upload
		fileInfo, _ := file.Stat()
		if fileInfo.Size() > 0 {
			document := tu.Document(
				tu.ID(chatId),
				tu.File(file),
			)
			_, err = bot.SendDocument(context.Background(), document)
			if err != nil {
				logger.Error("Error in uploading IPLimitBannedPrevLog: ", err)
			}
		} else {
			logger.Warning("IPLimitBannedPrevLog file is empty, not uploading.")
		}
		file.Close()
	} else {
		logger.Error("Error in opening IPLimitBannedPrevLog file for backup: ", err)
	}

	file, err = os.Open(xray.GetIPLimitBannedLogPath())
	if err == nil {
		// Check if the file is non-empty before attempting to upload
		fileInfo, _ := file.Stat()
		if fileInfo.Size() > 0 {
			document := tu.Document(
				tu.ID(chatId),
				tu.File(file),
			)
			_, err = bot.SendDocument(context.Background(), document)
			if err != nil {
				logger.Error("Error in uploading IPLimitBannedLog: ", err)
			}
		} else {
			logger.Warning("IPLimitBannedLog file is empty, not uploading.")
		}
		file.Close()
	} else {
		logger.Error("Error in opening IPLimitBannedLog file for backup: ", err)
	}
}

// sendCallbackAnswerTgBot answers a callback query with a message.
func (t *Tgbot) sendCallbackAnswerTgBot(id string, message string) {
	if bot == nil || !isRunning.Load() {
		return
	}
	params := telego.AnswerCallbackQueryParams{
		CallbackQueryID: id,
		Text:            message,
	}
	if err := bot.AnswerCallbackQuery(context.Background(), &params); err != nil {
		logger.Warning(err)
	}
}

// editMessageCallbackTgBot edits the reply markup of a message.
func (t *Tgbot) editMessageCallbackTgBot(chatId int64, messageID int, inlineKeyboard *telego.InlineKeyboardMarkup) {
	if bot == nil || !isRunning.Load() {
		return
	}
	params := telego.EditMessageReplyMarkupParams{
		ChatID:      tu.ID(chatId),
		MessageID:   messageID,
		ReplyMarkup: inlineKeyboard,
	}
	if _, err := bot.EditMessageReplyMarkup(context.Background(), &params); err != nil {
		logger.Warning(err)
	}
}

// editMessageTgBot edits the text and reply markup of a message.
func (t *Tgbot) editMessageTgBot(chatId int64, messageID int, text string, inlineKeyboard ...*telego.InlineKeyboardMarkup) {
	if bot == nil || !isRunning.Load() {
		return
	}
	params := telego.EditMessageTextParams{
		ChatID:    tu.ID(chatId),
		MessageID: messageID,
		Text:      text,
		ParseMode: "HTML",
	}
	if len(inlineKeyboard) > 0 {
		params.ReplyMarkup = inlineKeyboard[0]
	}
	if _, err := bot.EditMessageText(context.Background(), &params); err != nil {
		logger.Warning(err)
	}
}

// SendMsgToTgbotDeleteAfter sends a message and deletes it after a
// specified delay. The timer only deletes the message: it must never
// touch the add-client input state. The state of a flow is updated
// synchronously by the input handler and the callback handler; a timer
// armed by an earlier prompt would otherwise fire after the user has
// already moved on to the next step and silently discard that step,
// so the next text input is ignored.
func (t *Tgbot) SendMsgToTgbotDeleteAfter(chatId int64, msg string, delayInSeconds int, replyMarkup ...telego.ReplyMarkup) {
	if bot == nil || !isRunning.Load() {
		return
	}
	// Determine if replyMarkup was passed; otherwise, set it to nil
	var replyMarkupParam telego.ReplyMarkup
	if len(replyMarkup) > 0 {
		replyMarkupParam = replyMarkup[0] // Use the first element
	}

	// Send the message
	sentMsg, err := bot.SendMessage(context.Background(), &telego.SendMessageParams{
		ChatID:      tu.ID(chatId),
		Text:        msg,
		ReplyMarkup: replyMarkupParam, // Use the correct replyMarkup value
	})
	if err != nil {
		logger.Warning("Failed to send message:", err)
		return
	}

	// Delete the sent message after the specified number of seconds.
	// The timer deletes only the message; it deliberately does not
	// clear the add-client input state (see the function comment).
	go func() {
		// N-4: recover so a panic in the delayed delete cannot kill
		// the panel process.
		defer func() {
			if r := recover(); r != nil {
				logger.Error("TgBot delayed delete panic recovered: ", r)
			}
		}()
		time.Sleep(time.Duration(delayInSeconds) * time.Second) // Wait for the specified delay
		t.deleteMessageTgBot(chatId, sentMsg.MessageID)         // Delete the message
	}()
}

// deleteMessageTgBot deletes a message from the chat.
func (t *Tgbot) deleteMessageTgBot(chatId int64, messageID int) {
	if bot == nil || !isRunning.Load() {
		return
	}
	params := telego.DeleteMessageParams{
		ChatID:    tu.ID(chatId),
		MessageID: messageID,
	}
	if err := bot.DeleteMessage(context.Background(), &params); err != nil {
		logger.Warning("Failed to delete message:", err)
	} else {
		logger.Info("Message deleted successfully")
	}
}

// isSingleWord checks if the text contains only a single word.
func (t *Tgbot) isSingleWord(text string) bool {
	text = strings.TrimSpace(text)
	re := regexp.MustCompile(`\s+`)
	return re.MatchString(text)
}
