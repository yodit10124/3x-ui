// Package session provides session management utilities for the 3x-ui web panel.
// It handles user authentication state, login sessions, and session storage using Gin sessions.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	// loginUserKey is retained ONLY to detect cookies issued before
	// the user object was removed from the cookie (see GetLoginUser):
	// an old-format cookie still carries the full user, including the
	// bcrypt password hash. It is revoked on sight and the caller must
	// log in again for a cookie that holds only the session ID. New
	// cookies never contain this key.
	loginUserKey = "LOGIN_USER"
	// loginSessionKey holds the random session ID of the current login
	// inside the signed session cookie. It is the ONLY thing the cookie
	// carries: the user record, password hash and permissions live
	// server-side (the login_sessions row plus the users table) and are
	// looked up on every request. The signature only proves the cookie
	// was not tampered with — anyone holding it could still read its
	// contents — so nothing sensitive may be stored in it. The matching
	// server-side row is what makes a session revocable: logout
	// deletes the row, so replaying the cookie afterwards fails even
	// though the cookie signature is still valid.
	loginSessionKey = "LOGIN_SESSION_ID"
	// defaultSessionMaxAgeMinutes matches the sessionMaxAge settings
	// default (360 minutes); SetSessionMaxAge overwrites it at startup.
	defaultSessionMaxAgeMinutes = 360
)

// secureCookie mirrors the Secure attribute of the session cookie created
// at login. Set once at startup by web.initRouter (same decision as the
// login cookie) so ClearSession can delete the cookie with identical
// attributes; a Secure cookie deleted without Secure would survive in
// the browser. Guarded by an atomic value because the web server reads it
// from request goroutines.
var secureCookie atomic.Bool

// SetSecureCookie records whether session cookies carry the Secure flag.
// Called once during router setup; later calls (e.g. a settings change
// followed by a panel restart) simply overwrite it.
func SetSecureCookie(secure bool) {
	secureCookie.Store(secure)
}

// SecureCookie reports the flag recorded by SetSecureCookie.
func SecureCookie() bool {
	return secureCookie.Load()
}

// sessionMaxAgeMinutes mirrors the session cookie lifetime configured in
// initRouter (same value as the cookie MaxAge). Guarded by an atomic
// value because logins happen on request goroutines.
var sessionMaxAgeMinutes atomic.Int64

// SetSessionMaxAge records the login-session lifetime in minutes. Called
// once during router setup; later calls simply overwrite it. A
// non-positive value leaves the default (360 minutes) in place.
func SetSessionMaxAge(minutes int) {
	if minutes > 0 {
		sessionMaxAgeMinutes.Store(int64(minutes))
	}
}

func sessionTTL() time.Duration {
	minutes := sessionMaxAgeMinutes.Load()
	if minutes <= 0 {
		minutes = defaultSessionMaxAgeMinutes
	}
	return time.Duration(minutes) * time.Minute
}

// newSessionID returns an unpredictable random session ID (256 bits from
// crypto/rand). A fresh ID is generated on every login, so a session
// cannot be fixed by planting a known value before authentication.
func newSessionID() (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// hashSessionID is the value stored in the database for a session ID.
// The raw ID only ever travels inside the signed cookie, so a database
// dump alone yields no usable session.
func hashSessionID(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:])
}

// revokeSessionRow deletes the server-side record of one session. The
// cookie keeps validating against its signature, but without the row the
// session is dead.
func revokeSessionRow(id string) error {
	return database.GetDB().Delete(&model.LoginSession{}, "id = ?", hashSessionID(id)).Error
}

// RevokeAllSessions deletes every server-side session of a user, e.g. on
// a password change. The current browser gets a fresh session afterwards
// (see updateUser), other browsers are logged out at once.
func RevokeAllSessions(userID int) error {
	return database.GetDB().Delete(&model.LoginSession{}, "user_id = ?", userID).Error
}

// GetSessionID returns the random session ID of the current login, as
// stored in the signed session cookie. Empty when the request carries no
// server-side session (anonymous, or a cookie issued before sessions
// became server-side). The WebSocket upgrade binds the connection to
// this ID so logout can close it.
func GetSessionID(c *gin.Context) string {
	if c == nil {
		return ""
	}
	id, _ := sessions.Default(c).Get(loginSessionKey).(string)
	return id
}

// lookupSessionRow returns the server-side record for a session ID.
func lookupSessionRow(id string) (model.LoginSession, error) {
	var row model.LoginSession
	err := database.GetDB().Where("id = ?", hashSessionID(id)).First(&row).Error
	return row, err
}

// ValidateSessionID checks a session without a gin context, for the
// WebSocket hub sweeper: the row must exist, belong to the user, be
// unexpired, the user must still exist, and the password hash must be
// unchanged since the session was created. It enforces exactly the same
// validity as HTTP auth (see GetLoginUser), so a live connection dies on
// logout, expiry, password change or user deletion — at most one sweep
// interval after the event. A database error is NOT proof of revocation:
// it keeps the connection (and logs), because a transient DB hiccup must
// not drop every live WebSocket at once.
func ValidateSessionID(sessionID string, userID int) bool {
	if sessionID == "" || userID == 0 {
		return false
	}
	row, err := lookupSessionRow(sessionID)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false
		}
		logger.Warning("session: failed to validate session:", err)
		return true
	}
	if row.UserId != userID || !row.ExpiresAt.After(time.Now()) {
		return false
	}
	fresh := &model.User{}
	if err := database.GetDB().Model(model.User{}).Where("id = ?", userID).First(fresh).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false
		}
		logger.Warning("session: failed to validate session user:", err)
		return true
	}
	return fresh.Password == row.PasswordHash
}

func init() {
	// Kept so cookies issued before the user object was removed from
	// the cookie still decode: GetLoginUser must be able to recognise
	// (and revoke) them instead of failing the whole session load.
	gob.Register(model.User{})
}

// SetLoginUser creates a server-side session for the authenticated user
// and stores only its random session ID in the cookie.
// gin-contrib/sessions does not auto-save; callers that forget Save()
// leave the cookie out of sync with server state — this helper avoids
// that pitfall.
//
// A fresh random session ID is generated on every call and recorded
// server-side with its expiry, so the session can later be revoked
// individually (logout deletes the row; see ClearSession). If a previous
// session ID is already present (re-login, or the password-change
// refresh), its row is revoked first so no orphan rows accumulate. If
// the row cannot be created the login fails closed: no cookie is saved.
func SetLoginUser(c *gin.Context, user *model.User) error {
	if user == nil {
		return nil
	}
	s := sessions.Default(c)
	if old, ok := s.Get(loginSessionKey).(string); ok && old != "" {
		if err := revokeSessionRow(old); err != nil {
			logger.Warning("session: failed to revoke previous session:", err)
		}
	}
	id, err := newSessionID()
	if err != nil {
		return err
	}
	db := database.GetDB()
	// Best-effort cleanup of expired rows keeps the table small.
	db.Where("expires_at < ?", time.Now()).Delete(&model.LoginSession{})
	row := &model.LoginSession{
		Id:           hashSessionID(id),
		UserId:       user.Id,
		Username:     user.Username,
		PasswordHash: user.Password,
		ExpiresAt:    time.Now().Add(sessionTTL()),
	}
	if err := db.Create(row).Error; err != nil {
		return err
	}
	s.Set(loginSessionKey, id)
	return s.Save()
}

// GetLoginUser retrieves the authenticated user for the request.
//
// The cookie holds only the unpredictable random session ID. The user
// record, password hash and permissions live server-side — the
// login_sessions row plus the users table — and are looked up on every
// request, so a stolen cookie yields no password hash for offline
// guessing (the signature only proves the cookie was not tampered with;
// it never hid its contents). Returns nil when the request carries no
// session, the row is missing or expired, the user is gone, or the
// password hash changed since the session was created (password
// change revokes the row; see RevokeAllSessions).
func GetLoginUser(c *gin.Context) *model.User {
	s := sessions.Default(c)
	// Old-format cookies carry the full user object, including the
	// bcrypt hash. Revoke the session on sight and force a fresh login,
	// which issues a cookie holding only the session ID.
	if s.Get(loginUserKey) != nil {
		if id, ok := s.Get(loginSessionKey).(string); ok && id != "" {
			_ = revokeSessionRow(id)
		}
		return nil
	}
	// The session must exist server-side and not be expired. Logout
	// deletes the row, so a replayed cookie stops working even though
	// its signature is still valid — clearing the browser cookie alone
	// cannot stop a stolen copy. Cookies issued before server-side
	// sessions existed carry no session ID and are rejected here, so
	// users log in once after the upgrade.
	id, ok := s.Get(loginSessionKey).(string)
	if !ok || id == "" {
		return nil
	}
	row, err := lookupSessionRow(id)
	if err != nil {
		return nil
	}
	if !row.ExpiresAt.After(time.Now()) {
		database.GetDB().Delete(&model.LoginSession{}, "id = ?", row.Id)
		return nil
	}
	// The session only proves who logged in, not that the credentials
	// are still current. Re-validate against the database on every
	// request: if the user was deleted or the password hash changed
	// (password change), the old cookie stops working immediately.
	// The hash comparison uses the row's recorded hash, not anything
	// from the cookie.
	fresh := &model.User{}
	if err := database.GetDB().Model(model.User{}).Where("id = ?", row.UserId).First(fresh).Error; err != nil {
		return nil
	}
	if row.PasswordHash != "" && fresh.Password != row.PasswordHash {
		return nil
	}
	// Sessions created before the password-hash column existed carry an
	// empty hash; backfill once from the current hash so the WebSocket
	// sweeper accepts them. (The WebSocket upgrade request backfills
	// too, before the connection is registered.)
	if row.PasswordHash == "" {
		if err := database.GetDB().Model(&model.LoginSession{}).Where("id = ?", row.Id).Update("password_hash", fresh.Password).Error; err != nil {
			logger.Warning("session: failed to backfill session password hash:", err)
		}
	}
	return fresh
}

// IsLogin checks if a user is currently authenticated in the session.
func IsLogin(c *gin.Context) bool {
	return GetLoginUser(c) != nil
}

// ClearSession invalidates the session and tells the browser to drop the cookie.
// The cookie attributes (Path/HttpOnly/SameSite/Secure) must mirror those used when
// the cookie was created or browsers will keep it.
//
// Revocation happens server-side first: the session row is deleted, so a
// copy of the cookie stolen before logout cannot be replayed. Only the
// current session is revoked; other sessions of the same user keep
// working. A logout must never rotate the global cookie-signing secret
// to achieve this — that would kill every user's session at once.
func ClearSession(c *gin.Context) error {
	s := sessions.Default(c)
	if id, ok := s.Get(loginSessionKey).(string); ok && id != "" {
		if err := revokeSessionRow(id); err != nil {
			logger.Warning("session: failed to revoke session on logout:", err)
		}
	}
	s.Clear()
	cookiePath := c.GetString("base_path")
	if cookiePath == "" {
		cookiePath = "/"
	}
	s.Options(sessions.Options{
		Path:     cookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   SecureCookie(),
		SameSite: http.SameSiteLaxMode,
	})
	return s.Save()
}
