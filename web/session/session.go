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
)

const (
	loginUserKey = "LOGIN_USER"
	// loginSessionKey holds the random session ID of the current login
	// inside the signed session cookie. The matching server-side row in
	// the login_sessions table is what makes a session revocable: logout
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

func init() {
	gob.Register(model.User{})
}

// SetLoginUser stores the authenticated user in the session and persists it.
// gin-contrib/sessions does not auto-save; callers that forget Save() leave
// the cookie out of sync with server state — this helper avoids that pitfall.
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
		Id:        hashSessionID(id),
		UserId:    user.Id,
		Username:  user.Username,
		ExpiresAt: time.Now().Add(sessionTTL()),
	}
	if err := db.Create(row).Error; err != nil {
		return err
	}
	s.Set(loginUserKey, *user)
	s.Set(loginSessionKey, id)
	return s.Save()
}

// GetLoginUser retrieves the authenticated user from the session.
// Returns nil if no user is logged in or if the session data is invalid.
func GetLoginUser(c *gin.Context) *model.User {
	s := sessions.Default(c)
	obj := s.Get(loginUserKey)
	if obj == nil {
		return nil
	}
	user, ok := obj.(model.User)
	if !ok {
		// Stale or incompatible session payload — wipe and persist immediately
		// so subsequent requests don't keep hitting the same broken cookie.
		s.Delete(loginUserKey)
		if err := s.Save(); err != nil {
			logger.Warning("session: failed to drop stale user payload:", err)
		}
		return nil
	}
	// M1: the session only proves who logged in, not that the credentials
	// are still current. Re-validate against the database on every request:
	// if the user was deleted or the password hash changed (password change),
	// the old cookie stops working immediately.
	if user.Id == 0 {
		return nil
	}
	fresh := &model.User{}
	if err := database.GetDB().Model(model.User{}).Where("id = ?", user.Id).First(fresh).Error; err != nil {
		return nil
	}
	if fresh.Password != user.Password {
		return nil
	}
	// The session must also exist server-side and not be expired.
	// Logout deletes the row, so a replayed cookie stops working even
	// though its signature is still valid — clearing the browser cookie
	// alone cannot stop a stolen copy. Cookies issued before
	// server-side sessions existed carry no session ID and are rejected
	// here, so users log in once after the upgrade.
	id, ok := s.Get(loginSessionKey).(string)
	if !ok || id == "" {
		return nil
	}
	var row model.LoginSession
	if err := database.GetDB().Where("id = ?", hashSessionID(id)).First(&row).Error; err != nil {
		return nil
	}
	if row.UserId != user.Id {
		return nil
	}
	if !row.ExpiresAt.After(time.Now()) {
		database.GetDB().Delete(&model.LoginSession{}, "id = ?", row.Id)
		return nil
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
