package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
)

// TestUpdateFirstUserRevokesSessions: the CLI password change
// (x-ui setting -password) must revoke every server-side session of
// the user, the same way the web password change does. Otherwise a
// session issued under the old password would keep working until its
// next request hit the password-hash comparison.
func TestUpdateFirstUserRevokesSessions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })

	us := &UserService{}
	if err := us.UpdateFirstUser("admin", "admin"); err != nil {
		t.Fatalf("create first user: %v", err)
	}
	user, err := us.GetFirstUser()
	if err != nil {
		t.Fatalf("read first user: %v", err)
	}

	// A live session issued under the old password.
	row := &model.LoginSession{
		Id:           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		UserId:       user.Id,
		Username:     user.Username,
		PasswordHash: user.Password,
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	if err := database.GetDB().Create(row).Error; err != nil {
		t.Fatalf("create session row: %v", err)
	}

	// CLI password change.
	if err := us.UpdateFirstUser("admin", "newpassword"); err != nil {
		t.Fatalf("update first user: %v", err)
	}
	var count int64
	if err := database.GetDB().Model(&model.LoginSession{}).Count(&count).Error; err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if count != 0 {
		t.Fatalf("sessions %d after CLI password change, want 0 (revoked)", count)
	}

	// The new password is the one that works now.
	user, err = us.GetFirstUser()
	if err != nil {
		t.Fatalf("read first user after change: %v", err)
	}
	if !crypto.CheckPasswordHash(user.Password, "newpassword") {
		t.Fatal("password was not changed to the new one")
	}
}

// TestUpdateUserKeepsTwoFactorEnabled (M-2): a web password change must
// not silently disable two-factor authentication or clear its token.
func TestUpdateUserKeepsTwoFactorEnabled(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })

	us := &UserService{}
	if err := us.UpdateFirstUser("admin", "admin"); err != nil {
		t.Fatalf("create first user: %v", err)
	}
	user, err := us.GetFirstUser()
	if err != nil {
		t.Fatalf("read first user: %v", err)
	}

	ss := &SettingService{}
	if err := ss.SetTwoFactorEnable(true); err != nil {
		t.Fatalf("enable 2FA: %v", err)
	}
	if err := ss.SetTwoFactorToken("test-2fa-token"); err != nil {
		t.Fatalf("set 2FA token: %v", err)
	}

	if _, err := us.UpdateUser(user.Id, "admin", "newpassword"); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	enabled, err := ss.GetTwoFactorEnable()
	if err != nil {
		t.Fatalf("read 2FA enable: %v", err)
	}
	if !enabled {
		t.Fatal("2FA was disabled by a password change, want it kept enabled")
	}
	token, err := ss.GetTwoFactorToken()
	if err != nil {
		t.Fatalf("read 2FA token: %v", err)
	}
	if token != "test-2fa-token" {
		t.Fatalf("2FA token %q after password change, want %q", token, "test-2fa-token")
	}
}
