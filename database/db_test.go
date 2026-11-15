package database

import (
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
)

// TestInitDBGeneratesRandomAdminPassword: a fresh database started
// directly (no install script) must not contain the well-known admin/admin
// credentials. The admin user still exists, but its stored hash must not
// verify against "admin".
func TestInitDBGeneratesRandomAdminPassword(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { CloseDB() })

	var user model.User
	if err := GetDB().Model(model.User{}).First(&user).Error; err != nil {
		t.Fatalf("read admin user: %v", err)
	}
	if user.Username != "admin" {
		t.Fatalf("username = %q, want admin", user.Username)
	}
	if user.Password == "" || user.Password == "admin" {
		t.Fatal("admin password is empty or stored in plain text")
	}
	if crypto.CheckPasswordHash(user.Password, "admin") {
		t.Fatal("fresh database still accepts the default password admin")
	}
}

// TestInitDBKeepsExistingAdminPassword: a second InitDB on an existing
// database must not change the admin credentials.
func TestInitDBKeepsExistingAdminPassword(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}

	var first model.User
	if err := GetDB().Model(model.User{}).First(&first).Error; err != nil {
		t.Fatalf("read admin user: %v", err)
	}
	firstHash := first.Password

	// Re-initialise the same database (as a panel restart would).
	if err := CloseDB(); err != nil {
		t.Fatalf("CloseDB: %v", err)
	}
	if err := InitDB(dbPath); err != nil {
		t.Fatalf("second InitDB: %v", err)
	}
	t.Cleanup(func() { CloseDB() })

	var second model.User
	if err := GetDB().Model(model.User{}).First(&second).Error; err != nil {
		t.Fatalf("read admin user: %v", err)
	}
	if second.Password != firstHash {
		t.Fatal("re-initialising an existing database changed the admin password")
	}
	if crypto.CheckPasswordHash(second.Password, "admin") {
		t.Fatal("existing database accepts the default password admin")
	}
}
