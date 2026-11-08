package service

import (
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
)

// H-4: the session secret must change when it is rotated. This tests the
// RotateSecret call itself against a throw-away database; the ImportDB
// wiring (rotate after InitDB + RestartXray succeed) is verified by code
// review of web/service/server.go, because ImportDB also swaps the live
// database file, stops/starts Xray and needs a multipart upload.
func TestRotateSecretChangesSecret(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	defer database.CloseDB()

	s := &SettingService{}
	if err := s.RotateSecret(); err != nil {
		t.Fatalf("first RotateSecret: %v", err)
	}
	first, err := s.getString("secret")
	if err != nil {
		t.Fatalf("getString(secret): %v", err)
	}
	if first == "" {
		t.Fatal("secret is empty after rotation")
	}
	if err := s.RotateSecret(); err != nil {
		t.Fatalf("second RotateSecret: %v", err)
	}
	second, err := s.getString("secret")
	if err != nil {
		t.Fatalf("getString(secret): %v", err)
	}
	if second == "" {
		t.Fatal("secret is empty after second rotation")
	}
	if first == second {
		t.Fatal("RotateSecret did not change the secret")
	}
}
