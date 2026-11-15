package service

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
)

func TestGetWSTrustedOrigins(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })

	svc := &SettingService{}

	// Default: empty setting means same-origin only.
	got, err := svc.GetWSTrustedOrigins()
	if err != nil {
		t.Fatalf("GetWSTrustedOrigins: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("default trusted origins = %v, want empty", got)
	}

	// Comma-separated values are split, trimmed, and empty entries dropped.
	if err := database.GetDB().Create(&model.Setting{
		Key:   "wsTrustedOrigins",
		Value: " https://public.example.com:8443 , ,http://internal.example.com, ",
	}).Error; err != nil {
		t.Fatalf("set wsTrustedOrigins: %v", err)
	}
	got, err = svc.GetWSTrustedOrigins()
	if err != nil {
		t.Fatalf("GetWSTrustedOrigins: %v", err)
	}
	want := []string{"https://public.example.com:8443", "http://internal.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GetWSTrustedOrigins() = %v, want %v", got, want)
	}
}

func TestGetSecureCookieAndHSTSDefaults(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })

	svc := &SettingService{}

	secure, err := svc.GetSecureCookie()
	if err != nil {
		t.Fatalf("GetSecureCookie: %v", err)
	}
	if secure {
		t.Fatal("default webSecureCookie = true, want false (explicit opt-in)")
	}

	maxAge, err := svc.GetHSTSMaxAge()
	if err != nil {
		t.Fatalf("GetHSTSMaxAge: %v", err)
	}
	if maxAge != 31536000 {
		t.Fatalf("default webHSTSMaxAge = %d, want 31536000", maxAge)
	}

	maxMB, err := svc.GetGeoMaxFileSizeMB()
	if err != nil {
		t.Fatalf("GetGeoMaxFileSizeMB: %v", err)
	}
	if maxMB != 100 {
		t.Fatalf("default geoMaxFileSizeMB = %d, want 100", maxMB)
	}
}
