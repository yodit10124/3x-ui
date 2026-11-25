package service

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

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

func TestSetExternalTrafficInformURI_ValidatesURL(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })

	svc := &SettingService{}

	// Empty means disabled and is always storable.
	if err := svc.SetExternalTrafficInformURI(""); err != nil {
		t.Fatalf("empty inform URI should save, got %v", err)
	}
	// A public IP literal needs no DNS and is allowed.
	if err := svc.SetExternalTrafficInformURI("https://8.8.8.8/hook"); err != nil {
		t.Fatalf("public inform URI should save, got %v", err)
	}
	// Loopback, private, and documentation addresses are rejected.
	for _, bad := range []string{
		"http://127.0.0.1:8080/hook",
		"http://10.0.0.5/hook",
		"http://192.168.1.1/hook",
		"http://100.64.0.1/hook",
		"http://203.0.113.1/hook",
		"ftp://8.8.8.8/hook",
		"not-a-url",
	} {
		if err := svc.SetExternalTrafficInformURI(bad); err == nil {
			t.Errorf("SetExternalTrafficInformURI(%q) should fail, got nil error", bad)
		}
	}
	// The last successful save wins; a rejected save must not overwrite it.
	got, err := svc.GetExternalTrafficInformURI()
	if err != nil {
		t.Fatalf("GetExternalTrafficInformURI: %v", err)
	}
	if got != "https://8.8.8.8/hook" {
		t.Fatalf("inform URI = %q, want the last accepted value", got)
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

// TestGetAllSettingMasksLdapPassword (L-1): the LDAP bind password
// must come back masked like the other secrets, and a round-tripped
// "******" must not overwrite the stored password.
func TestGetAllSettingMasksLdapPassword(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })

	svc := &SettingService{}
	if err := database.GetDB().Create(&model.Setting{
		Key:   "ldapPassword",
		Value: "s3cret-ldap-pass",
	}).Error; err != nil {
		t.Fatalf("set ldapPassword: %v", err)
	}

	all, err := svc.GetAllSetting()
	if err != nil {
		t.Fatalf("GetAllSetting: %v", err)
	}
	if all.LdapPassword != "******" {
		t.Fatalf("LdapPassword = %q, want it masked", all.LdapPassword)
	}

	// Round-trip the masked value through UpdateAllSetting: the
	// stored password must survive.
	if err := svc.UpdateAllSetting(all); err != nil {
		t.Fatalf("UpdateAllSetting: %v", err)
	}
	var stored model.Setting
	if err := database.GetDB().Where("key = ?", "ldapPassword").First(&stored).Error; err != nil {
		t.Fatalf("read back ldapPassword: %v", err)
	}
	if stored.Value != "s3cret-ldap-pass" {
		t.Fatalf("stored ldapPassword = %q, want the original value", stored.Value)
	}
}

// TestResetSettingsDeletesUsers (L-2): `x-ui setting -reset` used to
// report success while the admin account survived (dead query: no
// Delete call). After the reset there must be no users, no settings,
// and no login sessions left.
func TestResetSettingsDeletesUsers(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })

	db := database.GetDB()
	if err := db.Create(&model.User{Username: "admin", Password: "hash"}).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := db.Create(&model.Setting{Key: "webPort", Value: "2053"}).Error; err != nil {
		t.Fatalf("create setting: %v", err)
	}
	if err := db.Create(&model.LoginSession{
		Id: "aabbcc", UserId: 1, Username: "admin",
		PasswordHash: "hash", ExpiresAt: time.Now().Add(time.Hour),
	}).Error; err != nil {
		t.Fatalf("create session: %v", err)
	}

	if err := (&SettingService{}).ResetSettings(); err != nil {
		t.Fatalf("ResetSettings: %v", err)
	}

	var users, settings, sessions int64
	db.Model(&model.User{}).Count(&users)
	db.Model(&model.Setting{}).Count(&settings)
	db.Model(&model.LoginSession{}).Count(&sessions)
	if users != 0 || settings != 0 || sessions != 0 {
		t.Fatalf("after reset: users=%d settings=%d sessions=%d, want all 0", users, settings, sessions)
	}
}

// TestSanitizeImportedSettings (L-6): an imported database must not
// silently keep a notification/exfiltration channel or an absurd Geo
// download cap. The Telegram token/chat are cleared, external traffic
// reporting is switched off, and geoMaxFileSizeMB is clamped to the
// ceiling; a legitimate value below the ceiling is left alone.
func TestSanitizeImportedSettings(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })

	svc := &SettingService{}
	seed := []struct{ key, value string }{
		{"tgBotToken", "123456:attacker-token"},
		{"tgBotChatId", "987654321"},
		{"externalTrafficInformEnable", "true"},
		{"externalTrafficInformURI", "https://attacker.example.com/hook"},
		{"geoMaxFileSizeMB", "99999"},
	}
	for _, s := range seed {
		if err := database.GetDB().Create(&model.Setting{Key: s.key, Value: s.value}).Error; err != nil {
			t.Fatalf("seed %s: %v", s.key, err)
		}
	}

	if err := svc.SanitizeImportedSettings(); err != nil {
		t.Fatalf("SanitizeImportedSettings: %v", err)
	}

	checks := []struct {
		key  string
		want string
	}{
		{"tgBotToken", ""},
		{"tgBotChatId", ""},
		{"externalTrafficInformEnable", "false"},
		{"geoMaxFileSizeMB", "100"},
		// The URI itself is left for the operator to review; with the
		// switch off nothing is sent to it.
		{"externalTrafficInformURI", "https://attacker.example.com/hook"},
	}
	for _, c := range checks {
		var stored model.Setting
		if err := database.GetDB().Where("key = ?", c.key).First(&stored).Error; err != nil {
			t.Fatalf("read back %s: %v", c.key, err)
		}
		if stored.Value != c.want {
			t.Fatalf("%s = %q, want %q", c.key, stored.Value, c.want)
		}
	}

	// A value already below the ceiling is untouched.
	if err := svc.setInt("geoMaxFileSizeMB", 50); err != nil {
		t.Fatalf("set geoMaxFileSizeMB=50: %v", err)
	}
	if err := svc.SanitizeImportedSettings(); err != nil {
		t.Fatalf("SanitizeImportedSettings again: %v", err)
	}
	mb, err := svc.GetGeoMaxFileSizeMB()
	if err != nil {
		t.Fatalf("GetGeoMaxFileSizeMB: %v", err)
	}
	if mb != 50 {
		t.Fatalf("geoMaxFileSizeMB = %d, want 50 (below the ceiling, untouched)", mb)
	}
}
