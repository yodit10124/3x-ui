package database

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database/model"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// makeImportDB builds a minimal sqlite file with a settings table holding
// one xrayTemplateConfig row, as produced by a real panel database.
func makeImportDB(t *testing.T, xrayTemplate string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "import.db")
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)").Error; err != nil {
		t.Fatal(err)
	}
	if xrayTemplate != "" {
		if err := db.Exec("INSERT INTO settings (key, value) VALUES (?, ?)", "xrayTemplateConfig", xrayTemplate).Error; err != nil {
			t.Fatal(err)
		}
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// A backup must never resurrect logged-out sessions: purging the
// candidate file removes every login_sessions row while leaving all
// other tables untouched. A file without the table (an old-version
// backup) is a no-op, and purging twice is safe.
func TestPurgeLoginSessionsFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "purge.db")
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.LoginSession{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&model.User{Username: "admin", Password: "hash"}).Error; err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"aaa", "bbb"} {
		sum := sha256.Sum256([]byte("session-" + id))
		row := model.LoginSession{
			Id:           hex.EncodeToString(sum[:]),
			UserId:       1,
			Username:     "admin",
			PasswordHash: "hash",
			ExpiresAt:    time.Now().Add(time.Hour),
		}
		if err := db.Create(&row).Error; err != nil {
			t.Fatal(err)
		}
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}

	if err := PurgeLoginSessionsFromFile(path); err != nil {
		t.Fatalf("PurgeLoginSessionsFromFile: %v", err)
	}
	if err := PurgeLoginSessionsFromFile(path); err != nil {
		t.Fatalf("second purge: %v", err)
	}
	check, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		sdb, _ := check.DB()
		if sdb != nil {
			_ = sdb.Close()
		}
	}()
	var sessions int64
	if err := check.Model(&model.LoginSession{}).Count(&sessions).Error; err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("login_sessions rows %d, want 0 after purge", sessions)
	}
	var users int64
	if err := check.Model(&model.User{}).Count(&users).Error; err != nil {
		t.Fatal(err)
	}
	if users != 1 {
		t.Fatalf("users rows %d, want 1 (purge must not touch other tables)", users)
	}
}

// A file without a login_sessions table (an old-version backup) must
// purge cleanly instead of failing the import.
func TestPurgeLoginSessionsFromFileNoTable(t *testing.T) {
	path := makeImportDB(t, "")
	if err := PurgeLoginSessionsFromFile(path); err != nil {
		t.Fatalf("PurgeLoginSessionsFromFile on a file without the table: %v", err)
	}
}
func TestValidateImportedXrayConfig(t *testing.T) {
	logDir := t.TempDir()
	t.Setenv("XUI_LOG_FOLDER", logDir)

	benign := `{"log": {"access": "` + filepath.Join(logDir, "access.log") + `", "error": "` + filepath.Join(logDir, "error.log") + `", "loglevel": "warning"}}`
	if err := ValidateImportedXrayConfig(makeImportDB(t, benign)); err != nil {
		t.Errorf("benign imported config should pass, got %v", err)
	}

	// No xrayTemplateConfig at all: nothing to validate.
	if err := ValidateImportedXrayConfig(makeImportDB(t, "")); err != nil {
		t.Errorf("import without xrayTemplateConfig should pass, got %v", err)
	}

	malicious := []string{
		// log.access to /tmp
		`{"log": {"access": "/tmp/evil.log", "error": "", "loglevel": "warning"}}`,
		// log.error to ~/.ssh
		`{"log": {"access": "none", "error": "/root/.ssh/authorized_keys", "loglevel": "warning"}}`,
		// ".." escape
		`{"log": {"access": "` + filepath.Join(logDir, "..", "evil.log") + `", "error": "", "loglevel": "warning"}}`,
		// relative path
		`{"log": {"access": "access.log", "error": "", "loglevel": "warning"}}`,
	}
	for _, cfg := range malicious {
		if err := ValidateImportedXrayConfig(makeImportDB(t, cfg)); err == nil {
			t.Errorf("malicious imported config should fail: %s", cfg)
		}
	}

	// A corrupt / non-sqlite file must still be rejected by the caller path
	// (ValidateSQLiteDB); here ValidateImportedXrayConfig itself errors.
	badPath := filepath.Join(t.TempDir(), "bad.db")
	if err := os.WriteFile(badPath, []byte("not a database"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateImportedXrayConfig(badPath); err == nil {
		t.Errorf("non-sqlite file should fail validation")
	}
}

// makeImportDBWithExtra is makeImportDB plus extra DDL (triggers, views,
// extra tables) executed before the file is closed.
func makeImportDBWithExtra(t *testing.T, xrayTemplate string, stmts ...string) string {
	t.Helper()
	path := makeImportDB(t, xrayTemplate)
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range stmts {
		if err := db.Exec(stmt).Error; err != nil {
			t.Fatalf("extra DDL %q failed: %v (statement skipped, not a validation result)", stmt, err)
		}
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// H-3 / H-7: import validation must reuse the full template check, not
// just the log fields.
func TestValidateImportedXrayConfig_H3H7(t *testing.T) {
	logDir := t.TempDir()
	t.Setenv("XUI_LOG_FOLDER", logDir)

	benign := `{"log": {"access": "none", "error": "", "loglevel": "warning"},
		"inbounds": [{"tag": "api", "listen": "127.0.0.1", "port": 62789, "protocol": "tunnel", "settings": {"address": "127.0.0.1"}}],
		"outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"redirect": ""}}],
		"metrics": {"listen": "127.0.0.1:11111"},
		"routing": {"rules": [{"type": "field", "outboundTag": "blocked", "ip": ["geoip:private"]}]}}`
	if err := ValidateImportedXrayConfig(makeImportDB(t, benign)); err != nil {
		t.Errorf("benign imported config should pass, got %v", err)
	}

	malicious := map[string]string{
		"api listen 0.0.0.0":    `{"inbounds": [{"tag": "api", "listen": "0.0.0.0", "port": 62789}]}`,
		"api listen empty":      `{"inbounds": [{"tag": "api", "port": 62789}]}`,
		"metrics 0.0.0.0":       `{"metrics": {"listen": "0.0.0.0:11111"}}`,
		"reverse bridge":        `{"reverse": {"bridges": [{"tag": "b", "domain": "x"}]}}`,
		"private routed direct": `{"routing": {"rules": [{"type": "field", "outboundTag": "direct", "ip": ["geoip:private"]}]}}`,
		"freedom redirect":      `{"outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:8080"}}]}`,
		"non-api tunnel":        `{"inbounds": [{"tag": "tun1", "listen": "127.0.0.1", "port": 10000, "protocol": "tunnel", "settings": {"address": "127.0.0.1"}}]}`,
		"dokodemo-door":         `{"inbounds": [{"tag": "dd", "listen": "127.0.0.1", "port": 10001, "protocol": "dokodemo-door", "settings": {"address": "8.8.8.8", "port": 53}}]}`,
	}
	for name, cfg := range malicious {
		t.Run(name, func(t *testing.T) {
			if err := ValidateImportedXrayConfig(makeImportDB(t, cfg)); err == nil {
				t.Errorf("malicious imported config should fail: %s", cfg)
			}
		})
	}
}

// H-4: import validation must reject triggers, views and unexpected tables.
func TestValidateImportedDBObjects(t *testing.T) {
	// Only the panel's own tables: passes (settings alone is the minimal case).
	if err := ValidateImportedDBObjects(makeImportDB(t, "")); err != nil {
		t.Errorf("minimal import db should pass, got %v", err)
	}
	// All whitelisted tables, as a real panel database has them.
	allTables := makeImportDBWithExtra(t, "",
		"CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)",
		"CREATE TABLE inbounds (id INTEGER PRIMARY KEY AUTOINCREMENT, tag TEXT)",
		"CREATE TABLE outbound_traffics (id INTEGER PRIMARY KEY AUTOINCREMENT, tag TEXT)",
		"CREATE TABLE inbound_client_ips (id INTEGER PRIMARY KEY AUTOINCREMENT, client_email TEXT)",
		"CREATE TABLE client_traffics (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT)",
		"CREATE TABLE history_of_seeders (id INTEGER PRIMARY KEY AUTOINCREMENT, seeder_name TEXT)",
		"CREATE TABLE custom_geo_resources (id INTEGER PRIMARY KEY AUTOINCREMENT, geo_type TEXT)",
		// login_sessions holds the revocable login sessions: a backup
		// taken by a version that has the table must import, or the
		// backup cannot be restored at all.
		"CREATE TABLE login_sessions (id TEXT PRIMARY KEY, user_id INTEGER, username TEXT, password_hash TEXT, expires_at DATETIME)",
	)
	if err := ValidateImportedDBObjects(allTables); err != nil {
		t.Errorf("real-shape import db should pass, got %v", err)
	}

	rejected := map[string][]string{
		"trigger on settings": {
			"CREATE TRIGGER trg AFTER UPDATE ON settings BEGIN SELECT 1; END",
		},
		"view": {
			"CREATE VIEW v_users AS SELECT * FROM settings",
		},
		"extra table": {
			"CREATE TABLE evil (id INTEGER PRIMARY KEY, cmd TEXT)",
		},
		"trigger plus view": {
			"CREATE TRIGGER trg AFTER UPDATE ON settings BEGIN SELECT 1; END",
			"CREATE VIEW v AS SELECT 1 AS x",
		},
	}
	for name, stmts := range rejected {
		t.Run(name, func(t *testing.T) {
			if err := ValidateImportedDBObjects(makeImportDBWithExtra(t, "", stmts...)); err == nil {
				t.Errorf("import db with %s should fail", name)
			}
		})
	}

	// Virtual tables report type='table', so they are caught by the DDL
	// check, not the name whitelist. FTS5 may be compiled out of some
	// SQLite builds; skip rather than fail there.
	t.Run("virtual table", func(t *testing.T) {
		path := makeImportDB(t, "")
		db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.Exec("CREATE VIRTUAL TABLE vt USING fts5(x)").Error; err != nil {
			t.Skipf("fts5 not available in this sqlite build: %v", err)
		}
		sqlDB, _ := db.DB()
		_ = sqlDB.Close()
		if err := ValidateImportedDBObjects(path); err == nil {
			t.Errorf("import db with a virtual table should fail")
		}
	})
}

// Import validation opens the candidate read-only and immutable: the file
// must be byte-identical afterwards and no WAL/journal sidecars may appear.
func TestImportValidationIsReadOnly(t *testing.T) {
	path := makeImportDBWithExtra(t, `{"log": {"access": "none"}}`,
		"CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)",
	)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeHash := sha256.Sum256(before)
	for _, fn := range []func(string) error{ValidateSQLiteDB, ValidateImportedDBObjects, ValidateImportedXrayConfig} {
		if err := fn(path); err != nil {
			t.Fatalf("validation should pass: %v", err)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(after) != beforeHash {
		t.Errorf("import validation modified the candidate file")
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(path + suffix); !os.IsNotExist(err) {
			t.Errorf("import validation created sidecar file %s", path+suffix)
		}
	}
}
