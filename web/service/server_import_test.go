package service

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/session"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"github.com/op/go-logging"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// setupImportTestEnv builds a throw-away panel database at the path
// config.GetDBPath() reads (via XUI_DB_FOLDER) and, when asked,
// installs a fake Xray binary that answers -version and otherwise
// sleeps, so RestartXrayService can succeed in tests.
func setupImportTestEnv(t *testing.T, withFakeXray bool) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	binDir := filepath.Join(dir, "bin")
	t.Setenv("XUI_BIN_FOLDER", binDir)
	t.Setenv("XUI_LOG_FOLDER", dir)
	logger.InitLogger(logging.ERROR)

	if withFakeXray {
		if err := os.MkdirAll(binDir, 0o755); err != nil {
			t.Fatal(err)
		}
		script := "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo \"Xray 99.0-test (test)\"; exit 0; fi\nexec sleep 60\n"
		if err := os.WriteFile(filepath.Join(binDir, xray.GetBinaryName()), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = (&XrayService{}).StopXray() })
	}

	dbPath := config.GetDBPath()
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })
	return dbPath
}

func importTestSessionHash(sessionID string) string {
	sum := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(sum[:])
}

// insertImportTestSession creates one login session row for the admin
// (id 1) whose password hash matches the test password "test-hash",
// so session.ValidateSessionID answers true until the row is gone.
func insertImportTestSession(t *testing.T, sessionID string) {
	t.Helper()
	if err := database.GetDB().Model(&model.User{}).Where("id = ?", 1).Update("password", "test-hash").Error; err != nil {
		t.Fatalf("set test password: %v", err)
	}
	row := model.LoginSession{
		Id:           importTestSessionHash(sessionID),
		UserId:       1,
		Username:     "admin",
		PasswordHash: "test-hash",
		ExpiresAt:    time.Now().Add(time.Hour),
		CreatedAt:    time.Now(),
	}
	if err := database.GetDB().Create(&row).Error; err != nil {
		t.Fatalf("insert session: %v", err)
	}
	if !session.ValidateSessionID(sessionID, 1) {
		t.Fatal("test session should validate before import")
	}
}

func copyImportTestFile(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
}

// TestImportDBDiscardsRestoredSessions is the auditor's scenario:
// back up a database that holds a live session, log that session
// out, then restore the backup. The restored session must not come
// back to life: the old cookie (same signing secret, unexpired
// session) must be rejected after the import.
func TestImportDBDiscardsRestoredSessions(t *testing.T) {
	dbPath := setupImportTestEnv(t, true)
	insertImportTestSession(t, "session-old")

	// Back up the live database (it holds the session), then log out.
	backupPath := filepath.Join(t.TempDir(), "backup.db")
	if err := database.CloseDB(); err != nil {
		t.Fatal(err)
	}
	copyImportTestFile(t, dbPath, backupPath)
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("reopen live db: %v", err)
	}
	if err := database.GetDB().Delete(&model.LoginSession{}, "id = ?", importTestSessionHash("session-old")).Error; err != nil {
		t.Fatal(err)
	}
	if session.ValidateSessionID("session-old", 1) {
		t.Fatal("session should be dead after logout")
	}

	f, err := os.Open(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := (&ServerService{}).ImportDB(f); err != nil {
		t.Fatalf("ImportDB: %v", err)
	}

	if session.ValidateSessionID("session-old", 1) {
		t.Fatal("restored session validated after import, want it rejected")
	}
	var sessions int64
	if err := database.GetDB().Model(&model.LoginSession{}).Count(&sessions).Error; err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("login_sessions rows %d after import, want 0", sessions)
	}
	if _, err := os.Stat(dbPath + ".backup"); !os.IsNotExist(err) {
		t.Fatalf("fallback file still present after successful import: %v", err)
	}
	var users int64
	if err := database.GetDB().Model(&model.User{}).Count(&users).Error; err != nil {
		t.Fatal(err)
	}
	if users != 1 {
		t.Fatalf("users rows %d after import, want 1", users)
	}
	if !(&XrayService{}).IsXrayRunning() {
		t.Fatal("xray not running after import")
	}
}

// TestImportDBRollsBackOnXrayStartFailure: when Xray fails to start
// after the swap, the import must fail AND the original database
// must come back — file restored, connection reopened on it, and
// the fallback file gone (it was moved back, not deleted).
func TestImportDBRollsBackOnXrayStartFailure(t *testing.T) {
	dbPath := setupImportTestEnv(t, false)
	insertImportTestSession(t, "session-live")

	// The candidate is a copy of the live database plus one extra
	// user, so a missing rollback is visible in the live data.
	candidatePath := filepath.Join(t.TempDir(), "candidate.db")
	if err := database.CloseDB(); err != nil {
		t.Fatal(err)
	}
	copyImportTestFile(t, dbPath, candidatePath)
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("reopen live db: %v", err)
	}
	cand := openImportTestCandidate(t, candidatePath)
	if err := cand.Create(&model.User{Username: "imported", Password: "x"}).Error; err != nil {
		t.Fatal(err)
	}
	closeImportTestCandidate(t, cand)

	// Make Xray fail to start: the config file path is a directory,
	// so writing the runtime config fails synchronously.
	binDir := filepath.Join(filepath.Dir(dbPath), "bin")
	if err := os.MkdirAll(filepath.Join(binDir, "config.json"), 0o755); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(candidatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := (&ServerService{}).ImportDB(f); err == nil {
		t.Fatal("ImportDB should fail when Xray cannot start")
	}

	// The original database is back: the extra user is gone, the
	// original session still validates, and the live connection
	// answers queries against the restored file.
	var imported int64
	if err := database.GetDB().Model(&model.User{}).Where("username = ?", "imported").Count(&imported).Error; err != nil {
		t.Fatalf("live db unusable after rollback: %v", err)
	}
	if imported != 0 {
		t.Fatal("imported user survived a failed import, want the original database restored")
	}
	if !session.ValidateSessionID("session-live", 1) {
		t.Fatal("original session lost after rollback, want it intact")
	}
	if _, err := os.Stat(dbPath + ".backup"); !os.IsNotExist(err) {
		t.Fatalf("fallback file still present after rollback: %v", err)
	}
}

// openImportTestCandidate opens a database file with a throw-away
// connection for test setup (inserting rows into a candidate file).
func openImportTestCandidate(t *testing.T, path string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// closeImportTestCandidate closes a throw-away candidate connection.
func closeImportTestCandidate(t *testing.T, db *gorm.DB) {
	t.Helper()
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestRollbackImportRestoresOriginal exercises the rollback itself:
// with the live database swapped out for a candidate and the global
// handle pointing at the candidate, rollbackImport must close the
// candidate, move the original file back, and reopen it.
func TestRollbackImportRestoresOriginal(t *testing.T) {
	dbPath := setupImportTestEnv(t, false)
	if err := database.GetDB().Model(&model.User{}).Where("id = ?", 1).Update("password", "marker-pw").Error; err != nil {
		t.Fatal(err)
	}

	fallbackPath := dbPath + ".backup"
	if err := database.CloseDB(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dbPath, fallbackPath); err != nil {
		t.Fatal(err)
	}
	// The global handle now points at a fresh candidate database.
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("open candidate db: %v", err)
	}

	(&ServerService{}).rollbackImport(fallbackPath, false, true)

	if _, err := os.Stat(fallbackPath); !os.IsNotExist(err) {
		t.Fatalf("fallback file still present after rollback: %v", err)
	}
	var admin model.User
	if err := database.GetDB().First(&admin, 1).Error; err != nil {
		t.Fatalf("live db unusable after rollback: %v", err)
	}
	if admin.Password != "marker-pw" {
		t.Fatalf("admin password %q after rollback, want the original %q", admin.Password, "marker-pw")
	}
}

// TestRollbackImportWithoutBackup: a failure before the backup move
// (removing a stale fallback, or the backup rename itself) leaves
// the original database in place with its handle closed. The
// rollback must reopen it instead of looking for a fallback file
// that was never created — and must never rename a stale fallback
// over the live database.
func TestRollbackImportWithoutBackup(t *testing.T) {
	dbPath := setupImportTestEnv(t, false)
	if err := database.GetDB().Model(&model.User{}).Where("id = ?", 1).Update("password", "marker-pw").Error; err != nil {
		t.Fatal(err)
	}
	// A stale fallback left behind by an earlier failed import: it
	// must survive the rollback untouched, never restored over the
	// live database.
	fallbackPath := dbPath + ".backup"
	stale := []byte("stale fallback, not the live database")
	if err := os.WriteFile(fallbackPath, stale, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := database.CloseDB(); err != nil {
		t.Fatal(err)
	}

	(&ServerService{}).rollbackImport(fallbackPath, false, false)

	if got, err := os.ReadFile(fallbackPath); err != nil || string(got) != string(stale) {
		t.Fatalf("stale fallback changed by rollback: %q, err %v", got, err)
	}
	var admin model.User
	if err := database.GetDB().First(&admin, 1).Error; err != nil {
		t.Fatalf("live db unusable after rollback: %v", err)
	}
	if admin.Password != "marker-pw" {
		t.Fatalf("admin password %q after rollback, want the original %q", admin.Password, "marker-pw")
	}
}

// TestImportDBConcurrentImports: two imports racing each other must
// not interleave the file swap. With the import mutex both run to
// completion in some order; the live database afterwards is one of
// the two candidates and stays usable.
func TestImportDBConcurrentImports(t *testing.T) {
	dbPath := setupImportTestEnv(t, true)

	buildCandidate := func(marker string) string {
		candidatePath := filepath.Join(t.TempDir(), "candidate.db")
		copyImportTestFile(t, dbPath, candidatePath)
		cand := openImportTestCandidate(t, candidatePath)
		if err := cand.Model(&model.User{}).Where("id = ?", 1).Update("username", marker).Error; err != nil {
			t.Fatal(err)
		}
		closeImportTestCandidate(t, cand)
		return candidatePath
	}
	pathA := buildCandidate("import-a")
	pathB := buildCandidate("import-b")

	open := func(path string) *os.File {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}

	errs := make(chan error, 2)
	go func() { f := open(pathA); defer f.Close(); errs <- (&ServerService{}).ImportDB(f) }()
	go func() { f := open(pathB); defer f.Close(); errs <- (&ServerService{}).ImportDB(f) }()
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent import failed: %v", err)
		}
	}

	var admin model.User
	if err := database.GetDB().First(&admin, 1).Error; err != nil {
		t.Fatalf("live db unusable after concurrent imports: %v", err)
	}
	if admin.Username != "import-a" && admin.Username != "import-b" {
		t.Fatalf("live db holds unexpected username %q after concurrent imports", admin.Username)
	}
}
