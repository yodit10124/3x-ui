// Package database provides database initialization, migration, and management utilities
// for the 3x-ui panel using GORM with SQLite.
package database

import (
	"bytes"
	"database/sql"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var db *gorm.DB

const (
	defaultUsername = "admin"
	defaultPassword = "admin"
)

func initModels() error {
	models := []any{
		&model.User{},
		&model.Inbound{},
		&model.OutboundTraffics{},
		&model.Setting{},
		&model.InboundClientIps{},
		&xray.ClientTraffic{},
		&model.HistoryOfSeeders{},
		&model.CustomGeoResource{},
	}
	for _, model := range models {
		if err := db.AutoMigrate(model); err != nil {
			log.Printf("Error auto migrating model: %v", err)
			return err
		}
	}
	return nil
}

// initUser creates a default admin user if the users table is empty.
func initUser() error {
	empty, err := isTableEmpty("users")
	if err != nil {
		log.Printf("Error checking if users table is empty: %v", err)
		return err
	}
	if empty {
		hashedPassword, err := crypto.HashPasswordAsBcrypt(defaultPassword)

		if err != nil {
			log.Printf("Error hashing default password: %v", err)
			return err
		}

		user := &model.User{
			Username: defaultUsername,
			Password: hashedPassword,
		}
		return db.Create(user).Error
	}
	return nil
}

// runSeeders migrates user passwords to bcrypt and records seeder execution to prevent re-running.
func runSeeders(isUsersEmpty bool) error {
	empty, err := isTableEmpty("history_of_seeders")
	if err != nil {
		log.Printf("Error checking if users table is empty: %v", err)
		return err
	}

	if empty && isUsersEmpty {
		hashSeeder := &model.HistoryOfSeeders{
			SeederName: "UserPasswordHash",
		}
		return db.Create(hashSeeder).Error
	} else {
		var seedersHistory []string
		db.Model(&model.HistoryOfSeeders{}).Pluck("seeder_name", &seedersHistory)

		if !slices.Contains(seedersHistory, "UserPasswordHash") && !isUsersEmpty {
			var users []model.User
			db.Find(&users)

			for _, user := range users {
				hashedPassword, err := crypto.HashPasswordAsBcrypt(user.Password)
				if err != nil {
					log.Printf("Error hashing password for user '%s': %v", user.Username, err)
					return err
				}
				db.Model(&user).Update("password", hashedPassword)
			}

			hashSeeder := &model.HistoryOfSeeders{
				SeederName: "UserPasswordHash",
			}
			return db.Create(hashSeeder).Error
		}
	}

	return nil
}

// isTableEmpty returns true if the named table contains zero rows.
func isTableEmpty(tableName string) (bool, error) {
	var count int64
	err := db.Table(tableName).Count(&count).Error
	return count == 0, err
}

// InitDB sets up the database connection, migrates models, and runs seeders.
func InitDB(dbPath string) error {
	dir := path.Dir(dbPath)
	err := os.MkdirAll(dir, fs.ModePerm)
	if err != nil {
		return err
	}

	var gormLogger logger.Interface

	if config.IsDebug() {
		gormLogger = logger.Default
	} else {
		gormLogger = logger.Discard
	}

	c := &gorm.Config{
		Logger: gormLogger,
	}
	db, err = gorm.Open(sqlite.Open(dbPath), c)
	if err != nil {
		return err
	}

	if err := initModels(); err != nil {
		return err
	}

	isUsersEmpty, err := isTableEmpty("users")
	if err != nil {
		return err
	}

	if err := initUser(); err != nil {
		return err
	}
	return runSeeders(isUsersEmpty)
}

// CloseDB closes the database connection if it exists.
func CloseDB() error {
	if db != nil {
		sqlDB, err := db.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	return nil
}

// GetDB returns the global GORM database instance.
func GetDB() *gorm.DB {
	return db
}

func IsNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound)
}

// IsSQLiteDB checks if the given file is a valid SQLite database by reading its signature.
func IsSQLiteDB(file io.ReaderAt) (bool, error) {
	signature := []byte("SQLite format 3\x00")
	buf := make([]byte, len(signature))
	_, err := file.ReadAt(buf, 0)
	if err != nil {
		return false, err
	}
	return bytes.Equal(buf, signature), nil
}

// Checkpoint performs a WAL checkpoint on the SQLite database to ensure data consistency.
func Checkpoint() error {
	// Update WAL
	err := db.Exec("PRAGMA wal_checkpoint;").Error
	if err != nil {
		return err
	}
	return nil
}

// importDBDSN builds a SQLite DSN that opens dbPath read-only and immutable
// (mode=ro&immutable=1). Import validation must never write to the candidate
// file — not even WAL sidecar files — and must not let the file change under
// the validator. The caller still copies the plain file afterwards, so a
// WAL-mode database is validated by its main file only, which is exactly
// what gets imported (the -wal sidecar is never uploaded).
func importDBDSN(dbPath string) string {
	abs, err := filepath.Abs(dbPath)
	if err != nil {
		abs = dbPath
	}
	return (&url.URL{Scheme: "file", Path: abs, RawQuery: "mode=ro&immutable=1"}).String()
}

// openImportDB opens dbPath with a throw-away read-only, immutable connection
// for import validation. It does not mutate global state or run migrations.
func openImportDB(dbPath string) (*gorm.DB, *sql.DB, error) {
	gdb, err := gorm.Open(sqlite.Open(importDBDSN(dbPath)), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, nil, err
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		return nil, nil, err
	}
	return gdb, sqlDB, nil
}

// ValidateImportedXrayConfig opens a database file (without touching the live
// database) and validates the xrayTemplateConfig stored inside it, reusing
// the full template check from config.ValidateXrayTemplateConfig (log paths,
// api inbound listen, metrics, reverse, routing, freedom.redirect — H-3 /
// H-7). Previously it only decoded the log fields, so a malicious api
// listen or routing rule in an imported database was never checked.
// Returns nil when the file has no xrayTemplateConfig setting.
func ValidateImportedXrayConfig(dbPath string) error {
	gdb, sqlDB, err := openImportDB(dbPath)
	if err != nil {
		return err
	}
	defer sqlDB.Close()

	var rows []struct {
		Value string
	}
	if err := gdb.Raw("SELECT value FROM settings WHERE key = ?", "xrayTemplateConfig").Scan(&rows).Error; err != nil {
		// No settings table / no such row: nothing to validate.
		return nil
	}
	for _, row := range rows {
		if err := config.ValidateXrayTemplateConfig(row.Value); err != nil {
			return err
		}
	}
	return nil
}

// allowedImportTables is the whitelist of tables a 3x-ui database may
// contain (H-4). Names are the GORM table names of the models in
// initModels (database/model/model.go and xray.ClientTraffic), plus the
// tables SQLite itself creates: sqlite_sequence (AUTOINCREMENT) and the
// sqlite_stat* tables (ANALYZE). Anything else is rejected on import.
var allowedImportTables = map[string]bool{
	"users":                true,
	"inbounds":             true,
	"outbound_traffics":    true,
	"settings":             true,
	"inbound_client_ips":   true,
	"client_traffics":      true,
	"history_of_seeders":   true,
	"custom_geo_resources": true,
	"sqlite_sequence":      true,
	"sqlite_stat1":         true,
	"sqlite_stat4":         true,
}

// ValidateImportedDBObjects enumerates sqlite_master of the candidate
// database (read-only, immutable) and rejects anything that could carry a
// persistent backdoor or hidden behaviour into the panel (H-4): any trigger
// or view, any table outside allowedImportTables, and any virtual table.
// It does not check indexes: indexes cannot execute code and an index on a
// non-whitelisted table cannot exist without the table itself.
func ValidateImportedDBObjects(dbPath string) error {
	gdb, sqlDB, err := openImportDB(dbPath)
	if err != nil {
		return err
	}
	defer sqlDB.Close()

	var objects []struct {
		Type string
		Name string
	}
	if err := gdb.Raw("SELECT type, name FROM sqlite_master").Scan(&objects).Error; err != nil {
		return err
	}
	for _, obj := range objects {
		switch obj.Type {
		case "trigger":
			return errors.New("imported db contains a trigger: " + obj.Name)
		case "view":
			return errors.New("imported db contains a view: " + obj.Name)
		case "table":
			if !allowedImportTables[obj.Name] {
				return errors.New("imported db contains an unexpected table: " + obj.Name)
			}
		}
	}
	// Virtual tables (e.g. FTS) report type='table', so check the DDL too.
	var virtual []struct {
		Name string
	}
	if err := gdb.Raw("SELECT name FROM sqlite_master WHERE type = 'table' AND sql LIKE 'CREATE VIRTUAL TABLE%'").Scan(&virtual).Error; err != nil {
		return err
	}
	for _, v := range virtual {
		return errors.New("imported db contains a virtual table: " + v.Name)
	}
	return nil
}

func ValidateSQLiteDB(dbPath string) error {
	if _, err := os.Stat(dbPath); err != nil { // file must exist
		return err
	}
	gdb, sqlDB, err := openImportDB(dbPath)
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	var res string
	if err := gdb.Raw("PRAGMA integrity_check;").Scan(&res).Error; err != nil {
		return err
	}
	if res != "ok" {
		return errors.New("sqlite integrity check failed: " + res)
	}
	return nil
}
