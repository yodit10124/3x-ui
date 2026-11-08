// Package config provides configuration management utilities for the 3x-ui panel,
// including version information, logging levels, database paths, and environment variable handling.
package config

import (
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

//go:embed version
var version string

//go:embed name
var name string

// LogLevel represents the logging level for the application.
type LogLevel string

// Logging level constants
const (
	Debug   LogLevel = "debug"
	Info    LogLevel = "info"
	Notice  LogLevel = "notice"
	Warning LogLevel = "warning"
	Error   LogLevel = "error"
)

// GetVersion returns the version string of the 3x-ui application.
func GetVersion() string {
	return strings.TrimSpace(version)
}

// GetName returns the name of the 3x-ui application.
func GetName() string {
	return strings.TrimSpace(name)
}

// GetLogLevel returns the current logging level based on environment variables or defaults to Info.
func GetLogLevel() LogLevel {
	if IsDebug() {
		return Debug
	}
	logLevel := os.Getenv("XUI_LOG_LEVEL")
	if logLevel == "" {
		return Info
	}
	return LogLevel(logLevel)
}

// IsDebug returns true if debug mode is enabled via the XUI_DEBUG environment variable.
func IsDebug() bool {
	return os.Getenv("XUI_DEBUG") == "true"
}

// GetBinFolderPath returns the path to the binary folder, defaulting to "bin" if not set via XUI_BIN_FOLDER.
func GetBinFolderPath() string {
	binFolderPath := os.Getenv("XUI_BIN_FOLDER")
	if binFolderPath == "" {
		binFolderPath = "bin"
	}
	return binFolderPath
}

func getBaseDir() string {
	exePath, err := os.Executable()
	if err != nil {
		return "."
	}
	exeDir := filepath.Dir(exePath)
	exeDirLower := strings.ToLower(filepath.ToSlash(exeDir))
	if strings.Contains(exeDirLower, "/appdata/local/temp/") || strings.Contains(exeDirLower, "/go-build") {
		wd, err := os.Getwd()
		if err != nil {
			return "."
		}
		return wd
	}
	return exeDir
}

// GetDBFolderPath returns the path to the database folder based on environment variables or platform defaults.
func GetDBFolderPath() string {
	dbFolderPath := os.Getenv("XUI_DB_FOLDER")
	if dbFolderPath != "" {
		return dbFolderPath
	}
	if runtime.GOOS == "windows" {
		return getBaseDir()
	}
	return "/etc/x-ui"
}

// GetDBPath returns the full path to the database file.
func GetDBPath() string {
	return fmt.Sprintf("%s/%s.db", GetDBFolderPath(), GetName())
}

// ValidateXrayLogPath checks that an Xray log path is safe (H1 / CVE-2026-55477).
// Allowed values: empty, "none" (logging disabled), or an absolute *.log path
// inside the panel log folder (config.GetLogFolder(), /var/log/x-ui by default).
// The path is cleaned first, ".." escapes are rejected, and any symlink in the
// resolved path (or its parent directory, when the file does not exist yet)
// is resolved with filepath.EvalSymlinks and re-checked against the folder.
func ValidateXrayLogPath(path string) error {
	if path == "" || path == "none" {
		return nil
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("xray log path must be absolute: %q", path)
	}
	clean := filepath.Clean(path)
	if filepath.Ext(clean) != ".log" {
		return fmt.Errorf("xray log path must end with .log: %q", path)
	}
	logFolder := filepath.Clean(GetLogFolder())
	prefix := logFolder + string(filepath.Separator)
	if clean != logFolder && !strings.HasPrefix(clean, prefix) {
		return fmt.Errorf("xray log path %q is outside the log folder %q", path, logFolder)
	}
	// Resolve symlinks: if the file exists, resolve it; otherwise resolve its
	// parent directory (an attacker-controlled symlink on the parent would
	// otherwise redirect the write elsewhere).
	resolved := clean
	if target, err := filepath.EvalSymlinks(clean); err == nil {
		resolved = target
	} else if parent, err := filepath.EvalSymlinks(filepath.Dir(clean)); err == nil {
		resolved = filepath.Join(parent, filepath.Base(clean))
	}
	resolved = filepath.Clean(resolved)
	if resolved != logFolder && !strings.HasPrefix(resolved, prefix) {
		return fmt.Errorf("xray log path %q resolves outside the log folder %q", path, logFolder)
	}
	return nil
}

// ValidateXrayLogPaths validates both the access and error log paths.
func ValidateXrayLogPaths(access, errorPath string) error {
	if err := ValidateXrayLogPath(access); err != nil {
		return err
	}
	return ValidateXrayLogPath(errorPath)
}

// GetLogFolder returns the log folder path based on the operating system and environment variables.
func GetLogFolder() string {
	logFolderPath := os.Getenv("XUI_LOG_FOLDER")
	if logFolderPath != "" {
		return logFolderPath
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(".", "log")
	}
	return "/var/log/x-ui"
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}

	return out.Sync()
}

func init() {
	if runtime.GOOS != "windows" {
		return
	}
	if os.Getenv("XUI_DB_FOLDER") != "" {
		return
	}
	oldDBFolder := "/etc/x-ui"
	oldDBPath := fmt.Sprintf("%s/%s.db", oldDBFolder, GetName())
	newDBFolder := GetDBFolderPath()
	newDBPath := fmt.Sprintf("%s/%s.db", newDBFolder, GetName())
	_, err := os.Stat(newDBPath)
	if err == nil {
		return // new exists
	}
	_, err = os.Stat(oldDBPath)
	if os.IsNotExist(err) {
		return // old does not exist
	}
	_ = copyFile(oldDBPath, newDBPath) // ignore error
}
