package config

import (
	"os"
	"path/filepath"
	"testing"
)

// H1 / CVE-2026-55477: log paths must stay inside the panel log folder.
func TestValidateXrayLogPath(t *testing.T) {
	logDir := t.TempDir()
	t.Setenv("XUI_LOG_FOLDER", logDir)

	valid := []string{
		"",     // logging disabled / unset
		"none", // logging disabled
		filepath.Join(logDir, "access.log"),
		filepath.Join(logDir, "sub", "error.log"),
	}
	for _, p := range valid {
		if err := ValidateXrayLogPath(p); err != nil {
			t.Errorf("ValidateXrayLogPath(%q) should pass, got %v", p, err)
		}
	}

	// Symlink escape: a .log file inside the folder that is a symlink to
	// outside must be rejected.
	outside := filepath.Join(t.TempDir(), "evil.log")
	if err := os.WriteFile(outside, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	evilLink := filepath.Join(logDir, "evil.log")
	if err := os.Symlink(outside, evilLink); err != nil {
		t.Fatal(err)
	}
	if err := ValidateXrayLogPath(evilLink); err == nil {
		t.Errorf("ValidateXrayLogPath(%q) should reject a symlink escaping the log folder", evilLink)
	}

	// Symlink escape via a parent directory.
	realOutside := t.TempDir()
	parentLink := filepath.Join(logDir, "linkdir")
	if err := os.Symlink(realOutside, parentLink); err != nil {
		t.Fatal(err)
	}
	if err := ValidateXrayLogPath(filepath.Join(parentLink, "access.log")); err == nil {
		t.Errorf("ValidateXrayLogPath should reject a path whose parent directory is a symlink outside the log folder")
	}

	invalid := []string{
		"/tmp/evil.log",                         // outside the log folder
		"/root/.ssh/authorized_keys",            // not a .log file, outside folder
		filepath.Join(logDir, "..", "evil.log"), // ".." escape
		"relative/path.log",                     // not absolute
		filepath.Join(logDir, "access.txt"),     // wrong extension
		"/etc/passwd",                           // outside folder
	}
	for _, p := range invalid {
		if err := ValidateXrayLogPath(p); err == nil {
			t.Errorf("ValidateXrayLogPath(%q) should fail, got nil", p)
		}
	}
}

func TestValidateXrayLogPaths(t *testing.T) {
	logDir := t.TempDir()
	t.Setenv("XUI_LOG_FOLDER", logDir)

	if err := ValidateXrayLogPaths(filepath.Join(logDir, "access.log"), filepath.Join(logDir, "error.log")); err != nil {
		t.Errorf("valid pair should pass, got %v", err)
	}
	if err := ValidateXrayLogPaths(filepath.Join(logDir, "access.log"), "/tmp/error.log"); err == nil {
		t.Errorf("invalid error path should fail")
	}
	if err := ValidateXrayLogPaths("/tmp/access.log", filepath.Join(logDir, "error.log")); err == nil {
		t.Errorf("invalid access path should fail")
	}
}
