package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/xray"
)

// TestWaitReadyExitsImmediately: a binary that starts but exits at
// once (bad config, missing files) must fail the readiness check
// fast — cmd.Start() succeeding proves only that the process was
// created.
func TestWaitReadyExitsImmediately(t *testing.T) {
	setupImportTestEnv(t, false)
	binDir := os.Getenv("XUI_BIN_FOLDER")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo \"Xray 99.0-test (test)\"; exit 0; fi\nexit 1\n"
	if err := os.WriteFile(filepath.Join(binDir, xray.GetBinaryName()), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = (&XrayService{}).StopXray() })

	if err := (&XrayService{}).RestartXray(true); err != nil {
		t.Fatalf("RestartXray: %v", err)
	}
	start := time.Now()
	err := (&XrayService{}).WaitReady(5 * time.Second)
	if err == nil {
		t.Fatal("WaitReady should fail when the process exits immediately")
	}
	if !strings.Contains(err.Error(), "exited during startup") {
		t.Fatalf("WaitReady error %q, want an exit-during-startup error", err)
	}
	if elapsed := time.Since(start); elapsed >= 4*time.Second {
		t.Fatalf("WaitReady took %v for an already-dead process, want a fast failure", elapsed)
	}
}

// TestWaitReadyNeverReady: a process that stays alive but never
// binds its management API must fail the readiness check on
// timeout, not pass on liveness alone.
func TestWaitReadyNeverReady(t *testing.T) {
	setupImportTestEnv(t, true)
	if err := (&XrayService{}).RestartXray(true); err != nil {
		t.Fatalf("RestartXray: %v", err)
	}
	start := time.Now()
	err := (&XrayService{}).WaitReady(2 * time.Second)
	if err == nil {
		t.Fatal("WaitReady should fail when the process never binds its API")
	}
	if !strings.Contains(err.Error(), "did not become ready") {
		t.Fatalf("WaitReady error %q, want a readiness-timeout error", err)
	}
	if elapsed := time.Since(start); elapsed < 1900*time.Millisecond {
		t.Fatalf("WaitReady returned after %v, want the full timeout", elapsed)
	}
}

// TestXrayUpdateTarget: the Windows update target comes from the
// configured binary folder, never the process working directory —
// updating ./bin while the panel runs the binary from its configured
// folder updated a different file and kept the old version running.
func TestXrayUpdateTarget(t *testing.T) {
	binDir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", binDir)
	// The working directory is deliberately different from the
	// configured binary folder.
	t.Chdir(t.TempDir())

	target, entry := xrayUpdateTarget("windows")
	if target != filepath.Join(binDir, "xray-windows-amd64.exe") {
		t.Fatalf("windows target %q, want the configured bin folder", target)
	}
	if entry != "xray.exe" {
		t.Fatalf("windows entry %q, want xray.exe", entry)
	}
	target, entry = xrayUpdateTarget("linux")
	if target != xray.GetBinaryPath() {
		t.Fatalf("linux target %q, want %q", target, xray.GetBinaryPath())
	}
	if entry != "xray" {
		t.Fatalf("linux entry %q, want xray", entry)
	}
}
