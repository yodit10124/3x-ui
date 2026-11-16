package service

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/xray"
	statsService "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
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

// foreignStatsServer answers QueryStats the way a real Xray
// would. It stands in for the foreign service the auditor found
// listening on the default API port: a probe aimed at that port
// would take its answer for our Xray's.
type foreignStatsServer struct {
	statsService.UnimplementedStatsServiceServer
}

func (foreignStatsServer) QueryStats(context.Context, *statsService.QueryStatsRequest) (*statsService.QueryStatsResponse, error) {
	return &statsService.QueryStatsResponse{}, nil
}

// plantForeignAPIServer puts a foreign gRPC stats server on the
// default API port 127.0.0.1:62789. If the port is already taken
// on this machine, the environment already provides the foreign
// service the test is about, so there is nothing left to plant.
func plantForeignAPIServer(t *testing.T) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:62789")
	if err != nil {
		t.Logf("could not plant a foreign API server on 62789: %v", err)
		return
	}
	srv := grpc.NewServer()
	statsService.RegisterStatsServiceServer(srv, foreignStatsServer{})
	go srv.Serve(ln)
	t.Cleanup(srv.Stop)
}

// TestWaitReadyNeverReady: a process that stays alive but never
// binds its management API must fail the readiness check on
// timeout, not pass on liveness alone — even when a foreign
// service answers QueryStats on the default API port. The probe
// must go to this start's own ephemeral port, never to 62789.
func TestWaitReadyNeverReady(t *testing.T) {
	setupImportTestEnv(t, true)
	plantForeignAPIServer(t)
	if err := (&XrayService{}).RestartXray(true); err != nil {
		t.Fatalf("RestartXray: %v", err)
	}
	if port := p.GetAPIPort(); port <= 0 || port == 62789 {
		t.Fatalf("API port %d, want a fresh ephemeral port, not the default 62789", port)
	}
	// The on-disk config is what the process really runs with:
	// its api port must be the same ephemeral one.
	configData, err := os.ReadFile(filepath.Join(os.Getenv("XUI_BIN_FOLDER"), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var written struct {
		Inbounds []struct {
			Tag  string `json:"tag"`
			Port int    `json:"port"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(configData, &written); err != nil {
		t.Fatal(err)
	}
	foundAPI := false
	for _, inbound := range written.Inbounds {
		if inbound.Tag == "api" {
			foundAPI = true
			if inbound.Port != p.GetAPIPort() {
				t.Fatalf("config.json api port %d, want the process port %d", inbound.Port, p.GetAPIPort())
			}
		}
	}
	if !foundAPI {
		t.Fatal("config.json has no api inbound, want one")
	}
	start := time.Now()
	err = (&XrayService{}).WaitReady(2 * time.Second)
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

// TestStopWaitsForProcessExit: Stop sends SIGTERM and used to
// return at once, so a caller that started a replacement right
// after Stop could race the old process for its ports — and the
// readiness probe could connect to the OLD api and declare the new
// process ready early. The fake traps SIGTERM and exits a second
// later: Stop must wait for it instead of returning while it still
// runs.
func TestStopWaitsForProcessExit(t *testing.T) {
	setupImportTestEnv(t, false)
	binDir := os.Getenv("XUI_BIN_FOLDER")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo \"Xray 99.0-test (test)\"; exit 0; fi\ntrap 'sleep 1; exit 0' TERM\nwhile true; do sleep 1; done\n"
	if err := os.WriteFile(filepath.Join(binDir, xray.GetBinaryName()), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = (&XrayService{}).StopXray() })

	if err := (&XrayService{}).RestartXray(true); err != nil {
		t.Fatalf("RestartXray: %v", err)
	}
	if !(&XrayService{}).IsXrayRunning() {
		t.Fatal("Xray should be running before Stop")
	}
	start := time.Now()
	if err := (&XrayService{}).StopXray(); err != nil {
		t.Fatalf("StopXray: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 800*time.Millisecond {
		t.Fatalf("Stop returned after %v, want it to wait for the slow-exiting process", elapsed)
	}
	if (&XrayService{}).IsXrayRunning() {
		t.Fatal("Xray still running after Stop returned")
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
