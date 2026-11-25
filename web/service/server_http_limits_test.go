package service

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestGetPublicIPBodyLimit (L-12): the IP lookup must not read an
// unbounded body, and a stalled endpoint must hit the timeout.
func TestGetPublicIPBodyLimit(t *testing.T) {
	if got := getPublicIP(httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.7"))
	})).URL); got != "203.0.113.7" {
		t.Fatalf("getPublicIP(valid) = %q, want 203.0.113.7", got)
	}

	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("9"), 1<<20))
	}))
	defer huge.Close()
	if got := getPublicIP(huge.URL); got != "N/A" {
		t.Fatalf("getPublicIP(1 MiB body) = %q, want N/A", got)
	}

	oldTimeout := getPublicIPTimeout
	getPublicIPTimeout = 100 * time.Millisecond
	t.Cleanup(func() { getPublicIPTimeout = oldTimeout })
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer stalled.Close()
	start := time.Now()
	if got := getPublicIP(stalled.URL); got != "N/A" {
		t.Fatalf("getPublicIP(stalled) = %q, want N/A", got)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("getPublicIP(stalled) took %v, want it to fail fast on the timeout", time.Since(start))
	}
}

// TestFetchXrayVersionsLimits (L-12): the releases list request must
// have a timeout and a bounded body.
func TestFetchXrayVersionsLimits(t *testing.T) {
	valid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"tag_name":"v26.3.10"},{"tag_name":"v1.2.3"}]`))
	}))
	defer valid.Close()
	versions, err := fetchXrayVersions(valid.URL)
	if err != nil {
		t.Fatalf("fetchXrayVersions(valid): %v", err)
	}
	if len(versions) != 1 || versions[0] != "v26.3.10" {
		t.Fatalf("fetchXrayVersions(valid) = %v, want [v26.3.10]", versions)
	}

	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 1<<20))
	}))
	defer huge.Close()
	oldCap := xrayVersionsMaxBodyBytes
	xrayVersionsMaxBodyBytes = 1024
	t.Cleanup(func() { xrayVersionsMaxBodyBytes = oldCap })
	if _, err := fetchXrayVersions(huge.URL); err == nil {
		t.Fatal("fetchXrayVersions(1 MiB body over a 1 KiB cap) should fail")
	}

	errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	}))
	defer errServer.Close()
	if _, err := fetchXrayVersions(errServer.URL); err == nil || !strings.Contains(err.Error(), "API rate limit exceeded") {
		t.Fatalf("fetchXrayVersions(error status) err = %v, want the GitHub message", err)
	}

	oldTimeout := xrayVersionsTimeout
	xrayVersionsTimeout = 100 * time.Millisecond
	t.Cleanup(func() { xrayVersionsTimeout = oldTimeout })
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer stalled.Close()
	start := time.Now()
	if _, err := fetchXrayVersions(stalled.URL); err == nil {
		t.Fatal("fetchXrayVersions(stalled) should fail")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("fetchXrayVersions(stalled) took %v, want it to fail fast on the timeout", time.Since(start))
	}
}

// TestFetchLatestPanelVersionLimits (L-12): same bounds on the panel
// version check.
func TestFetchLatestPanelVersionLimits(t *testing.T) {
	oldURL := panelReleasesURL
	t.Cleanup(func() { panelReleasesURL = oldURL })

	valid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"tag_name":"v2.9.4-c6"}]`))
	}))
	defer valid.Close()
	panelReleasesURL = valid.URL
	if got, err := fetchLatestPanelVersion(); err != nil || got != "v2.9.4-c6" {
		t.Fatalf("fetchLatestPanelVersion(valid) = (%q, %v), want (v2.9.4-c6, nil)", got, err)
	}

	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 1<<20))
	}))
	defer huge.Close()
	oldCap := panelVersionMaxBodyBytes
	panelVersionMaxBodyBytes = 1024
	t.Cleanup(func() { panelVersionMaxBodyBytes = oldCap })
	panelReleasesURL = huge.URL
	if _, err := fetchLatestPanelVersion(); err == nil {
		t.Fatal("fetchLatestPanelVersion(1 MiB body over a 1 KiB cap) should fail")
	}

	oldTimeout := panelVersionTimeout
	panelVersionTimeout = 100 * time.Millisecond
	t.Cleanup(func() { panelVersionTimeout = oldTimeout })
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer stalled.Close()
	panelReleasesURL = stalled.URL
	start := time.Now()
	if _, err := fetchLatestPanelVersion(); err == nil {
		t.Fatal("fetchLatestPanelVersion(stalled) should fail")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("fetchLatestPanelVersion(stalled) took %v, want it to fail fast on the timeout", time.Since(start))
	}
}
