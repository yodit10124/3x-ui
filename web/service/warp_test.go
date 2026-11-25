package service

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestParseRegResponse (L-13): a 429-style reply without id/token, or
// a reply without an account/license, must return an error — never
// panic on an unchecked type assertion.
func TestParseRegResponse(t *testing.T) {
	valid := `{"id":"dev-1","token":"tok-1","account":{"license":"lic-1"}}`
	deviceID, token, license, err := parseRegResponse([]byte(valid))
	if err != nil || deviceID != "dev-1" || token != "tok-1" || license != "lic-1" {
		t.Fatalf("parseRegResponse(valid) = (%q, %q, %q, %v)", deviceID, token, license, err)
	}

	cases := map[string]string{
		"429 reply":      `{"success":false,"errors":[{"code":1015,"message":"rate limited"}]}`,
		"missing id":     `{"token":"tok-1","account":{"license":"lic-1"}}`,
		"missing token":  `{"id":"dev-1","account":{"license":"lic-1"}}`,
		"account string": `{"id":"dev-1","token":"tok-1","account":"oops"}`,
		"missing lic":    `{"id":"dev-1","token":"tok-1","account":{}}`,
		"empty lic":      `{"id":"dev-1","token":"tok-1","account":{"license":""}}`,
		"not json":       `not json`,
	}
	for name, body := range cases {
		if _, _, _, err := parseRegResponse([]byte(body)); err == nil {
			t.Fatalf("parseRegResponse(%s) should fail", name)
		}
	}
}

// TestCheckLicenseResponse (L-13): success:false with a missing,
// empty, or non-object errors array must return a readable error —
// never panic on errorArr[0].(map[string]any).
func TestCheckLicenseResponse(t *testing.T) {
	if err := checkLicenseResponse([]byte(`{"success":true}`)); err != nil {
		t.Fatalf("checkLicenseResponse(success) = %v, want nil", err)
	}
	if err := checkLicenseResponse([]byte(`{}`)); err != nil {
		t.Fatalf("checkLicenseResponse(no success key) = %v, want nil", err)
	}

	err := checkLicenseResponse([]byte(`{"success":false,"errors":[{"code":1015,"message":"rate limited"}]}`))
	if err == nil || !strings.Contains(err.Error(), "1015") || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("checkLicenseResponse(error object) = %v, want code and message", err)
	}
	for name, body := range map[string]string{
		"empty errors":   `{"success":false,"errors":[]}`,
		"missing errors": `{"success":false}`,
		"string error":   `{"success":false,"errors":["oops"]}`,
		"not json":       `not json`,
	} {
		if err := checkLicenseResponse([]byte(body)); err == nil {
			t.Fatalf("checkLicenseResponse(%s) should fail", name)
		}
	}
}

// TestWarpRegRequestMarshal (L-13): the registration payload must
// stay valid JSON when the hostname carries quotes or backslashes.
func TestWarpRegRequestMarshal(t *testing.T) {
	raw, err := json.Marshal(warpRegRequest{
		Key: "pub", Tos: "2026-11-25T00:00:00.000Z", Type: "PC", Model: "x-ui", Name: `host"na\me`,
	})
	if err != nil {
		t.Fatalf("json.Marshal(warpRegRequest): %v", err)
	}
	var back map[string]string
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("registration payload is not valid JSON: %v (%s)", err, raw)
	}
	if back["name"] != `host"na\me` {
		t.Fatalf("hostname round-trip = %q", back["name"])
	}
}

// TestDoWarpRequestLimits (L-13): the shared client must time out
// and the body must be capped.
func TestDoWarpRequestLimits(t *testing.T) {
	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), 1<<20))
	}))
	defer huge.Close()
	oldCap := warpMaxBodyBytes
	warpMaxBodyBytes = 1024
	t.Cleanup(func() { warpMaxBodyBytes = oldCap })
	req, _ := http.NewRequest("GET", huge.URL, nil)
	if _, err := doWarpRequest(req); err == nil {
		t.Fatal("doWarpRequest(1 MiB body over a 1 KiB cap) should fail")
	}

	oldClient := warpHTTPClient
	warpHTTPClient = &http.Client{Timeout: 100 * time.Millisecond}
	t.Cleanup(func() { warpHTTPClient = oldClient })
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer stalled.Close()
	req, _ = http.NewRequest("GET", stalled.URL, nil)
	start := time.Now()
	if _, err := doWarpRequest(req); err == nil {
		t.Fatal("doWarpRequest(stalled) should fail")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("doWarpRequest(stalled) took %v, want it to fail fast on the timeout", time.Since(start))
	}
}
