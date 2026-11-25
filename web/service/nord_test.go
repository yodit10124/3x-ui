package service

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// stubRoundTripper returns canned responses for the NordVPN API client.
type stubRoundTripper struct {
	statusCode int
	status     string
	body       string
}

func (s stubRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		Status:     s.status,
		StatusCode: s.statusCode,
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Header:     make(http.Header),
	}, nil
}

func stubNordClient(statusCode int, status, body string) *http.Client {
	return &http.Client{Transport: stubRoundTripper{statusCode: statusCode, status: status, body: body}}
}

// L-18: GetServers must keep low-load servers (load < 70), not the
// near-unfiltered old condition (load > 7).
func TestGetServersKeepsLowLoadServers(t *testing.T) {
	old := nordHTTPClient
	nordHTTPClient = stubNordClient(http.StatusOK, "200 OK", `{"servers": [
		{"id": 1, "load": 5},
		{"id": 2, "load": 50},
		{"id": 3, "load": 69.9},
		{"id": 4, "load": 70},
		{"id": 5, "load": 85},
		{"id": 6, "load": 95}
	]}`)
	defer func() { nordHTTPClient = old }()

	svc := &NordService{}
	result, err := svc.GetServers("1")
	if err != nil {
		t.Fatalf("GetServers returned error: %v", err)
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(result), &data); err != nil {
		t.Fatalf("GetServers returned invalid JSON: %v", err)
	}
	servers, ok := data["servers"].([]any)
	if !ok {
		t.Fatalf("result has no servers list: %s", result)
	}
	if len(servers) != 3 {
		t.Fatalf("expected 3 low-load servers, got %d: %s", len(servers), result)
	}
	for _, s := range servers {
		server := s.(map[string]any)
		if load := server["load"].(float64); load >= 70 {
			t.Fatalf("server with load %v should have been filtered out: %s", load, result)
		}
	}
}

// L-18: GetCountries must reject non-200 responses instead of
// returning an error page as the country list.
func TestGetCountriesRejectsNon200(t *testing.T) {
	old := nordHTTPClient
	nordHTTPClient = stubNordClient(http.StatusInternalServerError, "500 Internal Server Error", `{"error": "boom"}`)
	defer func() { nordHTTPClient = old }()

	svc := &NordService{}
	if _, err := svc.GetCountries(); err == nil {
		t.Fatal("GetCountries should reject a 500 response")
	}
}

func TestGetCountriesReturnsBodyOn200(t *testing.T) {
	old := nordHTTPClient
	nordHTTPClient = stubNordClient(http.StatusOK, "200 OK", `[{"id": 1, "name": "United States"}]`)
	defer func() { nordHTTPClient = old }()

	svc := &NordService{}
	body, err := svc.GetCountries()
	if err != nil {
		t.Fatalf("GetCountries returned error: %v", err)
	}
	if !strings.Contains(body, "United States") {
		t.Fatalf("unexpected body: %s", body)
	}
}
