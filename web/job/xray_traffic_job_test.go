package job

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

func TestInformTrafficToExternalAPI_BlocksPrivateURL(t *testing.T) {
	setupIntegrationDB(t)

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := service.SettingService{}
	// Save-time guard: a loopback URL must not be storable.
	if err := svc.SetExternalTrafficInformURI(server.URL + "/hook"); err == nil {
		t.Fatalf("saving a loopback inform URL should fail, got nil error")
	}

	// Use-time guard: force the value in anyway (as a database import
	// would) and prove the report still never leaves the panel.
	if err := database.GetDB().Create(&model.Setting{Key: "externalTrafficInformURI", Value: server.URL + "/hook"}).Error; err != nil {
		t.Fatalf("seed inform URI: %v", err)
	}
	job := &XrayTrafficJob{settingService: svc}
	job.informTrafficToExternalAPI(
		[]*xray.Traffic{},
		[]*xray.ClientTraffic{{Email: "victim@example.com", Up: 1, Down: 2}},
	)
	if got := hits.Load(); got != 0 {
		t.Fatalf("private inform URL was contacted %d times, want 0", got)
	}
}

func TestInformTrafficToExternalAPI_PostsPayload(t *testing.T) {
	setupIntegrationDB(t)

	var gotMethod, gotContentType string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	// The test server is loopback, so the SSRF seams are overridden
	// here; the SSRF behavior itself is covered by the block test above
	// and by the CustomGeo transport tests.
	origValidate := trafficInformValidateURL
	trafficInformValidateURL = func(raw string) (string, error) { return raw, nil }
	t.Cleanup(func() { trafficInformValidateURL = origValidate })
	origClient := trafficInformClient
	trafficInformClient = &http.Client{Timeout: 10 * time.Second}
	t.Cleanup(func() { trafficInformClient = origClient })

	if err := database.GetDB().Create(&model.Setting{Key: "externalTrafficInformURI", Value: server.URL + "/hook"}).Error; err != nil {
		t.Fatalf("seed inform URI: %v", err)
	}
	job := &XrayTrafficJob{settingService: service.SettingService{}}
	job.informTrafficToExternalAPI(
		[]*xray.Traffic{},
		[]*xray.ClientTraffic{{Email: "victim@example.com", Up: 1, Down: 2}},
	)
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
	if !strings.HasPrefix(gotContentType, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", gotContentType)
	}
	var payload map[string]any
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	body := string(gotBody)
	if !strings.Contains(body, "victim@example.com") {
		t.Fatalf("payload missing client email: %s", body)
	}
}

func TestInformTrafficToExternalAPI_CapsResponseBody(t *testing.T) {
	setupIntegrationDB(t)

	// An endpoint that drips bytes forever. Without the 1 MiB read cap
	// the report call would never return.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}
		chunk := make([]byte, 64<<10)
		for {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			flusher.Flush()
		}
	}))
	defer server.Close()

	origValidate := trafficInformValidateURL
	trafficInformValidateURL = func(raw string) (string, error) { return raw, nil }
	t.Cleanup(func() { trafficInformValidateURL = origValidate })
	origClient := trafficInformClient
	trafficInformClient = &http.Client{Timeout: 30 * time.Second}
	t.Cleanup(func() { trafficInformClient = origClient })

	if err := database.GetDB().Create(&model.Setting{Key: "externalTrafficInformURI", Value: server.URL + "/hook"}).Error; err != nil {
		t.Fatalf("seed inform URI: %v", err)
	}
	job := &XrayTrafficJob{settingService: service.SettingService{}}

	done := make(chan struct{})
	go func() {
		defer close(done)
		job.informTrafficToExternalAPI(
			[]*xray.Traffic{},
			[]*xray.ClientTraffic{{Email: "victim@example.com", Up: 1, Down: 2}},
		)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("inform did not return within 10s against an unbounded response body")
	}
}
