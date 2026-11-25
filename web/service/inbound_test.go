package service

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
)

// N-2: InboundService.GetOnlineClients dereferenced the package-global
// Xray process pointer without a nil guard. With Xray never started it
// must return nil instead of panicking.
func TestInboundGetOnlineClientsWithNilXrayProcess(t *testing.T) {
	oldP := p
	p = nil
	t.Cleanup(func() { p = oldP })
	if got := (&InboundService{}).GetOnlineClients(); got != nil {
		t.Fatalf("GetOnlineClients with nil Xray process returned %v, want nil", got)
	}
}

// TestUpdateInboundClientWithNilXrayProcess (leftover 1): with Xray
// never started (p is nil), a legit client update — the path a TG
// user bind takes via SetClientTelegramUserID — must persist the
// change instead of panicking on p.GetAPIPort(), same class as H-2.
func TestUpdateInboundClientWithNilXrayProcess(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })

	oldP := p
	p = nil
	t.Cleanup(func() { p = oldP })

	svc := &InboundService{}
	const clientID = "11111111-1111-4111-8111-111111111111"
	created, _, err := svc.AddInbound(&model.Inbound{
		Protocol: "vmess", Port: 10002, Listen: "0.0.0.0",
		Settings: `{"clients":[{"id":"` + clientID + `","email":"old@example.com","enable":true}]}`,
	})
	if err != nil {
		t.Fatalf("AddInbound: %v", err)
	}

	// Same client, only a tgId attached — the TG bind shape.
	updated := *created
	updated.Settings = `{"clients":[{"id":"` + clientID + `","email":"old@example.com","enable":true,"tgId":12345}]}`
	needRestart, err := svc.UpdateInboundClient(&updated, clientID)
	if err != nil {
		t.Fatalf("UpdateInboundClient with nil Xray process: %v", err)
	}
	if needRestart {
		t.Fatalf("UpdateInboundClient with nil Xray process returned needRestart=true, want false (Xray reads the DB on its next start)")
	}

	stored, err := svc.GetInbound(created.Id)
	if err != nil {
		t.Fatalf("GetInbound: %v", err)
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(stored.Settings), &settings); err != nil {
		t.Fatalf("stored settings are not JSON: %v", err)
	}
	clients, _ := settings["clients"].([]any)
	if len(clients) != 1 {
		t.Fatalf("stored clients = %d, want 1", len(clients))
	}
	client, _ := clients[0].(map[string]any)
	if got, _ := client["tgId"].(float64); got != 12345 {
		t.Fatalf("stored tgId = %v, want 12345 (change was not persisted)", client["tgId"])
	}
}
