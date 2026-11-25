package service

import (
	"encoding/json"
	"path/filepath"
	"strings"
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

// TestAddInboundRejectsUnknownProtocol (L-4): protocols the panel
// does not offer (notably dokodemo-door, which the template checks
// forbid) must not enter through the API.
func TestAddInboundRejectsUnknownProtocol(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })

	svc := &InboundService{}
	for _, protocol := range []model.Protocol{"dokodemo-door", "freedom", "blackhole", "tun", ""} {
		_, _, err := svc.AddInbound(&model.Inbound{
			Protocol: protocol, Port: 10000, Listen: "0.0.0.0",
			Settings: "{}", Tag: "t-" + string(protocol),
		})
		if err == nil {
			t.Fatalf("AddInbound(%q) accepted, want an error", protocol)
		}
	}

	// Every protocol the panel offers must pass the allowlist gate
	// (the call proceeds past it; it may fail later for other
	// reasons, e.g. Xray not running — that is not the gate).
	for _, protocol := range []model.Protocol{"vmess", "vless", "trojan", "shadowsocks", "wireguard", "hysteria", "hysteria2", "mixed", "http", "tunnel"} {
		_, _, err := svc.AddInbound(&model.Inbound{
			Protocol: protocol, Port: 10001, Listen: "0.0.0.0",
			Settings: "{}", Tag: "t-" + string(protocol),
		})
		if err != nil && strings.Contains(err.Error(), "Unsupported protocol") {
			t.Fatalf("AddInbound(%q) rejected by the allowlist, want it to pass the gate", protocol)
		}
	}
}

// TestUpdateInboundRejectsUnknownProtocol (L-4): same allowlist on update.
func TestUpdateInboundRejectsUnknownProtocol(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })

	_, _, err := (&InboundService{}).UpdateInbound(&model.Inbound{
		Id: 1, Protocol: "dokodemo-door", Port: 10000, Listen: "0.0.0.0",
		Settings: "{}", Tag: "t-dokodemo",
	})
	if err == nil {
		t.Fatal("UpdateInbound(dokodemo-door) accepted, want an error")
	}
}

// TestAddInboundRejectsInvalidEmail (L-8): a client email containing
// a newline or "||" could forge [LIMIT_IP] lines in the fail2ban log.
// It must be rejected at creation; a plain address or token label
// passes the gate.
func TestAddInboundRejectsInvalidEmail(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })

	svc := &InboundService{}
	for _, bad := range []string{
		"evil\n|| 1.2.3.4",
		"a@b.com\r\n[LIMIT_IP] x",
		"has space@example.com",
		"quote\"@example.com",
	} {
		settings := `{"clients":[{"email":"` + strings.ReplaceAll(strings.ReplaceAll(bad, `\`, `\\`), `"`, `\"`) + `","id":"550e8400-e29b-41d4-a716-446655440000","enable":true}]}`
		// The newline must survive as a JSON escape, not a raw byte.
		settings = strings.ReplaceAll(settings, "\n", `\n`)
		settings = strings.ReplaceAll(settings, "\r", `\r`)
		_, _, err := svc.AddInbound(&model.Inbound{
			Protocol: "vless", Port: 10000, Listen: "0.0.0.0",
			Settings: settings, Tag: "t-bad", Enable: false,
		})
		if err == nil || !strings.Contains(err.Error(), "invalid client email") {
			t.Fatalf("AddInbound(email %q) err = %v, want an invalid-client-email error", bad, err)
		}
	}

	// Valid emails pass the gate (Enable=false, so no Xray is touched).
	for i, good := range []string{"alice@example.com", "pr4091-abuse"} {
		settings := `{"clients":[{"email":"` + good + `","id":"550e8400-e29b-41d4-a716-446655440000","enable":true}]}`
		if _, _, err := svc.AddInbound(&model.Inbound{
			Protocol: "vless", Port: 10001 + i, Listen: "0.0.0.0",
			Settings: settings, Tag: "t-" + good, Enable: false,
		}); err != nil {
			t.Fatalf("AddInbound(email %q) err = %v, want it accepted", good, err)
		}
	}
}

// TestUpdateInboundRejectsInvalidEmail (L-8): same gate on update.
func TestUpdateInboundRejectsInvalidEmail(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "x-ui.db")
	if err := database.InitDB(dbPath); err != nil {
		t.Fatalf("InitDB: %v", err)
	}
	t.Cleanup(func() { database.CloseDB() })

	seed := &model.Inbound{
		Protocol: "vless", Port: 10000, Listen: "0.0.0.0",
		Settings: `{"clients":[{"email":"alice@example.com","id":"550e8400-e29b-41d4-a716-446655440000","enable":true}]}`,
		Tag:      "t-seed", Enable: false,
	}
	if err := database.GetDB().Create(seed).Error; err != nil {
		t.Fatalf("seed inbound: %v", err)
	}

	_, _, err := (&InboundService{}).UpdateInbound(&model.Inbound{
		Id: seed.Id, Protocol: "vless", Port: 10000, Listen: "0.0.0.0",
		Settings: `{"clients":[{"email":"evil\n|| 1.2.3.4","id":"550e8400-e29b-41d4-a716-446655440000","enable":true}]}`,
		Tag:      "t-seed", Enable: false,
	})
	if err == nil || !strings.Contains(err.Error(), "invalid client email") {
		t.Fatalf("UpdateInbound(bad email) err = %v, want an invalid-client-email error", err)
	}
}

// TestUpdateInboundClientWithNilXrayProcess (leftover 1): with Xray
// never started (p is nil), a legit client update must persist the
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

	// Same client, only a comment attached.
	updated := *created
	updated.Settings = `{"clients":[{"id":"` + clientID + `","email":"old@example.com","enable":true,"comment":"nil-xray"}]}`
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
	if got, _ := client["comment"].(string); got != "nil-xray" {
		t.Fatalf("stored comment = %v, want nil-xray (change was not persisted)", client["comment"])
	}
}
