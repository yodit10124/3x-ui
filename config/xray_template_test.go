package config

import (
	"os"
	"path/filepath"
	"testing"
)

// H-3 / H-7: the shared template validator used by the save path
// (web/service.CheckXrayConfig), the import path
// (database.ValidateImportedXrayConfig) and xray.Process.Start()
// (via ValidateXrayRuntimeConfig).
func TestValidateXrayTemplateConfig(t *testing.T) {
	logDir := t.TempDir()
	t.Setenv("XUI_LOG_FOLDER", logDir)
	goodLog := `"access": "` + filepath.Join(logDir, "access.log") + `", "error": "` + filepath.Join(logDir, "error.log") + `"`

	// The shipped default template must always pass.
	raw, err := os.ReadFile(filepath.Join("..", "web", "service", "config.json"))
	if err != nil {
		t.Fatalf("read default template: %v", err)
	}
	if err := ValidateXrayTemplateConfig(string(raw)); err != nil {
		t.Fatalf("default template should pass, got %v", err)
	}
	if err := ValidateXrayRuntimeConfig(string(raw)); err != nil {
		t.Fatalf("default template should pass runtime validation, got %v", err)
	}

	cases := []struct {
		name    string
		cfg     string
		wantErr bool
	}{
		{"empty config", `{}`, false},
		{"no routing at all", `{"log": {` + goodLog + `}}`, false},
		{"benign log paths", `{"log": {` + goodLog + `}}`, false},
		{"malicious log path", `{"log": {"access": "/tmp/evil.log"}}`, true},
		{"invalid json", `not json`, true},

		// H-3: api inbound listen.
		{"api listen 127.0.0.1", `{"inbounds": [{"tag": "api", "listen": "127.0.0.1", "port": 62789}]}`, false},
		{"api listen localhost", `{"inbounds": [{"tag": "api", "listen": "localhost", "port": 62789}]}`, false},
		{"api listen ::1", `{"inbounds": [{"tag": "api", "listen": "::1", "port": 62789}]}`, false},
		{"api listen empty is 0.0.0.0", `{"inbounds": [{"tag": "api", "port": 62789}]}`, true},
		{"api listen empty string", `{"inbounds": [{"tag": "api", "listen": "", "port": 62789}]}`, true},
		{"api listen 0.0.0.0", `{"inbounds": [{"tag": "api", "listen": "0.0.0.0", "port": 62789}]}`, true},
		{"non-api inbound may listen anywhere", `{"inbounds": [{"tag": "vless", "listen": "0.0.0.0", "port": 443}]}`, false},

		// H-7: metrics.
		{"metrics loopback", `{"metrics": {"listen": "127.0.0.1:11111"}}`, false},
		{"metrics localhost", `{"metrics": {"listen": "localhost:11111"}}`, false},
		{"metrics empty", `{"metrics": {}}`, false},
		{"metrics 0.0.0.0", `{"metrics": {"listen": "0.0.0.0:11111"}}`, true},
		{"metrics empty host binds all", `{"metrics": {"listen": ":11111"}}`, true},

		// H-7: reverse.
		{"reverse empty object", `{"reverse": {}}`, false},
		{"reverse empty arrays", `{"reverse": {"bridges": [], "portals": []}}`, false},
		{"reverse bridge", `{"reverse": {"bridges": [{"tag": "b", "domain": "x"}]}}`, true},
		{"reverse portal", `{"reverse": {"portals": [{"tag": "p", "domain": "x"}]}}`, true},

		// H-7: routing geoip:private.
		{"routing private blocked", `{"routing": {"rules": [{"type": "field", "outboundTag": "blocked", "ip": ["geoip:private"]}]}}`, false},
		{"routing private to direct", `{"routing": {"rules": [{"type": "field", "outboundTag": "direct", "ip": ["geoip:private"]}]}}`, true},
		{"routing private via source", `{"routing": {"rules": [{"type": "field", "outboundTag": "direct", "source": ["geoip:private"]}]}}`, true},
		{"routing private via balancer", `{"routing": {"rules": [{"type": "field", "balancerTag": "b", "ip": ["geoip:private"]}]}}`, true},
		{"routing without any private rule", `{"routing": {"rules": [{"type": "field", "outboundTag": "blocked", "protocol": ["bittorrent"]}]}}`, false},
		{"routing empty rules", `{"routing": {"rules": []}}`, false},

		// H-7: freedom.redirect.
		{"freedom redirect empty", `{"outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"redirect": ""}}]}`, false},
		{"freedom redirect set", `{"outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:8080"}}]}`, true},
		{"freedom no settings", `{"outbounds": [{"tag": "direct", "protocol": "freedom"}]}`, false},
		{"non-freedom outbound untouched", `{"outbounds": [{"tag": "x", "protocol": "blackhole", "settings": {}}]}`, false},

		// H-7: forwarding-class inbounds in the template.
		{"api tunnel loopback (default)", `{"inbounds": [{"tag": "api", "listen": "127.0.0.1", "port": 62789, "protocol": "tunnel", "settings": {"address": "127.0.0.1"}}]}`, false},
		{"api tunnel retargeted", `{"inbounds": [{"tag": "api", "listen": "127.0.0.1", "port": 62789, "protocol": "tunnel", "settings": {"address": "192.168.1.1"}}]}`, true},
		{"non-api tunnel inbound", `{"inbounds": [{"tag": "tun1", "listen": "127.0.0.1", "port": 10000, "protocol": "tunnel", "settings": {"address": "127.0.0.1"}}]}`, true},
		{"dokodemo-door inbound", `{"inbounds": [{"tag": "dd", "listen": "127.0.0.1", "port": 10001, "protocol": "dokodemo-door", "settings": {"address": "8.8.8.8", "port": 53}}]}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateXrayTemplateConfig(tc.cfg)
			if tc.wantErr && err == nil {
				t.Errorf("expected rejection, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected pass, got %v", err)
			}
		})
	}
}

// The runtime check (used by xray.Process.Start on the merged config)
// skips only the inbound-protocol rule: panel-managed DB inbounds may
// legitimately use "tunnel". Everything else must behave identically.
func TestValidateXrayRuntimeConfig(t *testing.T) {
	dbTunnel := `{"inbounds": [{"tag": "tun1", "listen": "0.0.0.0", "port": 10000, "protocol": "tunnel", "settings": {"address": "8.8.8.8", "port": 53}}]}`
	if err := ValidateXrayTemplateConfig(dbTunnel); err == nil {
		t.Fatalf("template check should reject a non-api tunnel inbound")
	}
	if err := ValidateXrayRuntimeConfig(dbTunnel); err != nil {
		t.Fatalf("runtime check should allow a panel-managed tunnel inbound, got %v", err)
	}

	// But the runtime check still closes the api / metrics / routing holes.
	for _, cfg := range []string{
		`{"inbounds": [{"tag": "api", "port": 62789}]}`, // empty listen
		`{"inbounds": [{"tag": "api", "listen": "0.0.0.0", "port": 62789}]}`,
		`{"metrics": {"listen": "0.0.0.0:11111"}}`,
		`{"reverse": {"bridges": [{"tag": "b"}]}}`,
		`{"routing": {"rules": [{"type": "field", "outboundTag": "direct", "ip": ["geoip:private"]}]}}`,
		`{"outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"redirect": "127.0.0.1:8080"}}]}`,
		`{"log": {"access": "/tmp/evil.log"}}`,
	} {
		if err := ValidateXrayRuntimeConfig(cfg); err == nil {
			t.Errorf("runtime check should reject: %s", cfg)
		}
	}
}
