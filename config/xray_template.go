package config

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// ValidateXrayTemplateConfig validates a full Xray template configuration
// (the xrayTemplateConfig string saved from the panel, or stored in an
// imported database).
//
// It lives in the config package — rather than in web/service — so that
// database.ValidateImportedXrayConfig and xray.Process.Start() can reuse
// the exact same checks without an import cycle: database and xray cannot
// import web/service, but all three already import config.
//
// Checks (H-3 / H-7):
//   - log.access / log.error must be inside the panel log folder
//     (ValidateXrayLogPaths, H1 / CVE-2026-55477).
//   - an "api" inbound must listen on a loopback address; an empty listen
//     is rejected too, because Xray treats empty as 0.0.0.0.
//   - forwarding-class inbounds: dokodemo-door is rejected outright, and
//     tunnel is only allowed for the built-in "api" inbound (the shipped
//     default template uses tunnel for api). A retargeted api tunnel whose
//     settings.address is not loopback is also rejected.
//   - a freedom outbound with a non-empty settings.redirect is rejected.
//   - metrics.listen must be loopback or empty.
//   - a non-empty reverse section (bridges/portals) is rejected.
//   - routing: any rule matching geoip:private (in "ip" or "source") whose
//     outboundTag is not "blocked" is rejected.
//
// Deliberately NOT checked here: whether a routing section that never
// mentions geoip:private is missing the default geoip:private -> blocked
// rule. That state is indistinguishable from a legitimate minimal/custom
// routing config that never contained the rule, so rejecting it would
// break configs that were never derived from the default template.
// Only the positively identifiable case (a private rule routed somewhere
// other than "blocked") is rejected. Likewise, a catch-all rule placed
// above the blocked rule that shadows it without mentioning geoip:private
// is not detected.
func ValidateXrayTemplateConfig(raw string) error {
	return validateXrayConfig(raw, true)
}

// ValidateXrayRuntimeConfig validates the merged runtime configuration
// that xray.Process.Start() is about to write to disk and launch: the
// template plus the panel-managed inbounds from the database.
//
// It is the same core check as ValidateXrayTemplateConfig, except the
// inbound-protocol rule is skipped: panel-managed (DB) inbounds may
// legitimately use the "tunnel" protocol (it is one of the protocols the
// panel UI offers), so that rule can only be applied to the raw template,
// where the only legitimate forwarding inbound is the built-in api one.
// Everything else (log paths, api listen, metrics, reverse, routing,
// freedom.redirect) comes from the template only, so it is checked here
// exactly as in the template case.
func ValidateXrayRuntimeConfig(raw string) error {
	return validateXrayConfig(raw, false)
}

// xrayTemplateCheck is the subset of the Xray config schema this
// validation understands. Anything else is passed through untouched.
type xrayTemplateCheck struct {
	Log struct {
		Access string `json:"access"`
		Error  string `json:"error"`
	} `json:"log"`
	Inbounds []struct {
		Tag      string          `json:"tag"`
		Listen   string          `json:"listen"`
		Protocol string          `json:"protocol"`
		Settings json.RawMessage `json:"settings"`
	} `json:"inbounds"`
	Outbounds []struct {
		Protocol string          `json:"protocol"`
		Settings json.RawMessage `json:"settings"`
	} `json:"outbounds"`
	Routing struct {
		Rules []struct {
			OutboundTag string          `json:"outboundTag"`
			BalancerTag string          `json:"balancerTag"`
			IP          json.RawMessage `json:"ip"`
			Source      json.RawMessage `json:"source"`
		} `json:"rules"`
	} `json:"routing"`
	Metrics struct {
		Listen string `json:"listen"`
	} `json:"metrics"`
	Reverse struct {
		Bridges []json.RawMessage `json:"bridges"`
		Portals []json.RawMessage `json:"portals"`
	} `json:"reverse"`
}

// isLoopbackListen reports whether a listen address is one of the loopback
// values the panel accepts: 127.0.0.1, localhost or ::1. Anything else —
// including an empty host, which binds all interfaces — is not loopback.
func isLoopbackListen(listen string) bool {
	host := strings.TrimSpace(listen)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// net.SplitHostPort fails when there is no port (plain "127.0.0.1");
	// in that case host is already the bare address.
	host = strings.Trim(host, "[]")
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

// containsGeoIPPrivate reports whether a routing match list (the "ip" or
// "source" field, normally []string, occasionally a single string) mentions
// geoip:private.
func containsGeoIPPrivate(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		for _, v := range list {
			if strings.EqualFold(strings.TrimSpace(v), "geoip:private") {
				return true
			}
		}
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return strings.EqualFold(strings.TrimSpace(single), "geoip:private")
	}
	return false
}

func validateXrayConfig(raw string, checkInboundProtocols bool) error {
	var cfg xrayTemplateCheck
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return fmt.Errorf("xray template config invalid: %w", err)
	}

	// H1: log paths must stay inside the panel log folder.
	if err := ValidateXrayLogPaths(cfg.Log.Access, cfg.Log.Error); err != nil {
		return err
	}

	// H-3: the api inbound exposes an unauthenticated gRPC API. It must
	// bind loopback only; an empty listen is rejected because Xray treats
	// empty as 0.0.0.0.
	for _, inbound := range cfg.Inbounds {
		if inbound.Tag != "api" {
			continue
		}
		if !isLoopbackListen(inbound.Listen) {
			return fmt.Errorf("xray api inbound must listen on 127.0.0.1 only, got %q", inbound.Listen)
		}
	}

	// H-7 (template only): forwarding-class inbounds.
	if checkInboundProtocols {
		for _, inbound := range cfg.Inbounds {
			switch strings.ToLower(inbound.Protocol) {
			case "dokodemo-door":
				return fmt.Errorf("xray template must not contain a dokodemo-door inbound (tag %q)", inbound.Tag)
			case "tunnel":
				if inbound.Tag == "api" {
					// The shipped default template uses tunnel for the
					// api inbound, pointing at 127.0.0.1. Keep allowing
					// that, but reject a retargeted api tunnel.
					if len(inbound.Settings) > 0 {
						var settings struct {
							Address string `json:"address"`
						}
						if err := json.Unmarshal(inbound.Settings, &settings); err != nil {
							return fmt.Errorf("xray api inbound has invalid settings: %w", err)
						}
						if addr := strings.TrimSpace(settings.Address); addr != "" && !isLoopbackListen(addr) {
							return fmt.Errorf("xray api tunnel inbound must forward to a loopback address, got %q", addr)
						}
					}
					continue
				}
				return fmt.Errorf("xray template must not contain a tunnel inbound (tag %q); only the built-in api inbound may use tunnel", inbound.Tag)
			}
		}
	}

	// H-7: a freedom outbound with redirect rewrites traffic to a fixed
	// address. The shipped default has "redirect": "".
	for _, outbound := range cfg.Outbounds {
		if !strings.EqualFold(outbound.Protocol, "freedom") {
			continue
		}
		if len(outbound.Settings) == 0 {
			continue
		}
		var settings struct {
			Redirect string `json:"redirect"`
		}
		if err := json.Unmarshal(outbound.Settings, &settings); err != nil {
			return fmt.Errorf("xray freedom outbound has invalid settings: %w", err)
		}
		if strings.TrimSpace(settings.Redirect) != "" {
			return fmt.Errorf("xray freedom outbound must not set redirect (got %q)", settings.Redirect)
		}
	}

	// H-7: metrics.listen exposes unauthenticated Prometheus metrics.
	if strings.TrimSpace(cfg.Metrics.Listen) != "" && !isLoopbackListen(cfg.Metrics.Listen) {
		return fmt.Errorf("xray metrics must listen on 127.0.0.1 only, got %q", cfg.Metrics.Listen)
	}

	// H-7: reverse bridges/portals expose internal TCP services.
	if len(cfg.Reverse.Bridges) > 0 || len(cfg.Reverse.Portals) > 0 {
		return fmt.Errorf("xray template must not contain a reverse section")
	}

	// H-7: routing must keep geoip:private traffic blocked. Only the
	// positively identifiable case is rejected: a rule that matches
	// geoip:private but routes it somewhere other than "blocked".
	// A routing section with no geoip:private rule at all is allowed —
	// see the doc comment on ValidateXrayTemplateConfig.
	for i, rule := range cfg.Routing.Rules {
		if !containsGeoIPPrivate(rule.IP) && !containsGeoIPPrivate(rule.Source) {
			continue
		}
		if rule.OutboundTag != "blocked" {
			return fmt.Errorf("xray routing rule %d sends geoip:private traffic to %q instead of \"blocked\"", i, rule.OutboundTag)
		}
	}

	return nil
}
