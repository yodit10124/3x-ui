package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
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
//   - a loopback outbound must not target the "api" inbound: it would
//     re-dispatch unauthenticated proxy traffic straight into the
//     unauthenticated Xray gRPC API (HandlerService), bypassing the
//     geoip:private rule and the per-start ephemeral API port.
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
		Tag      string          `json:"tag"`
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
//
// Besides the exact "geoip:private" form, several spellings that mean the
// same thing to Xray are treated as private (L-3, N-1):
//   - "ext:<file>:private" / "ext-ip:<file>:private" (an external geoip
//     file's private category; Xray accepts both prefixes);
//   - a literal CIDR whose range overlaps any private range
//     (e.g. "192.0.0.0/8" covers 192.168.0.0/16), not just one whose
//     network address is private;
//   - a bare IP, which Xray treats as a /32 (or /128) rule;
//   - a reverse "!X" entry, judged by its complement: it counts as
//     private unless X covers the whole private space.
//
// A catch-all "0.0.0.0/0" (or "::/0") is deliberately NOT treated as
// private: it matches everything, and rejecting every catch-all rule
// would break legitimate minimal configs.
func containsGeoIPPrivate(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		for _, v := range list {
			if matchesPrivateEntry(v) {
				return true
			}
		}
		return false
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return matchesPrivateEntry(single)
	}
	return false
}

// privatePrefixes are the address ranges geoip:private covers (RFC 1918
// private, loopback, link-local, "this network"), used for CIDR overlap
// and bare-IP checks. CGNAT (100.64.0.0/10) and the reserved 240.0.0.0/4
// range are deliberately NOT included: Go's IsPrivate does not cover
// them, and whether geoip.dat counts them as private is unverified, so
// they stay out of this check's scope.
var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// matchesPrivateEntry reports whether one routing match entry means
// "private addresses" to Xray.
func matchesPrivateEntry(entry string) bool {
	v := strings.TrimSpace(entry)
	if v == "" {
		return false
	}
	// Reverse match: "!X" matches everything X does not. It sends
	// private traffic to the outbound unless X covers the whole
	// private space ("!geoip:private" is harmless and allowed;
	// "!geoip:cn" and "!10.0.0.0/8" are not).
	if strings.HasPrefix(v, "!") {
		return !coversAllPrivate(strings.TrimSpace(v[1:]))
	}
	if strings.EqualFold(v, "geoip:private") {
		return true
	}
	// ext:<file>:private / ext-ip:<file>:private — the category after
	// the last colon is what Xray looks up in the external geoip file.
	lower := strings.ToLower(v)
	if strings.HasPrefix(lower, "ext:") || strings.HasPrefix(lower, "ext-ip:") {
		if idx := strings.LastIndex(v, ":"); idx >= 0 && strings.EqualFold(strings.TrimSpace(v[idx+1:]), "private") {
			return true
		}
	}
	// Literal CIDR: reject when the range overlaps any private range,
	// not just when its network address is private.
	if prefix, err := netip.ParsePrefix(v); err == nil {
		return cidrOverlapsPrivate(prefix)
	}
	// Bare IP: Xray treats it as a /32 (or /128) rule.
	if addr, err := netip.ParseAddr(v); err == nil {
		return isPrivateAddr(addr)
	}
	return false
}

// coversAllPrivate reports whether an entry matches the entire private
// address space, so that its reverse ("!entry") matches no private
// address at all. Only geoip:private (and its ext: spellings) and
// catch-all CIDRs qualify; a single CIDR can only cover all private
// addresses if it is a catch-all.
func coversAllPrivate(entry string) bool {
	v := strings.TrimSpace(entry)
	if strings.EqualFold(v, "geoip:private") {
		return true
	}
	lower := strings.ToLower(v)
	if strings.HasPrefix(lower, "ext:") || strings.HasPrefix(lower, "ext-ip:") {
		if idx := strings.LastIndex(v, ":"); idx >= 0 && strings.EqualFold(strings.TrimSpace(v[idx+1:]), "private") {
			return true
		}
	}
	if prefix, err := netip.ParsePrefix(v); err == nil {
		return prefix.Bits() == 0
	}
	return false
}

// cidrOverlapsPrivate reports whether a CIDR range overlaps any private
// range. A /0 catch-all is deliberately not treated as private.
func cidrOverlapsPrivate(prefix netip.Prefix) bool {
	if prefix.Bits() == 0 {
		return false // catch-all, see containsGeoIPPrivate
	}
	addr := prefix.Addr()
	if addr.Is4In6() {
		// IPv4-mapped IPv6 prefix: judge it in IPv4 space.
		if prefix.Bits() < 96 {
			// Shorter than the mapped /96 range: it necessarily spans
			// the whole mapped space, including private IPv4.
			return true
		}
		prefix = netip.PrefixFrom(addr.Unmap(), prefix.Bits()-96)
	}
	prefix = prefix.Masked()
	for _, p := range privatePrefixes {
		if prefix.Overlaps(p) {
			return true
		}
	}
	return false
}

// isPrivateAddr reports whether a single address is private, loopback,
// link-local, or unspecified.
func isPrivateAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range privatePrefixes {
		if p.Contains(addr) {
			return true
		}
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
	//
	// H-1: a loopback outbound re-dispatches traffic into another
	// inbound by tag. Pointing it at the "api" inbound hands any
	// unauthenticated proxy user the unauthenticated Xray gRPC API
	// (HandlerService: AddUser/RemoveUser/AddInbound/...), bypassing
	// both the geoip:private -> blocked rule and the per-start ephemeral
	// API port (no TCP port is involved). Reject loopback -> api; a
	// loopback outbound whose target cannot be verified (unparseable or
	// missing settings) is rejected too, fail closed.
	for _, outbound := range cfg.Outbounds {
		switch {
		case strings.EqualFold(outbound.Protocol, "freedom"):
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
		case strings.EqualFold(outbound.Protocol, "loopback"):
			if len(outbound.Settings) == 0 {
				return fmt.Errorf("xray loopback outbound (tag %q) has no settings; its target inbound cannot be verified", outbound.Tag)
			}
			var settings struct {
				InboundTag string `json:"inboundTag"`
			}
			if err := json.Unmarshal(outbound.Settings, &settings); err != nil {
				return fmt.Errorf("xray loopback outbound (tag %q) has invalid settings: %w", outbound.Tag, err)
			}
			if target := strings.TrimSpace(settings.InboundTag); strings.EqualFold(target, "api") {
				return fmt.Errorf("xray loopback outbound (tag %q) must not target the api inbound", outbound.Tag)
			} else if target == "" {
				return fmt.Errorf("xray loopback outbound (tag %q) has no inboundTag; its target inbound cannot be verified", outbound.Tag)
			}
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
	//
	// L-3: a balancerTag on such a rule defeats the check — Xray's
	// Rule.GetTag() prefers the balancer's pick over outboundTag, so a
	// rule that "looks" blocked can still send private traffic to a
	// direct balancer. Any balancerTag on a private-matching rule is
	// rejected outright.
	for i, rule := range cfg.Routing.Rules {
		if !containsGeoIPPrivate(rule.IP) && !containsGeoIPPrivate(rule.Source) {
			continue
		}
		if strings.TrimSpace(rule.BalancerTag) != "" {
			return fmt.Errorf("xray routing rule %d matches geoip:private traffic but uses balancer %q; a balancer can override the blocked outbound", i, rule.BalancerTag)
		}
		if rule.OutboundTag != "blocked" {
			return fmt.Errorf("xray routing rule %d sends geoip:private traffic to %q instead of \"blocked\"", i, rule.OutboundTag)
		}
	}

	return nil
}
