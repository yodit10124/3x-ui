package main

import (
	"strings"
	"testing"
)

// TestResolveSettingPassword (L-17): the password must be readable
// from stdin so it never appears in the process arguments, and a
// literal -password keeps working for compatibility.
func TestResolveSettingPassword(t *testing.T) {
	// From stdin, with a trailing newline trimmed.
	got, err := resolveSettingPassword("", true, strings.NewReader("s3cret\n"))
	if err != nil || got != "s3cret" {
		t.Fatalf("resolveSettingPassword(stdin) = (%q, %v), want (\"s3cret\", nil)", got, err)
	}
	// Without a trailing newline.
	got, err = resolveSettingPassword("", true, strings.NewReader("s3cret"))
	if err != nil || got != "s3cret" {
		t.Fatalf("resolveSettingPassword(stdin, no newline) = (%q, %v), want (\"s3cret\", nil)", got, err)
	}
	// Empty stdin is an error, not a silent empty password.
	if _, err := resolveSettingPassword("", true, strings.NewReader("")); err == nil {
		t.Fatal("resolveSettingPassword(empty stdin) should fail")
	}
	if _, err := resolveSettingPassword("", true, strings.NewReader("\n")); err == nil {
		t.Fatal("resolveSettingPassword(blank stdin) should fail")
	}
	// A literal -password still works (with a stderr warning).
	got, err = resolveSettingPassword("s3cret", false, strings.NewReader(""))
	if err != nil || got != "s3cret" {
		t.Fatalf("resolveSettingPassword(flag) = (%q, %v), want (\"s3cret\", nil)", got, err)
	}
	// Stdin wins over the flag when both are given.
	got, err = resolveSettingPassword("from-flag", true, strings.NewReader("from-stdin"))
	if err != nil || got != "from-stdin" {
		t.Fatalf("resolveSettingPassword(both) = (%q, %v), want (\"from-stdin\", nil)", got, err)
	}
	// Neither given: no password change.
	got, err = resolveSettingPassword("", false, strings.NewReader(""))
	if err != nil || got != "" {
		t.Fatalf("resolveSettingPassword(neither) = (%q, %v), want (\"\", nil)", got, err)
	}
}

// TestResolveSettingTgbotToken (leftover 3): same stdin shape as the
// password resolver (L-17) — the token must be readable from stdin so
// it never appears in the process arguments, and a literal
// -tgbottoken keeps working for compatibility.
func TestResolveSettingTgbotToken(t *testing.T) {
	// From stdin, with a trailing newline trimmed.
	got, err := resolveSettingTgbotToken("", true, strings.NewReader("123456:ABC-DEF\n"))
	if err != nil || got != "123456:ABC-DEF" {
		t.Fatalf("resolveSettingTgbotToken(stdin) = (%q, %v), want (\"123456:ABC-DEF\", nil)", got, err)
	}
	// Without a trailing newline.
	got, err = resolveSettingTgbotToken("", true, strings.NewReader("123456:ABC-DEF"))
	if err != nil || got != "123456:ABC-DEF" {
		t.Fatalf("resolveSettingTgbotToken(stdin, no newline) = (%q, %v), want (\"123456:ABC-DEF\", nil)", got, err)
	}
	// Empty stdin is an error, not a silent empty token.
	if _, err := resolveSettingTgbotToken("", true, strings.NewReader("")); err == nil {
		t.Fatal("resolveSettingTgbotToken(empty stdin) should fail")
	}
	if _, err := resolveSettingTgbotToken("", true, strings.NewReader("\n")); err == nil {
		t.Fatal("resolveSettingTgbotToken(blank stdin) should fail")
	}
	// A literal -tgbottoken still works (with a stderr warning).
	got, err = resolveSettingTgbotToken("123456:ABC-DEF", false, strings.NewReader(""))
	if err != nil || got != "123456:ABC-DEF" {
		t.Fatalf("resolveSettingTgbotToken(flag) = (%q, %v), want (\"123456:ABC-DEF\", nil)", got, err)
	}
	// Stdin wins over the flag when both are given.
	got, err = resolveSettingTgbotToken("from-flag", true, strings.NewReader("from-stdin"))
	if err != nil || got != "from-stdin" {
		t.Fatalf("resolveSettingTgbotToken(both) = (%q, %v), want (\"from-stdin\", nil)", got, err)
	}
	// Neither given: no token change.
	got, err = resolveSettingTgbotToken("", false, strings.NewReader(""))
	if err != nil || got != "" {
		t.Fatalf("resolveSettingTgbotToken(neither) = (%q, %v), want (\"\", nil)", got, err)
	}
}
