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
