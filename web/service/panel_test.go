package service

import "testing"

func TestIsNewerVersion(t *testing.T) {
	cases := []struct {
		latest  string
		current string
		want    bool
	}{
		{"v2.9.4", "2.9.3", true},
		{"v2.10.0", "2.9.9", true},
		{"v2.9.3", "2.9.3", false},
		{"v2.9.2", "2.9.3", false},
		{"v3.0.0", "2.9.3", true},
	}

	for _, tc := range cases {
		if got := isNewerVersion(tc.latest, tc.current); got != tc.want {
			t.Fatalf("isNewerVersion(%q, %q) = %v, want %v", tc.latest, tc.current, got, tc.want)
		}
	}
}

func TestCompareVersionStringsRejectsUnexpectedFormats(t *testing.T) {
	if _, ok := compareVersionStrings("latest", "2.9.3"); ok {
		t.Fatal("expected non-semver latest tag to be rejected")
	}
	if _, ok := compareVersionStrings("v2.9", "2.9.3"); ok {
		t.Fatal("expected short version to be rejected")
	}
}

func TestShellQuote(t *testing.T) {
	if got := shellQuote("/usr/bin/curl"); got != "'/usr/bin/curl'" {
		t.Fatalf("unexpected quote result: %s", got)
	}
	if got := shellQuote("/tmp/a'b"); got != "'/tmp/a'\\''b'" {
		t.Fatalf("unexpected quote result with single quote: %s", got)
	}
}

// The panel updater is fetched from the installed release tag, never from
// the rolling main branch, so the SHA256 pinned at install time stays
// valid. A bad version must refuse the update instead of producing an
// arbitrary download URL.
func TestUpdateScriptURLForVersion(t *testing.T) {
	url, err := updateScriptURLForVersion("2.9.4-c6")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "https://raw.githubusercontent.com/yodit10124/3x-ui/v2.9.4-c6/update.sh"
	if url != want {
		t.Fatalf("got %q, want %q", url, want)
	}

	// A leading "v" is normalized, not doubled.
	url, err = updateScriptURLForVersion("v2.9.4-c6")
	if err != nil {
		t.Fatalf("unexpected error for v-prefixed version: %v", err)
	}
	if url != want {
		t.Fatalf("got %q, want %q", url, want)
	}

	// Surrounding whitespace is trimmed.
	url, err = updateScriptURLForVersion("  2.9.4-c6\n")
	if err != nil {
		t.Fatalf("unexpected error for padded version: %v", err)
	}
	if url != want {
		t.Fatalf("got %q, want %q", url, want)
	}

	for _, bad := range []string{
		"",
		"   ",
		"2.9.4/c6",
		"../etc/passwd",
		"2.9.4 c6",
		"https://evil.example/x",
		"2.9.4-c6\nx",
		"2.9.4-c6?x=1",
	} {
		if _, err := updateScriptURLForVersion(bad); err == nil {
			t.Fatalf("version %q should have been rejected", bad)
		}
	}
}
