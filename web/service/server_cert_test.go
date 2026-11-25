package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// installFakeXrayOutput installs a fake xray binary that prints the
// contents of the given file to stdout, whatever subcommand it is
// called with. The test rewrites the file per case.
func installFakeXrayOutput(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", binDir)
	outPath := filepath.Join(t.TempDir(), "fake-output.txt")
	if err := os.WriteFile(outPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_XRAY_OUTPUT", outPath)
	script := "#!/bin/sh\ncat \"$FAKE_XRAY_OUTPUT\"\n"
	if err := os.WriteFile(filepath.Join(binDir, xray.GetBinaryName()), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// Sanity: the binary path resolves inside the temp bin dir.
	if got := config.GetBinFolderPath(); got != binDir {
		t.Fatalf("XUI_BIN_FOLDER = %q, want %q", got, binDir)
	}
	return outPath
}

// TestParseKeyValueLines (L-10): the x25519/mldsa65/mlkem768 output
// parser must reject malformed output instead of panicking on an
// out-of-range index.
func TestParseKeyValueLines(t *testing.T) {
	a, b, err := parseKeyValueLines("Private key: abc\nPublic key: def\n", "x25519")
	if err != nil || a != "abc" || b != "def" {
		t.Fatalf("valid output: got (%q, %q, %v), want (abc, def, nil)", a, b, err)
	}
	// A value containing ":" stays intact.
	a, b, err = parseKeyValueLines("Seed: a:b:c\nVerify: d\n", "mldsa65")
	if err != nil || a != "a:b:c" || b != "d" {
		t.Fatalf("colon in value: got (%q, %q, %v), want (a:b:c, d, nil)", a, b, err)
	}
	for _, bad := range []string{
		"",
		"only one line",
		"garbage\nmore garbage\n",
		"Private key: abc\n",
		"Private key: abc\nPublic key\n",
		"No colon here\nNeither here\n",
	} {
		if _, _, err := parseKeyValueLines(bad, "x25519"); err == nil {
			t.Fatalf("parseKeyValueLines(%q) should fail", bad)
		}
	}
}

// TestGetNewCertsRejectMalformedOutput (L-10): all three cert
// generators must return an error — not panic — when the xray binary
// prints unexpected output.
func TestGetNewCertsRejectMalformedOutput(t *testing.T) {
	outPath := installFakeXrayOutput(t)
	svc := &ServerService{}

	for _, tc := range []struct {
		name string
		fn   func() (any, error)
	}{
		{"x25519", svc.GetNewX25519Cert},
		{"mldsa65", svc.GetNewmldsa65},
		{"mlkem768", svc.GetNewmlkem768},
	} {
		t.Run(tc.name+" garbage", func(t *testing.T) {
			if err := os.WriteFile(outPath, []byte("garbage\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("GetNew%s panicked on garbage output: %v", tc.name, r)
				}
			}()
			if _, err := tc.fn(); err == nil {
				t.Fatalf("GetNew%s on garbage output should fail", tc.name)
			}
		})
		t.Run(tc.name+" valid", func(t *testing.T) {
			if err := os.WriteFile(outPath, []byte("First: one\nSecond: two\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := tc.fn()
			if err != nil {
				t.Fatalf("GetNew%s on valid output: %v", tc.name, err)
			}
			m, ok := got.(map[string]any)
			if !ok {
				t.Fatalf("GetNew%s returned %T, want map[string]any", tc.name, got)
			}
			for _, v := range m {
				if v != "one" && v != "two" {
					t.Fatalf("GetNew%s returned unexpected value %v in %v", tc.name, v, m)
				}
			}
		})
	}
}
