package service

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestDownloadGeofile: a failed download must never damage the old
// file Xray still references. Success replaces it; 404, a truncated
// body, and 304 all leave it intact.
func TestDownloadGeofile(t *testing.T) {
	newContent := []byte("NEW-GEOFILE-CONTENT")
	oldContent := []byte("OLD-GEOFILE-CONTENT")

	serve := func(handler http.HandlerFunc) *httptest.Server {
		return httptest.NewServer(handler)
	}

	t.Run("success replaces", func(t *testing.T) {
		ts := serve(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(newContent)
		})
		defer ts.Close()
		dest := filepath.Join(t.TempDir(), "geoip.dat")
		if err := os.WriteFile(dest, oldContent, 0o644); err != nil {
			t.Fatal(err)
		}
		if replaced, err := downloadGeofile(ts.URL, dest); err != nil {
			t.Fatalf("downloadGeofile: %v", err)
		} else if !replaced {
			t.Fatal("downloadGeofile should report the file replaced")
		}
		if got, err := os.ReadFile(dest); err != nil || !bytes.Equal(got, newContent) {
			t.Fatalf("file %q, want the new content", got)
		}
		// The old content is backed up next to the file, and the
		// caller can roll the replacement back from it.
		backupPath := dest + ".bak"
		if got, err := os.ReadFile(backupPath); err != nil || !bytes.Equal(got, oldContent) {
			t.Fatalf("backup %q, want the old content, err %v", got, err)
		}
		restoreGeofileBackup(dest)
		if got, err := os.ReadFile(dest); err != nil || !bytes.Equal(got, oldContent) {
			t.Fatalf("file after restore %q, want the old content", got)
		}
		if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
			t.Fatalf("backup still present after restore: %v", err)
		}
	})

	t.Run("404 keeps old file", func(t *testing.T) {
		ts := serve(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		defer ts.Close()
		dest := filepath.Join(t.TempDir(), "geoip.dat")
		if err := os.WriteFile(dest, oldContent, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := downloadGeofile(ts.URL, dest); err == nil {
			t.Fatal("404 should return an error")
		}
		if got, err := os.ReadFile(dest); err != nil || !bytes.Equal(got, oldContent) {
			t.Fatalf("old file lost or changed on 404: %q, %v", got, err)
		}
		if _, err := os.Stat(dest + ".bak"); !os.IsNotExist(err) {
			t.Fatalf("backup left behind on 404: %v", err)
		}
	})

	t.Run("truncated body keeps old file", func(t *testing.T) {
		ts := serve(func(w http.ResponseWriter, r *http.Request) {
			// Declare more bytes than the handler writes: the client
			// sees an unexpected EOF mid-download.
			w.Header().Set("Content-Length", "1000")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("partial"))
		})
		defer ts.Close()
		dest := filepath.Join(t.TempDir(), "geoip.dat")
		if err := os.WriteFile(dest, oldContent, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := downloadGeofile(ts.URL, dest); err == nil {
			t.Fatal("truncated body should return an error")
		}
		if got, err := os.ReadFile(dest); err != nil || !bytes.Equal(got, oldContent) {
			t.Fatalf("old file lost or changed on truncated download: %q, %v", got, err)
		}
		if _, err := os.Stat(dest + ".bak"); !os.IsNotExist(err) {
			t.Fatalf("backup left behind on truncated download: %v", err)
		}
	})

	t.Run("304 keeps old file", func(t *testing.T) {
		ts := serve(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("If-Modified-Since") == "" {
				t.Error("expected a conditional request for an existing file")
			}
			w.WriteHeader(http.StatusNotModified)
		})
		defer ts.Close()
		dest := filepath.Join(t.TempDir(), "geoip.dat")
		if err := os.WriteFile(dest, oldContent, 0o644); err != nil {
			t.Fatal(err)
		}
		if replaced, err := downloadGeofile(ts.URL, dest); err != nil {
			t.Fatalf("downloadGeofile on 304: %v", err)
		} else if replaced {
			t.Fatal("downloadGeofile should report no replacement on 304")
		}
		if got, err := os.ReadFile(dest); err != nil || !bytes.Equal(got, oldContent) {
			t.Fatalf("old file changed on 304: %q, %v", got, err)
		}
		if _, err := os.Stat(dest + ".bak"); !os.IsNotExist(err) {
			t.Fatalf("backup left behind on 304: %v", err)
		}
	})
}

// makeUpdateTestZip builds a zip archive holding one entry.
func makeUpdateTestZip(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "xray.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, content := range entries {
		ew, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ew.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestExtractZipEntry: a good archive extracts; a missing entry, a
// corrupt archive, and an empty entry all fail without leaving a
// partial binary behind.
func TestExtractZipEntry(t *testing.T) {
	t.Run("good zip extracts", func(t *testing.T) {
		zipPath := makeUpdateTestZip(t, map[string][]byte{"xray": []byte("FAKE-XRAY-BINARY")})
		dest := filepath.Join(t.TempDir(), "xray-linux-amd64")
		if err := extractZipEntry(zipPath, "xray", dest); err != nil {
			t.Fatalf("extractZipEntry: %v", err)
		}
		got, err := os.ReadFile(dest)
		if err != nil || !bytes.Equal(got, []byte("FAKE-XRAY-BINARY")) {
			t.Fatalf("extracted %q, %v", got, err)
		}
		if st, err := os.Stat(dest); err != nil || st.Mode().Perm()&0o111 == 0 {
			t.Fatalf("extracted binary is not executable: %v", err)
		}
		if _, err := os.Stat(dest + ".tmp"); !os.IsNotExist(err) {
			t.Fatalf("temp file left behind: %v", err)
		}
	})

	t.Run("missing entry fails cleanly", func(t *testing.T) {
		zipPath := makeUpdateTestZip(t, map[string][]byte{"other": []byte("x")})
		dest := filepath.Join(t.TempDir(), "xray-linux-amd64")
		if err := extractZipEntry(zipPath, "xray", dest); err == nil {
			t.Fatal("missing entry should return an error")
		}
		if _, err := os.Stat(dest); !os.IsNotExist(err) {
			t.Fatal("destination created from a zip without the entry")
		}
	})

	t.Run("corrupt zip fails cleanly", func(t *testing.T) {
		zipPath := filepath.Join(t.TempDir(), "bad.zip")
		good := makeUpdateTestZip(t, map[string][]byte{"xray": []byte("FAKE-XRAY-BINARY")})
		raw, err := os.ReadFile(good)
		if err != nil {
			t.Fatal(err)
		}
		// Truncate the archive in half: the central directory is gone.
		if err := os.WriteFile(zipPath, raw[:len(raw)/2], 0o644); err != nil {
			t.Fatal(err)
		}
		dest := filepath.Join(t.TempDir(), "xray-linux-amd64")
		if err := extractZipEntry(zipPath, "xray", dest); err == nil {
			t.Fatal("corrupt zip should return an error")
		}
		if _, err := os.Stat(dest); !os.IsNotExist(err) {
			t.Fatal("destination created from a corrupt zip")
		}
	})

	t.Run("empty entry fails cleanly", func(t *testing.T) {
		zipPath := makeUpdateTestZip(t, map[string][]byte{"xray": []byte{}})
		dest := filepath.Join(t.TempDir(), "xray-linux-amd64")
		if err := extractZipEntry(zipPath, "xray", dest); err == nil {
			t.Fatal("empty entry should return an error")
		}
		if _, err := os.Stat(dest); !os.IsNotExist(err) {
			t.Fatal("destination created from an empty entry")
		}
	})
}

// TestStageRollbackCommitBinary covers the binary swap used by
// UpdateXray: stage moves the live binary aside and installs the new
// one, commit drops the backup, rollback restores the old binary.
func TestStageRollbackCommitBinary(t *testing.T) {
	write := func(t *testing.T, path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	read := func(t *testing.T, path string) string {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	t.Run("stage and commit", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "xray")
		staged := filepath.Join(dir, "xray.new")
		write(t, target, "OLD")
		write(t, staged, "NEW")
		backup, err := stageBinaryReplace(target, staged)
		if err != nil {
			t.Fatalf("stageBinaryReplace: %v", err)
		}
		if backup == "" {
			t.Fatal("expected a backup path for an existing binary")
		}
		if got := read(t, target); got != "NEW" {
			t.Fatalf("target %q, want NEW", got)
		}
		if got := read(t, backup); got != "OLD" {
			t.Fatalf("backup %q, want OLD", got)
		}
		if err := commitBinaryReplace(backup); err != nil {
			t.Fatalf("commitBinaryReplace: %v", err)
		}
		if _, err := os.Stat(backup); !os.IsNotExist(err) {
			t.Fatal("backup still present after commit")
		}
		if got := read(t, target); got != "NEW" {
			t.Fatalf("target %q after commit, want NEW", got)
		}
	})

	t.Run("stage without a live binary", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "xray")
		staged := filepath.Join(dir, "xray.new")
		write(t, staged, "NEW")
		backup, err := stageBinaryReplace(target, staged)
		if err != nil {
			t.Fatalf("stageBinaryReplace: %v", err)
		}
		if backup != "" {
			t.Fatalf("backup %q, want none when there is no live binary", backup)
		}
		if got := read(t, target); got != "NEW" {
			t.Fatalf("target %q, want NEW", got)
		}
	})

	t.Run("stage failure keeps the live binary", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "xray")
		write(t, target, "OLD")
		if _, err := stageBinaryReplace(target, filepath.Join(dir, "missing.new")); err == nil {
			t.Fatal("staging a missing file should return an error")
		}
		if got := read(t, target); got != "OLD" {
			t.Fatalf("target %q after failed stage, want OLD", got)
		}
	})

	t.Run("rollback restores the old binary", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "xray")
		staged := filepath.Join(dir, "xray.new")
		write(t, target, "OLD")
		write(t, staged, "NEW")
		backup, err := stageBinaryReplace(target, staged)
		if err != nil {
			t.Fatal(err)
		}
		if err := rollbackBinaryReplace(target, backup); err != nil {
			t.Fatalf("rollbackBinaryReplace: %v", err)
		}
		if got := read(t, target); got != "OLD" {
			t.Fatalf("target %q after rollback, want OLD", got)
		}
		if _, err := os.Stat(backup); !os.IsNotExist(err) {
			t.Fatal("backup still present after rollback")
		}
	})

	t.Run("rollback without a backup removes the new binary", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "xray")
		staged := filepath.Join(dir, "xray.new")
		write(t, staged, "NEW")
		backup, err := stageBinaryReplace(target, staged)
		if err != nil {
			t.Fatal(err)
		}
		if err := rollbackBinaryReplace(target, backup); err != nil {
			t.Fatalf("rollbackBinaryReplace: %v", err)
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatal("new binary still present after rollback without a backup")
		}
	})
}
