package service

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		replaced, backupPath, err := downloadGeofile(ts.URL, dest)
		if err != nil {
			t.Fatalf("downloadGeofile: %v", err)
		}
		if !replaced {
			t.Fatal("downloadGeofile should report the file replaced")
		}
		if backupPath == "" {
			t.Fatal("downloadGeofile should return a backup path when it replaced a file")
		}
		if got, err := os.ReadFile(dest); err != nil || !bytes.Equal(got, newContent) {
			t.Fatalf("file %q, want the new content", got)
		}
		// The old content is backed up next to the file, and the
		// caller can roll the replacement back from it.
		if got, err := os.ReadFile(backupPath); err != nil || !bytes.Equal(got, oldContent) {
			t.Fatalf("backup %q, want the old content, err %v", got, err)
		}
		restoreGeofileBackup(backupPath, dest)
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
		if _, _, err := downloadGeofile(ts.URL, dest); err == nil {
			t.Fatal("404 should return an error")
		}
		if got, err := os.ReadFile(dest); err != nil || !bytes.Equal(got, oldContent) {
			t.Fatalf("old file lost or changed on 404: %q, %v", got, err)
		}
		if leftovers, _ := filepath.Glob(dest + ".bak-*"); len(leftovers) != 0 {
			t.Fatalf("backup left behind on 404: %v", leftovers)
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
		if _, _, err := downloadGeofile(ts.URL, dest); err == nil {
			t.Fatal("truncated body should return an error")
		}
		if got, err := os.ReadFile(dest); err != nil || !bytes.Equal(got, oldContent) {
			t.Fatalf("old file lost or changed on truncated download: %q, %v", got, err)
		}
		if leftovers, _ := filepath.Glob(dest + ".bak-*"); len(leftovers) != 0 {
			t.Fatalf("backup left behind on truncated download: %v", leftovers)
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
		if replaced, _, err := downloadGeofile(ts.URL, dest); err != nil {
			t.Fatalf("downloadGeofile on 304: %v", err)
		} else if replaced {
			t.Fatal("downloadGeofile should report no replacement on 304")
		}
		if got, err := os.ReadFile(dest); err != nil || !bytes.Equal(got, oldContent) {
			t.Fatalf("old file changed on 304: %q, %v", got, err)
		}
		if leftovers, _ := filepath.Glob(dest + ".bak-*"); len(leftovers) != 0 {
			t.Fatalf("backup left behind on 304: %v", leftovers)
		}
	})

	// M-5: an oversized file is refused and the old file is left
	// intact, with no temporary or backup file left behind.
	t.Run("oversized body refused", func(t *testing.T) {
		orig := geofileDownloadMaxBytes
		geofileDownloadMaxBytes = 1024
		t.Cleanup(func() { geofileDownloadMaxBytes = orig })
		ts := serve(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(bytes.Repeat([]byte("x"), 2048))
		})
		defer ts.Close()
		dest := filepath.Join(t.TempDir(), "geoip.dat")
		if err := os.WriteFile(dest, oldContent, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, _, err := downloadGeofile(ts.URL, dest); err == nil {
			t.Fatal("oversized body should return an error")
		} else if !strings.Contains(err.Error(), "too large") {
			t.Fatalf("error %v, want a size-limit error", err)
		}
		if got, err := os.ReadFile(dest); err != nil || !bytes.Equal(got, oldContent) {
			t.Fatalf("old file lost or changed on oversized download: %q, %v", got, err)
		}
		if leftovers, _ := filepath.Glob(dest + ".tmp-*"); len(leftovers) != 0 {
			t.Fatalf("temporary file left behind on oversized download: %v", leftovers)
		}
	})

	// M-5: a stalled server must fail with the download timeout
	// instead of hanging the update forever.
	t.Run("stalled server times out", func(t *testing.T) {
		orig := geofileDownloadTimeout
		geofileDownloadTimeout = 100 * time.Millisecond
		t.Cleanup(func() { geofileDownloadTimeout = orig })
		ts := serve(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(2 * time.Second)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(newContent)
		})
		defer ts.Close()
		dest := filepath.Join(t.TempDir(), "geoip.dat")
		if err := os.WriteFile(dest, oldContent, 0o644); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if _, _, err := downloadGeofile(ts.URL, dest); err == nil {
			t.Fatal("stalled download should return an error")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("download took %v, want it bounded by the timeout", elapsed)
		}
		if got, err := os.ReadFile(dest); err != nil || !bytes.Equal(got, oldContent) {
			t.Fatalf("old file lost or changed on stalled download: %q, %v", got, err)
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

// TestDownloadXRayFromURL (M-4): the Xray release download must be
// bounded (timeout, size cap, GitHub-only redirects) and the zip must
// be refused when its .dgst hash file is missing or mismatching.
func TestDownloadXRayFromURL(t *testing.T) {
	zipBytes := []byte("fake-xray-zip-content")
	zipHash := sha256.Sum256(zipBytes)
	dgst := fmt.Sprintf("SHA256(Xray-test.zip) = %s\n", hex.EncodeToString(zipHash[:]))

	serve := func(t *testing.T, zipBody []byte, dgstBody string, dgstStatus int, redirectTo string) *httptest.Server {
		t.Helper()
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if redirectTo != "" {
				http.Redirect(w, r, redirectTo, http.StatusFound)
				return
			}
			switch {
			case strings.HasSuffix(r.URL.Path, ".dgst"):
				w.WriteHeader(dgstStatus)
				_, _ = w.Write([]byte(dgstBody))
			default:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(zipBody)
			}
		}))
	}

	t.Run("success with matching dgst", func(t *testing.T) {
		t.Chdir(t.TempDir())
		ts := serve(t, zipBytes, dgst, http.StatusOK, "")
		defer ts.Close()
		got, err := downloadXRayFromURL(ts.URL+"/Xray-test.zip", "Xray-test.zip")
		if err != nil {
			t.Fatalf("downloadXRayFromURL: %v", err)
		}
		if got != "Xray-test.zip" {
			t.Fatalf("got file %q", got)
		}
		if content, err := os.ReadFile("Xray-test.zip"); err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(content, zipBytes) {
			t.Fatal("downloaded zip content differs")
		}
	})

	t.Run("missing dgst refused", func(t *testing.T) {
		t.Chdir(t.TempDir())
		ts := serve(t, zipBytes, "", http.StatusNotFound, "")
		defer ts.Close()
		if _, err := downloadXRayFromURL(ts.URL+"/Xray-test.zip", "Xray-test.zip"); err == nil {
			t.Fatal("download accepted without a .dgst file")
		} else if !strings.Contains(err.Error(), ".dgst") {
			t.Fatalf("error %v, want a .dgst error", err)
		}
		if _, err := os.Stat("Xray-test.zip"); !os.IsNotExist(err) {
			t.Fatal("unverified zip was left on disk")
		}
	})

	t.Run("mismatching hash refused", func(t *testing.T) {
		t.Chdir(t.TempDir())
		badDgst := fmt.Sprintf("SHA256(Xray-test.zip) = %s\n", strings.Repeat("0", 64))
		ts := serve(t, zipBytes, badDgst, http.StatusOK, "")
		defer ts.Close()
		if _, err := downloadXRayFromURL(ts.URL+"/Xray-test.zip", "Xray-test.zip"); err == nil {
			t.Fatal("download accepted with a mismatching hash")
		} else if !strings.Contains(err.Error(), "mismatch") {
			t.Fatalf("error %v, want a mismatch error", err)
		}
	})

	t.Run("oversized zip refused", func(t *testing.T) {
		t.Chdir(t.TempDir())
		orig := xrayZipMaxBytes
		xrayZipMaxBytes = 1024
		t.Cleanup(func() { xrayZipMaxBytes = orig })
		ts := serve(t, bytes.Repeat([]byte("x"), 2048), dgst, http.StatusOK, "")
		defer ts.Close()
		if _, err := downloadXRayFromURL(ts.URL+"/Xray-test.zip", "Xray-test.zip"); err == nil {
			t.Fatal("download accepted an oversized zip")
		} else if !strings.Contains(err.Error(), "exceeds the maximum") {
			t.Fatalf("error %v, want a size-limit error", err)
		}
	})

	t.Run("redirect to disallowed host refused", func(t *testing.T) {
		t.Chdir(t.TempDir())
		ts := serve(t, zipBytes, dgst, http.StatusOK, "http://example.com/Xray-test.zip")
		defer ts.Close()
		if _, err := downloadXRayFromURL(ts.URL+"/Xray-test.zip", "Xray-test.zip"); err == nil {
			t.Fatal("download followed a redirect to a disallowed host")
		} else if !strings.Contains(err.Error(), "disallowed host") {
			t.Fatalf("error %v, want a disallowed-host error", err)
		}
	})
}

// makeTestZip builds a zip file with a single entry of the given size
// (filled with 'x') and returns its path.
func makeTestZip(t *testing.T, entryName string, size int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	entry, err := w.Create(entryName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write(bytes.Repeat([]byte("x"), size)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestExtractZipEntrySizeLimit (L-9): an entry over the cap must be
// refused and leave nothing behind; a small entry extracts intact.
func TestExtractZipEntrySizeLimit(t *testing.T) {
	oldCap := maxExtractedEntrySize
	maxExtractedEntrySize = 1024
	t.Cleanup(func() { maxExtractedEntrySize = oldCap })

	dir := t.TempDir()
	dest := filepath.Join(dir, "xray")

	// Exactly at the cap: passes.
	if err := extractZipEntry(makeTestZip(t, "xray", 1024), "xray", dest); err != nil {
		t.Fatalf("entry at the cap should extract, got %v", err)
	}
	if got, err := os.ReadFile(dest); err != nil || len(got) != 1024 {
		t.Fatalf("extracted file size = %d, err = %v, want 1024 bytes", len(got), err)
	}

	// One byte over: refused, and neither the destination nor the
	// temp file survives.
	dest2 := filepath.Join(dir, "xray2")
	if err := extractZipEntry(makeTestZip(t, "xray", 1025), "xray", dest2); err == nil {
		t.Fatal("oversized entry should be refused")
	}
	if _, err := os.Stat(dest2); !os.IsNotExist(err) {
		t.Fatalf("oversized entry left a destination behind (stat err = %v)", err)
	}
	if _, err := os.Stat(dest2 + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("oversized entry left a temp file behind (stat err = %v)", err)
	}

	// A huge entry (1 MiB of 'x' compresses to almost nothing in the
	// zip, so the archive stays small while the entry expands): the
	// zip-bomb shape must be refused too.
	dest3 := filepath.Join(dir, "xray3")
	if err := extractZipEntry(makeTestZip(t, "xray", 1<<20), "xray", dest3); err == nil {
		t.Fatal("1 MiB entry over the 1 KiB test cap should be refused")
	}
	if _, err := os.Stat(dest3); !os.IsNotExist(err) {
		t.Fatalf("zip-bomb entry left a destination behind (stat err = %v)", err)
	}
}
