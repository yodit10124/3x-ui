package service

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// PanelService provides business logic for panel management operations.
// It handles panel restart, updates, and system-level panel controls.
type PanelService struct{}

// PanelUpdateInfo contains the current and latest available panel versions.
type PanelUpdateInfo struct {
	CurrentVersion  string `json:"currentVersion"`
	LatestVersion   string `json:"latestVersion"`
	UpdateAvailable bool   `json:"updateAvailable"`
}

func (s *PanelService) RestartPanel(delay time.Duration) error {
	p, err := os.FindProcess(syscall.Getpid())
	if err != nil {
		return err
	}
	go func() {
		time.Sleep(delay)
		err := p.Signal(syscall.SIGHUP)
		if err != nil {
			logger.Error("failed to send SIGHUP signal:", err)
		}
	}()
	return nil
}

// GetUpdateInfo checks GitHub for the latest 3x-ui release.
func (s *PanelService) GetUpdateInfo() (*PanelUpdateInfo, error) {
	latest, err := fetchLatestPanelVersion()
	if err != nil {
		return nil, err
	}
	current := config.GetVersion()
	return &PanelUpdateInfo{
		CurrentVersion:  current,
		LatestVersion:   latest,
		UpdateAvailable: isNewerVersion(latest, current),
	}, nil
}

// StartUpdate starts the official updater outside of the current web request.
//
// H-6: the updater script is never executed straight from the network. It is
// downloaded with the Go HTTP client, SHA256-verified against the
// operator-supplied XUI_UPDATE_SHA256, and only then executed from a local
// temp file. There is no official checksum file for update.sh (it is a
// rolling script fetched from the main branch, not a release asset), so the
// expected hash must come from the operator; when it is missing or does not
// match, the update is refused instead of warning and continuing.
func (s *PanelService) StartUpdate() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("panel web update is supported only on Linux installations")
	}

	bash, err := exec.LookPath("bash")
	if err != nil {
		return fmt.Errorf("bash is required to run the panel updater: %w", err)
	}

	// Download and verify first; refuse on any failure. No curl|bash pipe.
	scriptPath, err := downloadVerifiedUpdateScript()
	if err != nil {
		return err
	}
	// The updater runs detached (a systemd unit or a background process) and
	// restarts the panel itself, so the parent cannot delete the temp file
	// on return: the child shell removes it after the updater exits. Only
	// delete it here if the update job could not be started at all.
	started := false
	defer func() {
		if !started {
			os.Remove(scriptPath)
		}
	}()

	mainFolder, serviceFolder := resolveUpdateFolders()
	// Execute the verified local file, never a network pipe. The path is
	// shell-quoted (CreateTemp names are safe, but quote anyway), and the
	// temp file is removed by this same shell once the updater exits.
	updateScript := fmt.Sprintf("%s %s; rm -f %s", shellQuote(bash), shellQuote(scriptPath), shellQuote(scriptPath))

	if systemdRun, err := exec.LookPath("systemd-run"); err == nil {
		unitName := fmt.Sprintf("x-ui-web-update-%d", time.Now().Unix())
		cmd := exec.Command(systemdRun,
			"--unit", unitName,
			"--setenv", "XUI_MAIN_FOLDER="+mainFolder,
			"--setenv", "XUI_SERVICE="+serviceFolder,
			bash, "-lc", updateScript,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			output := strings.TrimSpace(string(out))
			if !strings.Contains(output, "System has not been booted with systemd") &&
				!strings.Contains(output, "Failed to connect to bus") {
				return fmt.Errorf("failed to start panel update job: %w: %s", err, output)
			}
			logger.Warning("systemd-run is unavailable, falling back to detached update process:", output)
		} else {
			started = true
			logger.Infof("started panel update job via systemd-run unit %s", unitName)
			return nil
		}
	}

	cmd := exec.Command(bash, "-lc", updateScript)
	cmd.Env = append(os.Environ(),
		"XUI_MAIN_FOLDER="+mainFolder,
		"XUI_SERVICE="+serviceFolder,
	)
	setDetachedProcess(cmd)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start panel update job: %w", err)
	}
	started = true
	if err := cmd.Process.Release(); err != nil {
		logger.Warning("failed to release panel update process:", err)
	}
	logger.Infof("started panel update job with pid %d", cmd.Process.Pid)
	return nil
}

// updateScriptURL is the only source of the updater script.
const updateScriptURL = "https://raw.githubusercontent.com/yodit10124/3x-ui/main/update.sh"

// updateScriptMaxBytes caps the downloaded updater script. update.sh is a
// small shell script; anything larger is rejected instead of written to disk.
const updateScriptMaxBytes = 1 << 20 // 1 MiB

// updateDownloadTimeout bounds the updater download.
const updateDownloadTimeout = 30 * time.Second

// downloadVerifiedUpdateScript downloads update.sh, verifies its SHA256
// against the operator-supplied XUI_UPDATE_SHA256 environment variable, and
// writes the verified script to a 0600 temp file (os.CreateTemp, random
// name, in os.TempDir()). The caller owns the returned path and must remove
// it once the updater has run; on any error the file is removed here and no
// path is returned, so unverified content is never executed.
func downloadVerifiedUpdateScript() (string, error) {
	expectedHex := strings.TrimSpace(os.Getenv("XUI_UPDATE_SHA256"))
	if expectedHex == "" {
		return "", fmt.Errorf("panel update refused: XUI_UPDATE_SHA256 is not set; set it to the SHA256 of %s before updating (compute it with: curl -fsSL %s | sha256sum)", updateScriptURL, updateScriptURL)
	}
	expected, err := hex.DecodeString(expectedHex)
	if err != nil || len(expected) != sha256.Size {
		return "", fmt.Errorf("panel update refused: XUI_UPDATE_SHA256 must be a 64-character hex SHA256 digest")
	}

	client := &http.Client{Timeout: updateDownloadTimeout}
	resp, err := client.Get(updateScriptURL)
	if err != nil {
		return "", fmt.Errorf("failed to download panel updater: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download panel updater: unexpected HTTP status %s", resp.Status)
	}
	if resp.ContentLength > updateScriptMaxBytes {
		return "", fmt.Errorf("panel update refused: updater script exceeds the %d byte limit", updateScriptMaxBytes)
	}
	// LimitReader caps the body at max+1 bytes so an oversized response is
	// detected instead of buffering unbounded data.
	body, err := io.ReadAll(io.LimitReader(resp.Body, updateScriptMaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("failed to download panel updater: %w", err)
	}
	if int64(len(body)) > updateScriptMaxBytes {
		return "", fmt.Errorf("panel update refused: updater script exceeds the %d byte limit", updateScriptMaxBytes)
	}

	sum := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(sum[:], expected) != 1 {
		return "", fmt.Errorf("panel update refused: SHA256 mismatch for the downloaded updater script")
	}

	// os.CreateTemp creates the file with 0600 and a random, unpredictable
	// name. The script is written only after the hash has been verified.
	tmp, err := os.CreateTemp("", "x-ui-update-*.sh")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file for panel updater: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", fmt.Errorf("failed to write panel updater to temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", fmt.Errorf("failed to write panel updater to temp file: %w", err)
	}
	logger.Infof("downloaded and SHA256-verified panel updater %s", tmp.Name())
	return tmp.Name(), nil
}

func fetchLatestPanelVersion() (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	// The fork publishes prereleases, and GitHub's /releases/latest endpoint
	// only returns full releases, so list releases instead and take the
	// newest one (the list is newest-first, prereleases included).
	resp, err := client.Get("https://api.github.com/repos/yodit10124/3x-ui/releases?per_page=1")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, resp.Status)
	}

	var releases []Release
	if err := json.NewDecoder(resp.Body).Decode(&releases); err != nil {
		return "", err
	}
	if len(releases) == 0 || releases[0].TagName == "" {
		return "", fmt.Errorf("latest panel release tag is empty")
	}
	return releases[0].TagName, nil
}

func resolveUpdateFolders() (string, string) {
	mainFolder := os.Getenv("XUI_MAIN_FOLDER")
	if mainFolder == "" {
		if exePath, err := os.Executable(); err == nil {
			mainFolder = filepath.Dir(exePath)
		}
	}
	if mainFolder == "" {
		mainFolder = "/usr/local/x-ui"
	}

	serviceFolder := os.Getenv("XUI_SERVICE")
	if serviceFolder == "" {
		serviceFolder = "/etc/systemd/system"
	}
	return mainFolder, serviceFolder
}

func isNewerVersion(latest string, current string) bool {
	cmp, ok := compareVersionStrings(latest, current)
	if !ok {
		return normalizeVersionTag(latest) != normalizeVersionTag(current)
	}
	return cmp > 0
}

func compareVersionStrings(a string, b string) (int, bool) {
	aParts, okA := parseVersionParts(a)
	bParts, okB := parseVersionParts(b)
	if !okA || !okB {
		return 0, false
	}
	for i := 0; i < len(aParts); i++ {
		if aParts[i] > bParts[i] {
			return 1, true
		}
		if aParts[i] < bParts[i] {
			return -1, true
		}
	}
	return 0, true
}

func parseVersionParts(version string) ([3]int, bool) {
	var result [3]int
	parts := strings.Split(normalizeVersionTag(version), ".")
	if len(parts) != 3 {
		return result, false
	}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return result, false
		}
		result[i] = n
	}
	return result, true
}

func normalizeVersionTag(version string) string {
	return strings.TrimPrefix(strings.TrimSpace(version), "v")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
