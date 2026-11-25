package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/random"
)

const (
	customGeoTypeGeosite  = "geosite"
	customGeoTypeGeoip    = "geoip"
	minDatBytes           = 64
	customGeoProbeTimeout = 12 * time.Second
	// defaultGeoMaxFileSizeMB caps a single Geo file download when no
	// valid limit is configured. Real GeoIP/GeoSite databases are ~15 MiB
	// at most, so 100 MiB leaves ample room while bounding how much a
	// malicious or compromised remote source can write to the disk.
	defaultGeoMaxFileSizeMB = 100
)

var (
	customGeoAliasPattern = regexp.MustCompile(`^[a-z0-9_-]+$`)
	reservedCustomAliases = map[string]struct{}{
		"geoip": {}, "geosite": {},
		"geoip_ir": {}, "geosite_ir": {},
		"geoip_ru": {}, "geosite_ru": {},
	}
	ErrCustomGeoInvalidType    = errors.New("custom_geo_invalid_type")
	ErrCustomGeoAliasRequired  = errors.New("custom_geo_alias_required")
	ErrCustomGeoAliasPattern   = errors.New("custom_geo_alias_pattern")
	ErrCustomGeoAliasReserved  = errors.New("custom_geo_alias_reserved")
	ErrCustomGeoURLRequired    = errors.New("custom_geo_url_required")
	ErrCustomGeoInvalidURL     = errors.New("custom_geo_invalid_url")
	ErrCustomGeoURLScheme      = errors.New("custom_geo_url_scheme")
	ErrCustomGeoURLHost        = errors.New("custom_geo_url_host")
	ErrCustomGeoDuplicateAlias = errors.New("custom_geo_duplicate_alias")
	ErrCustomGeoNotFound       = errors.New("custom_geo_not_found")
	ErrCustomGeoDownload       = errors.New("custom_geo_download")
	ErrCustomGeoSSRFBlocked    = errors.New("custom_geo_ssrf_blocked")
	ErrCustomGeoPathTraversal  = errors.New("custom_geo_path_traversal")
)

type CustomGeoUpdateAllItem struct {
	Id       int    `json:"id"`
	Alias    string `json:"alias"`
	FileName string `json:"fileName"`
}

type CustomGeoUpdateAllFailure struct {
	Id       int    `json:"id"`
	Alias    string `json:"alias"`
	FileName string `json:"fileName"`
	Err      string `json:"error"`
}

type CustomGeoUpdateAllResult struct {
	Succeeded []CustomGeoUpdateAllItem    `json:"succeeded"`
	Failed    []CustomGeoUpdateAllFailure `json:"failed"`
}

type CustomGeoService struct {
	serverService      *ServerService
	settingService     *SettingService
	updateAllGetAll    func() ([]model.CustomGeoResource, error)
	updateAllApply     func(id int, onStartup bool) (string, *geoCommit, error)
	updateAllRestart   func() error
	updateAllWaitReady func() error
}

func NewCustomGeoService() *CustomGeoService {
	s := &CustomGeoService{
		serverService:  &ServerService{},
		settingService: &SettingService{},
	}
	s.updateAllGetAll = s.GetAll
	s.updateAllApply = s.applyDownloadAndPersist
	s.updateAllRestart = func() error { return s.serverService.RestartXrayService() }
	s.updateAllWaitReady = func() error { return s.serverService.WaitReady(10 * time.Second) }
	return s
}

// geoMaxFileSizeBytes returns the configured maximum download size in
// bytes. A missing setting service (zero-value service in tests), a
// missing setting, or a stored value <= 0 all fall back to the default,
// so the limit can never be disabled by accident.
func (s *CustomGeoService) geoMaxFileSizeBytes() int64 {
	if s == nil || s.settingService == nil {
		return defaultGeoMaxFileSizeMB * 1024 * 1024
	}
	mb, err := s.settingService.GetGeoMaxFileSizeMB()
	if err != nil || mb <= 0 {
		return defaultGeoMaxFileSizeMB * 1024 * 1024
	}
	return int64(mb) * 1024 * 1024
}

func NormalizeAliasKey(alias string) string {
	return strings.ToLower(strings.ReplaceAll(alias, "-", "_"))
}

func (s *CustomGeoService) fileNameFor(typ, alias string) string {
	if typ == customGeoTypeGeoip {
		return fmt.Sprintf("geoip_%s.dat", alias)
	}
	return fmt.Sprintf("geosite_%s.dat", alias)
}

func (s *CustomGeoService) validateType(typ string) error {
	if typ != customGeoTypeGeosite && typ != customGeoTypeGeoip {
		return ErrCustomGeoInvalidType
	}
	return nil
}

func (s *CustomGeoService) validateAlias(alias string) error {
	if alias == "" {
		return ErrCustomGeoAliasRequired
	}
	if !customGeoAliasPattern.MatchString(alias) {
		return ErrCustomGeoAliasPattern
	}
	if _, ok := reservedCustomAliases[NormalizeAliasKey(alias)]; ok {
		return ErrCustomGeoAliasReserved
	}
	return nil
}

func (s *CustomGeoService) sanitizeURL(raw string) (string, error) {
	if raw == "" {
		return "", ErrCustomGeoURLRequired
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", ErrCustomGeoInvalidURL
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", ErrCustomGeoURLScheme
	}
	if u.Host == "" {
		return "", ErrCustomGeoURLHost
	}
	if err := checkSSRF(context.Background(), u.Hostname()); err != nil {
		return "", err
	}
	// Reconstruct URL from parsed components to break taint propagation.
	clean := &url.URL{
		Scheme:   u.Scheme,
		Host:     u.Host,
		Path:     u.Path,
		RawPath:  u.RawPath,
		RawQuery: u.RawQuery,
		Fragment: u.Fragment,
	}
	return clean.String(), nil
}

func localDatFileNeedsRepair(path string) bool {
	safePath, err := sanitizeDestPath(path)
	if err != nil {
		return true
	}
	fi, err := os.Stat(safePath)
	if err != nil {
		return true
	}
	if fi.IsDir() {
		return true
	}
	return fi.Size() < int64(minDatBytes)
}

func CustomGeoLocalFileNeedsRepair(path string) bool {
	return localDatFileNeedsRepair(path)
}

func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// checkBlockedIP is the active blocklist decision, used both when resolving
// a hostname and when validating an IP literal. Override in tests (via
// disableSSRFCheck) to allow httptest servers on localhost.
var checkBlockedIP = func(ip net.IP) bool { return isBlockedIP(ip) }

// resolveHostIPs resolves a hostname exactly once and returns every
// candidate IP. It performs no policy check itself: the caller (the
// dialer, or checkSSRFDefault for URL validation) validates the answers
// with checkBlockedIP before using them. Override in tests to control
// the answers the dialer sees.
var resolveHostIPs = func(ctx context.Context, hostname string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot resolve host %s", ErrCustomGeoSSRFBlocked, hostname)
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ips = append(ips, addr.IP)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s resolves to no address", ErrCustomGeoSSRFBlocked, hostname)
	}
	return ips, nil
}

// checkSSRFDefault validates that the given host does not resolve to a private/internal IP.
// It is context-aware so that dial context cancellation/deadlines are respected during DNS resolution.
func checkSSRFDefault(ctx context.Context, hostname string) error {
	ips, err := resolveHostIPs(ctx, hostname)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if checkBlockedIP(ip) {
			return fmt.Errorf("%w: %s resolves to blocked address %s", ErrCustomGeoSSRFBlocked, hostname, ip)
		}
	}
	return nil
}

// checkSSRF is the active SSRF guard for URL validation (sanitizeURL),
// where no connection follows yet. Override in tests to allow localhost
// test servers.
var checkSSRF = checkSSRFDefault

// ssrfDialer opens the TCP connection to a validated address. Override in
// tests to record the dialed address without touching the network.
var ssrfDialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func ssrfSafeTransport() http.RoundTripper {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		base = &http.Transport{}
	}
	cloned := base.Clone()
	// Geo downloads connect directly: an environment proxy (HTTP_PROXY
	// and friends) would receive the raw hostname and resolve it itself,
	// bypassing this validation entirely. These are server-to-server
	// fetches of public files, so no proxy is needed.
	cloned.Proxy = nil
	cloned.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCustomGeoSSRFBlocked, err)
		}
		// Resolve once, validate every candidate, and dial a validated IP
		// directly. IP literals are validated as-is; hostnames are
		// resolved by resolveHostIPs (one lookup) and the first validated
		// IP is dialled. The validated addresses are exactly the ones
		// that can be connected to, so a DNS answer that changes between
		// the check and the connect (rebinding) cannot move the
		// connection to an internal address. Redirects re-enter this
		// function, so every hop gets the same treatment.
		var candidates []net.IP
		if ip := net.ParseIP(host); ip != nil {
			if checkBlockedIP(ip) {
				return nil, fmt.Errorf("%w: %s is a blocked address", ErrCustomGeoSSRFBlocked, host)
			}
			candidates = []net.IP{ip}
		} else {
			candidates, err = resolveHostIPs(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range candidates {
				if checkBlockedIP(ip) {
					return nil, fmt.Errorf("%w: %s resolves to blocked address %s", ErrCustomGeoSSRFBlocked, host, ip)
				}
			}
		}
		var dialErr error
		for _, ip := range candidates {
			conn, err := ssrfDialer(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			dialErr = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, dialErr
	}
	// TLS ServerName and the HTTP Host header are derived from the
	// request URL by the Transport, not from the dial address, so HTTPS
	// still verifies the original domain and HTTP still sends the
	// original Host.
	return cloned
}

// ValidatePublicHTTPURL parses rawURL and rejects anything that is not a
// public http(s) URL: bad scheme, missing host, or a host resolving to a
// blocked (internal/reserved) address. It returns the reconstructed,
// normalized URL. Empty input is rejected here; callers that treat an
// empty value as "disabled" must check for it first.
func ValidatePublicHTTPURL(rawURL string) (string, error) {
	return (&CustomGeoService{}).sanitizeURL(rawURL)
}

// NewSSRFCheckedHTTPClient returns an HTTP client that only ever dials
// public addresses (the SSRF-safe transport re-validates every address
// at dial time, so a DNS answer that changes between check and connect
// cannot redirect the request inward), refuses redirects, and bounds
// the whole request by timeout.
func NewSSRFCheckedHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: ssrfSafeTransport(),
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func probeCustomGeoURLWithGET(rawURL string) error {
	sanitizedURL, err := (&CustomGeoService{}).sanitizeURL(rawURL)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: customGeoProbeTimeout, Transport: ssrfSafeTransport()}
	req, err := http.NewRequest(http.MethodGet, sanitizedURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Range", "bytes=0-0")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 256))
	switch resp.StatusCode {
	case http.StatusOK, http.StatusPartialContent:
		return nil
	default:
		return fmt.Errorf("get range status %d", resp.StatusCode)
	}
}

func probeCustomGeoURL(rawURL string) error {
	sanitizedURL, err := (&CustomGeoService{}).sanitizeURL(rawURL)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: customGeoProbeTimeout, Transport: ssrfSafeTransport()}
	req, err := http.NewRequest(http.MethodHead, sanitizedURL, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	sc := resp.StatusCode
	if sc >= 200 && sc < 300 {
		return nil
	}
	if sc == http.StatusMethodNotAllowed || sc == http.StatusNotImplemented {
		return probeCustomGeoURLWithGET(rawURL)
	}
	return fmt.Errorf("head status %d", sc)
}

func (s *CustomGeoService) EnsureOnStartup() {
	list, err := s.GetAll()
	if err != nil {
		logger.Warning("custom geo startup: load list:", err)
		return
	}
	n := len(list)
	if n == 0 {
		logger.Info("custom geo startup: no custom geofiles configured")
		return
	}
	logger.Infof("custom geo startup: checking %d custom geofile(s)", n)
	for i := range list {
		r := &list[i]
		sanitizedURL, err := s.sanitizeURL(r.Url)
		if err != nil {
			logger.Warningf("custom geo startup id=%d: invalid url: %v", r.Id, err)
			continue
		}
		r.Url = sanitizedURL
		s.syncLocalPath(r)
		localPath := r.LocalPath
		if !localDatFileNeedsRepair(localPath) {
			logger.Infof("custom geo startup id=%d alias=%s path=%s: present", r.Id, r.Alias, localPath)
			continue
		}
		logger.Infof("custom geo startup id=%d alias=%s path=%s: missing or needs repair, probing source", r.Id, r.Alias, localPath)
		if err := probeCustomGeoURL(r.Url); err != nil {
			logger.Warningf("custom geo startup id=%d alias=%s url=%s: probe: %v (attempting download anyway)", r.Id, r.Alias, r.Url, err)
		}
		// On startup there is no restart to gate on (Xray starts
		// later): a successful repair commits at once and its
		// backup is discarded.
		_, commit, _ := s.applyDownloadAndPersist(r.Id, true)
		if commit != nil {
			commit.discard()
		}
	}
}

func (s *CustomGeoService) downloadToPath(resourceURL, destPath string, lastModifiedHeader string) (skipped bool, newLastModified string, err error) {
	safeDestPath, err := sanitizeDestPath(destPath)
	if err != nil {
		return false, "", fmt.Errorf("%w: %v", ErrCustomGeoDownload, err)
	}

	skipped, lm, err := s.downloadToPathOnce(resourceURL, safeDestPath, lastModifiedHeader, false)
	if err != nil {
		return false, "", err
	}
	if skipped {
		if _, statErr := os.Stat(safeDestPath); statErr == nil && !localDatFileNeedsRepair(safeDestPath) {
			return true, lm, nil
		}
		return s.downloadToPathOnce(resourceURL, safeDestPath, lastModifiedHeader, true)
	}
	return false, lm, nil
}

// sanitizeDestPath ensures destPath is inside the bin folder, preventing path traversal.
// It resolves symlinks to prevent symlink-based escapes.
// Returns the cleaned absolute path that is safe to use in file operations.
func sanitizeDestPath(destPath string) (string, error) {
	baseDirAbs, err := filepath.Abs(config.GetBinFolderPath())
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCustomGeoPathTraversal, err)
	}
	// Resolve symlinks in base directory to get the real path.
	if resolved, evalErr := filepath.EvalSymlinks(baseDirAbs); evalErr == nil {
		baseDirAbs = resolved
	}
	destPathAbs, err := filepath.Abs(destPath)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrCustomGeoPathTraversal, err)
	}
	// Resolve symlinks for the parent directory of the destination path.
	destDir := filepath.Dir(destPathAbs)
	if resolved, evalErr := filepath.EvalSymlinks(destDir); evalErr == nil {
		destPathAbs = filepath.Join(resolved, filepath.Base(destPathAbs))
	}
	// Verify the resolved path is within the safe base directory using prefix check.
	safeDirPrefix := baseDirAbs + string(filepath.Separator)
	if !strings.HasPrefix(destPathAbs, safeDirPrefix) {
		return "", ErrCustomGeoPathTraversal
	}
	return destPathAbs, nil
}

// downloadToPathFull downloads without a conditional request: used
// when the source URL changed, so the old source's Last-Modified is
// never sent to the new source — a 304 there would keep the old
// source's data under the new URL.
func (s *CustomGeoService) downloadToPathFull(resourceURL, destPath string) (skipped bool, newLastModified string, err error) {
	safeDestPath, err := sanitizeDestPath(destPath)
	if err != nil {
		return false, "", fmt.Errorf("%w: %v", ErrCustomGeoDownload, err)
	}
	return s.downloadToPathOnce(resourceURL, safeDestPath, "", true)
}

func (s *CustomGeoService) downloadToPathOnce(resourceURL, destPath string, lastModifiedHeader string, forceFull bool) (skipped bool, newLastModified string, err error) {
	safeDestPath, err := sanitizeDestPath(destPath)
	if err != nil {
		return false, "", fmt.Errorf("%w: %v", ErrCustomGeoDownload, err)
	}
	sanitizedURL, err := s.sanitizeURL(resourceURL)
	if err != nil {
		return false, "", fmt.Errorf("%w: %v", ErrCustomGeoDownload, err)
	}

	var req *http.Request
	req, err = http.NewRequest(http.MethodGet, sanitizedURL, nil)
	if err != nil {
		return false, "", fmt.Errorf("%w: %v", ErrCustomGeoDownload, err)
	}

	if !forceFull {
		if fi, statErr := os.Stat(safeDestPath); statErr == nil && !localDatFileNeedsRepair(safeDestPath) {
			if !fi.ModTime().IsZero() {
				req.Header.Set("If-Modified-Since", fi.ModTime().UTC().Format(http.TimeFormat))
			} else if lastModifiedHeader != "" {
				if t, perr := time.Parse(http.TimeFormat, lastModifiedHeader); perr == nil {
					req.Header.Set("If-Modified-Since", t.UTC().Format(http.TimeFormat))
				}
			}
		}
	}

	client := &http.Client{Timeout: 10 * time.Minute, Transport: ssrfSafeTransport()}
	// codeql[go/request-forgery]
	resp, err := client.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("%w: %v", ErrCustomGeoDownload, err)
	}
	defer resp.Body.Close()

	var serverModTime time.Time
	if lm := resp.Header.Get("Last-Modified"); lm != "" {
		if parsed, perr := time.Parse(http.TimeFormat, lm); perr == nil {
			serverModTime = parsed
			newLastModified = lm
		}
	}

	updateModTime := func() {
		if !serverModTime.IsZero() {
			_ = os.Chtimes(safeDestPath, serverModTime, serverModTime)
		}
	}

	if resp.StatusCode == http.StatusNotModified {
		if forceFull {
			return false, "", fmt.Errorf("%w: unexpected 304 on unconditional get", ErrCustomGeoDownload)
		}
		updateModTime()
		return true, newLastModified, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("%w: unexpected status %d", ErrCustomGeoDownload, resp.StatusCode)
	}

	// Enforce the download size limit before writing anything: a
	// malicious or compromised remote source must not be able to fill
	// the disk. The Content-Length check rejects oversized files
	// without downloading; the LimitReader below is the hard limit for
	// chunked responses that carry no Content-Length.
	maxBytes := s.geoMaxFileSizeBytes()
	if resp.ContentLength > maxBytes {
		return false, "", fmt.Errorf("%w: file too large: Content-Length %d exceeds limit %d", ErrCustomGeoDownload, resp.ContentLength, maxBytes)
	}

	binDir := filepath.Dir(safeDestPath)
	if err = os.MkdirAll(binDir, 0o755); err != nil {
		return false, "", fmt.Errorf("%w: %v", ErrCustomGeoDownload, err)
	}

	safeTmpPath, err := sanitizeDestPath(safeDestPath + ".tmp-" + random.Seq(8))
	if err != nil {
		return false, "", fmt.Errorf("%w: %v", ErrCustomGeoDownload, err)
	}
	out, err := os.Create(safeTmpPath)
	if err != nil {
		return false, "", fmt.Errorf("%w: %v", ErrCustomGeoDownload, err)
	}
	n, err := io.Copy(out, io.LimitReader(resp.Body, maxBytes+1))
	closeErr := out.Close()
	if err != nil {
		_ = os.Remove(safeTmpPath)
		return false, "", fmt.Errorf("%w: %v", ErrCustomGeoDownload, err)
	}
	if closeErr != nil {
		_ = os.Remove(safeTmpPath)
		return false, "", fmt.Errorf("%w: %v", ErrCustomGeoDownload, closeErr)
	}
	if n > maxBytes {
		_ = os.Remove(safeTmpPath)
		return false, "", fmt.Errorf("%w: file too large: exceeds limit %d bytes", ErrCustomGeoDownload, maxBytes)
	}
	if n < minDatBytes {
		_ = os.Remove(safeTmpPath)
		return false, "", fmt.Errorf("%w: file too small", ErrCustomGeoDownload)
	}

	if err = os.Rename(safeTmpPath, safeDestPath); err != nil {
		_ = os.Remove(safeTmpPath)
		return false, "", fmt.Errorf("%w: %v", ErrCustomGeoDownload, err)
	}

	updateModTime()
	if newLastModified == "" && resp.Header.Get("Last-Modified") != "" {
		newLastModified = resp.Header.Get("Last-Modified")
	}
	return false, newLastModified, nil
}

func (s *CustomGeoService) resolveDestPath(r *model.CustomGeoResource) string {
	if r.LocalPath != "" {
		return r.LocalPath
	}
	return filepath.Join(config.GetBinFolderPath(), s.fileNameFor(r.Type, r.Alias))
}

func (s *CustomGeoService) syncLocalPath(r *model.CustomGeoResource) {
	p := filepath.Join(config.GetBinFolderPath(), s.fileNameFor(r.Type, r.Alias))
	r.LocalPath = p
}

func (s *CustomGeoService) syncAndSanitizeLocalPath(r *model.CustomGeoResource) error {
	s.syncLocalPath(r)
	safePath, err := sanitizeDestPath(r.LocalPath)
	if err != nil {
		return err
	}
	r.LocalPath = safePath
	return nil
}

func removeSafePathIfExists(path string) error {
	safePath, err := sanitizeDestPath(path)
	if err != nil {
		return err
	}
	if _, err := os.Stat(safePath); err == nil {
		if err := os.Remove(safePath); err != nil {
			return err
		}
	}
	return nil
}

// backupGeoFile copies the file at destPath to a uniquely named
// backup (same directory) so a failed commit can restore the
// previous content. It returns the backup path, or "" when no file
// existed to back up. The copy leaves the original in place, so the
// conditional download (If-Modified-Since from the file mtime)
// keeps working exactly as before. The backup name is unique per
// operation so a concurrent update cannot overwrite another one's
// only copy of the old file.
func backupGeoFile(destPath string) (string, error) {
	if _, err := os.Stat(destPath); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	backupPath := destPath + ".bak-" + random.Seq(8)
	data, err := os.ReadFile(destPath)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		return "", err
	}
	return backupPath, nil
}

// rollbackGeoFile undoes a download the database refused: it
// restores the backed-up content when one was kept, or removes the
// just-downloaded file when the destination was empty before.
func rollbackGeoFile(backupPath, destPath string) {
	if backupPath == "" {
		_ = removeSafePathIfExists(destPath)
		return
	}
	if err := os.Rename(backupPath, destPath); err != nil {
		logger.Errorf("custom geo rollback: failed to restore %s from backup: %v", destPath, err)
	}
}

// discardGeoFileBackup removes a backup that is no longer needed
// (the commit succeeded). Failures are only logged.
func discardGeoFileBackup(backupPath string) {
	if backupPath == "" {
		return
	}
	if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
		logger.Warningf("custom geo remove backup %s: %v", backupPath, err)
	}
}

// geoCommit tracks one replaced geo file and its previous database
// record until the service restart and readiness check pass. Only
// then is the backup discarded; on any failure the old file and the
// old record come back. old is nil for a newly created resource,
// whose rollback deletes the record instead.
type geoCommit struct {
	destPath   string
	backupPath string
	old        *model.CustomGeoResource
	recordID   int
}

func (g *geoCommit) discard() {
	discardGeoFileBackup(g.backupPath)
}

func (g *geoCommit) rollback() {
	rollbackGeoFile(g.backupPath, g.destPath)
	if g.old != nil {
		if err := database.GetDB().Save(g.old).Error; err != nil {
			logger.Errorf("custom geo rollback: failed to restore record %d: %v", g.recordID, err)
		}
		return
	}
	if err := database.GetDB().Delete(&model.CustomGeoResource{}, g.recordID).Error; err != nil {
		logger.Errorf("custom geo rollback: failed to delete new record %d: %v", g.recordID, err)
	}
}

// restartAndCommit restarts Xray and waits for it to become ready,
// then discards the geo change's backup. On a restart failure or a
// new Xray that never becomes ready, it rolls the file and the
// record back, restores the pre-update running state, and returns
// the error: a geo update must never report success while Xray runs
// the new files unready, or leave the panel stopped after a failed
// update.
func (s *CustomGeoService) restartAndCommit(commit *geoCommit, wasRunning, wasManuallyStopped bool) error {
	if err := s.serverService.RestartXrayService(); err != nil {
		s.rollbackGeoChange(commit, wasRunning, wasManuallyStopped)
		return err
	}
	if err := s.serverService.WaitReady(10 * time.Second); err != nil {
		s.rollbackGeoChange(commit, wasRunning, wasManuallyStopped)
		return err
	}
	commit.discard()
	return nil
}

// rollbackGeoChange stops the candidate process first — it runs
// the new configuration and must not keep serving the new files —
// then restores the file and record and the pre-update running
// state.
func (s *CustomGeoService) rollbackGeoChange(commit *geoCommit, wasRunning, wasManuallyStopped bool) {
	// Stop the candidate process first — it runs the new
	// configuration and must not keep serving the new files — then
	// restore the file and record and the pre-update running state.
	if s.serverService.IsXrayRunning() {
		_ = s.serverService.StopXrayService()
	}
	if commit != nil {
		commit.rollback()
	}
	s.serverService.restoreXrayState(wasRunning, wasManuallyStopped)
}

// preRestartState records the service state before a geo update
// restarts Xray, so a failed update can restore it.
func (s *CustomGeoService) preRestartState() (wasRunning, wasManuallyStopped bool) {
	if s.serverService == nil {
		return false, false
	}
	return s.serverService.IsXrayRunning(), s.serverService.IsManuallyStopped()
}

func (s *CustomGeoService) Create(r *model.CustomGeoResource) error {
	// The whole update transaction is serialised with Xray updates,
	// other geo updates, and imports.
	updateMu.Lock()
	defer updateMu.Unlock()
	if err := s.validateType(r.Type); err != nil {
		return err
	}
	if err := s.validateAlias(r.Alias); err != nil {
		return err
	}
	sanitizedURL, err := s.sanitizeURL(r.Url)
	if err != nil {
		return err
	}
	r.Url = sanitizedURL
	var existing int64
	database.GetDB().Model(&model.CustomGeoResource{}).
		Where("geo_type = ? AND alias = ?", r.Type, r.Alias).Count(&existing)
	if existing > 0 {
		return ErrCustomGeoDuplicateAlias
	}
	if err := s.syncAndSanitizeLocalPath(r); err != nil {
		return err
	}
	// Back up any file already at the destination before the
	// download replaces it, so a failed database insert restores
	// the old content instead of deleting a file the record never
	// owned.
	backupPath, err := backupGeoFile(r.LocalPath)
	if err != nil {
		return err
	}
	skipped, lm, err := s.downloadToPath(r.Url, r.LocalPath, r.LastModified)
	if err != nil {
		discardGeoFileBackup(backupPath)
		return err
	}
	now := time.Now().Unix()
	r.LastUpdatedAt = now
	r.LastModified = lm
	if err = database.GetDB().Create(r).Error; err != nil {
		rollbackGeoFile(backupPath, r.LocalPath)
		return err
	}
	// The file and the record are committed, but the backup stays
	// until the restart and readiness check pass: a new Xray that
	// never becomes ready rolls the file and the record back.
	wasRunning, wasManuallyStopped := s.preRestartState()
	commit := &geoCommit{destPath: r.LocalPath, backupPath: backupPath, recordID: int(r.Id)}
	logger.Infof("custom geo created id=%d type=%s alias=%s skipped=%v", r.Id, r.Type, r.Alias, skipped)
	return s.restartAndCommit(commit, wasRunning, wasManuallyStopped)
}

func (s *CustomGeoService) Update(id int, r *model.CustomGeoResource) error {
	// The whole update transaction is serialised with Xray updates,
	// other geo updates, and imports.
	updateMu.Lock()
	defer updateMu.Unlock()
	var cur model.CustomGeoResource
	if err := database.GetDB().First(&cur, id).Error; err != nil {
		if database.IsNotFound(err) {
			return ErrCustomGeoNotFound
		}
		return err
	}
	if err := s.validateType(r.Type); err != nil {
		return err
	}
	if err := s.validateAlias(r.Alias); err != nil {
		return err
	}
	sanitizedURL, err := s.sanitizeURL(r.Url)
	if err != nil {
		return err
	}
	r.Url = sanitizedURL
	if cur.Type != r.Type || cur.Alias != r.Alias {
		var cnt int64
		database.GetDB().Model(&model.CustomGeoResource{}).
			Where("geo_type = ? AND alias = ? AND id <> ?", r.Type, r.Alias, id).
			Count(&cnt)
		if cnt > 0 {
			return ErrCustomGeoDuplicateAlias
		}
	}
	oldPath := s.resolveDestPath(&cur)
	r.Id = id
	if err := s.syncAndSanitizeLocalPath(r); err != nil {
		return err
	}
	// Download first, commit last. Before the download, back up
	// whatever file already sits at the destination: if the
	// database update fails after the file was replaced, the old
	// content is restored instead of leaving the file and the
	// record inconsistent (the new content under the old URL and
	// Last-Modified). The old file is deleted only after the
	// download AND the database update succeed: if the new source
	// answers 404, is oversized, or the network drops, the old file
	// and the old record stay untouched, so Xray keeps working.
	// When the source URL changed, the old source's Last-Modified
	// must not be sent to the new source: a 304 there would keep the
	// old source's data while the record is updated to the new URL.
	// Force a full download in that case.
	backupPath, err := backupGeoFile(r.LocalPath)
	if err != nil {
		return err
	}
	var lm string
	if r.Url != cur.Url {
		_, lm, err = s.downloadToPathFull(r.Url, r.LocalPath)
	} else {
		_, lm, err = s.downloadToPath(r.Url, r.LocalPath, cur.LastModified)
	}
	if err != nil {
		// The download failed before replacing anything; the
		// backup is a redundant copy now.
		discardGeoFileBackup(backupPath)
		return err
	}
	r.LastUpdatedAt = time.Now().Unix()
	r.LastModified = lm
	err = database.GetDB().Model(&model.CustomGeoResource{}).Where("id = ?", id).Updates(map[string]any{
		"geo_type":        r.Type,
		"alias":           r.Alias,
		"url":             r.Url,
		"local_path":      r.LocalPath,
		"last_updated_at": r.LastUpdatedAt,
		"last_modified":   r.LastModified,
	}).Error
	if err != nil {
		rollbackGeoFile(backupPath, r.LocalPath)
		return err
	}
	// The file and the record are committed, but the backup stays
	// until the restart and readiness check pass: a new Xray that
	// never becomes ready rolls the file and the record back, and
	// only then is the old file removed when the path changed.
	wasRunning, wasManuallyStopped := s.preRestartState()
	commit := &geoCommit{destPath: r.LocalPath, backupPath: backupPath, old: &cur, recordID: id}
	logger.Infof("custom geo updated id=%d", id)
	if err := s.restartAndCommit(commit, wasRunning, wasManuallyStopped); err != nil {
		return err
	}
	// Only now, with the download, the record, and the running
	// service all confirmed, remove the old file when the path
	// changed.
	if oldPath != r.LocalPath && oldPath != "" {
		if err := removeSafePathIfExists(oldPath); err != nil && !errors.Is(err, ErrCustomGeoPathTraversal) {
			logger.Warningf("custom geo remove old path %s: %v", oldPath, err)
		}
	}
	return nil
}

func (s *CustomGeoService) Delete(id int) (displayName string, err error) {
	// Serialised with the other update transactions so a delete
	// cannot interleave another update's file swap.
	updateMu.Lock()
	defer updateMu.Unlock()
	var r model.CustomGeoResource
	if err := database.GetDB().First(&r, id).Error; err != nil {
		if database.IsNotFound(err) {
			return "", ErrCustomGeoNotFound
		}
		return "", err
	}
	displayName = s.fileNameFor(r.Type, r.Alias)
	p := s.resolveDestPath(&r)
	if _, err := sanitizeDestPath(p); err != nil {
		return displayName, err
	}
	if err := database.GetDB().Delete(&model.CustomGeoResource{}, id).Error; err != nil {
		return displayName, err
	}
	if p != "" {
		if err := removeSafePathIfExists(p); err != nil {
			logger.Warningf("custom geo delete file %s: %v", p, err)
		}
	}
	logger.Infof("custom geo deleted id=%d", id)
	if err := s.serverService.RestartXrayService(); err != nil {
		logger.Warning("custom geo delete: restart xray:", err)
	}
	return displayName, nil
}

func (s *CustomGeoService) GetAll() ([]model.CustomGeoResource, error) {
	var list []model.CustomGeoResource
	err := database.GetDB().Order("id asc").Find(&list).Error
	return list, err
}

func (s *CustomGeoService) applyDownloadAndPersist(id int, onStartup bool) (displayName string, commit *geoCommit, err error) {
	var r model.CustomGeoResource
	if err := database.GetDB().First(&r, id).Error; err != nil {
		if database.IsNotFound(err) {
			return "", nil, ErrCustomGeoNotFound
		}
		return "", nil, err
	}
	displayName = s.fileNameFor(r.Type, r.Alias)
	if err := s.syncAndSanitizeLocalPath(&r); err != nil {
		return displayName, nil, err
	}
	sanitizedURL, sanitizeErr := s.sanitizeURL(r.Url)
	if sanitizeErr != nil {
		return displayName, nil, sanitizeErr
	}
	// Back up the current file before the download replaces it, so
	// a failed metadata update restores the old content instead of
	// leaving the file and the record inconsistent. The backup is
	// returned to the caller, which owns it until the service
	// restart and readiness check pass.
	backupPath, err := backupGeoFile(r.LocalPath)
	if err != nil {
		return displayName, nil, err
	}
	skipped, lm, err := s.downloadToPath(sanitizedURL, r.LocalPath, r.LastModified)
	if err != nil {
		discardGeoFileBackup(backupPath)
		if onStartup {
			logger.Warningf("custom geo startup download id=%d: %v", id, err)
		} else {
			logger.Warningf("custom geo manual update id=%d: %v", id, err)
		}
		return displayName, nil, err
	}
	now := time.Now().Unix()
	updates := map[string]any{
		"last_modified":   lm,
		"local_path":      r.LocalPath,
		"last_updated_at": now,
	}
	if err = database.GetDB().Model(&model.CustomGeoResource{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		rollbackGeoFile(backupPath, r.LocalPath)
		if onStartup {
			logger.Warningf("custom geo startup id=%d: persist metadata: %v", id, err)
		} else {
			logger.Warningf("custom geo manual update id=%d: persist metadata: %v", id, err)
		}
		return displayName, nil, err
	}
	if skipped {
		if onStartup {
			logger.Infof("custom geo startup download skipped (not modified) id=%d", id)
		} else {
			logger.Infof("custom geo manual update skipped (not modified) id=%d", id)
		}
	} else {
		if onStartup {
			logger.Infof("custom geo startup download ok id=%d", id)
		} else {
			logger.Infof("custom geo manual update ok id=%d", id)
		}
	}
	return displayName, &geoCommit{destPath: r.LocalPath, backupPath: backupPath, old: &r, recordID: id}, nil
}

func (s *CustomGeoService) TriggerUpdate(id int) (string, error) {
	// The whole update transaction is serialised with Xray updates,
	// other geo updates, and imports.
	updateMu.Lock()
	defer updateMu.Unlock()
	wasRunning, wasManuallyStopped := s.preRestartState()
	displayName, commit, err := s.applyDownloadAndPersist(id, false)
	if err != nil {
		return displayName, err
	}
	if err := s.restartAndCommit(commit, wasRunning, wasManuallyStopped); err != nil {
		return displayName, err
	}
	return displayName, nil
}

func (s *CustomGeoService) TriggerUpdateAll() (*CustomGeoUpdateAllResult, error) {
	// The whole batch is one serialised update transaction: the
	// per-resource applies, the single restart, and the readiness
	// check.
	updateMu.Lock()
	defer updateMu.Unlock()
	var list []model.CustomGeoResource
	var err error
	if s.updateAllGetAll != nil {
		list, err = s.updateAllGetAll()
	} else {
		list, err = s.GetAll()
	}
	if err != nil {
		return nil, err
	}
	res := &CustomGeoUpdateAllResult{}
	if len(list) == 0 {
		return res, nil
	}
	wasRunning, wasManuallyStopped := s.preRestartState()
	var commits []*geoCommit
	for _, r := range list {
		var name string
		var commit *geoCommit
		var applyErr error
		if s.updateAllApply != nil {
			name, commit, applyErr = s.updateAllApply(r.Id, false)
		} else {
			name, commit, applyErr = s.applyDownloadAndPersist(r.Id, false)
		}
		if applyErr != nil {
			res.Failed = append(res.Failed, CustomGeoUpdateAllFailure{
				Id: r.Id, Alias: r.Alias, FileName: name, Err: applyErr.Error(),
			})
			continue
		}
		res.Succeeded = append(res.Succeeded, CustomGeoUpdateAllItem{
			Id: r.Id, Alias: r.Alias, FileName: name,
		})
		commits = append(commits, commit)
	}
	if len(res.Succeeded) > 0 {
		// The batch commits only when the restart AND the
		// readiness check pass. On either failure, every item the
		// batch already applied rolls its file and record back,
		// the candidate process is stopped, the pre-update running
		// state is restored, and the error is returned instead of
		// a success with a half-applied batch.
		rollBackBatch := func() {
			if s.serverService != nil && s.serverService.IsXrayRunning() {
				_ = s.serverService.StopXrayService()
			}
			for _, c := range commits {
				if c != nil {
					c.rollback()
				}
			}
			if s.serverService != nil {
				s.serverService.restoreXrayState(wasRunning, wasManuallyStopped)
			}
			for _, item := range res.Succeeded {
				res.Failed = append(res.Failed, CustomGeoUpdateAllFailure{
					Id: item.Id, Alias: item.Alias, FileName: item.FileName,
				})
			}
			res.Succeeded = nil
		}
		var restartErr error
		if s.updateAllRestart != nil {
			restartErr = s.updateAllRestart()
		} else {
			restartErr = s.serverService.RestartXrayService()
		}
		if restartErr != nil {
			rollBackBatch()
			for i := range res.Failed {
				if res.Failed[i].Err == "" {
					res.Failed[i].Err = restartErr.Error()
				}
			}
			return res, restartErr
		}
		var readyErr error
		if s.updateAllWaitReady != nil {
			readyErr = s.updateAllWaitReady()
		} else if s.serverService != nil {
			readyErr = s.serverService.WaitReady(10 * time.Second)
		}
		if readyErr != nil {
			rollBackBatch()
			for i := range res.Failed {
				if res.Failed[i].Err == "" {
					res.Failed[i].Err = readyErr.Error()
				}
			}
			return res, readyErr
		}
		for _, c := range commits {
			if c != nil {
				c.discard()
			}
		}
	}
	return res, nil
}

type CustomGeoAliasItem struct {
	Alias      string `json:"alias"`
	Type       string `json:"type"`
	FileName   string `json:"fileName"`
	ExtExample string `json:"extExample"`
}

type CustomGeoAliasesResponse struct {
	Geosite []CustomGeoAliasItem `json:"geosite"`
	Geoip   []CustomGeoAliasItem `json:"geoip"`
}

func (s *CustomGeoService) GetAliasesForUI() (CustomGeoAliasesResponse, error) {
	list, err := s.GetAll()
	if err != nil {
		logger.Warning("custom geo GetAliasesForUI:", err)
		return CustomGeoAliasesResponse{}, err
	}
	var out CustomGeoAliasesResponse
	for _, r := range list {
		fn := s.fileNameFor(r.Type, r.Alias)
		ex := fmt.Sprintf("ext:%s:tag", fn)
		item := CustomGeoAliasItem{
			Alias:      r.Alias,
			Type:       r.Type,
			FileName:   fn,
			ExtExample: ex,
		}
		if r.Type == customGeoTypeGeoip {
			out.Geoip = append(out.Geoip, item)
		} else {
			out.Geosite = append(out.Geosite, item)
		}
	}
	return out, nil
}
