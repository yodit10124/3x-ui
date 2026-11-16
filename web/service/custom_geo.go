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
	serverService    *ServerService
	settingService   *SettingService
	updateAllGetAll  func() ([]model.CustomGeoResource, error)
	updateAllApply   func(id int, onStartup bool) (string, error)
	updateAllRestart func() error
}

func NewCustomGeoService() *CustomGeoService {
	s := &CustomGeoService{
		serverService:  &ServerService{},
		settingService: &SettingService{},
	}
	s.updateAllGetAll = s.GetAll
	s.updateAllApply = s.applyDownloadAndPersist
	s.updateAllRestart = func() error { return s.serverService.RestartXrayService() }
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
		_, _ = s.applyDownloadAndPersist(r.Id, true)
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

	safeTmpPath, err := sanitizeDestPath(safeDestPath + ".tmp")
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

func (s *CustomGeoService) Create(r *model.CustomGeoResource) error {
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
	skipped, lm, err := s.downloadToPath(r.Url, r.LocalPath, r.LastModified)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	r.LastUpdatedAt = now
	r.LastModified = lm
	if err = database.GetDB().Create(r).Error; err != nil {
		_ = removeSafePathIfExists(r.LocalPath)
		return err
	}
	logger.Infof("custom geo created id=%d type=%s alias=%s skipped=%v", r.Id, r.Type, r.Alias, skipped)
	if err = s.serverService.RestartXrayService(); err != nil {
		logger.Warning("custom geo create: restart xray:", err)
	}
	return nil
}

func (s *CustomGeoService) Update(id int, r *model.CustomGeoResource) error {
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
	// Download first, commit last. The old file is deleted only after
	// the download AND the database update succeed: if the new source
	// answers 404, is oversized, or the network drops, the old file
	// and the old record stay untouched, so Xray keeps working.
	// When the source URL changed, the old source's Last-Modified
	// must not be sent to the new source: a 304 there would keep the
	// old source's data while the record is updated to the new URL.
	// Force a full download in that case.
	var lm string
	if r.Url != cur.Url {
		_, lm, err = s.downloadToPathFull(r.Url, r.LocalPath)
	} else {
		_, lm, err = s.downloadToPath(r.Url, r.LocalPath, cur.LastModified)
	}
	if err != nil {
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
		// The new file was just downloaded to a path the database
		// does not reference; remove it so a failed update leaves no
		// orphan behind. The old file is untouched.
		if r.LocalPath != oldPath {
			_ = removeSafePathIfExists(r.LocalPath)
		}
		return err
	}
	// Only now, with the download and the record committed, remove
	// the old file when the path changed.
	if oldPath != r.LocalPath && oldPath != "" {
		if err := removeSafePathIfExists(oldPath); err != nil && !errors.Is(err, ErrCustomGeoPathTraversal) {
			logger.Warningf("custom geo remove old path %s: %v", oldPath, err)
		}
	}
	logger.Infof("custom geo updated id=%d", id)
	if err = s.serverService.RestartXrayService(); err != nil {
		logger.Warning("custom geo update: restart xray:", err)
	}
	return nil
}

func (s *CustomGeoService) Delete(id int) (displayName string, err error) {
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

func (s *CustomGeoService) applyDownloadAndPersist(id int, onStartup bool) (displayName string, err error) {
	var r model.CustomGeoResource
	if err := database.GetDB().First(&r, id).Error; err != nil {
		if database.IsNotFound(err) {
			return "", ErrCustomGeoNotFound
		}
		return "", err
	}
	displayName = s.fileNameFor(r.Type, r.Alias)
	if err := s.syncAndSanitizeLocalPath(&r); err != nil {
		return displayName, err
	}
	sanitizedURL, sanitizeErr := s.sanitizeURL(r.Url)
	if sanitizeErr != nil {
		return displayName, sanitizeErr
	}
	skipped, lm, err := s.downloadToPath(sanitizedURL, r.LocalPath, r.LastModified)
	if err != nil {
		if onStartup {
			logger.Warningf("custom geo startup download id=%d: %v", id, err)
		} else {
			logger.Warningf("custom geo manual update id=%d: %v", id, err)
		}
		return displayName, err
	}
	now := time.Now().Unix()
	updates := map[string]any{
		"last_modified":   lm,
		"local_path":      r.LocalPath,
		"last_updated_at": now,
	}
	if err = database.GetDB().Model(&model.CustomGeoResource{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		if onStartup {
			logger.Warningf("custom geo startup id=%d: persist metadata: %v", id, err)
		} else {
			logger.Warningf("custom geo manual update id=%d: persist metadata: %v", id, err)
		}
		return displayName, err
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
	return displayName, nil
}

func (s *CustomGeoService) TriggerUpdate(id int) (string, error) {
	displayName, err := s.applyDownloadAndPersist(id, false)
	if err != nil {
		return displayName, err
	}
	if err = s.serverService.RestartXrayService(); err != nil {
		logger.Warning("custom geo manual update: restart xray:", err)
	}
	return displayName, nil
}

func (s *CustomGeoService) TriggerUpdateAll() (*CustomGeoUpdateAllResult, error) {
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
	for _, r := range list {
		var name string
		var applyErr error
		if s.updateAllApply != nil {
			name, applyErr = s.updateAllApply(r.Id, false)
		} else {
			name, applyErr = s.applyDownloadAndPersist(r.Id, false)
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
	}
	if len(res.Succeeded) > 0 {
		var restartErr error
		if s.updateAllRestart != nil {
			restartErr = s.updateAllRestart()
		} else {
			restartErr = s.serverService.RestartXrayService()
		}
		if restartErr != nil {
			logger.Warning("custom geo update all: restart xray:", restartErr)
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
