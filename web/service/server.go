package service

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/util/random"
	"github.com/mhsanaei/3x-ui/v2/util/sys"
	"github.com/mhsanaei/3x-ui/v2/web/websocket"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"github.com/google/uuid"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/net"
)

// ProcessState represents the current state of a system process.
type ProcessState string

// Process state constants
const (
	Running ProcessState = "running" // Process is running normally
	Stop    ProcessState = "stop"    // Process is stopped
	Error   ProcessState = "error"   // Process is in error state
)

// Status represents comprehensive system and application status information.
// It includes CPU, memory, disk, network statistics, and Xray process status.
type Status struct {
	T           time.Time `json:"-"`
	Cpu         float64   `json:"cpu"`
	CpuCores    int       `json:"cpuCores"`
	LogicalPro  int       `json:"logicalPro"`
	CpuSpeedMhz float64   `json:"cpuSpeedMhz"`
	Mem         struct {
		Current uint64 `json:"current"`
		Total   uint64 `json:"total"`
	} `json:"mem"`
	Swap struct {
		Current uint64 `json:"current"`
		Total   uint64 `json:"total"`
	} `json:"swap"`
	Disk struct {
		Current uint64 `json:"current"`
		Total   uint64 `json:"total"`
	} `json:"disk"`
	Xray struct {
		State    ProcessState `json:"state"`
		ErrorMsg string       `json:"errorMsg"`
		Version  string       `json:"version"`
	} `json:"xray"`
	Uptime   uint64    `json:"uptime"`
	Loads    []float64 `json:"loads"`
	TcpCount int       `json:"tcpCount"`
	UdpCount int       `json:"udpCount"`
	NetIO    struct {
		Up   uint64 `json:"up"`
		Down uint64 `json:"down"`
	} `json:"netIO"`
	NetTraffic struct {
		Sent uint64 `json:"sent"`
		Recv uint64 `json:"recv"`
	} `json:"netTraffic"`
	PublicIP struct {
		IPv4 string `json:"ipv4"`
		IPv6 string `json:"ipv6"`
	} `json:"publicIP"`
	AppStats struct {
		Threads uint32 `json:"threads"`
		Mem     uint64 `json:"mem"`
		Uptime  uint64 `json:"uptime"`
	} `json:"appStats"`
}

// Release represents information about a software release from GitHub.
type Release struct {
	TagName string `json:"tag_name"` // The tag name of the release
}

// ServerService provides business logic for server monitoring and management.
// It handles system status collection, IP detection, and application statistics.
type ServerService struct {
	xrayService        XrayService
	inboundService     InboundService
	cachedIPv4         string
	cachedIPv6         string
	noIPv6             bool
	mu                 sync.Mutex
	lastCPUTimes       cpu.TimesStat
	hasLastCPUSample   bool
	hasNativeCPUSample bool
	emaCPU             float64
	cpuHistory         []CPUSample
	cachedCpuSpeedMhz  float64
	lastCpuInfoAttempt time.Time
}

// AggregateCpuHistory returns up to maxPoints averaged buckets of size bucketSeconds over recent data.
func (s *ServerService) AggregateCpuHistory(bucketSeconds int, maxPoints int) []map[string]any {
	if bucketSeconds <= 0 || maxPoints <= 0 {
		return nil
	}
	cutoff := time.Now().Add(-time.Duration(bucketSeconds*maxPoints) * time.Second).Unix()
	s.mu.Lock()
	// find start index (history sorted ascending)
	hist := s.cpuHistory
	// binary-ish scan (simple linear from end since size capped ~10800 is fine)
	startIdx := 0
	for i := len(hist) - 1; i >= 0; i-- {
		if hist[i].T < cutoff {
			startIdx = i + 1
			break
		}
	}
	if startIdx >= len(hist) {
		s.mu.Unlock()
		return []map[string]any{}
	}
	slice := hist[startIdx:]
	// copy for unlock
	tmp := make([]CPUSample, len(slice))
	copy(tmp, slice)
	s.mu.Unlock()
	if len(tmp) == 0 {
		return []map[string]any{}
	}
	var out []map[string]any
	var acc []float64
	bSize := int64(bucketSeconds)
	curBucket := (tmp[0].T / bSize) * bSize
	flush := func(ts int64) {
		if len(acc) == 0 {
			return
		}
		sum := 0.0
		for _, v := range acc {
			sum += v
		}
		avg := sum / float64(len(acc))
		out = append(out, map[string]any{"t": ts, "cpu": avg})
		acc = acc[:0]
	}
	for _, p := range tmp {
		b := (p.T / bSize) * bSize
		if b != curBucket {
			flush(curBucket)
			curBucket = b
		}
		acc = append(acc, p.Cpu)
	}
	flush(curBucket)
	if len(out) > maxPoints {
		out = out[len(out)-maxPoints:]
	}
	return out
}

// CPUSample single CPU utilization sample
type CPUSample struct {
	T   int64   `json:"t"`   // unix seconds
	Cpu float64 `json:"cpu"` // percent 0..100
}

type LogEntry struct {
	DateTime    time.Time
	FromAddress string
	ToAddress   string
	Inbound     string
	Outbound    string
	Email       string
	Event       int
}

// getPublicIPTimeout bounds the IP lookup, and maxPublicIPBodyBytes
// bounds the response (L-12): an IP is a few dozen bytes at most.
// Both are vars so tests can shorten them.
var getPublicIPTimeout = 3 * time.Second
var maxPublicIPBodyBytes int64 = 1024

func getPublicIP(url string) string {
	client := &http.Client{
		Timeout: getPublicIPTimeout,
	}

	resp, err := client.Get(url)
	if err != nil {
		return "N/A"
	}
	defer resp.Body.Close()

	// Don't retry if access is blocked or region-restricted
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnavailableForLegalReasons {
		return "N/A"
	}
	if resp.StatusCode != http.StatusOK {
		return "N/A"
	}

	ip, err := io.ReadAll(io.LimitReader(resp.Body, maxPublicIPBodyBytes+1))
	if err != nil || int64(len(ip)) > maxPublicIPBodyBytes {
		return "N/A"
	}

	ipString := strings.TrimSpace(string(ip))
	if ipString == "" {
		return "N/A"
	}

	return ipString
}

func (s *ServerService) GetStatus(lastStatus *Status) *Status {
	now := time.Now()
	status := &Status{
		T: now,
	}

	// CPU stats
	util, err := s.sampleCPUUtilization()
	if err != nil {
		logger.Warning("get cpu percent failed:", err)
	} else {
		status.Cpu = util
	}

	status.CpuCores, err = cpu.Counts(false)
	if err != nil {
		logger.Warning("get cpu cores count failed:", err)
	}

	status.LogicalPro = runtime.NumCPU()

	if status.CpuSpeedMhz = s.cachedCpuSpeedMhz; s.cachedCpuSpeedMhz == 0 && time.Since(s.lastCpuInfoAttempt) > 5*time.Minute {
		s.lastCpuInfoAttempt = time.Now()
		done := make(chan struct{})
		go func() {
			defer close(done)
			cpuInfos, err := cpu.Info()
			if err != nil {
				logger.Warning("get cpu info failed:", err)
				return
			}
			if len(cpuInfos) > 0 {
				s.cachedCpuSpeedMhz = cpuInfos[0].Mhz
				status.CpuSpeedMhz = s.cachedCpuSpeedMhz
			} else {
				logger.Warning("could not find cpu info")
			}
		}()
		select {
		case <-done:
		case <-time.After(1500 * time.Millisecond):
			logger.Warning("cpu info query timed out; will retry later")
		}
	} else if s.cachedCpuSpeedMhz != 0 {
		status.CpuSpeedMhz = s.cachedCpuSpeedMhz
	}

	// Uptime
	upTime, err := host.Uptime()
	if err != nil {
		logger.Warning("get uptime failed:", err)
	} else {
		status.Uptime = upTime
	}

	// Memory stats
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		logger.Warning("get virtual memory failed:", err)
	} else {
		status.Mem.Current = memInfo.Used
		status.Mem.Total = memInfo.Total
	}

	swapInfo, err := mem.SwapMemory()
	if err != nil {
		logger.Warning("get swap memory failed:", err)
	} else {
		status.Swap.Current = swapInfo.Used
		status.Swap.Total = swapInfo.Total
	}

	// Disk stats
	diskInfo, err := disk.Usage("/")
	if err != nil {
		logger.Warning("get disk usage failed:", err)
	} else {
		status.Disk.Current = diskInfo.Used
		status.Disk.Total = diskInfo.Total
	}

	// Load averages
	avgState, err := load.Avg()
	if err != nil {
		logger.Warning("get load avg failed:", err)
	} else {
		status.Loads = []float64{avgState.Load1, avgState.Load5, avgState.Load15}
	}

	// Network stats
	ioStats, err := net.IOCounters(false)
	if err != nil {
		logger.Warning("get io counters failed:", err)
	} else if len(ioStats) > 0 {
		ioStat := ioStats[0]
		status.NetTraffic.Sent = ioStat.BytesSent
		status.NetTraffic.Recv = ioStat.BytesRecv

		if lastStatus != nil {
			duration := now.Sub(lastStatus.T)
			seconds := float64(duration) / float64(time.Second)
			up := uint64(float64(status.NetTraffic.Sent-lastStatus.NetTraffic.Sent) / seconds)
			down := uint64(float64(status.NetTraffic.Recv-lastStatus.NetTraffic.Recv) / seconds)
			status.NetIO.Up = up
			status.NetIO.Down = down
		}
	} else {
		logger.Warning("can not find io counters")
	}

	// TCP/UDP connections
	status.TcpCount, err = sys.GetTCPCount()
	if err != nil {
		logger.Warning("get tcp connections failed:", err)
	}

	status.UdpCount, err = sys.GetUDPCount()
	if err != nil {
		logger.Warning("get udp connections failed:", err)
	}

	// IP fetching with caching
	showIp4ServiceLists := []string{
		"https://api4.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://v4.api.ipinfo.io/ip",
		"https://ipv4.myexternalip.com/raw",
		"https://4.ident.me",
		"https://check-host.net/ip",
	}
	showIp6ServiceLists := []string{
		"https://api6.ipify.org",
		"https://ipv6.icanhazip.com",
		"https://v6.api.ipinfo.io/ip",
		"https://ipv6.myexternalip.com/raw",
		"https://6.ident.me",
	}

	if s.cachedIPv4 == "" {
		for _, ip4Service := range showIp4ServiceLists {
			s.cachedIPv4 = getPublicIP(ip4Service)
			if s.cachedIPv4 != "N/A" {
				break
			}
		}
	}

	if s.cachedIPv6 == "" && !s.noIPv6 {
		for _, ip6Service := range showIp6ServiceLists {
			s.cachedIPv6 = getPublicIP(ip6Service)
			if s.cachedIPv6 != "N/A" {
				break
			}
		}
	}

	if s.cachedIPv6 == "N/A" {
		s.noIPv6 = true
	}

	status.PublicIP.IPv4 = s.cachedIPv4
	status.PublicIP.IPv6 = s.cachedIPv6

	// Xray status
	if s.xrayService.IsXrayRunning() {
		status.Xray.State = Running
		status.Xray.ErrorMsg = ""
	} else {
		err := s.xrayService.GetXrayErr()
		if err != nil {
			status.Xray.State = Error
		} else {
			status.Xray.State = Stop
		}
		status.Xray.ErrorMsg = s.xrayService.GetXrayResult()
	}
	status.Xray.Version = s.xrayService.GetXrayVersion()

	// Application stats
	var rtm runtime.MemStats
	runtime.ReadMemStats(&rtm)
	status.AppStats.Mem = rtm.Sys
	status.AppStats.Threads = uint32(runtime.NumGoroutine())
	if p != nil && p.IsRunning() {
		status.AppStats.Uptime = p.GetUptime()
	} else {
		status.AppStats.Uptime = 0
	}

	return status
}

func (s *ServerService) AppendCpuSample(t time.Time, v float64) {
	const capacity = 9000 // ~5 hours @ 2s interval
	s.mu.Lock()
	defer s.mu.Unlock()
	p := CPUSample{T: t.Unix(), Cpu: v}
	if n := len(s.cpuHistory); n > 0 && s.cpuHistory[n-1].T == p.T {
		s.cpuHistory[n-1] = p
	} else {
		s.cpuHistory = append(s.cpuHistory, p)
	}
	if len(s.cpuHistory) > capacity {
		s.cpuHistory = s.cpuHistory[len(s.cpuHistory)-capacity:]
	}
}

func (s *ServerService) sampleCPUUtilization() (float64, error) {
	// Try native platform-specific CPU implementation first (Windows, Linux, macOS)
	if pct, err := sys.CPUPercentRaw(); err == nil {
		s.mu.Lock()
		// First call to native method returns 0 (initializes baseline)
		if !s.hasNativeCPUSample {
			s.hasNativeCPUSample = true
			s.mu.Unlock()
			return 0, nil
		}
		// Smooth with EMA
		const alpha = 0.3
		if s.emaCPU == 0 {
			s.emaCPU = pct
		} else {
			s.emaCPU = alpha*pct + (1-alpha)*s.emaCPU
		}
		val := s.emaCPU
		s.mu.Unlock()
		return val, nil
	}
	// If native call fails, fall back to gopsutil times
	// Read aggregate CPU times (all CPUs combined)
	times, err := cpu.Times(false)
	if err != nil {
		return 0, err
	}
	if len(times) == 0 {
		return 0, fmt.Errorf("no cpu times available")
	}

	cur := times[0]

	s.mu.Lock()
	defer s.mu.Unlock()

	// If this is the first sample, initialize and return current EMA (0 by default)
	if !s.hasLastCPUSample {
		s.lastCPUTimes = cur
		s.hasLastCPUSample = true
		return s.emaCPU, nil
	}

	// Compute busy and total deltas
	// Note: Guest and GuestNice times are already included in User and Nice respectively,
	// so we exclude them to avoid double-counting (Linux kernel accounting)
	idleDelta := cur.Idle - s.lastCPUTimes.Idle
	busyDelta := (cur.User - s.lastCPUTimes.User) +
		(cur.System - s.lastCPUTimes.System) +
		(cur.Nice - s.lastCPUTimes.Nice) +
		(cur.Iowait - s.lastCPUTimes.Iowait) +
		(cur.Irq - s.lastCPUTimes.Irq) +
		(cur.Softirq - s.lastCPUTimes.Softirq) +
		(cur.Steal - s.lastCPUTimes.Steal)

	totalDelta := busyDelta + idleDelta

	// Update last sample for next time
	s.lastCPUTimes = cur

	// Guard against division by zero or negative deltas (e.g., counter resets)
	if totalDelta <= 0 {
		return s.emaCPU, nil
	}

	raw := 100.0 * (busyDelta / totalDelta)
	if raw < 0 {
		raw = 0
	}
	if raw > 100 {
		raw = 100
	}

	// Exponential moving average to smooth spikes
	const alpha = 0.3 // smoothing factor (0<alpha<=1). Higher = more responsive, lower = smoother
	if s.emaCPU == 0 {
		// Initialize EMA with the first real reading to avoid long warm-up from zero
		s.emaCPU = raw
	} else {
		s.emaCPU = alpha*raw + (1-alpha)*s.emaCPU
	}

	return s.emaCPU, nil
}

// xrayVersionsTimeout bounds the GitHub releases list request
// (L-12: the old http.Get had no timeout at all, so a stalled
// network left the handler hanging forever).
// xrayVersionsMaxBodyBytes bounds the response: the list is
// per_page=30 and well under 1 MiB in practice. Both are vars so
// tests can shorten them.
var xrayVersionsTimeout = 30 * time.Second
var xrayVersionsMaxBodyBytes int64 = 2 << 20

func (s *ServerService) GetXrayVersions() ([]string, error) {
	return fetchXrayVersions("https://api.github.com/repos/XTLS/Xray-core/releases")
}

func fetchXrayVersions(versionsURL string) ([]string, error) {
	client := &http.Client{Timeout: xrayVersionsTimeout}

	resp, err := client.Get(versionsURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check HTTP status code - GitHub API returns object instead of array on error
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		var errorResponse struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(bodyBytes, &errorResponse) == nil && errorResponse.Message != "" {
			return nil, fmt.Errorf("GitHub API error: %s", errorResponse.Message)
		}
		return nil, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, resp.Status)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, xrayVersionsMaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(bodyBytes)) > xrayVersionsMaxBodyBytes {
		return nil, fmt.Errorf("GitHub API response exceeds the %d-byte limit", xrayVersionsMaxBodyBytes)
	}

	var releases []Release
	if err := json.Unmarshal(bodyBytes, &releases); err != nil {
		return nil, err
	}

	var versions []string
	for _, release := range releases {
		tagVersion := strings.TrimPrefix(release.TagName, "v")
		tagParts := strings.Split(tagVersion, ".")
		if len(tagParts) != 3 {
			continue
		}

		major, err1 := strconv.Atoi(tagParts[0])
		minor, err2 := strconv.Atoi(tagParts[1])
		patch, err3 := strconv.Atoi(tagParts[2])
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}

		if major > 26 || (major == 26 && minor > 3) || (major == 26 && minor == 3 && patch >= 10) {
			versions = append(versions, release.TagName)
		}
	}
	return versions, nil
}

func (s *ServerService) StopXrayService() error {
	err := s.xrayService.StopXray()
	if err != nil {
		logger.Error("stop xray failed:", err)
		return err
	}
	return nil
}

func (s *ServerService) RestartXrayService() error {
	err := s.xrayService.RestartXray(true)
	if err != nil {
		logger.Error("start xray failed:", err)
		return err
	}
	return nil
}

// IsXrayRunning reports whether Xray is currently running.
func (s *ServerService) IsXrayRunning() bool {
	return s.xrayService.IsXrayRunning()
}

// WaitReady waits until the running Xray has proven itself ready
// (still alive with its management API answering).
func (s *ServerService) WaitReady(timeout time.Duration) error {
	return s.xrayService.WaitReady(timeout)
}

// IsManuallyStopped reports whether Xray was stopped manually from
// the panel.
func (s *ServerService) IsManuallyStopped() bool {
	return s.xrayService.IsManuallyStopped()
}

// SetManuallyStopped restores the manual-stop flag.
func (s *ServerService) SetManuallyStopped(stopped bool) {
	s.xrayService.SetManuallyStopped(stopped)
}

// restoreXrayState restores the pre-operation service state after a
// failed update or import: restart Xray when it was running, or put
// the manual-stop flag back when it was not. A restart attempt
// clears the flag even when the operation then fails, so without
// this a manually stopped Xray would be auto-started by the health
// check after a failed rollback.
func (s *ServerService) restoreXrayState(wasRunning, wasManuallyStopped bool) {
	if wasRunning {
		if err := s.RestartXrayService(); err != nil {
			logger.Errorf("failed to restore Xray running state: %v", err)
		}
		return
	}
	s.SetManuallyStopped(wasManuallyStopped)
}

func (s *ServerService) downloadXRay(version string) (string, error) {
	// M4: only allow an official release tag (x.y.z, optionally with a
	// leading "v"). An unchecked version string was interpolated directly
	// into the download URL.
	versionRe := regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+$`)
	if !versionRe.MatchString(version) {
		return "", errors.New("invalid xray version format")
	}
	osName := runtime.GOOS
	arch := runtime.GOARCH

	switch osName {
	case "darwin":
		osName = "macos"
	case "windows":
		osName = "windows"
	}

	switch arch {
	case "amd64":
		arch = "64"
	case "arm64":
		arch = "arm64-v8a"
	case "armv7":
		arch = "arm32-v7a"
	case "armv6":
		arch = "arm32-v6"
	case "armv5":
		arch = "arm32-v5"
	case "386":
		arch = "32"
	case "s390x":
		arch = "s390x"
	}

	fileName := fmt.Sprintf("Xray-%s-%s.zip", osName, arch)
	url := fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/download/%s/%s", version, fileName)
	return downloadXRayFromURL(url, fileName)
}

// xrayDownloadTimeout bounds a whole Xray release download (M-4). The
// zip is ~20-30 MiB; five minutes is ample on a slow link while a
// stalled connection can no longer hang the update (and, through
// updateMu, geo updates and imports) forever. It is a var so tests
// can shorten it.
var xrayDownloadTimeout = 5 * time.Minute

// xrayZipMaxBytes caps a downloaded Xray release zip (M-4). It is a var
// so tests can lower it.
var xrayZipMaxBytes int64 = 500 << 20

// xrayDownloadClient builds the HTTP client for Xray release downloads
// (M-4): a total timeout, at most 10 redirects, and redirects only to
// GitHub hosts — a compromised or misbehaving mirror must not pull the
// update from an arbitrary host.
func xrayDownloadClient() *http.Client {
	return &http.Client{
		Timeout: xrayDownloadTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects downloading xray")
			}
			switch req.URL.Hostname() {
			case "github.com", "objects.githubusercontent.com":
				return nil
			default:
				return fmt.Errorf("xray download redirected to disallowed host %q", req.URL.Hostname())
			}
		},
	}
}

func downloadXRayFromURL(url, fileName string) (string, error) {
	client := xrayDownloadClient()
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to download xray: %s", resp.Status)
	}

	os.Remove(fileName)
	file, err := os.Create(fileName)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// M-4: cap the download; a response larger than the cap is refused
	// instead of being written to disk unbounded. Copying one byte past
	// the limit makes the overflow detectable.
	written, err := io.Copy(file, io.LimitReader(resp.Body, xrayZipMaxBytes+1))
	if err != nil {
		return "", err
	}
	if written > xrayZipMaxBytes {
		file.Close()
		os.Remove(fileName)
		return "", fmt.Errorf("xray zip exceeds the maximum allowed size of %d bytes", xrayZipMaxBytes)
	}
	file.Close()

	// M-4: a .dgst file is published with every Xray-core release. If
	// it cannot be fetched or carries no entry for this zip, the zip is
	// refused instead of being used unverified (previously this only
	// logged a warning and continued).
	if err := verifyXrayZipSHA256(client, url, fileName); err != nil {
		os.Remove(fileName)
		return "", err
	}

	return fileName, nil
}

// verifyXrayZipSHA256 fetches url+".dgst" (the hash file published with an
// Xray-core release) and compares the SHA256 entry for the zip file with the
// hash of the downloaded file. A missing .dgst, a missing entry, or a
// mismatching hash is an error: an unverified zip is refused.
func verifyXrayZipSHA256(client *http.Client, url, zipPath string) error {
	resp, err := client.Get(url + ".dgst")
	if err != nil {
		return fmt.Errorf("failed to fetch xray .dgst: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("xray .dgst not available: %s", resp.Status)
	}
	// The .dgst is a small text file; cap the read.
	dgstBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("failed to read xray .dgst: %w", err)
	}
	base := filepath.Base(zipPath)
	re := regexp.MustCompile(`(?i)SHA256\s*\(` + regexp.QuoteMeta(base) + `\)\s*=\s*([0-9a-fA-F]{64})`)
	matches := re.FindSubmatch(dgstBody)
	if len(matches) < 2 {
		return fmt.Errorf("no SHA256 entry for %s in xray .dgst, refusing unverified zip", base)
	}
	f, err := os.Open(zipPath)
	if err != nil {
		return err
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return err
	}
	if fmt.Sprintf("%x", sum.Sum(nil)) != strings.ToLower(string(matches[1])) {
		return fmt.Errorf("xray zip sha256 mismatch for %s, refusing to use it", base)
	}
	return nil
}

func (s *ServerService) UpdateXray(version string) error {
	// The whole update transaction is serialised with geo updates
	// and imports: two concurrent updates would overwrite each
	// other's staged files and the single backup.
	updateMu.Lock()
	defer updateMu.Unlock()

	// 1. Download and verify the zip BEFORE stopping Xray: a failed
	// download, a bad checksum, or an unreadable zip must leave the
	// running Xray untouched. (Previously the stop came first, so any
	// of these left the panel without a running Xray — and the stop
	// is marked manual, so the health check never revived it.)
	zipFileName, err := s.downloadXRay(version)
	if err != nil {
		return err
	}
	defer os.Remove(zipFileName)

	// 2. Extract the new binary to a staged file next to the live
	// one (same filesystem, so the swap is a rename). The live
	// binary is not touched yet. The staged name is unique per
	// update so a concurrent update cannot overwrite it.
	targetBinary, zipEntry := xrayUpdateTarget(runtime.GOOS)
	stagedPath := targetBinary + ".new-" + random.Seq(8)
	if err := extractZipEntry(zipFileName, zipEntry, stagedPath); err != nil {
		return err
	}
	// The staged file only exists until the swap; remove it on any
	// failure before the swap. After a successful swap it no longer
	// exists (it was renamed into place).
	staged := true
	defer func() {
		if staged {
			_ = os.Remove(stagedPath)
		}
	}()

	// 3. Only now stop the running Xray. The pre-update running
	// state and manual-stop flag are recorded first: the stop
	// overwrites the flag, and a failed update must put it back.
	xrayWasRunning := s.xrayService.IsXrayRunning()
	xrayWasManuallyStopped := s.xrayService.IsManuallyStopped()
	if err := s.StopXrayService(); err != nil {
		logger.Warning("failed to stop xray before update:", err)
	}

	// rollBackNewBinary undoes a failed start of the new binary:
	// stop the candidate process first (it may still be alive but
	// unready), restore the old binary, then restore the previous
	// running state.
	rollBackNewBinary := func(backupPath string, err error) error {
		_ = s.xrayService.StopXray()
		if rerr := rollbackBinaryReplace(targetBinary, backupPath); rerr != nil {
			return common.NewErrorf("Failed to roll back the Xray binary after %v: %v", err, rerr)
		}
		s.restoreXrayState(xrayWasRunning, xrayWasManuallyStopped)
		return err
	}

	// 4. Swap the binaries, keeping a backup until the new one is
	// confirmed ready. If the swap itself fails, Xray is already
	// stopped — restore the previous running state.
	backupPath, err := stageBinaryReplace(targetBinary, stagedPath)
	if err != nil {
		s.restoreXrayState(xrayWasRunning, xrayWasManuallyStopped)
		return err
	}
	staged = false

	// 5. Restart xray with the new binary. On failure, roll the old
	// binary back and restore the previous running state.
	if err := s.xrayService.RestartXray(true); err != nil {
		logger.Error("start xray failed, rolling back to the previous binary:", err)
		return rollBackNewBinary(backupPath, err)
	}

	// 6. The new binary started, but cmd.Start() only proves the
	// process was created: a binary that exits on a bad config is
	// discovered asynchronously by Wait(). Do not delete the backup
	// until the new Xray has proven itself ready — still running
	// with its management API answering — within a timeout.
	// Otherwise roll the old binary back and restore the previous
	// state.
	if err := s.xrayService.WaitReady(10 * time.Second); err != nil {
		logger.Error("new xray did not become ready, rolling back to the previous binary:", err)
		return rollBackNewBinary(backupPath, common.NewErrorf("New Xray did not become ready: %v", err))
	}

	// 7. The new binary is confirmed ready: the backup is no longer needed.
	if err := commitBinaryReplace(backupPath); err != nil {
		logger.Warningf("Failed to remove Xray backup binary %s: %v", backupPath, err)
	}

	return nil
}

// xrayUpdateTarget returns the on-disk path of the live Xray binary
// for the given OS and the zip entry name holding the new binary.
// The path comes from the configured binary folder, never the
// process working directory: on Windows the updater used to write
// to ./bin while the panel runs the binary from its configured
// folder, so it updated a different file and kept running the old
// version. The Windows binary name keeps its .exe suffix —
// xray.GetBinaryPath() omits it (Go's exec appends .exe on
// Windows), so it cannot be used for file operations there.
func xrayUpdateTarget(goos string) (targetBinary, zipEntry string) {
	if goos == "windows" {
		return filepath.Join(config.GetBinFolderPath(), "xray-windows-amd64.exe"), "xray.exe"
	}
	return xray.GetBinaryPath(), "xray"
}

// maxExtractedEntrySize caps a single extracted zip entry (L-9). A
// real Xray binary is ~30 MiB; 200 MiB leaves ample room while a
// swapped zip can no longer fill the bin disk with one huge entry.
// It is a var so tests can lower it.
var maxExtractedEntrySize int64 = 200 << 20

// extractZipEntry extracts one entry from a zip archive to destPath
// (0755), refusing an empty result. The destination is written to a
// temporary file and renamed into place, so a corrupt or truncated
// archive never leaves a partial binary behind.
func extractZipEntry(zipPath, entryName, destPath string) error {
	zipFile, err := os.Open(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()
	stat, err := zipFile.Stat()
	if err != nil {
		return err
	}
	reader, err := zip.NewReader(zipFile, stat.Size())
	if err != nil {
		return err
	}
	entry, err := reader.Open(entryName)
	if err != nil {
		return err
	}
	defer entry.Close()
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}
	tmpPath := destPath + ".tmp"
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	// L-9: bound the extraction. The zip itself is already capped
	// at download time (M-4), but a zip bomb expands far beyond its
	// archive size; read one byte past the cap so an entry exactly at
	// the cap still passes and anything over it is refused.
	n, err := io.Copy(out, io.LimitReader(entry, maxExtractedEntrySize+1))
	closeErr := out.Close()
	if err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return closeErr
	}
	if n == 0 {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("empty entry %q in %s", entryName, zipPath)
	}
	if n > maxExtractedEntrySize {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("entry %q in %s exceeds the %d-byte limit", entryName, zipPath, maxExtractedEntrySize)
	}
	// Verify the file on disk matches what was copied.
	if st, statErr := os.Stat(tmpPath); statErr != nil || st.Size() != n {
		_ = os.Remove(tmpPath)
		if statErr != nil {
			return statErr
		}
		return fmt.Errorf("extracted entry %q size mismatch: file %d bytes, copied %d", entryName, st.Size(), n)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// stageBinaryReplace moves the live binary at target aside (to
// target+".bak") and puts the staged new binary in its place. When
// there is no live binary, only the rename happens. It returns the
// backup path, or "" when there was nothing to back up. The caller
// must either commitBinaryReplace (new binary confirmed) or
// rollbackBinaryReplace (swap or start failed).
func stageBinaryReplace(target, staged string) (backupPath string, err error) {
	if _, err := os.Stat(target); err == nil {
		// The backup name is unique per update so a concurrent
		// update cannot overwrite another one's only copy of the
		// old binary.
		backupPath = target + ".bak-" + random.Seq(8)
		if err := os.Rename(target, backupPath); err != nil {
			return "", fmt.Errorf("failed to back up current binary: %w", err)
		}
	}
	if err := os.Rename(staged, target); err != nil {
		if backupPath != "" {
			_ = os.Rename(backupPath, target)
		}
		return "", fmt.Errorf("failed to install new binary: %w", err)
	}
	return backupPath, nil
}

// rollbackBinaryReplace restores the backup over the new binary.
// With no backup (there was no live binary before), it removes the
// new binary instead, restoring the previous "no binary" state.
func rollbackBinaryReplace(target, backupPath string) error {
	if backupPath == "" {
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove new binary: %w", err)
		}
		return nil
	}
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove new binary: %w", err)
	}
	if err := os.Rename(backupPath, target); err != nil {
		return fmt.Errorf("failed to restore backed-up binary: %w", err)
	}
	return nil
}

// commitBinaryReplace removes the backup after the new binary is
// confirmed running.
func commitBinaryReplace(backupPath string) error {
	if backupPath == "" {
		return nil
	}
	return os.Remove(backupPath)
}

func (s *ServerService) GetLogs(count string, level string, syslog string) []string {
	c, _ := strconv.Atoi(count)
	var lines []string

	if syslog == "true" {
		// Check if running on Windows - journalctl is not available
		if runtime.GOOS == "windows" {
			return []string{"Syslog is not supported on Windows. Please use application logs instead by unchecking the 'Syslog' option."}
		}

		// Validate and sanitize count parameter
		countInt, err := strconv.Atoi(count)
		if err != nil || countInt < 1 || countInt > 10000 {
			return []string{"Invalid count parameter - must be a number between 1 and 10000"}
		}

		// Validate level parameter - only allow valid syslog levels
		validLevels := map[string]bool{
			"0": true, "emerg": true,
			"1": true, "alert": true,
			"2": true, "crit": true,
			"3": true, "err": true,
			"4": true, "warning": true,
			"5": true, "notice": true,
			"6": true, "info": true,
			"7": true, "debug": true,
		}
		if !validLevels[level] {
			return []string{"Invalid level parameter - must be a valid syslog level"}
		}

		// Use hardcoded command with validated parameters
		cmd := exec.Command("journalctl", "-u", "x-ui", "--no-pager", "-n", strconv.Itoa(countInt), "-p", level)
		var out bytes.Buffer
		cmd.Stdout = &out
		err = cmd.Run()
		if err != nil {
			return []string{"Failed to run journalctl command! Make sure systemd is available and x-ui service is registered."}
		}
		lines = strings.Split(out.String(), "\n")
	} else {
		lines = logger.GetLogs(c, level)
	}

	return lines
}

func (s *ServerService) GetXrayLogs(
	count string,
	filter string,
	showDirect string,
	showBlocked string,
	showProxy string,
	freedoms []string,
	blackholes []string) []LogEntry {

	const (
		Direct = iota
		Blocked
		Proxied
	)

	countInt, _ := strconv.Atoi(count)
	var entries []LogEntry

	pathToAccessLog, err := xray.GetAccessLogPath()
	if err != nil {
		return nil
	}

	file, err := os.Open(pathToAccessLog)
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.Contains(line, "api -> api") {
			//skipping empty lines and api calls
			continue
		}

		if filter != "" && !strings.Contains(line, filter) {
			//applying filter if it's not empty
			continue
		}

		var entry LogEntry
		parts := strings.Fields(line)

		for i, part := range parts {

			if i == 0 {
				dateTime, err := time.ParseInLocation("2006/01/02 15:04:05.999999", parts[0]+" "+parts[1], time.Local)
				if err != nil {
					continue
				}
				entry.DateTime = dateTime.UTC()
			}

			if part == "from" {
				entry.FromAddress = strings.TrimLeft(parts[i+1], "/")
			} else if part == "accepted" {
				entry.ToAddress = strings.TrimLeft(parts[i+1], "/")
			} else if strings.HasPrefix(part, "[") {
				entry.Inbound = part[1:]
			} else if strings.HasSuffix(part, "]") {
				entry.Outbound = part[:len(part)-1]
			} else if part == "email:" {
				entry.Email = parts[i+1]
			}
		}

		if logEntryContains(line, freedoms) {
			if showDirect == "false" {
				continue
			}
			entry.Event = Direct
		} else if logEntryContains(line, blackholes) {
			if showBlocked == "false" {
				continue
			}
			entry.Event = Blocked
		} else {
			if showProxy == "false" {
				continue
			}
			entry.Event = Proxied
		}

		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return nil
	}

	if len(entries) > countInt {
		entries = entries[len(entries)-countInt:]
	}

	return entries
}

func logEntryContains(line string, suffixes []string) bool {
	for _, sfx := range suffixes {
		if strings.Contains(line, sfx+"]") {
			return true
		}
	}
	return false
}

func (s *ServerService) GetConfigJson() (any, error) {
	config, err := s.xrayService.GetXrayConfig()
	if err != nil {
		return nil, err
	}
	contents, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, err
	}

	var jsonData any
	err = json.Unmarshal(contents, &jsonData)
	if err != nil {
		return nil, err
	}

	return jsonData, nil
}

func (s *ServerService) GetDb() ([]byte, error) {
	// Update by manually trigger a checkpoint operation
	err := database.Checkpoint()
	if err != nil {
		return nil, err
	}
	// Open the file for reading
	file, err := os.Open(config.GetDBPath())
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Read the file contents
	fileContents, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return fileContents, nil
}

// updateMu serialises the full update transactions that replace
// Xray's binary, its geo files, or the live database and restart
// it: an Xray update, a geo update, and an import interleaved would
// overwrite each other's temporary files and backups and race the
// process they all restart.
var updateMu sync.Mutex

// importMu serialises database imports: two concurrent imports would
// interleave the file swap (live db -> fallback, temp -> live) and
// leave the panel on a half-swapped database.
var importMu sync.Mutex

// ImportDBMaxSize caps an imported database file (M-3). A real x-ui.db
// is a few megabytes; 512 MiB leaves ample room while a multi-gigabyte
// upload can no longer fill the disk before any validation runs. It is
// a var so tests can lower it, and the controller enforces the same
// limit with MaxBytesReader before parsing the multipart form.
var ImportDBMaxSize int64 = 512 << 20

func (s *ServerService) ImportDB(file multipart.File) error {
	// Imports are serialised: two concurrent imports would
	// interleave the file swap (live db -> fallback, temp -> live)
	// and leave the panel on a half-swapped database.
	importMu.Lock()
	defer importMu.Unlock()
	// Imports also hold the update mutex: an Xray or geo update
	// running at the same time would race the process the import
	// stops and restarts.
	updateMu.Lock()
	defer updateMu.Unlock()

	// Check if the file is a SQLite database
	isValidDb, err := database.IsSQLiteDB(file)
	if err != nil {
		return common.NewErrorf("Error checking db file format: %v", err)
	}
	if !isValidDb {
		return common.NewError("Invalid db file format")
	}

	// Reset the file reader to the beginning
	_, err = file.Seek(0, 0)
	if err != nil {
		return common.NewErrorf("Error resetting file reader: %v", err)
	}

	// Save the file as a temporary file in the database folder (same
	// filesystem as the live database, so the swap is a rename). The
	// name is unique per import: a fixed ".temp" name let two
	// concurrent imports overwrite each other's candidate file.
	tempFile, err := os.CreateTemp(filepath.Dir(config.GetDBPath()), ".x-ui-import-*.db")
	if err != nil {
		return common.NewErrorf("Error creating temporary db file: %v", err)
	}
	tempPath := tempFile.Name()
	// Match the permissions of a normally created database file
	// (CreateTemp makes 0600).
	if err := tempFile.Chmod(0644); err != nil {
		return common.NewErrorf("Error setting temporary db file permissions: %v", err)
	}

	// Robust deferred cleanup for the temporary file
	defer func() {
		if tempFile != nil {
			if cerr := tempFile.Close(); cerr != nil {
				logger.Warningf("Warning: failed to close temp file: %v", cerr)
			}
		}
		if _, err := os.Stat(tempPath); err == nil {
			if rerr := os.Remove(tempPath); rerr != nil {
				logger.Warningf("Warning: failed to remove temp file: %v", rerr)
			}
		}
	}()

	// Save uploaded file to temporary file, capped (M-3): the limit is
	// enforced before any validation reads the file. Copying one byte
	// past the limit makes the overflow detectable.
	written, err := io.Copy(tempFile, io.LimitReader(file, ImportDBMaxSize+1))
	if err != nil {
		return common.NewErrorf("Error saving db: %v", err)
	}
	if written > ImportDBMaxSize {
		return common.NewErrorf("Database file exceeds the maximum allowed size of %d bytes", ImportDBMaxSize)
	}

	// Close temp file before opening via sqlite
	if err = tempFile.Close(); err != nil {
		return common.NewErrorf("Error closing temporary db file: %v", err)
	}
	tempFile = nil

	// Validate integrity (no migrations / side effects)
	if err = database.ValidateSQLiteDB(tempPath); err != nil {
		return common.NewErrorf("Invalid or corrupt db file: %v", err)
	}

	// H-4: reject imported databases carrying triggers, views or unexpected
	// tables BEFORE the file replaces the live database. A trigger on
	// settings/inbounds could otherwise fire on a later admin write and
	// silently re-open a hole the import validation just closed.
	if err = database.ValidateImportedDBObjects(tempPath); err != nil {
		return common.NewErrorf("Imported db has unexpected database objects: %v", err)
	}

	// H1 / H-3 / H-7: validate the xrayTemplateConfig stored in the
	// imported database BEFORE it replaces the live database, reusing the
	// full template check (log paths, api inbound listen, metrics, reverse,
	// routing, freedom.redirect). A malicious log.access / log.error would
	// otherwise make Xray write arbitrary files when the panel restarts
	// Xray after the import.
	if err = database.ValidateImportedXrayConfig(tempPath); err != nil {
		return common.NewErrorf("Imported db has unsafe xray config: %v", err)
	}

	// A backup must never resurrect sessions that were already logged
	// out. The running process keeps the secret it loaded at startup,
	// so rotating the secret in the database alone cannot stop a
	// replayed old cookie from re-authenticating against a restored
	// row until the next restart. Purge every restored login session
	// from the candidate file before it ever becomes the live
	// database; the import fails closed if the purge fails.
	if err = database.PurgeLoginSessionsFromFile(tempPath); err != nil {
		return common.NewErrorf("Error discarding imported login sessions: %v", err)
	}

	// Record whether Xray was running before the swap so a failed
	// import can restore the original service state. The manual-stop
	// flag is recorded too, before the stop below overwrites it:
	// a restart attempt clears the flag even when the import then
	// fails, so without this a manually stopped Xray would be
	// auto-started by the health check after a failed rollback.
	xrayWasRunning := s.xrayService.IsXrayRunning()
	xrayWasManuallyStopped := s.xrayService.IsManuallyStopped()

	// Stop Xray (ignore error but log)
	if errStop := s.StopXrayService(); errStop != nil {
		logger.Warningf("Failed to stop Xray before DB import: %v", errStop)
	}

	// Close existing DB to release file locks (especially on Windows)
	if errClose := database.CloseDB(); errClose != nil {
		logger.Warningf("Failed to close existing DB before replacement: %v", errClose)
	}

	// Backup the current database for fallback
	fallbackPath := fmt.Sprintf("%s.backup", config.GetDBPath())

	// From here on the import either commits or rolls back, including
	// failures BEFORE the backup is established: if the fallback
	// removal or the backup move itself fails, the original database
	// is still in place but its handle is closed, so the rollback
	// reopens it (and restores Xray) instead of leaving the panel
	// without a database. backedUp records whether the fallback file
	// actually holds the original database — a stale fallback left
	// behind by a failed removal must never be renamed over it.
	committed := false
	backedUp := false
	defer func() {
		if committed {
			if err := os.Remove(fallbackPath); err != nil && !os.IsNotExist(err) {
				logger.Warningf("Warning: failed to remove fallback file: %v", err)
			}
			return
		}
		s.rollbackImport(fallbackPath, xrayWasRunning, backedUp, xrayWasManuallyStopped)
	}()

	// Remove the existing fallback file (if any)
	if _, err := os.Stat(fallbackPath); err == nil {
		if errRemove := os.Remove(fallbackPath); errRemove != nil {
			return common.NewErrorf("Error removing existing fallback db file: %v", errRemove)
		}
	}

	// Move the current database to the fallback location
	if err = os.Rename(config.GetDBPath(), fallbackPath); err != nil {
		return common.NewErrorf("Error backing up current db file: %v", err)
	}
	backedUp = true

	// Move temp to DB path
	if err = os.Rename(tempPath, config.GetDBPath()); err != nil {
		return common.NewErrorf("Error moving db file: %v", err)
	}

	// Open & migrate new DB
	if err = database.InitDB(config.GetDBPath()); err != nil {
		return common.NewErrorf("Error migrating db: %v", err)
	}

	// The import invalidates every pre-import session (their rows
	// were purged from the candidate, and the old database is gone),
	// so close every live WebSocket now: a connection bound to a dead
	// session must not keep receiving pushes. Clients reconnect
	// automatically once the operator logs in again.
	if hub := websocket.GetHub(); hub != nil {
		hub.CloseAllClients()
	}

	s.inboundService.MigrateDB()

	// Start Xray
	if err = s.RestartXrayService(); err != nil {
		return common.NewErrorf("Imported DB but failed to start Xray: %v", err)
	}

	// The imported configuration passed the database and template
	// checks, but a runtime error (a port conflict, a bad file
	// reference) still kills the process after Start returns.
	// Commit the import only once the new Xray has proven itself
	// ready; otherwise the deferred rollback restores the original
	// database and service state.
	if err = s.WaitReady(10 * time.Second); err != nil {
		return common.NewErrorf("Imported DB but Xray did not become ready: %v", err)
	}

	// H-4: the imported database may carry an attacker-known secret (which
	// can be used to forge session cookies from the imported users table)
	// and unknown administrator accounts. Rotate the secret now that the
	// new database is live. This runs after InitDB succeeded, never during
	// validation. Note the rotation only takes full effect after the next
	// panel restart (the running process keeps the secret it loaded at
	// startup, see SettingService.RotateSecret); the success message tells
	// the operator to review the admin accounts.
	// A rotation failure is reported loudly instead of silently skipped,
	// and the deferred rollback restores the original database, like
	// any other post-swap failure.
	if err := (&SettingService{}).RotateSecret(); err != nil {
		return common.NewErrorf("Imported DB but failed to rotate secret: %v", err)
	}

	// L-6: the imported settings are not all trustworthy — clear the
	// Telegram channel, switch off external traffic reporting, and
	// clamp the Geo download cap. A sanitisation failure is reported
	// loudly, and the deferred rollback restores the original
	// database, like any other post-swap failure.
	if err := (&SettingService{}).SanitizeImportedSettings(); err != nil {
		return common.NewErrorf("Imported DB but failed to sanitize settings: %v", err)
	}

	committed = true
	return nil
}

// rollbackImport restores the pre-import state after a failed database
// swap. It first stops the candidate process — it runs the imported
// configuration and must not keep serving (or holding ports) while
// the original database is restored. It then closes the live handle
// (which may still point at the failed candidate file), moves the
// fallback file back when it actually holds the original database,
// reopens the original database, and restores the pre-import running
// state and manual-stop flag. When backedUp is false the failure
// happened before the backup was established, so the original file
// is still at the live path and is simply reopened.
// Every step is best-effort and logs its failure; the caller still
// returns the original import error.
func (s *ServerService) rollbackImport(fallbackPath string, xrayWasRunning bool, backedUp bool, xrayWasManuallyStopped bool) {
	// Stop the candidate process before touching the database: it
	// runs the imported configuration, and a rollback that restores
	// the old database while the new process keeps running would
	// leave the panel serving the candidate config.
	if err := s.xrayService.StopXray(); err != nil {
		logger.Debugf("ImportDB rollback: candidate Xray already stopped: %v", err)
	}
	if err := database.CloseDB(); err != nil {
		logger.Warningf("ImportDB rollback: failed to close candidate db: %v", err)
	}
	if backedUp {
		if _, err := os.Stat(fallbackPath); err != nil {
			logger.Errorf("ImportDB rollback: fallback db is missing (%s): %v", fallbackPath, err)
			return
		}
		if err := os.Rename(fallbackPath, config.GetDBPath()); err != nil {
			logger.Errorf("ImportDB rollback: failed to restore original db: %v", err)
			return
		}
	}
	if err := database.InitDB(config.GetDBPath()); err != nil {
		logger.Errorf("ImportDB rollback: failed to reopen original db: %v", err)
		return
	}
	s.inboundService.MigrateDB()
	s.restoreXrayState(xrayWasRunning, xrayWasManuallyStopped)
}

// IsValidGeofileName validates that the filename is safe for geofile operations.
// It checks for path traversal attempts and ensures the filename contains only safe characters.
func (s *ServerService) IsValidGeofileName(filename string) bool {
	if filename == "" {
		return false
	}

	// Check for path traversal attempts
	if strings.Contains(filename, "..") {
		return false
	}

	// Check for path separators (both forward and backward slash)
	if strings.ContainsAny(filename, `/\`) {
		return false
	}

	// Check for absolute path indicators
	if filepath.IsAbs(filename) {
		return false
	}

	// Additional security: only allow alphanumeric, dots, underscores, and hyphens
	// This is stricter than the general filename regex
	validGeofilePattern := `^[a-zA-Z0-9._-]+\.dat$`
	matched, _ := regexp.MatchString(validGeofilePattern, filename)
	return matched
}

// geofileDownloadTimeout bounds a built-in Geo file download (M-5);
// the same 10-minute bound CustomGeo uses. It is a var so tests
// can shorten it.
var geofileDownloadTimeout = 10 * time.Minute

// geofileDownloadMaxBytes caps a built-in Geo file download (M-5),
// reusing CustomGeo's 100 MiB default; real .dat files are a few MiB.
// It is a var so tests can lower it.
var geofileDownloadMaxBytes int64 = defaultGeoMaxFileSizeMB * 1024 * 1024

// downloadGeofile downloads one geofile to destPath. The download
// goes to a temporary file in the same directory and is renamed into
// place only after the full body is received: a 404, a network
// failure mid-download, or a write error must not truncate or replace
// the old file, which Xray still references. A 304 leaves the old
// file untouched.
func downloadGeofile(url, destPath string) (replaced bool, backupPath string, err error) {
	var req *http.Request
	req, err = http.NewRequest("GET", url, nil)
	if err != nil {
		return false, "", common.NewErrorf("Failed to create HTTP request for %s: %v", url, err)
	}

	var localFileModTime time.Time
	if fileInfo, err := os.Stat(destPath); err == nil {
		localFileModTime = fileInfo.ModTime()
		if !localFileModTime.IsZero() {
			req.Header.Set("If-Modified-Since", localFileModTime.UTC().Format(http.TimeFormat))
		}
	}

	client := &http.Client{Timeout: geofileDownloadTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return false, "", common.NewErrorf("Failed to download Geofile from %s: %v", url, err)
	}
	defer resp.Body.Close()

	// Parse Last-Modified header from server
	var serverModTime time.Time
	serverModTimeStr := resp.Header.Get("Last-Modified")
	if serverModTimeStr != "" {
		parsedTime, err := time.Parse(http.TimeFormat, serverModTimeStr)
		if err != nil {
			logger.Warningf("Failed to parse Last-Modified header for %s: %v", url, err)
		} else {
			serverModTime = parsedTime
		}
	}

	// Function to update local file's modification time
	updateFileModTime := func() {
		if !serverModTime.IsZero() {
			if err := os.Chtimes(destPath, serverModTime, serverModTime); err != nil {
				logger.Warningf("Failed to update modification time for %s: %v", destPath, err)
			}
		}
	}

	// Handle 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		updateFileModTime()
		return false, "", nil
	}

	if resp.StatusCode != http.StatusOK {
		return false, "", common.NewErrorf("Failed to download Geofile from %s: received status code %d", url, resp.StatusCode)
	}

	// M-5: refuse an oversized file before downloading it; the
	// LimitReader below is the hard limit for chunked responses
	// that carry no Content-Length.
	if resp.ContentLength > geofileDownloadMaxBytes {
		return false, "", common.NewErrorf("Failed to download Geofile from %s: file too large: Content-Length %d exceeds limit %d", url, resp.ContentLength, geofileDownloadMaxBytes)
	}

	// The temporary file name is unique per download so a
	// concurrent update cannot overwrite another one's download.
	tmpPath := destPath + ".tmp-" + random.Seq(8)
	file, err := os.Create(tmpPath)
	if err != nil {
		return false, "", common.NewErrorf("Failed to create Geofile %s: %v", destPath, err)
	}
	// M-5: cap the body; a response larger than the cap is refused
	// instead of being written to disk unbounded. Copying one byte
	// past the limit makes the overflow detectable.
	written, err := io.Copy(file, io.LimitReader(resp.Body, geofileDownloadMaxBytes+1))
	closeErr := file.Close()
	if err != nil {
		_ = os.Remove(tmpPath)
		return false, "", common.NewErrorf("Failed to save Geofile %s: %v", destPath, err)
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return false, "", common.NewErrorf("Failed to save Geofile %s: %v", destPath, closeErr)
	}
	if written > geofileDownloadMaxBytes {
		_ = os.Remove(tmpPath)
		return false, "", common.NewErrorf("Failed to save Geofile %s: file too large: exceeds limit %d bytes", destPath, geofileDownloadMaxBytes)
	}
	// Back up the old file before the rename so the caller can roll
	// the replacement back when the update fails later (another file
	// failed, or the restart failed). The backup name is unique per
	// download; the backup is the caller's once this function
	// returns replaced=true. On any failure here it is removed and
	// the old file is untouched.
	backupPath = destPath + ".bak-" + random.Seq(8)
	if data, readErr := os.ReadFile(destPath); readErr == nil {
		if writeErr := os.WriteFile(backupPath, data, 0644); writeErr != nil {
			_ = os.Remove(tmpPath)
			return false, "", common.NewErrorf("Failed to back up Geofile %s: %v", destPath, writeErr)
		}
	} else if !os.IsNotExist(readErr) {
		_ = os.Remove(tmpPath)
		return false, "", common.NewErrorf("Failed to back up Geofile %s: %v", destPath, readErr)
	} else {
		backupPath = ""
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(tmpPath)
		_ = os.Remove(backupPath)
		return false, "", common.NewErrorf("Failed to save Geofile %s: %v", destPath, err)
	}

	updateFileModTime()
	return true, backupPath, nil
}

// restoreGeofileBackup puts the backed-up content back at destPath
// and removes the backup. A missing backup is a no-op; a failed
// rename is only logged.
func restoreGeofileBackup(backupPath, destPath string) {
	if backupPath == "" {
		return
	}
	if _, err := os.Stat(backupPath); err != nil {
		return
	}
	if err := os.Rename(backupPath, destPath); err != nil {
		logger.Warningf("Failed to restore Geofile backup %s: %v", destPath, err)
	}
}

// discardGeofileBackup removes a backup that is no longer needed
// (the update succeeded and the new files are live).
func discardGeofileBackup(backupPath string) {
	if backupPath == "" {
		return
	}
	_ = os.Remove(backupPath)
}

func (s *ServerService) UpdateGeofile(fileName string) error {
	type geofileEntry struct {
		URL      string
		FileName string
	}
	geofileAllowlist := map[string]geofileEntry{
		"geoip.dat":      {"https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat", "geoip.dat"},
		"geosite.dat":    {"https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat", "geosite.dat"},
		"geoip_IR.dat":   {"https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geoip.dat", "geoip_IR.dat"},
		"geosite_IR.dat": {"https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download/geosite.dat", "geosite_IR.dat"},
		"geoip_RU.dat":   {"https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geoip.dat", "geoip_RU.dat"},
		"geosite_RU.dat": {"https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat", "geosite_RU.dat"},
	}

	// Strict allowlist check to avoid writing uncontrolled files
	if fileName != "" {
		if _, ok := geofileAllowlist[fileName]; !ok {
			return common.NewErrorf("Invalid geofile name: %q not in allowlist", fileName)
		}
	}

	// The whole update transaction is serialised with Xray updates,
	// custom geo updates, and imports.
	updateMu.Lock()
	defer updateMu.Unlock()

	var errorMessages []string
	type geofileReplacement struct {
		destPath   string
		backupPath string
	}
	var replaced []geofileReplacement

	download := func(entry geofileEntry) {
		destPath := filepath.Join(config.GetBinFolderPath(), entry.FileName)
		ok, backupPath, err := downloadGeofile(entry.URL, destPath)
		if err != nil {
			errorMessages = append(errorMessages, fmt.Sprintf("Error downloading Geofile '%s': %v", entry.FileName, err))
			return
		}
		if ok {
			replaced = append(replaced, geofileReplacement{destPath: destPath, backupPath: backupPath})
		}
	}

	if fileName == "" {
		// Download all geofiles
		for _, entry := range geofileAllowlist {
			download(entry)
		}
	} else {
		download(geofileAllowlist[fileName])
	}

	// All-or-nothing: a failed download must not restart Xray onto
	// a half-updated set of files. Restore every file that was
	// already replaced and return the errors without touching Xray.
	if len(errorMessages) > 0 {
		for _, r := range replaced {
			restoreGeofileBackup(r.backupPath, r.destPath)
		}
		return common.NewErrorf("%s", strings.Join(errorMessages, "\r\n"))
	}

	// The pre-update running state, recorded before the restart
	// below overwrites the manual-stop flag.
	wasRunning := s.xrayService.IsXrayRunning()
	wasManuallyStopped := s.xrayService.IsManuallyStopped()

	// rollBackFilesAndState restores the replaced files and the
	// pre-update running state after a failed restart or a new
	// Xray that never became ready. The candidate process is
	// stopped first so it does not keep serving the new files.
	rollBack := func() {
		_ = s.xrayService.StopXray()
		for _, r := range replaced {
			restoreGeofileBackup(r.backupPath, r.destPath)
		}
		s.restoreXrayState(wasRunning, wasManuallyStopped)
	}

	// Every file is up to date; restart Xray to load them.
	if err := s.RestartXrayService(); err != nil {
		rollBack()
		return common.NewErrorf("Updated Geofile '%s' but Failed to start Xray: %v", fileName, err)
	}

	// A restart that returns success only proves the process was
	// created: new data can still kill it right after start. The
	// old files stay backed up until the new Xray has proven
	// itself ready.
	if err := s.WaitReady(10 * time.Second); err != nil {
		rollBack()
		return common.NewErrorf("Updated Geofile '%s' but Xray did not become ready: %v", fileName, err)
	}

	// The new files are live: the backups are no longer needed.
	for _, r := range replaced {
		discardGeofileBackup(r.backupPath)
	}
	return nil
}

func (s *ServerService) GetNewX25519Cert() (any, error) {
	// Run the command
	cmd := exec.Command(xray.GetBinaryPath(), "x25519")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	privateKey, publicKey, err := parseKeyValueLines(out.String(), "x25519")
	if err != nil {
		return nil, err
	}

	keyPair := map[string]any{
		"privateKey": privateKey,
		"publicKey":  publicKey,
	}

	return keyPair, nil
}

func (s *ServerService) GetNewmldsa65() (any, error) {
	// Run the command
	cmd := exec.Command(xray.GetBinaryPath(), "mldsa65")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	seed, verify, err := parseKeyValueLines(out.String(), "mldsa65")
	if err != nil {
		return nil, err
	}

	keyPair := map[string]any{
		"seed":   seed,
		"verify": verify,
	}

	return keyPair, nil
}

func (s *ServerService) GetNewEchCert(sni string) (any, error) {
	// M5: validate the SNI before it is passed to the xray CLI. It must be a
	// plain hostname: no leading '-', no spaces, no shell metacharacters.
	// exec.Command does not invoke a shell, but a leading '-' would be
	// parsed as a flag by the xray binary.
	sniRe := regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	if !sniRe.MatchString(sni) {
		return nil, errors.New("invalid sni hostname")
	}
	// Run the command
	cmd := exec.Command(xray.GetBinaryPath(), "tls", "ech", "--serverName="+sni)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(out.String(), "\n")
	if len(lines) < 4 {
		return nil, common.NewError("invalid ech cert")
	}

	configList := lines[1]
	serverKeys := lines[3]

	return map[string]any{
		"echServerKeys": serverKeys,
		"echConfigList": configList,
	}, nil
}

func (s *ServerService) GetNewVlessEnc() (any, error) {
	cmd := exec.Command(xray.GetBinaryPath(), "vlessenc")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	lines := strings.Split(out.String(), "\n")
	var auths []map[string]string
	var current map[string]string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Authentication:") {
			if current != nil {
				auths = append(auths, current)
			}
			current = map[string]string{
				"label": strings.TrimSpace(strings.TrimPrefix(line, "Authentication:")),
			}
		} else if strings.HasPrefix(line, `"decryption"`) || strings.HasPrefix(line, `"encryption"`) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 && current != nil {
				key := strings.Trim(parts[0], `" `)
				val := strings.Trim(parts[1], `" `)
				current[key] = val
			}
		}
	}

	if current != nil {
		auths = append(auths, current)
	}

	return map[string]any{
		"auths": auths,
	}, nil
}

func (s *ServerService) GetNewUUID() (map[string]string, error) {
	newUUID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate UUID: %w", err)
	}

	return map[string]string{
		"uuid": newUUID.String(),
	}, nil
}

func (s *ServerService) GetNewmlkem768() (any, error) {
	// Run the command
	cmd := exec.Command(xray.GetBinaryPath(), "mlkem768")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	seed, client, err := parseKeyValueLines(out.String(), "mlkem768")
	if err != nil {
		return nil, err
	}

	keyPair := map[string]any{
		"seed":   seed,
		"client": client,
	}

	return keyPair, nil
}

// parseKeyValueLines extracts two "Label: value" lines from a CLI's
// stdout (L-10). The xray subcommands print exactly this shape, but
// an unexpected output format used to panic on lines[0]/lines[1] or
// on the split's [1] instead of returning an error — the same guard
// GetNewEchCert already has. SplitN keeps a value that itself
// contains ":" intact.
func parseKeyValueLines(output string, what string) (string, string, error) {
	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		return "", "", common.NewErrorf("invalid %s output: %d lines", what, len(lines))
	}
	first := strings.SplitN(lines[0], ":", 2)
	second := strings.SplitN(lines[1], ":", 2)
	if len(first) < 2 || len(second) < 2 {
		return "", "", common.NewErrorf("invalid %s output: expected \"Label: value\" lines", what)
	}
	return strings.TrimSpace(first[1]), strings.TrimSpace(second[1]), nil
}
