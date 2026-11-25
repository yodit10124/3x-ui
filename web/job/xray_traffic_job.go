package job

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/websocket"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// XrayTrafficJob collects and processes traffic statistics from Xray, updating the database and optionally informing external APIs.
type XrayTrafficJob struct {
	settingService  service.SettingService
	xrayService     service.XrayService
	inboundService  service.InboundService
	outboundService service.OutboundService
}

// NewXrayTrafficJob creates a new traffic collection job instance.
func NewXrayTrafficJob() *XrayTrafficJob {
	return new(XrayTrafficJob)
}

// Run collects traffic statistics from Xray, updates the database, and pushes
// real-time updates over WebSocket using compact delta payloads — no REST
// fallback, scales to 10k–20k+ clients per inbound.
func (j *XrayTrafficJob) Run() {
	if !j.xrayService.IsXrayRunning() {
		return
	}
	traffics, clientTraffics, err := j.xrayService.GetXrayTraffic()
	if err != nil {
		return
	}
	needRestart0, clientsDisabled, err := j.inboundService.AddTraffic(traffics, clientTraffics)
	if err != nil {
		logger.Warning("add inbound traffic failed:", err)
	}
	err, needRestart1 := j.outboundService.AddTraffic(traffics, clientTraffics)
	if err != nil {
		logger.Warning("add outbound traffic failed:", err)
	}
	if clientsDisabled {
		restartOnDisable, settingErr := j.settingService.GetRestartXrayOnClientDisable()
		if settingErr != nil {
			logger.Warning("get RestartXrayOnClientDisable failed:", settingErr)
		}
		if restartOnDisable {
			if err := j.xrayService.RestartXray(true); err != nil {
				logger.Warning("restart xray after disabling clients failed:", err)
				j.xrayService.SetToNeedRestart()
			}
		}
	}
	if ExternalTrafficInformEnable, err := j.settingService.GetExternalTrafficInformEnable(); ExternalTrafficInformEnable {
		j.informTrafficToExternalAPI(traffics, clientTraffics)
	} else if err != nil {
		logger.Warning("get ExternalTrafficInformEnable failed:", err)
	}
	if needRestart0 || needRestart1 {
		j.xrayService.SetToNeedRestart()
	}

	// If no frontend client is connected, skip all WebSocket broadcasting
	// routines — including the active-client DB query and JSON marshaling.
	if !websocket.HasClients() {
		return
	}

	// Online presence + traffic deltas — small payload, always fits in WS.
	// Force non-nil slice/map so JSON marshalling produces [] / {} instead of
	// `null` when everyone is offline. The frontend's traffic handler treats
	// a missing/null onlineClients field as "no update", so without this the
	// "everyone went offline" transition was silently dropped — stale online
	// users lingered in the list and the online filter kept showing them.
	onlineClients := j.inboundService.GetOnlineClients()
	if onlineClients == nil {
		onlineClients = []string{}
	}
	lastOnlineMap, err := j.inboundService.GetClientsLastOnline()
	if err != nil {
		logger.Warning("get clients last online failed:", err)
	}
	if lastOnlineMap == nil {
		lastOnlineMap = make(map[string]int64)
	}
	websocket.BroadcastTraffic(map[string]any{
		"traffics":       traffics,
		"clientTraffics": clientTraffics,
		"onlineClients":  onlineClients,
		"lastOnlineMap":  lastOnlineMap,
	})

	// Compact delta payload: per-client absolute counters for clients active
	// this cycle, plus inbound-level absolute totals. Frontend applies both
	// in-place — typical payload ~10–50KB even for 10k+ client deployments.
	// Replaces the old full-inbound-list broadcast that hit WS size limits
	// (5–10MB) and forced the frontend into a REST refetch.
	clientStatsPayload := map[string]any{}
	if activeEmails := activeEmails(clientTraffics); len(activeEmails) > 0 {
		if stats, err := j.inboundService.GetActiveClientTraffics(activeEmails); err != nil {
			logger.Warning("get active client traffics for websocket failed:", err)
		} else if len(stats) > 0 {
			clientStatsPayload["clients"] = stats
		}
	}
	if inboundSummary, err := j.inboundService.GetInboundsTrafficSummary(); err != nil {
		logger.Warning("get inbounds traffic summary for websocket failed:", err)
	} else if len(inboundSummary) > 0 {
		clientStatsPayload["inbounds"] = inboundSummary
	}
	if len(clientStatsPayload) > 0 {
		websocket.BroadcastClientStats(clientStatsPayload)
	}

	// Outbounds list is small (one row per outbound, no per-client expansion)
	// so the full snapshot still fits comfortably in WS.
	if updatedOutbounds, err := j.outboundService.GetOutboundsTraffic(); err == nil && updatedOutbounds != nil {
		websocket.BroadcastOutbounds(updatedOutbounds)
	} else if err != nil {
		logger.Warning("get all outbounds for websocket failed:", err)
	}
}

// activeEmails returns the set of client emails that had non-zero traffic in
// the current collection window. Idle clients are skipped — no need to push
// their (unchanged) counters to the frontend.
func activeEmails(clientTraffics []*xray.ClientTraffic) []string {
	if len(clientTraffics) == 0 {
		return nil
	}
	emails := make([]string, 0, len(clientTraffics))
	for _, ct := range clientTraffics {
		if ct == nil || ct.Email == "" {
			continue
		}
		if ct.Up == 0 && ct.Down == 0 {
			continue
		}
		emails = append(emails, ct.Email)
	}
	return emails
}

// trafficInformTimeout bounds a single traffic-report POST end to end.
const trafficInformTimeout = 10 * time.Second

// trafficInformMaxResponseBody caps how much of a report response is
// read; the body is discarded, so anything beyond this is never needed.
const trafficInformMaxResponseBody = 1 << 20 // 1 MiB

// Seams for tests: the URL validator and HTTP client used by the traffic
// inform. Production values are the SSRF-checked ones from web/service.
var (
	trafficInformValidateURL = service.ValidatePublicHTTPURL
	trafficInformClient      = service.NewSSRFCheckedHTTPClient(trafficInformTimeout)
)

func (j *XrayTrafficJob) informTrafficToExternalAPI(inboundTraffics []*xray.Traffic, clientTraffics []*xray.ClientTraffic) {
	informURL, err := j.settingService.GetExternalTrafficInformURI()
	if err != nil {
		logger.Warning("get ExternalTrafficInformURI failed:", err)
		return
	}
	if informURL == "" {
		return
	}
	// Re-validate at send time: the stored value may predate the
	// save-time check (e.g. smuggled in by a database import), and the
	// client re-validates every address again at dial time, so a DNS
	// answer that flips to an internal address mid-flight still cannot
	// move the request inward.
	cleanURL, err := trafficInformValidateURL(informURL)
	if err != nil {
		logger.Warning("ExternalTrafficInformURI failed validation:", err)
		return
	}
	requestBody, err := json.Marshal(map[string]any{"clientTraffics": clientTraffics, "inboundTraffics": inboundTraffics})
	if err != nil {
		logger.Warning("parse client/inbound traffic failed:", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), trafficInformTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, cleanURL, bytes.NewReader(requestBody))
	if err != nil {
		logger.Warning("build ExternalTrafficInformURI request failed:", err)
		return
	}
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	response, err := trafficInformClient.Do(request)
	if err != nil {
		logger.Warning("POST ExternalTrafficInformURI failed:", err)
		return
	}
	defer response.Body.Close()
	// The response is not used; drain at most 1 MiB so a hostile or
	// broken endpoint cannot hold the job hostage with an unbounded body.
	if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, trafficInformMaxResponseBody)); err != nil {
		logger.Warning("read ExternalTrafficInformURI response failed:", err)
	}
}
