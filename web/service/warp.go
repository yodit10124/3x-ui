package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/mhsanaei/3x-ui/v2/util/common"
)

// WarpService provides business logic for Cloudflare WARP integration.
// It manages WARP configuration and connectivity settings.
type WarpService struct {
	SettingService
}

// warpHTTPClient is shared by the three Cloudflare requests (L-13):
// the old per-call http.Client{} had no timeout, so a stalled
// Cloudflare endpoint held the handler forever. A var so tests can
// shorten the timeout.
var warpHTTPClient = &http.Client{Timeout: 15 * time.Second}

// warpMaxBodyBytes bounds the Cloudflare responses (L-13): the
// registration payloads are a few KiB. A var so tests can lower it.
var warpMaxBodyBytes int64 = 1 << 20

func (s *WarpService) GetWarpData() (string, error) {
	warp, err := s.SettingService.GetWarp()
	if err != nil {
		return "", err
	}
	return warp, nil
}

func (s *WarpService) DelWarpData() error {
	err := s.SettingService.SetWarp("")
	if err != nil {
		return err
	}
	return nil
}

// doWarpRequest performs a Cloudflare request and returns the body,
// capped at warpMaxBodyBytes (L-13).
func doWarpRequest(req *http.Request) ([]byte, error) {
	resp, err := warpHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, warpMaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > warpMaxBodyBytes {
		return nil, fmt.Errorf("WARP response exceeds the %d-byte limit", warpMaxBodyBytes)
	}
	return body, nil
}

func (s *WarpService) GetWarpConfig() (string, error) {
	var warpData map[string]string
	warp, err := s.SettingService.GetWarp()
	if err != nil {
		return "", err
	}
	err = json.Unmarshal([]byte(warp), &warpData)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://api.cloudflareclient.com/v0a2158/reg/%s", warpData["device_id"])

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+warpData["access_token"])

	body, err := doWarpRequest(req)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// warpRegRequest is the registration payload (L-13): marshalled,
// never Sprintf-built — a hostname containing a quote or backslash
// used to break the JSON.
type warpRegRequest struct {
	Key   string `json:"key"`
	Tos   string `json:"tos"`
	Type  string `json:"type"`
	Model string `json:"model"`
	Name  string `json:"name"`
}

// warpCredentials is the stored WARP identity, in the same field
// order as the old hand-built JSON.
type warpCredentials struct {
	AccessToken string `json:"access_token"`
	DeviceID    string `json:"device_id"`
	LicenseKey  string `json:"license_key"`
	PrivateKey  string `json:"private_key"`
}

// warpRegResult is the registration reply: the stored identity and
// Cloudflare's own response.
type warpRegResult struct {
	Data   warpCredentials `json:"data"`
	Config map[string]any  `json:"config"`
}

// parseRegResponse extracts the device id, token, and license from a
// Cloudflare registration reply (L-13). Every lookup is an ok
// assertion: a 429 reply carries no id/token, and the old unchecked
// assertions panicked on it. The old license-missing branch also
// returned the (nil) unmarshal error, i.e. a silent success with an
// empty result; it now returns a real error.
func parseRegResponse(body []byte) (deviceID, token, license string, err error) {
	var rspData map[string]any
	if err := json.Unmarshal(body, &rspData); err != nil {
		return "", "", "", err
	}
	deviceID, ok := rspData["id"].(string)
	if !ok || deviceID == "" {
		return "", "", "", common.NewError("WARP registration response has no device id")
	}
	token, ok = rspData["token"].(string)
	if !ok || token == "" {
		return "", "", "", common.NewError("WARP registration response has no token")
	}
	account, ok := rspData["account"].(map[string]any)
	if !ok {
		return "", "", "", common.NewError("WARP registration response has no account")
	}
	license, ok = account["license"].(string)
	if !ok || license == "" {
		return "", "", "", common.NewError("WARP registration response has no license")
	}
	return deviceID, token, license, nil
}

func (s *WarpService) RegWarp(secretKey string, publicKey string) (string, error) {
	tos := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	hostName, _ := os.Hostname()
	reqBody, err := json.Marshal(warpRegRequest{
		Key: publicKey, Tos: tos, Type: "PC", Model: "x-ui", Name: hostName,
	})
	if err != nil {
		return "", err
	}

	url := "https://api.cloudflareclient.com/v0a2158/reg"

	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}

	req.Header.Add("CF-Client-Version", "a-7.21-0721")
	req.Header.Add("Content-Type", "application/json")

	body, err := doWarpRequest(req)
	if err != nil {
		return "", err
	}

	deviceID, token, license, err := parseRegResponse(body)
	if err != nil {
		return "", err
	}

	creds := warpCredentials{
		AccessToken: token, DeviceID: deviceID, LicenseKey: license, PrivateKey: secretKey,
	}
	warpJSON, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return "", err
	}
	s.SettingService.SetWarp(string(warpJSON))

	var rspData map[string]any
	_ = json.Unmarshal(body, &rspData)
	result, err := json.MarshalIndent(warpRegResult{Data: creds, Config: rspData}, "", "  ")
	if err != nil {
		return "", err
	}

	return string(result), nil
}

// checkLicenseResponse returns nil when the Cloudflare reply reports
// success, and a readable error otherwise (L-13). The errors array
// may be missing, empty, or hold non-objects — none of those may
// panic, as the old errorArr[0].(map[string]any) did.
func checkLicenseResponse(body []byte) error {
	var response map[string]any
	if err := json.Unmarshal(body, &response); err != nil {
		return err
	}
	if response["success"] != false {
		return nil
	}
	var code, message string
	if errorArr, ok := response["errors"].([]any); ok && len(errorArr) > 0 {
		if errorObj, ok := errorArr[0].(map[string]any); ok {
			// Cloudflare error codes are numbers (e.g. 1015), not strings.
			switch c := errorObj["code"].(type) {
			case string:
				code = c
			case float64:
				code = fmt.Sprintf("%d", int64(c))
			}
			message, _ = errorObj["message"].(string)
		}
	}
	if message == "" {
		message = "WARP license update failed"
	}
	if code != "" {
		return common.NewErrorf("WARP error %s: %s", code, message)
	}
	return common.NewError(message)
}

func (s *WarpService) SetWarpLicense(license string) (string, error) {
	var warpData map[string]string
	warp, err := s.SettingService.GetWarp()
	if err != nil {
		return "", err
	}
	err = json.Unmarshal([]byte(warp), &warpData)
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://api.cloudflareclient.com/v0a2158/reg/%s/account", warpData["device_id"])
	reqBody, err := json.Marshal(map[string]string{"license": license})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+warpData["access_token"])

	body, err := doWarpRequest(req)
	if err != nil {
		return "", err
	}

	if err := checkLicenseResponse(body); err != nil {
		return "", err
	}

	warpData["license_key"] = license
	newWarpData, err := json.MarshalIndent(warpData, "", "  ")
	if err != nil {
		return "", err
	}
	s.SettingService.SetWarp(string(newWarpData))

	return string(newWarpData), nil
}
