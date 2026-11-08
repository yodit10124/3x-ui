package controller

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/entity"

	"github.com/gin-gonic/gin"
)

// getRemoteIp returns the IP to use for logging and login rate limiting.
//
// H-1: X-Real-IP / X-Forwarded-For are plain request headers that any
// client can set to any value, so they must never be trusted blindly.
// The only IP that cannot be forged in a completed TCP (HTTP) request is
// the direct peer address in RemoteAddr. By default this function returns
// exactly that and ignores both forwarding headers.
//
// The forwarding headers are honoured only when the direct peer is a
// trusted reverse proxy, configured via the XUI_TRUSTED_PROXIES
// environment variable (comma-separated IPs and/or CIDRs, e.g.
// "127.0.0.1,10.0.0.0/8"; empty means trust no proxy). When the peer is
// trusted, the X-Forwarded-For chain is walked from the rightmost entry
// (closest to us) leftwards, skipping trusted proxies, and the first
// untrusted entry is the real client. X-Real-IP is only used when there
// is no X-Forwarded-For chain and the peer is trusted.
func getRemoteIp(c *gin.Context) string {
	remoteIP, ok := extractTrustedIP(c.Request.RemoteAddr)
	if !ok {
		return "unknown"
	}
	if !isTrustedProxy(remoteIP) {
		return remoteIP
	}
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		chain := make([]string, 0, 8)
		for _, part := range strings.Split(xff, ",") {
			if ip, ok := extractTrustedIP(part); ok {
				chain = append(chain, ip)
			}
		}
		chain = append(chain, remoteIP)
		// Walk from the peer (rightmost) leftwards, skipping trusted
		// proxies; the first untrusted entry is the real client.
		for i := len(chain) - 1; i > 0; i-- {
			if !isTrustedProxy(chain[i]) {
				return chain[i]
			}
		}
		return chain[0]
	}
	if ip, ok := extractTrustedIP(c.GetHeader("X-Real-IP")); ok {
		return ip
	}
	return remoteIP
}

// isTrustedProxy reports whether ip belongs to the reverse proxies the
// operator explicitly trusts via XUI_TRUSTED_PROXIES. An empty list trusts
// nobody, which is the safe default for a directly exposed panel.
func isTrustedProxy(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, entry := range strings.Split(os.Getenv("XUI_TRUSTED_PROXIES"), ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				continue
			}
			if prefix.Contains(addr) {
				return true
			}
			continue
		}
		if trusted, err := netip.ParseAddr(entry); err == nil && trusted.Unmap() == addr {
			return true
		}
	}
	return false
}

func extractTrustedIP(value string) (string, bool) {
	candidate := strings.TrimSpace(value)
	if candidate == "" {
		return "", false
	}

	if ip, ok := parseIPCandidate(candidate); ok {
		return ip.String(), true
	}

	if host, _, err := net.SplitHostPort(candidate); err == nil {
		if ip, ok := parseIPCandidate(host); ok {
			return ip.String(), true
		}
	}

	if strings.Count(candidate, ":") == 1 {
		if host, _, err := net.SplitHostPort(fmt.Sprintf("[%s]", candidate)); err == nil {
			if ip, ok := parseIPCandidate(host); ok {
				return ip.String(), true
			}
		}
	}

	return "", false
}

func parseIPCandidate(value string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap(), true
}

// jsonMsg sends a JSON response with a message and error status.
func jsonMsg(c *gin.Context, msg string, err error) {
	jsonMsgObj(c, msg, nil, err)
}

// jsonObj sends a JSON response with an object and error status.
func jsonObj(c *gin.Context, obj any, err error) {
	jsonMsgObj(c, "", obj, err)
}

// jsonMsgObj sends a JSON response with a message, object, and error status.
func jsonMsgObj(c *gin.Context, msg string, obj any, err error) {
	m := entity.Msg{
		Obj: obj,
	}
	if err == nil {
		m.Success = true
		if msg != "" {
			m.Msg = msg
		}
	} else {
		m.Success = false
		errStr := err.Error()
		if errStr != "" {
			m.Msg = msg + " (" + errStr + ")"
			logger.Warning(msg+" "+I18nWeb(c, "fail")+": ", err)
		} else if msg != "" {
			m.Msg = msg
			logger.Warning(msg + " " + I18nWeb(c, "fail"))
		} else {
			m.Msg = I18nWeb(c, "somethingWentWrong")
			logger.Warning(I18nWeb(c, "somethingWentWrong") + " " + I18nWeb(c, "fail"))
		}
	}
	c.JSON(http.StatusOK, m)
}

// pureJsonMsg sends a pure JSON message response with custom status code.
func pureJsonMsg(c *gin.Context, statusCode int, success bool, msg string) {
	c.JSON(statusCode, entity.Msg{
		Success: success,
		Msg:     msg,
	})
}

// html renders an HTML template with the provided data and title.
func html(c *gin.Context, name string, title string, data gin.H) {
	if data == nil {
		data = gin.H{}
	}
	data["title"] = title
	host := c.GetHeader("X-Forwarded-Host")
	if host == "" {
		host = c.GetHeader("X-Real-IP")
	}
	if host == "" {
		var err error
		host, _, err = net.SplitHostPort(c.Request.Host)
		if err != nil {
			host = c.Request.Host
		}
	}
	data["host"] = host
	data["request_uri"] = c.Request.RequestURI
	data["base_path"] = c.GetString("base_path")
	c.HTML(http.StatusOK, name, getContext(data))
}

// getContext adds version and other context data to the provided gin.H.
func getContext(h gin.H) gin.H {
	a := gin.H{
		"cur_ver": config.GetVersion(),
	}
	for key, value := range h {
		a[key] = value
	}
	return a
}

// isAjax checks if the request is an AJAX request.
func isAjax(c *gin.Context) bool {
	return c.GetHeader("X-Requested-With") == "XMLHttpRequest"
}
