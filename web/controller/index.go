package controller

import (
	"fmt"
	"net/http"
	"sync"
	"text/template"
	"time"

	"github.com/mhsanaei/3x-ui/v2/logger"
	"github.com/mhsanaei/3x-ui/v2/web/service"
	"github.com/mhsanaei/3x-ui/v2/web/session"

	"github.com/gin-gonic/gin"
)

// LoginForm represents the login request structure.
type LoginForm struct {
	Username      string `json:"username" form:"username"`
	Password      string `json:"password" form:"password"`
	TwoFactorCode string `json:"twoFactorCode" form:"twoFactorCode"`
}

// IndexController handles the main index and login-related routes.
type IndexController struct {
	BaseController

	settingService service.SettingService
	userService    service.UserService
	tgbot          service.Tgbot
}

// NewIndexController creates a new IndexController and initializes its routes.
func NewIndexController(g *gin.RouterGroup) *IndexController {
	a := &IndexController{}
	a.initRouter(g)
	return a
}

// initRouter sets up the routes for index, login, logout, and two-factor authentication.
func (a *IndexController) initRouter(g *gin.RouterGroup) {
	g.GET("/", a.index)
	// L-3: logout is POST-only and covered by the CSRF middleware
	// (a GET /logout could be triggered by a cross-site top-level
	// navigation and log the admin out). GET /logout no longer exists.
	g.POST("/logout", a.logout)

	g.POST("/login", a.login)
	g.POST("/getTwoFactorEnable", a.getTwoFactorEnable)
}

// index handles the root route, redirecting logged-in users to the panel or showing the login page.
func (a *IndexController) index(c *gin.Context) {
	if session.IsLogin(c) {
		c.Redirect(http.StatusTemporaryRedirect, "panel/")
		return
	}
	html(c, "login.html", "pages.login.title", nil)
}

// H2: login rate limiting. After 5 failed attempts from one IP, further
// login attempts from that IP are rejected for 15 minutes. State is kept in
// memory (it resets on panel restart, which is acceptable for a brute-force
// throttle); the default admin/admin credentials are NOT changed here -
// operators must change them after first login (see the warning logged on
// a successful login with the default credentials).
const (
	maxLoginFailures  = 5
	loginLockDuration = 15 * time.Minute
)

type loginAttempt struct {
	failures    int
	lockedUntil time.Time
	// lastSeen is the last failed attempt from this IP; failure counts
	// older than loginLockDuration are discarded so stale entries do not
	// accumulate forever.
	lastSeen time.Time
}

var (
	loginAttemptsMu sync.Mutex
	loginAttempts   = map[string]*loginAttempt{}
)

// cleanupLoginAttempts drops expired entries. Callers must hold
// loginAttemptsMu. Without this, random keys (previously: random
// X-Forwarded-For values; now: random source IPs) would grow the map
// without bound for the lifetime of the process.
func cleanupLoginAttempts(now time.Time) {
	for ip, a := range loginAttempts {
		if !a.lockedUntil.IsZero() && now.Before(a.lockedUntil) {
			continue
		}
		if !a.lastSeen.IsZero() && now.Sub(a.lastSeen) < loginLockDuration {
			continue
		}
		delete(loginAttempts, ip)
	}
}

func isLoginLocked(ip string) bool {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	cleanupLoginAttempts(time.Now())
	if a, ok := loginAttempts[ip]; ok && time.Now().Before(a.lockedUntil) {
		return true
	}
	return false
}

func recordLoginFailure(ip string) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	cleanupLoginAttempts(time.Now())
	a, ok := loginAttempts[ip]
	if !ok {
		a = &loginAttempt{}
		loginAttempts[ip] = a
	}
	a.failures++
	a.lastSeen = time.Now()
	if a.failures >= maxLoginFailures {
		a.lockedUntil = time.Now().Add(loginLockDuration)
		a.failures = 0
	}
}

func resetLoginFailures(ip string) {
	loginAttemptsMu.Lock()
	defer loginAttemptsMu.Unlock()
	delete(loginAttempts, ip)
}

// login handles user authentication and session creation.
func (a *IndexController) login(c *gin.Context) {
	var form LoginForm

	if err := c.ShouldBind(&form); err != nil {
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.invalidFormData"))
		return
	}
	if form.Username == "" {
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.emptyUsername"))
		return
	}
	if form.Password == "" {
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.emptyPassword"))
		return
	}

	// H2: reject logins from a locked-out IP before checking credentials.
	if isLoginLocked(getRemoteIp(c)) {
		pureJsonMsg(c, http.StatusTooManyRequests, false, "Too many failed login attempts. Please try again later.")
		return
	}

	user, checkErr := a.userService.CheckUser(form.Username, form.Password, form.TwoFactorCode)
	timeStr := time.Now().Format("2006-01-02 15:04:05")
	safeUser := template.HTMLEscapeString(form.Username)

	if user == nil {
		// H5: never log or forward the submitted password, not even escaped.
		logger.Warningf("failed login attempt for username: \"%s\", IP: \"%s\"", safeUser, getRemoteIp(c))
		recordLoginFailure(getRemoteIp(c))

		notifyPass := "***"
		if checkErr != nil && checkErr.Error() == "invalid 2fa code" {
			translatedError := a.tgbot.I18nBot("tgbot.messages.2faFailed")
			notifyPass = fmt.Sprintf("*** (%s)", translatedError)
		}

		a.tgbot.UserLoginNotify(safeUser, notifyPass, getRemoteIp(c), timeStr, 0)
		pureJsonMsg(c, http.StatusOK, false, I18nWeb(c, "pages.login.toasts.wrongUsernameOrPassword"))
		return
	}

	resetLoginFailures(getRemoteIp(c))
	logger.Infof("%s logged in successfully, Ip Address: %s\n", safeUser, getRemoteIp(c))
	// H2: warn loudly while the well-known default credentials are still in use.
	if form.Username == "admin" && form.Password == "admin" {
		logger.Warning("SECURITY: the panel is still using the default admin/admin credentials - change them immediately in Settings")
	}
	a.tgbot.UserLoginNotify(safeUser, ``, getRemoteIp(c), timeStr, 1)

	if err := session.SetLoginUser(c, user); err != nil {
		logger.Warning("Unable to save session:", err)
		return
	}

	logger.Infof("%s logged in successfully", safeUser)
	jsonMsg(c, I18nWeb(c, "pages.login.toasts.successLogin"), nil)
}

// logout handles user logout by clearing the session and redirecting to the login page.
func (a *IndexController) logout(c *gin.Context) {
	user := session.GetLoginUser(c)
	if user != nil {
		logger.Infof("%s logged out successfully", user.Username)
	}
	if err := session.ClearSession(c); err != nil {
		logger.Warning("Unable to clear session on logout:", err)
	}
	c.Redirect(http.StatusTemporaryRedirect, c.GetString("base_path"))
}

// getTwoFactorEnable retrieves the current status of two-factor authentication.
func (a *IndexController) getTwoFactorEnable(c *gin.Context) {
	status, err := a.settingService.GetTwoFactorEnable()
	if err == nil {
		jsonObj(c, status, nil)
	}
}
