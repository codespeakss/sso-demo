package main

import (
	"embed"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type User struct {
	Username string
	Password string
}

var users = map[string]User{
	"alice": {Username: "alice", Password: "pass"},
	"bob":   {Username: "bob", Password: "pass"},
}

var sessions = struct {
	sync.RWMutex
	data map[string]string // sso_token -> username
}{data: make(map[string]string)}

var authCodes = struct {
	sync.Mutex
	data map[string]string // code -> username
}{data: make(map[string]string)}

var accessTokens = struct {
	sync.RWMutex
	data map[string]string // access_token -> username
}{data: make(map[string]string)}

const (
	SSO_SESSION_MAX_AGE_SECONDS     = 3600
	ACCESS_TOKEN_EXPIRES_IN_SECONDS = 3600
	AUTH_CODE_EXPIRES_IN_SECONDS    = 300
)

//go:embed static
var content embed.FS

func main() {
	r := gin.Default()

	// CORS middleware for demo
	r.Use(func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
			c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
		}
		c.Next()
	})
	// catch-all OPTIONS for preflight
	r.OPTIONS("/*path", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	fsys, _ := fs.Sub(content, "static")
	r.StaticFS("/static", http.FS(fsys))

	// 登录接口
	r.POST("/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")
		redirect := c.PostForm("redirect")

		user, ok := users[username]
		if !ok || user.Password != password {
			// 回到登录页（静态页）并附加错误信息
			redir := "/static/login.html"
			if redirect != "" {
				redir = redir + "?redirect=" + url.QueryEscape(redirect) + "&error=" + url.QueryEscape("用户名或密码错误")
			}
			c.Redirect(http.StatusFound, redir)
			return
		}

		// 创建 SSO 会话 cookie
		ssoToken := uuid.NewString()
		sessions.Lock()
		sessions.data[ssoToken] = username
		sessions.Unlock()
		c.SetCookie("sso_token", ssoToken, SSO_SESSION_MAX_AGE_SECONDS, "/", "", false, true)

		// 成功后，如果带 redirect，就直接回跳，不再拼接 token（OAuth 流程由 /authorize 处理）
		if redirect != "" {
			c.Redirect(http.StatusFound, redirect)
			return
		}
		c.String(http.StatusOK, "登录成功")
	})

	// 旧的 token 验证接口（保留兼容）
	r.GET("/verify", func(c *gin.Context) {
		token := c.Query("token")
		sessions.RLock()
		username, ok := sessions.data[token]
		sessions.RUnlock()
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"valid": false})
			return
		}
		c.JSON(http.StatusOK, gin.H{"valid": true, "username": username})
	})

	// OAuth: 授权页（用户同意）
	r.GET("/authorize", func(c *gin.Context) {
		clientID := c.Query("client_id")
		redirectURI := c.Query("redirect_uri")
		state := c.Query("state")
		responseType := c.Query("response_type")
		if responseType == "" {
			responseType = "token" // 默认隐式模式
		}

		if (responseType != "token" && responseType != "code") || clientID == "" || redirectURI == "" {
			c.String(http.StatusBadRequest, "invalid_request")
			return
		}

		// 检查是否已登录
		ssoToken, err := c.Cookie("sso_token")
		if err != nil || ssoToken == "" {
			// 去登录页，登录成功后回到本次 /authorize
			current := c.Request.URL
			loginRedirect := "/static/login.html?redirect=" + url.QueryEscape(current.String())
			c.Redirect(http.StatusFound, loginRedirect)
			return
		}

		sessions.RLock()
		username, ok := sessions.data[ssoToken]
		sessions.RUnlock()
		if !ok {
			current := c.Request.URL
			loginRedirect := "/static/login.html?redirect=" + url.QueryEscape(current.String())
			c.Redirect(http.StatusFound, loginRedirect)
			return
		}

		// 展示一个简单的授权确认页面
		q := url.Values{}
		q.Set("client_id", clientID)
		q.Set("redirect_uri", redirectURI)
		q.Set("state", state)
		q.Set("username", username)
		q.Set("response_type", responseType)
		c.Redirect(http.StatusFound, "/static/authorize.html?"+q.Encode())
	})

	// OAuth: 用户确认（发放授权码或直接发放token）
	r.POST("/approve", func(c *gin.Context) {
		action := c.PostForm("action") // allow or deny
		clientID := c.PostForm("client_id")
		redirectURI := c.PostForm("redirect_uri")
		state := c.PostForm("state")
		responseType := c.PostForm("response_type")
		if responseType == "" {
			responseType = "token"
		}

		if clientID == "" || redirectURI == "" {
			c.String(http.StatusBadRequest, "invalid_request")
			return
		}

		if action != "allow" {
			// 拒绝
			sep := "?"
			if strings.Contains(redirectURI, "?") {
				sep = "&"
			}
			c.Redirect(http.StatusFound, redirectURI+sep+"error=access_denied&state="+url.QueryEscape(state))
			return
		}

		// 已登录的用户名
		ssoToken, _ := c.Cookie("sso_token")
		sessions.RLock()
		username := sessions.data[ssoToken]
		sessions.RUnlock()

		if responseType == "token" {
			// 隐式模式：直接颁发 access_token
			access := uuid.NewString()
			accessTokens.Lock()
			accessTokens.data[access] = username
			accessTokens.Unlock()

			// 通过 URL fragment 返回 token
			fragment := url.Values{}
			fragment.Set("access_token", access)
			fragment.Set("token_type", "Bearer")
			if state != "" {
				fragment.Set("state", state)
			}
			c.Redirect(http.StatusFound, redirectURI+"#"+fragment.Encode())
			return
		}

		// 兼容：授权码模式
		code := uuid.NewString()
		authCodes.Lock()
		authCodes.data[code] = username
		authCodes.Unlock()

		sep := "?"
		if strings.Contains(redirectURI, "?") {
			sep = "&"
		}
		c.Redirect(http.StatusFound, redirectURI+sep+"code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state))
	})

	// OAuth: 令牌交换
	r.POST("/token", func(c *gin.Context) {
		// CORS
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Header("Access-Control-Allow-Methods", "POST, OPTIONS")
		if c.Request.Method == http.MethodOptions {
			c.Status(http.StatusNoContent)
			return
		}

		grantType := c.PostForm("grant_type")
		if grantType != "authorization_code" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
			return
		}
		code := c.PostForm("code")
		if code == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}

		authCodes.Lock()
		username, ok := authCodes.data[code]
		if ok {
			delete(authCodes.data, code) // 一次性使用
		}
		authCodes.Unlock()
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
			return
		}

		access := uuid.NewString()
		accessTokens.Lock()
		accessTokens.data[access] = username
		accessTokens.Unlock()

		c.JSON(http.StatusOK, gin.H{
			"access_token": access,
			"token_type":   "Bearer",
			"expires_in":   ACCESS_TOKEN_EXPIRES_IN_SECONDS,
		})
	})

	// OAuth: 用户信息
	r.GET("/userinfo", func(c *gin.Context) {
		// CORS
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Header("Access-Control-Allow-Methods", "GET, OPTIONS")
		if c.Request.Method == http.MethodOptions {
			c.Status(http.StatusNoContent)
			return
		}

		authz := c.GetHeader("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(authz, prefix) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}
		token := strings.TrimPrefix(authz, prefix)

		accessTokens.RLock()
		username, ok := accessTokens.data[token]
		accessTokens.RUnlock()
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"username": username,
			"picture":  SSO_SERVER + "/avatar/" + url.PathEscape(username),
		})
	})

	// Avatar endpoint: returns an SVG avatar for the given username
	r.GET("/avatar/:username", func(c *gin.Context) {
		// Load classic avatar SVG from embedded static file
		data, err := content.ReadFile("static/avatar.svg")
		if err != nil {
			c.String(http.StatusInternalServerError, "avatar resource not found")
			return
		}
		c.Header("Content-Type", "image/svg+xml")
		c.Header("Cache-Control", "public, max-age=3600")
		c.Data(http.StatusOK, "image/svg+xml", data)
	})

	// ................ app01 start ................
	// ................ app01 end ................

	r.Run(":80")
}

const SSO_SERVER = "http://sso.bewantbe.com"
const URL_APP01 = "http://bewantbe.com/static/app01.html"
