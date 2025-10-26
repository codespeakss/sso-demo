package main

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
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
	data map[string]string
}{data: make(map[string]string)}

//go:embed static
var content embed.FS

func main() {
	r := gin.Default()

	fsys, _ := fs.Sub(content, "static")
	r.StaticFS("/static", http.FS(fsys))

	// 登录接口
	r.POST("/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")
		redirect := c.PostForm("redirect")

		user, ok := users[username]
		if !ok || user.Password != password {
			c.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "用户名或密码错误", "redirect": redirect})
			return
		}

		token := uuid.NewString()
		sessions.Lock()
		sessions.data[token] = username
		sessions.Unlock()

		c.SetCookie("sso_token", token, 3600, "/", "", false, true)

		if redirect != "" {
			c.Redirect(http.StatusFound, redirect+"?token="+token)
		} else {
			c.String(http.StatusOK, "登录成功, token: %s", token)
		}
	})

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

	// ................ app01 start ................
	r.GET("/app01", func(c *gin.Context) {
		token, err := c.Cookie("sso_token")
		if err != nil || token == "" {
			c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?redirect=%s", SSO_SERVER, URL_APP01))
			return
		}

		// 验证 token
		resp, err := http.Get(fmt.Sprintf("%s/verify?token=%s", SSO_SERVER, token))
		if err != nil || resp.StatusCode != http.StatusOK {
			c.String(http.StatusUnauthorized, "SSO 验证失败")
			return
		}

		// c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(fmt.Sprintf(indexHTML, token)))
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("app01"))
	})

	// ................ app01 end ................

	r.Run(":80")
}

const SSO_SERVER = "http://sso.bewantbe.com"
const URL_APP01 = "http://bewantbe.com/static/app01.html"
