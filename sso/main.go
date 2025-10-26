package main

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"sync"
	"github.com/google/uuid"
)

type User struct {
	Username string
	Password string
}

// 模拟数据库
var users = map[string]User{
	"alice": {Username: "alice", Password: "123456"},
	"bob":   {Username: "bob", Password: "password"},
}

// Session 存储
var sessions = struct{
	sync.RWMutex
	data map[string]string
}{data: make(map[string]string)}

func main() {
	r := gin.Default()
	r.LoadHTMLGlob("templates/*")

	// 登录页面
	r.GET("/login", func(c *gin.Context) {
		redirect := c.Query("redirect")
		c.HTML(http.StatusOK, "login.html", gin.H{"redirect": redirect})
	})

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

		// 生成 session token
		token := uuid.NewString()
		sessions.Lock()
		sessions.data[token] = username
		sessions.Unlock()

		// 设置 cookie
		c.SetCookie("sso_token", token, 3600, "/", "", false, true)

		if redirect != "" {
			c.Redirect(http.StatusFound, redirect+"?token="+token)
		} else {
			c.String(http.StatusOK, "登录成功, token: %s", token)
		}
	})

	// 验证 token
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

	r.Run(":80") // 使用 80 端口
}

