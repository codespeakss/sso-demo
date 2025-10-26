package main

import (
	_ "embed"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
)

const SSO_SERVER = "http://localhost" // SSO 服务地址

//go:embed templates/index.html
var indexHTML string

func main() {
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		token, err := c.Cookie("sso_token")
		if err != nil || token == "" {
			redirect := "http://localhost:8080"
			c.Redirect(http.StatusFound, fmt.Sprintf("%s/login?redirect=%s", SSO_SERVER, redirect))
			return
		}

		// 验证 token
		resp, err := http.Get(fmt.Sprintf("%s/verify?token=%s", SSO_SERVER, token))
		if err != nil || resp.StatusCode != http.StatusOK {
			c.String(http.StatusUnauthorized, "SSO 验证失败")
			return
		}

		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(fmt.Sprintf(indexHTML, token)))
	})

	r.Run(":80")
}

