package main

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
	"time"
)

var jwtKey = []byte("secureKey")
var tokens []string

type Claims struct {
	Username string `json:"Username"`
	jwt.RegisteredClaims
}

func main() {
	r := gin.Default()
	r.POST("/login", gin.BasicAuth(gin.Accounts{
		"admin": "pass",
	}), func(c *gin.Context) {
		token, _ := GenerateJWT()
		tokens = append(tokens, token)

		c.JSON(http.StatusOK, gin.H{
			"token": token,
		})
	})
	r.GET("/resource", func(c *gin.Context) {
		bearerToken := c.Request.Header.Get("Authorization")
		reqToken := strings.Split(bearerToken, " ")[1]
		claims := &Claims{}
		tkn, err := jwt.ParseWithClaims(reqToken, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				c.JSON(http.StatusUnauthorized, gin.H{
					"message": "unauthorized",
				})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "bad request",
			})
			return
		}
		if !tkn.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "unauthorized",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data": "resource data",
		})
	})
	r.Run()
}

func GenerateJWT() (string, error) {
	exprTime := time.Now().Add(5 * time.Minute)
	Claims := Claims{
		Username: "username",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(exprTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims)
	return token.SignedString(jwtKey)
}
