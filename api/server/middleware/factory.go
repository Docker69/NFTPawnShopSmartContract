package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Docker69/NFTPawnShopSmartContract/api/server/auth"

	"github.com/gin-gonic/gin"
)

const (
	AuthorizationHeaderKey  = "authorization"
	AuthorizationType       = "bearer"
	AuthorizationPayloadKey = "user"
)

func NewAuthMiddleware(tokenMaker auth.Maker) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authorizationHeader := ctx.GetHeader(AuthorizationHeaderKey)
		if authorizationHeader == "" {
			err := errors.New("authorization header is not provided")
			ctx.AbortWithError(http.StatusUnauthorized, err)
			return
		}
		fields := strings.Fields(authorizationHeader)
		if len(fields) != 2 {
			err := errors.New("invalid authorization header format")
			ctx.AbortWithError(http.StatusUnauthorized, err)
			return
		}
		authType := strings.ToLower(fields[0])
		if authType != AuthorizationType {
			err := fmt.Errorf("not support %v token type", authType)
			ctx.AbortWithError(http.StatusUnauthorized, err)
			return
		}
		accessToken := fields[1]
		payload, err := tokenMaker.VerifyToken(accessToken)
		if err != nil {
			err := errors.New("invalid token")
			ctx.AbortWithError(http.StatusUnauthorized, err)
			return
		}
		ctx.Set(AuthorizationPayloadKey, payload)
		ctx.Next()
	}
}
