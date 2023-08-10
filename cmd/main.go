package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/SawitProRecruitment/UserService/handler"
	"github.com/SawitProRecruitment/UserService/repository"
	"github.com/golang-jwt/jwt/v5"

	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()
	// var server generated.ServerInterface = newServer()
	// generated.RegisterHandlers(e, server)

	e.POST("/register", newServer().Register)
	e.POST("/login", newServer().Login)
	// authentication
	auth := e.Group("/auth")
	auth.Use(middlewareAuth)
	auth.GET("/profile", newServer().Profile)
	auth.PUT("/user/update", newServer().UpdateUser)
	e.Logger.Fatal(e.Start(":1323"))
}

func newServer() *handler.Server {
	dbDsn := os.Getenv("DATABASE_URL")
	var repo repository.RepositoryInterface = repository.NewRepository(repository.NewRepositoryOptions{
		Dsn: dbDsn,
	})
	opts := handler.NewServerOptions{
		Repository: repo,
	}
	return handler.NewServer(opts)
}

func middlewareAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")
		if !strings.Contains(authHeader, "Bearer") {
			return c.JSON(http.StatusUnauthorized, "Unauthorized, token parse with bearer")
		}

		tokenString := ""
		tokenSplit := strings.Split(authHeader, " ")
		if len(tokenSplit) == 2 {
			tokenString = tokenSplit[1]
		}

		rsaPubKey, rsaPubKeyErr := jwt.ParseRSAPublicKeyFromPEM([]byte(handler.Pubkey))
		if rsaPubKeyErr != nil {
			return c.JSON(http.StatusUnauthorized, rsaPubKeyErr.Error())
		}

		jwtParse, jwtParseErr := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected method: %s", t.Header["alg"])
			}
			return rsaPubKey, nil
		})

		if jwtParseErr != nil {
			return c.JSON(http.StatusUnauthorized, jwtParseErr.Error())
		}

		claim, ok := jwtParse.Claims.(jwt.MapClaims)
		if !ok || !jwtParse.Valid {
			return c.JSON(http.StatusUnauthorized, "request claim invalid")
		}

		userId := claim["jti"].(string)
		result, resultErr := newServer().Repository.FindUserByUserId(c.Request().Context(), userId)

		if resultErr != nil {
			return c.JSON(http.StatusUnauthorized, "Unauthorized")
		}

		c.Set("currentUser", result)
		return next(c)

	}
}
