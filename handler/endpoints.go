package handler

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
)

// This is just a test endpoint to get you started. Please delete this endpoint.
// (GET /hello)
// func (s *Server) Hello(ctx echo.Context, params generated.HelloParams) error {

//		var resp generated.HelloResponse
//		resp.Message = fmt.Sprintf("Hello User %d", params.Id)
//		return ctx.JSON(http.StatusOK, resp)
//	}
// const (
// 	jwtSecretKey = "secret-jwt"
// )

func (s *Server) Login(ctx echo.Context) error {
	userLogin := new(LoginRequest)

	if err := ctx.Bind(userLogin); err != nil {
		return ctx.JSON(http.StatusBadRequest, err.Error())
	}

	user, userErr := s.Repository.FindUserByPhoneNumber(ctx.Request().Context(), userLogin.PhoneNumber)
	if userErr != nil {
		err := errors.New("credential does not match phone number or password")
		return ctx.JSON(http.StatusBadRequest, err.Error())
	}

	userId := fmt.Sprintf("%v", user["userId"])
	passwordHash := fmt.Sprintf("%v", user["password"])

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(userLogin.Password)); err != nil {
		passHashErr := errors.New("credential does not match phone number or password")
		return ctx.JSON(http.StatusBadRequest, passHashErr.Error())
	}

	jwtPrivateSecret, jwtPrivateSecretErr := jwt.ParseRSAPrivateKeyFromPEM([]byte(key))
	if jwtPrivateSecretErr != nil {
		return ctx.JSON(http.StatusBadRequest, jwtPrivateSecretErr.Error())
	}

	_, jwtPublicSecretErr := jwt.ParseRSAPublicKeyFromPEM([]byte(Pubkey))
	if jwtPublicSecretErr != nil {
		return ctx.JSON(http.StatusBadRequest, jwtPublicSecretErr.Error())

	}

	claims := &jwt.RegisteredClaims{
		ID:        userId,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	token, tokenErr := jwtToken.SignedString(jwtPrivateSecret)

	if tokenErr != nil {
		return ctx.JSON(http.StatusBadRequest, tokenErr.Error())
	}

	result := map[string]interface{}{
		"accessToken": token,
	}

	return ctx.JSON(http.StatusOK, result)
}

func (s *Server) Register(ctx echo.Context) error {
	user := new(RegisterRequest)
	if err := ctx.Bind(user); err != nil {
		return ctx.JSON(http.StatusBadRequest, err.Error())
	}

	if err := s.validatedRegister(user); err != nil {
		return ctx.JSON(http.StatusBadRequest, err.Error())
	}

	if err := s.verifyPasswordStrengths(user.Password); err != nil {
		return ctx.JSON(http.StatusBadRequest, err.Error())
	}

	hashPass, hashPassErr := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if hashPassErr != nil {
		return ctx.JSON(http.StatusBadRequest, hashPassErr.Error())
	}

	if user.PhoneNumber[0:2] != "62" {
		return ctx.JSON(http.StatusBadRequest, "format phone number must 62878xxxx")
	}

	cmd := make(map[string]string)
	cmd["phoneNumber"] = user.PhoneNumber
	cmd["fullName"] = user.FullName
	cmd["password"] = string(hashPass)

	userId, userErr := s.Repository.CreateUser(ctx.Request().Context(), cmd)
	if userErr != nil {
		return ctx.JSON(http.StatusBadRequest, userErr.Error())
	}

	result := map[string]interface{}{
		"userId": userId,
	}

	return ctx.JSON(http.StatusOK, result)
}

func (s *Server) Profile(ctx echo.Context) error {
	curenUserLogged := ctx.Get("currentUser")
	if curenUserLogged == nil {
		return ctx.JSON(http.StatusForbidden, "forbidden page")
	}

	result := map[string]interface{}{
		"data": curenUserLogged,
	}

	return ctx.JSON(http.StatusOK, result)
}

func (s *Server) UpdateUser(ctx echo.Context) error {
	currentUserLogged := ctx.Get("currentUser")
	if currentUserLogged == nil {
		return ctx.JSON(http.StatusForbidden, "forbidden page")
	}

	userUpdate := new(UpdateRequest)
	if err := ctx.Bind(userUpdate); err != nil {
		return ctx.JSON(http.StatusBadRequest, err.Error())
	}

	if err := s.validateUpdate(userUpdate); err != nil {
		return ctx.JSON(http.StatusBadRequest, err.Error())
	}

	if userUpdate.PhoneNumber[0:2] != "62" {
		return ctx.JSON(http.StatusBadRequest, "format phone number must 62878xxxx")
	}

	userId := fmt.Sprintf("%v", currentUserLogged.(map[string]interface{})["userId"])
	cmd := make(map[string]string)
	cmd["phoneNumber"] = userUpdate.PhoneNumber
	cmd["fullName"] = userUpdate.FullName
	cmd["userId"] = userId

	updUser, updUserErr := s.Repository.UpdateUser(cmd)
	if updUserErr != nil {
		if strings.Contains(updUserErr.Error(), "duplicate key value violates unique constraint") {
			err := errors.New("phone number already exists")
			return ctx.JSON(http.StatusConflict, err.Error())
		}
		return ctx.JSON(http.StatusBadRequest, updUserErr.Error())
	}

	msg := fmt.Sprintf("success updated with id : %s", strconv.Itoa(updUser))

	response := map[string]interface{}{
		"data": msg,
	}
	return ctx.JSON(http.StatusOK, response)
}

func (s *Server) verifyPasswordStrengths(pass string) (err error) {
	var capital int
	var number int
	var nonCharacter int

	passwordRune := []rune(pass)
	for i := 0; i < len(passwordRune); i++ {
		switch {
		case unicode.IsUpper(passwordRune[i]):
			capital++
		case unicode.IsNumber(passwordRune[i]):
			number++
		case unicode.IsPunct(passwordRune[i]) || unicode.IsSymbol(passwordRune[i]):
			nonCharacter++
		case unicode.IsSpace(passwordRune[i]):
			err = errors.New("password cannot use space")
			return
		}
	}

	if capital == 0 || number == 0 || nonCharacter == 0 {
		err = errors.New("password must capital, numeric, non alphanumeric (minimum each one of character)")
		return
	}

	return
}

func (s *Server) validateUpdate(request *UpdateRequest) (err error) {
	validate := validator.New()
	if err = validate.Struct(request); err != nil {
		for _, errMsg := range err.(validator.ValidationErrors) {
			switch errMsg.StructField() {
			case "PhoneNumber":
				err = errors.New(errMsg.Error())
				return
			case "FullName":
				err = errors.New(errMsg.Error())
				return
			}
		}
		return
	}
	return
}

func (s *Server) validatedRegister(request *RegisterRequest) (err error) {
	validate := validator.New()
	if err = validate.Struct(request); err != nil {
		for _, errMsg := range err.(validator.ValidationErrors) {
			switch errMsg.StructField() {
			case "PhoneNumber":
				err = errors.New(errMsg.Error())
				return
			case "FullName":
				err = errors.New(errMsg.Error())
				return
			case "Password":
				err = errors.New(errMsg.Error())
				return
			}
		}
		return
	}

	return
}
