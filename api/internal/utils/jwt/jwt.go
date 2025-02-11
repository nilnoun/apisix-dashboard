package jwt

import (
	"errors"
	"github.com/golang-jwt/jwt"
	"time"
)

type Userinfo struct {
	Name   string `json:"name"`
	UserId string `json:"user_id"`
	Avatar string `json:"avatar"`
}

type Claims struct {
	*jwt.StandardClaims
	*Userinfo
}

func GenToken(userinfo *Userinfo, jwtExpire int, secret string, issuer string) (string, error) {
	claims := Claims{
		Userinfo: userinfo,
		StandardClaims: &jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Duration(jwtExpire) * time.Second).Unix(),
			Issuer:    issuer,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func ParseToken(tokenString string, secret string) (*Claims, error) {
	var claims = new(Claims)
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (i interface{}, err error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}
