package double_tokens_go

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

type DoubleTokenInterface interface {
	SetSignedKeyAndIssuer(key []byte, issuer string)
	CreateToken(info []byte, refreshTTL, accessTTL int64) (string, string, error)
	CheckValid(token string) (bool, bool, error)
	DecodeToken(token string) ([]byte, error)
}

type DoubleToken struct {
	signedKey []byte
	issuer    string
}

type DTClaims struct {
	Info []byte
	jwt.StandardClaims
}

func DefaultDoubleToken() *DoubleToken {
	return &DoubleToken{
		signedKey: nil,
		issuer:    "",
	}
}

func KeyDoubleToken(key []byte, issuer string) *DoubleToken {
	return &DoubleToken{
		signedKey: key,
		issuer:    issuer,
	}
}

func (dt *DoubleToken) SetSignedKeyAndIssuer(key []byte, issuer string) {
	dt.signedKey = key
	dt.issuer = issuer
}

func (dt *DoubleToken) CreateToken(info []byte, refreshTTL, accessTTL int64) (string, string, error) {
	nowTime := time.Now()

	refreshClaims := DTClaims{
		Info: info,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: nowTime.Add(time.Duration(refreshTTL) * time.Second).Unix(),
			Issuer:    dt.issuer,
		},
	}
	accessClaims := DTClaims{
		Info: info,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: nowTime.Add(time.Duration(accessTTL) * time.Second).Unix(),
			Issuer:    dt.issuer,
		},
	}

	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(dt.signedKey)
	if err != nil {
		return "", "", err
	}
	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).SignedString(dt.signedKey)
	if err != nil {
		return "", "", err
	}

	return refreshToken, accessToken, nil
}

func (dt *DoubleToken) CheckValid(token string) (bool, bool, error) {
	tokenClaims, err := jwt.ParseWithClaims(token, &DTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return dt.signedKey, nil
	})
	if err != nil {
		return false, false, err
	}

	if tokenClaims == nil {
		return false, false, nil
	}

	claims, ok := tokenClaims.Claims.(*DTClaims)
	if !ok || !tokenClaims.Valid {
		return false, false, nil
	}

	if claims.StandardClaims.ExpiresAt < time.Now().Unix() {
		return true, false, nil
	}

	return true, true, nil
}

func (dt *DoubleToken) DecodeToken(token string) ([]byte, error) {
	tokenClaims, err := jwt.ParseWithClaims(token, &DTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return dt.signedKey, nil
	})
	if err != nil {
		return nil, err
	}

	if tokenClaims == nil {
		return nil, err
	}

	if claims, ok := tokenClaims.Claims.(*DTClaims); ok {
		return claims.Info, nil
	}

	return nil, err
}
