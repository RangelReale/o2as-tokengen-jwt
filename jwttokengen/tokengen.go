package jwttokengen

import (
	"o2aserver"
	"time"
	jwt "github.com/dgrijalva/jwt-go"
	"encoding/base64"
	"code.google.com/p/go-uuid/uuid"
	"errors"
)

type TokenGenJWT struct {
	PrivateKey []byte
	PublicKey []byte
}

func NewTokenGenJWT(privatekey []byte, publickey []byte) *TokenGenJWT {
	return &TokenGenJWT{
		PrivateKey: privatekey,
		PublicKey: publickey,
	}
}

func (c *TokenGenJWT) GenerateAccessToken(data *o2aserver.AccessTokenData) error {
	// generate JWT access token
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	token.Claims["userid"] = data.UserId
	token.Claims["exp"] = data.CreatedAt.Add(time.Second * time.Duration(data.ExpiresIn)).Unix()

	tokenString, err := token.SignedString(c.PrivateKey)
	if err != nil {
		return err
	}

	data.AccessToken = tokenString

	// generate random refresh token
	data.RefreshToken = uuid.New()
	data.RefreshToken = base64.StdEncoding.EncodeToString([]byte(data.RefreshToken))

	return nil
}

func (c *TokenGenJWT) ParseAccessToken(data string) (interface{}, error) {

	dtoken, err := jwt.Parse(data, func(token *jwt.Token)([]byte, error) {
		return c.PublicKey, nil
	})

	if err != nil {
		return nil, err
	}
	if !dtoken.Valid {
		return nil, errors.New("Invalid token")
	}

	return dtoken, nil
}
