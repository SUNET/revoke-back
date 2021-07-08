package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"

	"github.com/golang-jwt/jwt"
)

func (certs certs) toJSON() ([]byte, error) {
	json, err := json.Marshal(certs)
	if err != nil {
		return nil, err
	}
	return json, nil
}

// Read `per_page` and `page` query strings from q.
func queryPagination(q url.Values) (*pagination, error) {
	perPageStr := q.Get("per_page")
	pageStr := q.Get("page")

	if perPageStr == "" && pageStr == "" {
		return nil, nil
	}

	if perPageStr == "" {
		perPageStr = os.Getenv("PER_PAGE")
	}

	if pageStr == "" {
		pageStr = "1"
	}

	perPage, err := strconv.Atoi(perPageStr)
	if err != nil {
		return nil, err
	}

	page, err := strconv.Atoi(pageStr)
	if err != nil {
		return nil, err
	}

	return &pagination{perPage, page}, nil
}

// Read `filter` query string from q.
func queryFilter(q url.Values) *filter {
	filterFields := map[string]string{
		"subject": "sub",
	}
	for apiKey, dbKey := range filterFields {
		if v := q.Get(fmt.Sprintf("filter[%s]", apiKey)); v != "" {
			return &filter{dbKey, v}
		}
	}
	return nil
}

func jwtVerify(tokenString string, key *ecdsa.PublicKey) (username string, err error) {
	token, err := jwt.ParseWithClaims(tokenString, new(jwt.StandardClaims), func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(*jwt.StandardClaims)
	if !ok {
		return "", errors.New(`JWT: Error reading claims`)
	}
	if claims.Subject == "" {
		return "", requestError(`JWT: "sub" claim missing`)
	}
	return claims.Subject, nil
}
