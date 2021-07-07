package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt"
)

type requestError struct {
	msg string
}

func (e requestError) Error() string {
	return fmt.Sprintf("Bad request: %s", e.msg)
}

type errHandler func(w http.ResponseWriter, r *http.Request) error

func (fn errHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := fn(w, r); err != nil {
		if _, ok := err.(requestError); ok {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (certs certs) toJSON() ([]byte, error) {
	json, err := json.Marshal(certs)
	if err != nil {
		return nil, err
	}
	return json, nil
}

// Read per_page and page query strings from q
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
		pageStr = os.Getenv("PAGE")
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

// Read filter query string from q
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
		return "", requestError{`JWT: "sub" claim missing`}
	}
	return claims.Subject, nil
}

func makeGETHandler(db *sql.DB, jwtKey *ecdsa.PublicKey) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != "GET" {
			return requestError{"Wrong method"}
		}
		w.Header().Set("Access-Control-Expose-Headers", "X-Total-Count")

		auth := r.Header.Get("Authorization")
		fmt.Println(auth)
		token := strings.Split(auth, " ")[1]
		user, err := jwtVerify(token, jwtKey)
		if err != nil {
			return err
		}
		fmt.Println("User", user)

		q := r.URL.Query()

		f := queryFilter(q)
		p, err := queryPagination(q)
		if err != nil {
			return requestError{"Invalid per_page or page"}
		}

		c, err := totalCount(db, f)
		if err != nil {
			return err
		}
		w.Header().Set("X-Total-Count", strconv.Itoa(c))

		// Query local database
		certs, err := readSigningLog(db, f, p)
		if err != nil {
			return err
		}

		// Query OCSP responder
		ocsp, err := readOCSP()
		if err != nil {
			return fmt.Errorf("Error querying OCSP server: %s", err.Error())
		}

		// Merge responses
		for _, c := range certs {
			if ocspEntry, ok := ocsp[c.Serial]; ok && !ocspEntry.Revoked.IsZero() {
				c.Revoked = ocspEntry.Revoked
			}
		}

		json, err := certs.toJSON()
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(json)
		return err
	}
}

// Read JSON from rc, populate struct pointed to by data
func readJSON(rc io.ReadCloser, data interface{}) (interface{}, error) {
	jsonData, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(jsonData, data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func makePUTHandler(db *sql.DB) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != "PUT" {
			return requestError{"Wrong method"}
		}

		// Parse request
		serialStr := path.Base(r.URL.Path)
		serial, err := strconv.ParseInt(serialStr, 10, 64)
		if err != nil {
			return requestError{"Bad URL"}
		}

		rBody := struct {
			Revoke bool
		}{}
		_, err = readJSON(r.Body, &rBody)

		// Push update to OCSP responder
		var status revocationResult
		if rBody.Revoke {
			status, err = revoke(serial)
		} else {
			status, err = unrevoke(serial)
		}
		if err != nil {
			return err
		}

		wBody := make(map[int64]string)
		wBody[serial] = status.String()
		json, err := json.Marshal(wBody)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(json)
		return err
	}
}

// Forwards a request to JWT issuer
func makeLoginHandler(db *sql.DB) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != "POST" {
			return requestError{"Wrong method"}
		}

		jwtReq, err := http.NewRequest("POST", os.Getenv("JWT_URL"), nil)
		if err != nil {
			return err
		}
		jwtReq.Header.Set("Authorization", r.Header.Get("Authorization"))

		// TODO: JWT dev server's certificate is not valid
		tr := http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		client := http.Client{Transport: &tr}

		jwtResp, err := client.Do(jwtReq)
		if err != nil {
			return err
		}
		defer jwtResp.Body.Close()

		switch jwtResp.StatusCode {
		case http.StatusUnauthorized:
			w.WriteHeader(jwtResp.StatusCode)
			return nil
		case http.StatusOK:
			json, err := io.ReadAll(jwtResp.Body)
			if err != nil {
				return err
			}
			w.Header().Set("Content-Type", "application/json")
			_, err = w.Write(json)
			return err
		default:
			return fmt.Errorf("JWT error: %v", jwtResp.Status)
		}
	}
}
