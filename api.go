package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
)

func headerMiddleware(next errHandler) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS, POST, PUT")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return nil
		}

		return next(w, r)
	}
}

func authMiddleware(jwtKey *ecdsa.PublicKey, next errHandler) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			return requestError("Missing Authorization header")
		}
		split := strings.Split(auth, " ")
		if len(split) < 2 || split[0] != "Bearer" {
			return requestError("Malformed Authorization header")
		}
		token := split[1]

		user, err := jwtVerify(token, jwtKey)
		if err != nil {
			return err
		}

		if user != os.Getenv("JWT_USER") {
			return authError("Wrong username")
		}

		return next(w, r)
	}
}

func apiGet(db *sql.DB) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != "GET" {
			return requestError("Wrong method")
		}
		w.Header().Set("Access-Control-Expose-Headers", "X-Total-Count")

		q := r.URL.Query()

		f := queryFilter(q)
		p, err := queryPagination(q)
		if err != nil {
			return requestError("Invalid per_page or page")
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

func apiUpdate(db *sql.DB) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != "PUT" {
			return requestError("Wrong method")
		}

		// Parse request
		serialStr := path.Base(r.URL.Path)
		serial, err := strconv.ParseInt(serialStr, 10, 64)
		if err != nil {
			return requestError("Bad URL")
		}

		rBody := struct {
			Revoke bool
		}{}
		_, err = readJSON(r.Body, &rBody)
		if err != nil {
			return err
		}

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

// Forwards a request to JWT issuer.
func apiLogin(db *sql.DB) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != "POST" {
			return requestError("Wrong method")
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
			return authError("Unrecognized username or password")
		case http.StatusOK:
			json, err := io.ReadAll(jwtResp.Body)
			if err != nil {
				return err
			}
			w.Header().Set("Content-Type", "application/json")
			_, err = w.Write(json)
			return err
		default:
			return fmt.Errorf("JWT server error: %v", jwtResp.Status)
		}
	}
}
