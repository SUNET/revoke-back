package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
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
	if err := fn(w, r); err != nil {
		if _, ok := err.(requestError); ok {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (certs certs) toJSON() ([]byte, error) {
	// TODO: Some of these fields are unused
	type jsonCert struct {
		Serial    int    `json:"serial"`
		Realm     string `json:"realm"`
		CA_sub    string `json:"ca"`
		Requester string `json:"requester"`
		Sub       string `json:"subject"`
		Issued    string `json:"issued"`
		Expires   string `json:"expires"`
		Revoked   bool   `json:"revoked"`
		RevokedAt string `json:"revoked_at"`
		Usage     string `json:"usage"`
	}

	jsonData := make([]*jsonCert, 0, len(certs))
	for _, c := range certs {
		j := jsonCert{
			Serial:    c.serial,
			Realm:     c.realm,
			CA_sub:    c.ca_sub,
			Requester: c.requester,
			Sub:       c.sub,
			Issued:    c.issued,
			Expires:   c.expires,
			Usage:     c.usage,
		}
		if c.revoked.Valid {
			j.Revoked = true
			j.RevokedAt = c.revoked.String
		} else {
			j.Revoked = false
		}
		jsonData = append(jsonData, &j)
	}

	json, err := json.Marshal(jsonData)
	if err != nil {
		return nil, err
	}

	return json, nil
}

// Read per_page and page query strings from q
func queryPagination(q url.Values) (*pagination, error) {
	perPageStr := q.Get("per_page")
	pageStr := q.Get("page")

	var perPage, page int

	if perPageStr == "" && pageStr == "" {
		return nil, nil
	}

	if perPageStr == "" {
		perPage = PER_PAGE
	} else {
		var err error
		perPage, err = strconv.Atoi(perPageStr)
		if err != nil {
			return nil, err
		}
	}

	if pageStr == "" {
		page = PAGE
	} else {
		var err error
		page, err = strconv.Atoi(pageStr)
		if err != nil {
			return nil, err
		}
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

func makeGETHandler(db *sql.DB) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != "GET" {
			return requestError{"Wrong method"}
		}
		w.Header().Set("Content-Type", "application/json")

		q := r.URL.Query()

		f := queryFilter(q)
		p, err := queryPagination(q)
		if err != nil {
			return requestError{"Invalid per_page or page"}
		}

		certs, err := readSigningLog(db, f, p)
		if err != nil {
			return err
		}
		json, err := certs.toJSON()
		if err != nil {
			return err
		}
		_, err = w.Write(json)
		return err
	}
}

func makePUTHandler(db *sql.DB) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		switch r.Method {
		case "OPTIONS":
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT")
			w.WriteHeader(http.StatusNoContent)
			return nil
		case "PUT":
			w.Header().Set("Content-Type", "application/json")
		default:
			return requestError{"Wrong method"}
		}

		serialStr := path.Base(r.URL.Path)
		serial, err := strconv.Atoi(serialStr)
		if err != nil {
			return requestError{"Bad URL"}
		}

		rBodyJson, err := io.ReadAll(r.Body)
		if err != nil {
			return requestError{"Bad body"}
		}

		rBody := struct {
			Revoke bool
		}{}
		err = json.Unmarshal(rBodyJson, &rBody)
		if err != nil {
			return requestError{"Bad body"}
		}

		var action dbAction
		if rBody.Revoke {
			action = revoke
		} else {
			action = unrevoke
		}

		status, err := modify(serial, action, db)
		if err != nil {
			return err
		}

		wBody := make(map[int]string)
		wBody[serial] = status
		json, err := json.Marshal(wBody)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(json)
		return err
	}
}
