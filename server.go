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
		w.Header().Set("Access-Control-Expose-Headers", "X-Total-Count")

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

// Read JSON from rc, populate struct pointed to by data
func readJSON(rc io.ReadCloser, data interface{}) (interface{}, error) {
	jsonData, err := io.ReadAll(rc)
	if err != nil {
		return nil, requestError{"Bad body"}
	}

	err = json.Unmarshal(jsonData, data)
	if err != nil {
		return nil, requestError{"Bad body"}
	}

	return data, nil
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

		rBody := struct {
			Revoke bool
		}{}
		_, err = readJSON(r.Body, &rBody)

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
