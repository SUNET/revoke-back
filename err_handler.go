package main

import (
	"fmt"
	"net/http"
)

type requestError string
type authError string

func (e requestError) Error() string {
	if e == "" {
		return "Bad request"
	}
	return fmt.Sprintf("Bad request: %s", string(e))
}

func (e authError) Error() string {
	if e == "" {
		return "Authorization error"
	}
	return fmt.Sprintf("Authorization error: %s", string(e))
}

type errHandler func(w http.ResponseWriter, r *http.Request) error

func (fn errHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := fn(w, r); err != nil {
		switch err.(type) {
		case authError:
			http.Error(w, err.Error(), http.StatusUnauthorized)
		case requestError:
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
