package main

import (
	"net/http"
)

// Functions for querying and updating the OCSP responder database

func readOCSP() (map[int64]*cert, error) {
	resp, err := http.Get(OCSP_RESPONDER_URL + "/all")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var body map[int64]*cert
	_, err = readJSON(resp.Body, &body)
	if err != nil {
		return nil, err
	}
	return body, nil
}
