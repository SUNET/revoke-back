package main

import (
	"encoding/json"
	"io"
	"time"
)

type filter struct {
	field string
	value string
}

type pagination struct {
	perPage int
	page    int
}

type cert struct {
	Serial    int64      `json:"serial"`
	Requester string     `json:"requester"`
	Subject   string     `json:"subject"`
	Issued    time.Time  `json:"issued"`
	Expires   time.Time  `json:"expires"`
	Revoked   *time.Time `json:"revoked"`
}

type certs []*cert

// Read JSON from rc, populate struct pointed to by data.
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
