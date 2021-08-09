package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// Functions for querying and updating the OCSP responder database.

type revocationResult int

const (
	revoked revocationResult = iota
	unrevoked
	unchanged
)

func (r revocationResult) String() string {
	return [...]string{"revoked", "unrevoked", "unchanged"}[r]
}

// Get a map of all certs in OCSP database.
func readOCSP() (map[int64]*cert, error) {
	resp, err := http.Get(os.Getenv("OCSP_URL") + "/all")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, errors.New(string(body))
	}

	var body map[int64]*cert
	_, err = readJSON(resp.Body, &body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// Update the OCSP database, setting the specified cert's revocation time.
func update(serial int64, revoked time.Time) error {
	body, err := json.Marshal(struct {
		Serial  int64
		Revoked time.Time
	}{serial, revoked})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", os.Getenv("OCSP_URL")+"/update", bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// Attempt a revocation. Do not change anything if c is already revoked.
func revoke(serial int64) (revocationResult, error) {
	ocsp, err := readOCSP()
	if err != nil {
		return 0, fmt.Errorf("Error querying OCSP server: %s", err.Error())
	}

	if old, ok := ocsp[serial]; ok && !old.Revoked.IsZero() {
		return unchanged, nil
	}

	err = update(serial, time.Now().Truncate(time.Second).UTC())
	if err != nil {
		return 0, err
	}
	return revoked, nil
}

// Attempt an unrevocation. Do not change anything if c is not revoked.
func unrevoke(serial int64) (revocationResult, error) {
	ocsp, err := readOCSP()
	if err != nil {
		return 0, fmt.Errorf("Error querying OCSP server: %s", err.Error())
	}

	if old, ok := ocsp[serial]; ok && old.Revoked.IsZero() {
		return unchanged, nil
	}

	err = update(serial, time.Time{})
	if err != nil {
		return 0, err
	}
	return unrevoked, nil
}
