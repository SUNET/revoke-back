package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/steinfletcher/apitest"
)

var db *sql.DB

func TestMain(m *testing.M) {
	var err error
	db, err = sql.Open("sqlite3", ":memory:") // In-memory database
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`
		CREATE TABLE realm_signing_log (
			serial INTEGER NOT NULL PRIMARY KEY,
			realm TEXT NOT NULL,
			ca_sub TEXT NOT NULL,
			requester TEXT NOT NULL,
			sub TEXT NOT NULL,
			issued TEXT NOT NULL,
			expires TEXT NOT NULL,
			csr TEXT NOT NULL,
			x509 TEXT,
			revoked TEXT,
			usage TEXT NOT NULL
		);
		INSERT INTO realm_signing_log VALUES (
			1,
			"realm_1",
			"ca_sub_1",
			"requester_1",
			"sub_1",
			"2020-06-23",
			"2021-06-23",
			"csr_1",
			"x509_1",
			NULL,
			"usage_1"
		);
		INSERT INTO realm_signing_log VALUES (
			2,
			"realm_2",
			"ca_sub_2",
			"requester_2",
			"sub_2",
			"2020-06-23",
			"2022-06-23",
			"csr_2",
			"x509_2",
			NULL,
			"usage_2"
		);
	`)
	if err != nil {
		log.Fatal(err)
	}

	os.Exit(m.Run())
}

func TestGET(t *testing.T) {
	apitest.New().
		Handler(makeGETHandler(db)).
		Get("/api/v0/noauth").
		Expect(t).
		Body(`[
			{
				"serial": 1,
				"realm": "realm_1",
				"ca": "ca_sub_1",
				"requester": "requester_1",
				"subject": "sub_1",
				"issued": "2020-06-23",
				"expires": "2021-06-23",
				"revoked": false,
				"revoked_at": "",
				"usage": "usage_1"
			},
			{
				"serial": 2,
				"realm": "realm_2",
				"ca": "ca_sub_2",
				"requester": "requester_2",
				"subject": "sub_2",
				"issued": "2020-06-23",
				"expires": "2022-06-23",
				"revoked": false,
				"revoked_at": "",
				"usage": "usage_2"
			}
		]`).
		Status(http.StatusOK).
		End()
}

func TestGETFilterSubject(t *testing.T) {
	apitest.New().
		Handler(makeGETHandler(db)).
		Get("/api/v0/noauth").
		Query("filter[subject]", "1").
		Expect(t).
		Body(`[
			{
				"serial": 1,
				"realm": "realm_1",
				"ca": "ca_sub_1",
				"requester": "requester_1",
				"subject": "sub_1",
				"issued": "2020-06-23",
				"expires": "2021-06-23",
				"revoked": false,
				"revoked_at": "",
				"usage": "usage_1"
			}
		]`).
		Status(http.StatusOK).
		End()
}
