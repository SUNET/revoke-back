package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/ernstwi/ocsp-responder/ocsp"
	"github.com/steinfletcher/apitest"
)

const (
	CA_CERT        = "test-data/ca.pem"
	RESPONDER_CERT = "test-data/responder.pem"
	RESPONDER_KEY  = "test-data/responder_key.pem"
	OCSP_PORT      = 8889
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

		CREATE TABLE "revoked" (
			"serial" INTEGER NOT NULL PRIMARY KEY,
			"revoked" DATE NOT NULL
		);

		INSERT INTO "revoked" VALUES
			(1, "0001-01-01T00:00:00Z"),
			(2, "2019-10-12T07:20:50Z");
	`)
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/update", ocsp.MakeUpdateHandler(db))
	http.Handle("/init", ocsp.MakeInitHandler(db))
	http.Handle("/all", ocsp.MakeAllHandler(db))

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", OCSP_PORT))
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		log.Fatal(http.Serve(l, nil))
	}()

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
				"requester": "requester_1",
				"subject": "sub_1",
				"issued": "2020-06-23T00:00:00Z",
				"expires": "2021-06-23T00:00:00Z",
				"revoked": null
			},
			{
				"serial": 2,
				"requester": "requester_2",
				"subject": "sub_2",
				"issued": "2020-06-23T00:00:00Z",
				"expires": "2022-06-23T00:00:00Z",
				"revoked": "2019-10-12T07:20:50Z"
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
				"requester": "requester_1",
				"subject": "sub_1",
				"issued": "2020-06-23T00:00:00Z",
				"expires": "2021-06-23T00:00:00Z",
				"revoked": null
			}
		]`).
		Status(http.StatusOK).
		End()
}
