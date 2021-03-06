package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/ernstwi/revoke-ocsp/ocsp"
	"github.com/steinfletcher/apitest"
	jsonpath "github.com/steinfletcher/apitest-jsonpath"
)

var db *sql.DB

func setup() {
	_, err := db.Exec(`
		DROP TABLE IF EXISTS "realm_signing_log";

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

		INSERT INTO realm_signing_log VALUES
			(
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
			),
			(
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

		DROP TABLE IF EXISTS "revoked";

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
}

func TestMain(m *testing.M) {
	loadEnv()
	assertEnv("PER_PAGE", "TEST_OCSP_PORT")

	var err error
	db, err = sql.Open("sqlite3", ":memory:") // In-memory database
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	http.Handle("/update", ocsp.MakeUpdateHandler(db))
	http.Handle("/init", ocsp.MakeInitHandler(db))
	http.Handle("/all", ocsp.MakeAllHandler(db))

	err = os.Setenv("OCSP_URL", fmt.Sprintf("http://localhost:%s", os.Getenv("TEST_OCSP_PORT")))
	if err != nil {
		log.Fatal(err)
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%s", os.Getenv("TEST_OCSP_PORT")))
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		log.Fatal(http.Serve(l, nil))
	}()

	os.Exit(m.Run())
}

func TestGET(t *testing.T) {
	setup()
	t.Run("No query strings", func(r *testing.T) {
		apitest.New().
			Handler(apiGet(db)).
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
	})
	t.Run("Filter by subject", func(r *testing.T) {
		apitest.New().
			Handler(apiGet(db)).
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
	})
	t.Run("Empty results", func(r *testing.T) {
		apitest.New().
			Handler(apiGet(db)).
			Get("/api/v0/noauth").
			Query("filter[subject]", "xyz").
			Expect(t).
			Body(`[]`).
			Status(http.StatusOK).
			End()
	})
}

func TestPUT(t *testing.T) {
	setup()
	t.Run("Revoke #1", func(t *testing.T) {
		apitest.New().
			Handler(apiUpdate(db)).
			Put("/api/v0/noauth/1").
			Body(`{ "revoke": true }`).
			Expect(t).
			Status(http.StatusOK).
			End()
	})
	t.Run("Confirm #1 is revoked", func(r *testing.T) {
		apitest.New().
			Handler(apiGet(db)).
			Get("/api/v0/noauth").
			Expect(t).
			Assert(jsonpath.NotEqual("$[0].revoked", nil)).
			Status(http.StatusOK).
			End()
	})
	t.Run("Unrevoke #1", func(t *testing.T) {
		apitest.New().
			Handler(apiUpdate(db)).
			Put("/api/v0/noauth/1").
			Body(`{ "revoke": false }`).
			Expect(t).
			Status(http.StatusOK).
			End()
	})
	t.Run("Confirm #1 is unrevoked", func(r *testing.T) {
		apitest.New().
			Handler(apiGet(db)).
			Get("/api/v0/noauth").
			Expect(t).
			Assert(jsonpath.Equal("$[0].revoked", nil)).
			Status(http.StatusOK).
			End()
	})
}
