/*
API specification

	URL: http://localhost:8888/api/v0/noauth
	Method: GET
	Body: None
	Response body: Array of certs (all)
	Side effect: None

	URL: http://localhost:8888/api/v0/noauth/<SERIAL>
	Method: PUT
	Body: {
		revoke: true OR false
	}
	Response body: {
		<SERIAL>: "revoked" OR "unrevoked" OR "unchanged"
	}
	Side effect: Revoke cert <SERIAL>
*/
package main

import (
	"database/sql"
	"log"
	"net/http"
	"os/exec"

	_ "github.com/mattn/go-sqlite3"
)

const (
	layoutISO  = "2006-01-02"
	layoutOSSL = "060102150405Z"
	OSSL_INDEX = "index.txt"
)

func main() {
	db, err := sql.Open("sqlite3", "./letswifi-dev.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	certs, err := readSigningLog(db)
	if err != nil {
		log.Fatal(err)
	}

	err = certs.writeOCSPIndex()
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		http.Handle("/api/v0/noauth", makeGETHandler(db))
		http.Handle("/api/v0/noauth/", makePUTHandler(db))
		log.Fatal(http.ListenAndServe("localhost:8888", nil))
	}()

	exec.Command("reload-localhost").Run() // TODO: For development
	select {}
}
