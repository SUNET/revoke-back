package main

import (
	"database/sql"
	"log"
	"net/http"
	"os/exec"

	_ "github.com/mattn/go-sqlite3"
)

const (
	layoutISO          = "2006-01-02"
	layoutOSSL         = "060102150405Z"
	OSSL_INDEX         = "index.txt"
	PER_PAGE           = 50
	PAGE               = 1
	OCSP_RESPONDER_URL = "http://localhost:8889"
)

func main() {
	db, err := sql.Open("sqlite3", "./letswifi-dev.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	go func() {
		http.Handle("/api/v0/noauth", makeGETHandler(db))
		http.Handle("/api/v0/noauth/", makePUTHandler(db))
		log.Fatal(http.ListenAndServe("localhost:8888", nil))
	}()

	exec.Command("reload-localhost").Run() // TODO: For development
	select {}
}
