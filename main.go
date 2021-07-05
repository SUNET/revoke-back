package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"

	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
)

var REQUIRED_ENV_VARS = [...]string{
	"OCSP_RESPONDER_URL",
	"PAGE",
	"PER_PAGE",
}

func loadEnv() {
	err := godotenv.Overload("default.env", "custom.env")
	if err != nil {
		log.Fatal(err)
	}

	for _, x := range REQUIRED_ENV_VARS {
		if _, ok := os.LookupEnv(x); !ok {
			log.Fatal(fmt.Errorf("Environment variable %s not defined", x))
		}
	}
}

func main() {
	loadEnv()

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
