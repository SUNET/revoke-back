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

var REQUIRED_ENV_VARS = []string{
	"JWT_URL",
	"OCSP_RESPONDER_URL",
	"PAGE",
	"PER_PAGE",
}

func loadEnv() {
	godotenv.Overload("default.env", "custom.env")
}

func assertEnv(required ...string) {
	for _, v := range required {
		if _, ok := os.LookupEnv(v); !ok {
			log.Fatal(fmt.Errorf("Environment variable %s not defined", v))
		}
	}
}

func main() {
	loadEnv()
	assertEnv(REQUIRED_ENV_VARS...)

	db, err := sql.Open("sqlite3", "./letswifi-dev.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	go func() {
		http.Handle("/api/v0/noauth", makeGETHandler(db))
		http.Handle("/api/v0/noauth/", makePUTHandler(db))
		http.Handle("/api/v0/login", makeLoginHandler(db))
		log.Fatal(http.ListenAndServe("localhost:8888", nil))
	}()

	exec.Command("reload-localhost").Run() // TODO: For development
	select {}
}
