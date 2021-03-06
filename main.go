package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	_ "github.com/mattn/go-sqlite3"
)

var REQUIRED_ENV_VARS = []string{
	"JWT_PUBLIC_KEY",
	"JWT_URL",
	"JWT_USER",
	"OCSP_URL",
	"PER_PAGE",
	"PORT",
}

func loadEnv() {
	godotenv.Load("default.env")
	godotenv.Overload("custom.env")
}

func assertEnv(required ...string) {
	for _, v := range required {
		if _, ok := os.LookupEnv(v); !ok {
			log.Fatal(fmt.Errorf("Environment variable %s not defined", v))
		}
	}
}

func readJWTPublicKey() (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(os.Getenv("JWT_PUBLIC_KEY"))
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(data))
	genericKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if key, ok := genericKey.(*ecdsa.PublicKey); ok {
		return key, nil
	}
	return nil, errors.New("Unexpected type, not ECDSA")
}

func main() {
	loadEnv()
	assertEnv(REQUIRED_ENV_VARS...)

	db, err := sql.Open("sqlite3", "./letswifi-dev.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	jwtKey, err := readJWTPublicKey()
	if err != nil {
		log.Fatal(fmt.Errorf("Problem reading JWT public key: %v", err))
	}

	http.Handle("/api/v0/auth",
		headerMiddleware(
			authMiddleware(jwtKey,
				apiGet(db))))
	http.Handle("/api/v0/auth/",
		headerMiddleware(
			authMiddleware(jwtKey,
				apiUpdate(db))))
	log.Fatal(http.ListenAndServe(":"+os.Getenv("PORT"), nil))
}
