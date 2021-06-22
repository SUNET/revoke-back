/*
API specification

	URL: http://localhost:8888/api/v1.0/noauth/
	Method: GET
	Body: None
	Response body: Array of certs (all)
	Side effect: None

	URL: http://localhost:8888/api/v1.0/noauth/$SERIAL
	Method: PUT
	Body: None
	Response body: {
		$SERIAL: "revoked" OR "unchanged"
	}
	Side effect: Revoke cert $SERIAL
*/
package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	layoutISO  = "2006-01-02"
	layoutOSSL = "060102150405Z"
	OSSL_INDEX = "index.txt"
)

// Internal server error
func checkInternal(err error, w http.ResponseWriter) bool {
	if err != nil {
		log.Print(err)
		if w != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
		return true
	}
	return false
}

// Fatal internal server error
func checkFatal(err error, w http.ResponseWriter) {
	if err != nil {
		log.Fatal(err)
		if w != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

// Bad request
func checkRequest(err error, w http.ResponseWriter) bool {
	if err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusBadRequest)
		return true
	}
	return false
}

// Corresponding 1:1 to realm_signing_log
type cert struct {
	serial      int
	realm       string
	ca_sub      string
	requester   string
	sub         string
	issued      string
	expires     string
	expiresTime time.Time
	csr         string
	x509        sql.NullString
	revoked     sql.NullString
	revokedTime time.Time
	usage       string
}

type certs []*cert

type jsonCert struct {
	Serial    int    `json:"serial"`
	Realm     string `json:"realm"`
	CA_sub    string `json:"ca"`
	Requester string `json:"requester"`
	Sub       string `json:"subject"`
	Issued    string `json:"issued"`
	Expires   string `json:"expires"`
	Revoked   bool   `json:"revoked"`
	RevokedAt string `json:"revoked_at"`
	Usage     string `json:"usage"`
}

func readSigningLog(db *sql.DB, w http.ResponseWriter) certs {
	rows, err := db.Query("select * from realm_signing_log")
	checkFatal(err, w)
	defer rows.Close()

	var res []*cert
	for rows.Next() {
		i := cert{}
		err = rows.Scan(
			&i.serial,
			&i.realm,
			&i.ca_sub,
			&i.requester,
			&i.sub,
			&i.issued,
			&i.expires,
			&i.csr,
			&i.x509,
			&i.revoked,
			&i.usage,
		)
		checkFatal(err, w)

		// TODO: Issued and expiration time is currently read (and output to
		// OpenSSL) as midnight UTC. Exact time is defined in the certificate,
		// but not in the database. Could read from certificate, but certificate
		// is nullable in database.
		i.expiresTime, err = time.Parse(layoutISO, i.expires)
		checkFatal(err, w)
		if i.revoked.Valid {
			i.revokedTime, err = time.Parse(layoutISO, i.revoked.String)
			checkFatal(err, w)
		}

		res = append(res, &i)
	}
	checkFatal(rows.Err(), w)

	return res
}

func (certs certs) toJSON() []byte {
	jsonData := make([]*jsonCert, 0, len(certs))
	for _, c := range certs {
		j := jsonCert{
			Serial:    c.serial,
			Realm:     c.realm,
			CA_sub:    c.ca_sub,
			Requester: c.requester,
			Sub:       c.sub,
			Issued:    c.issued,
			Expires:   c.expires,
			Usage:     c.usage,
		}
		if c.revoked.Valid {
			j.Revoked = true
			j.RevokedAt = c.revoked.String
		} else {
			j.Revoked = false
		}
		jsonData = append(jsonData, &j)
	}

	json, err := json.Marshal(jsonData)
	checkFatal(err, nil)

	return json
}

func (certs certs) writeOCSPIndex(w http.ResponseWriter) {
	f, err := os.Create(OSSL_INDEX)
	if checkInternal(err, w) {
		return
	}
	defer f.Close()
	bw := bufio.NewWriter(f)

	for _, c := range certs {
		status := "V"
		date := ""
		if c.revoked.Valid {
			status = "R"
			date = c.revokedTime.Format(layoutOSSL)
		}
		fmt.Fprintf(bw, "%s\t%s\t%s\t%d\tunknown\t/%s\n",
			status,
			c.expiresTime.Format(layoutOSSL),
			date,
			c.serial,
			c.sub)
	}
	bw.Flush()
}

func makeGETHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(readSigningLog(db, w).toJSON())
	}
}

func makePUTHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		serialStr := path.Base(r.URL.Path)
		serial, err := strconv.Atoi(serialStr)
		if checkRequest(err, w) {
			return
		}

		// Get row with serial number `serial`
		query, err := db.Prepare("select revoked from realm_signing_log where serial = ?")
		checkFatal(err, w)
		defer query.Close()
		rows, err := query.Query(serial)
		checkFatal(err, w)
		defer rows.Close()

		// Get revoked status
		var revoked sql.NullString
		rows.Next()
		err = rows.Scan(&revoked)
		if checkRequest(err, w) {
			return
		}

		// Make sure there are no more rows with the same serial number
		// TODO: Handle multiple CAs
		if rows.Next() {
			checkInternal(fmt.Errorf("Multiple rows returned for serial %d", serial), w)
			return
		}
		checkFatal(err, w)

		// If it is already revoked, do nothing. Else, set the revocation time to now.
		var status string
		if revoked.Valid {
			status = "unchanged"
		} else {
			status = "revoked"
			now := time.Now().Format(layoutISO) // TODO: Time
			update, err := db.Prepare("update realm_signing_log set revoked = ? where serial = ?")
			checkFatal(err, w)
			defer update.Close()
			_, err = update.Exec(now, serial)
			if checkInternal(err, w) {
				return
			}
		}

		body := make(map[int]string)
		body[serial] = status
		json, err := json.Marshal(body)
		if checkInternal(err, w) {
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(json)

		readSigningLog(db, w).writeOCSPIndex(w)
	}
}

func makeAPIHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		switch r.Method {
		case "GET":
			makeGETHandler(db)(w, r)
		case "PUT":
			makePUTHandler(db)(w, r)
		case "OPTIONS":
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT")
			w.WriteHeader(http.StatusNoContent)
		default:
			log.Printf("Method %s not implemented", r.Method)
		}
	}
}

func main() {
	db, err := sql.Open("sqlite3", "./letswifi-dev.sqlite")
	checkFatal(err, nil)
	defer db.Close()

	readSigningLog(db, nil).writeOCSPIndex(nil)

	go func() {
		http.HandleFunc("/api/v1.0/noauth/", makeAPIHandler(db))
		log.Fatal(http.ListenAndServe("localhost:8888", nil))
	}()

	exec.Command("reload-localhost").Run() // TODO: For development
	select {}
}
