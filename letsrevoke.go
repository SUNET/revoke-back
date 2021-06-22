/*
API specification

	URL: http://localhost:8888/api/v0/noauth
	Method: GET
	Body: None
	Response body: Array of certs (all)
	Side effect: None

	URL: http://localhost:8888/api/v0/noauth/$SERIAL
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

func readSigningLog(db *sql.DB) (certs, error) {
	rows, err := db.Query("select * from realm_signing_log")
	if err != nil {
		return nil, err
	}
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
		if err != nil {
			return nil, err
		}

		// TODO: Issued and expiration time is currently read (and output to
		// OpenSSL) as midnight UTC. Exact time is defined in the certificate,
		// but not in the database. Could read from certificate, but certificate
		// is nullable in database.
		i.expiresTime, err = time.Parse(layoutISO, i.expires)
		if err != nil {
			return nil, err
		}

		if i.revoked.Valid {
			i.revokedTime, err = time.Parse(layoutISO, i.revoked.String)
			if err != nil {
				return nil, err
			}
		}

		res = append(res, &i)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

func (certs certs) toJSON() ([]byte, error) {
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
	if err != nil {
		return nil, err
	}

	return json, nil
}

func (certs certs) writeOCSPIndex() error {
	f, err := os.Create(OSSL_INDEX)
	if err != nil {
		return err
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
	return bw.Flush()
}

type requestError struct {
	msg string
}

func (e requestError) Error() string {
	return fmt.Sprintf("Bad request: %s", e.msg)
}

func makeGETHandler(db *sql.DB) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.Method != "GET" {
			return requestError{"Wrong method"}
		}
		w.Header().Set("Content-Type", "application/json")

		certs, err := readSigningLog(db)
		if err != nil {
			return err
		}
		json, err := certs.toJSON()
		if err != nil {
			return err
		}
		_, err = w.Write(json)
		return err
	}
}

func makePUTHandler(db *sql.DB) errHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		switch r.Method {
		case "OPTIONS":
			w.Header().Set("Access-Control-Allow-Methods", "GET, PUT")
			w.WriteHeader(http.StatusNoContent)
			return nil
		case "PUT":
			w.Header().Set("Content-Type", "application/json")
		default:
			return requestError{"Wrong method"}
		}

		serialStr := path.Base(r.URL.Path)
		serial, err := strconv.Atoi(serialStr)
		if err != nil {
			return requestError{"Bad URL"}
		}

		// Get row with serial number `serial`
		query, err := db.Prepare("select revoked from realm_signing_log where serial = ?")
		if err != nil {
			return err
		}
		defer query.Close()

		rows, err := query.Query(serial)
		if err != nil {
			return err
		}
		defer rows.Close()

		// Get revoked status
		var revoked sql.NullString
		if !rows.Next() {
			if rows.Err() != nil {
				return rows.Err()
			}
			return requestError{"Invalid serial number"}
		}
		err = rows.Scan(&revoked)
		if err != nil {
			return err
		}

		// Make sure there are no more rows with the same serial number
		if rows.Next() {
			if rows.Err() != nil {
				return rows.Err()
			}
			return fmt.Errorf("Multiple rows returned for serial %d", serial)
		}

		// If it is already revoked, do nothing. Else, set the revocation time to now.
		var status string
		if revoked.Valid {
			status = "unchanged"
		} else {
			status = "revoked"
			now := time.Now().Format(layoutISO)

			update, err := db.Prepare("update realm_signing_log set revoked = ? where serial = ?")
			if err != nil {
				return err
			}
			defer update.Close()

			_, err = update.Exec(now, serial)
			if err != nil {
				return err
			}
		}

		body := make(map[int]string)
		body[serial] = status
		json, err := json.Marshal(body)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(json)
		return err
	}
}

type errHandler func(w http.ResponseWriter, r *http.Request) error

func (fn errHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if err := fn(w, r); err != nil {
		if _, ok := err.(requestError); ok {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

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
