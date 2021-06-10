package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

var templates = template.Must(template.ParseFiles("index.html"))

type CaEntry struct {
	Pub    []byte
	Key    []byte // TODO: key is nullable blob
	Issuer sql.NullString
}

type Issued struct {
	Realm     string
	Ca_sub    string
	Requester string
	Sub       string
	Issued    string
	Expires   string
	Csr       string
	X509      sql.NullString
	Revoked   sql.NullString
	Usage     string
}

func (i Issued) ExpiresOSSL() string {
	d := strings.Split(i.Expires, "-")
	return d[0][2:] + d[1] + d[2] + "000000Z" // Todo: UTC?
}

// Return map[`sub`]caEntry
func readCa(db *sql.DB) map[string]*CaEntry {
	rows, err := db.Query("select * from ca")
	check(err)
	defer rows.Close()

	res := make(map[string]*CaEntry)
	for rows.Next() {
		var sub string
		c := CaEntry{}
		err = rows.Scan(&sub, &c.Pub, &c.Key, &c.Issuer)
		check(err)
		res[sub] = &c
	}
	if err = rows.Err(); err != nil {
		log.Fatal(err)
	}

	return res
}

// Return map[`serial`]Issued
func readIssued(db *sql.DB) map[int]*Issued {
	rows, err := db.Query("select * from realm_signing_log")
	check(err)
	defer rows.Close()

	res := make(map[int]*Issued)
	for rows.Next() {
		var serial int
		i := Issued{}
		err = rows.Scan(&serial, &i.Realm, &i.Ca_sub, &i.Requester, &i.Sub, &i.Issued, &i.Expires, &i.Csr, &i.X509, &i.Revoked, &i.Usage)
		check(err)
		res[serial] = &i
	}

	if err = rows.Err(); err != nil {
		log.Fatal(err)
	}

	return res
}

func makeHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issued := readIssued(db)

		if r.Method == "POST" {
			f, err := os.Create("index.txt")
			check(err)
			defer f.Close()
			update, err := db.Prepare("update realm_signing_log set revoked = ? where serial = ?")
			check(err)
			defer update.Close()

			r.ParseForm()
			revokedSerials := r.Form
			for serial, i := range issued {
				_, revoked := revokedSerials[strconv.Itoa(serial)]
				revokeStatus := "V"
				revokeDateOSSL := ""
				if revoked {
					revokeStatus = "R"
					revokeTime := time.Now().UTC()
					revokeDateOSSL = revokeTime.Format("060102150405Z")
					revokeDateISO := revokeTime.Format("2006-01-02")
					_, err := update.Exec(revokeDateISO, serial) // TODO: Only update new revocations
					check(err)
					i.Revoked.Valid = true
					i.Revoked.String = revokeDateISO
				}
				fmt.Fprintf(f, "%s\t%s\t%s\t%d\tunknown\t/%s\n", revokeStatus, i.ExpiresOSSL(), revokeDateOSSL, serial, i.Sub)
			}
		}

		err := templates.ExecuteTemplate(w, "index.html", issued)
		check(err)
	}
}

func main() {
	db, err := sql.Open("sqlite3", "./letswifi-dev.sqlite")
	check(err)
	defer db.Close()

	http.HandleFunc("/", makeHandler(db))
	log.Fatal(http.ListenAndServe("localhost:8888", nil))
}
