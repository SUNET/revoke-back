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

var templates = template.Must(template.ParseFiles("index.html"))

type CaEntry struct {
	Pub    []byte
	Key    []byte // TODO: key is nullable blob
	Issuer sql.NullString
}

// Return map[`sub`]caEntry
func readCa(db *sql.DB) map[string]CaEntry {
	rows, err := db.Query("select * from ca")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	res := make(map[string]CaEntry)
	for rows.Next() {
		var sub string
		c := CaEntry{}
		err = rows.Scan(&sub, &c.Pub, &c.Key, &c.Issuer)
		if err != nil {
			log.Fatal(err)
		}
		res[sub] = c
	}
	if err = rows.Err(); err != nil {
		log.Fatal(err)
	}

	return res
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

func (i Issued) ExpiresFormatted() string {
	d := strings.Split(i.Expires, "-")
	return d[0][2:] + d[1] + d[2] + "000000Z" // Todo: UTC?
}

// Return map[`serial`]Issued
func readIssued(db *sql.DB) map[int]Issued {
	rows, err := db.Query("select * from realm_signing_log")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	res := make(map[int]Issued)
	for rows.Next() {
		var serial int
		i := Issued{}
		err = rows.Scan(&serial, &i.Realm, &i.Ca_sub, &i.Requester, &i.Sub, &i.Issued, &i.Expires, &i.Csr, &i.X509, &i.Revoked, &i.Usage)
		if err != nil {
			log.Fatal(err)
		}
		res[serial] = i
	}

	if err = rows.Err(); err != nil {
		log.Fatal(err)
	}

	return res
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func makeHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issued := readIssued(db)

		if r.Method == "POST" {
			f, err := os.Create("index.txt")
			check(err)
			defer f.Close()

			r.ParseForm()
			revokedSerials := r.Form
			for serial, i := range issued {
				_, revoked := revokedSerials[strconv.Itoa(serial)]
				revokeStatus := "V"
				revokeDate := ""
				if revoked {
					revokeStatus = "R"
					revokeDate = time.Now().UTC().Format("060102150405Z")
				}
				fmt.Fprintf(f, "%s\t%s\t%s\t%d\tunknown\t/%s\n", revokeStatus, i.ExpiresFormatted(), revokeDate, serial, i.Sub)
			}
		}

		err := templates.ExecuteTemplate(w, "index.html", issued)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func main() {
	db, err := sql.Open("sqlite3", "./letswifi-dev.sqlite")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	http.HandleFunc("/", makeHandler(db))
	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}
