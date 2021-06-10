package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	layoutISO  = "2006-01-02"
	layoutOSSL = "060102150405Z"
)

// TODO: Error handling
func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

var templates = template.Must(template.ParseFiles("index.html"))

type Issued struct {
	Realm       string
	Ca_sub      string
	Requester   string
	Sub         string
	Issued      string
	Expires     string
	ExpiresTime time.Time
	Csr         string
	X509        sql.NullString
	Revoked     sql.NullString
	RevokedTime time.Time
	Usage       string
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
		i.ExpiresTime, err = time.Parse(layoutISO, i.Expires) // TODO: Should this really be considered as midnight UTC?
		check(err)
		if i.Revoked.Valid {
			i.RevokedTime, err = time.Parse(layoutOSSL, i.Revoked.String)
			check(err)
		}
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
			bw := bufio.NewWriter(f)

			update, err := db.Prepare("update realm_signing_log set revoked = ? where serial = ?")
			check(err)
			defer update.Close()

			r.ParseForm()
			revokedSerials := make(map[int]bool)
			for serial, _ := range r.Form {
				serialInt, err := strconv.Atoi(serial)
				check(err)
				revokedSerials[serialInt] = true
			}

			now := time.Now().UTC()
			nowOSSL := now.Format(layoutOSSL)

			// Update database and structs
			for serial, _ := range revokedSerials {
				// TODO: Updates even if already revoked – desired behaviour?
				_, err := update.Exec(nowOSSL, serial)
				check(err)
				i := issued[serial]
				i.RevokedTime = now
				i.Revoked.Valid = true
				i.Revoked.String = nowOSSL
			}

			// Write index.txt
			for serial, i := range issued {
				status := "V"
				date := ""
				if i.Revoked.Valid {
					status = "R"
					date = i.RevokedTime.Format(layoutOSSL)
				}
				fmt.Fprintf(bw, "%s\t%s\t%s\t%d\tunknown\t/%s\n", status, i.ExpiresTime.Format(layoutOSSL), date, serial, i.Sub)
			}
			bw.Flush()
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
