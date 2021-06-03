package main

import (
	"database/sql"
	"html/template"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
)

var templates = template.Must(template.ParseFiles("index.html"))

type caEntry struct {
	pub    []byte
	key    []byte
	issuer string
}

// func readCa(db *DB) map[string]caEntry {
// 	rows, err := db.Query("select * from ca")
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer rows.Close()
// 	for rows.Next() {
// 		var sub string
// 		var issuer sql.NullString
// 		var pub, key []byte // TODO: key is nullable
// 		err = rows.Scan(&sub, &pub, &key, &issuer)
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 		fmt.Println(sub)
// 	}
// 	if err = rows.Err(); err != nil {
// 		log.Fatal(err)
// 	}
// }

type Issued struct {
	Serial    int
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

func readIssued(db *sql.DB) []Issued {
	rows, err := db.Query("select * from realm_signing_log")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	res := []Issued{}
	for rows.Next() {
		i := Issued{}
		err = rows.Scan(&i.Serial, &i.Realm, &i.Ca_sub, &i.Requester, &i.Sub, &i.Issued, &i.Expires, &i.Csr, &i.X509, &i.Revoked, &i.Usage)
		if err != nil {
			log.Fatal(err)
		}
		res = append(res, i)
	}

	if err = rows.Err(); err != nil {
		log.Fatal(err)
	}

	return res
}

func makeHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		issued := readIssued(db)
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
