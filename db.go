package main

import (
	"database/sql"
	"fmt"
	"time"
)

const (
	layoutISO  = "2006-01-02"
	layoutOSSL = "060102150405Z"
)

type cert struct {
	Serial    int64      `json:"serial"`
	Requester string     `json:"requester"`
	Subject   string     `json:"subject"`
	Issued    time.Time  `json:"issued"`
	Expires   time.Time  `json:"expires"`
	Revoked   *time.Time `json:"revoked"`
}

type certs []*cert

type filter struct {
	field string
	value string
}

type pagination struct {
	perPage int
	page    int
}

// Produce a "WHERE X CONTAINS ?" clause (actually: WHERE instr(X, ?) > 0)
// NOTE:
// - Caller is responsible for sanitation of f.field
// - f.value is parameterized
func (f *filter) SQL() string {
	if f == nil {
		return ""
	}
	return fmt.Sprintf("WHERE instr(%s, ?) > 0 ", f.field)
}

// Produce a "LIMIT X OFFSET Y" clause
func (p *pagination) SQL() string {
	if p == nil {
		return ""
	}
	offset := p.perPage * (p.page - 1)
	return fmt.Sprintf("LIMIT %d OFFSET %d ", p.perPage, offset)
}

func totalCount(db *sql.DB, f *filter) (res int, err error) {
	sql := "SELECT count(*) FROM realm_signing_log " + f.SQL()
	var filterValue string
	if f != nil {
		filterValue = f.value
	}
	row := db.QueryRow(sql, filterValue)
	err = row.Scan(&res)
	return
}

func readSigningLog(db *sql.DB, f *filter, p *pagination) (certs, error) {
	sql := "SELECT serial, requester, sub, issued, expires " +
		"FROM realm_signing_log " + f.SQL() + "ORDER BY serial " + p.SQL()
	var filterValue string
	if f != nil {
		filterValue = f.value
	}
	rows, err := db.Query(sql, filterValue)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var res []*cert
	for rows.Next() {
		var serial int64
		var requester, subject string
		var issuedStr, expiresStr string
		err = rows.Scan(
			&serial,
			&requester,
			&subject,
			&issuedStr,
			&expiresStr,
		)
		if err != nil {
			return nil, err
		}

		// TODO: If we can use more descriptive column types, sqlite driver
		// could handle conversion to time.Time.
		expires, err := time.Parse(layoutISO, expiresStr)
		if err != nil {
			return nil, err
		}
		issued, err := time.Parse(layoutISO, issuedStr)
		if err != nil {
			return nil, err
		}

		res = append(res, &cert{
			serial,
			requester,
			subject,
			issued,
			expires,
			nil,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}
