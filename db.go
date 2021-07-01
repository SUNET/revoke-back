package main

import (
	"database/sql"
	"fmt"
	"time"
)

type cert struct {
	Serial    int64     `json:"serial"`
	Requester string    `json:"requester"`
	Subject   string    `json:"subject"`
	Issued    time.Time `json:"issued"`
	Expires   time.Time `json:"expires"`
	Revoked   time.Time `json:"revoked"`
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
			time.Time{},
		})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

type dbAction int

const (
	revoke dbAction = iota
	unrevoke
)

// Attempt to revoke or unrevoke a certificate. Return a status string:
// "revoked", "unrevoked", or "unchanged".
func modify(serial int, action dbAction, db *sql.DB) (string, error) {
	// Get row with serial number `serial`
	query, err := db.Prepare("select revoked from realm_signing_log where serial = ?")
	if err != nil {
		return "", err
	}
	defer query.Close()

	rows, err := query.Query(serial)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	// Get revoked status
	var revoked sql.NullString
	if !rows.Next() {
		if rows.Err() != nil {
			return "", rows.Err()
		}
		return "", requestError{"Invalid serial number"}
	}
	err = rows.Scan(&revoked)
	if err != nil {
		return "", err
	}

	// Make sure there are no more rows with the same serial number
	if rows.Next() {
		if rows.Err() != nil {
			return "", rows.Err()
		}
		return "", fmt.Errorf("Multiple rows returned for serial %d", serial)
	}

	update, err := db.Prepare("update realm_signing_log set revoked = ? where serial = ?")
	if err != nil {
		return "", err
	}
	defer update.Close()

	if revoked.Valid {
		// Invariant: Cert is revoked

		if action == revoke {
			return "unchanged", nil
		}

		_, err = update.Exec(nil, serial)
		if err != nil {
			return "", err
		}
		return "unrevoked", nil
	}

	// Invariant: Cert is not revoked

	if action == unrevoke {
		return "unchanged", nil
	}

	now := time.Now().Format(layoutISO)
	_, err = update.Exec(now, serial)
	if err != nil {
		return "", err
	}
	return "revoked", nil
}
