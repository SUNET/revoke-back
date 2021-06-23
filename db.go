package main

import (
	"database/sql"
	"fmt"
	"time"
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

type filter struct {
	field string
	value string
}

func readSigningLog(db *sql.DB, f *filter) (certs, error) {
	var rows *sql.Rows
	var err error
	if f != nil {
		var stmt *sql.Stmt
		switch f.field {
		case "sub":
			stmt, err = db.Prepare("select * from realm_signing_log where instr(sub, ?) > 0 order by serial")
		default:
			return nil, err
		}
		if err != nil {
			return nil, err
		}
		defer stmt.Close()
		rows, err = stmt.Query(f.value)
	} else {
		rows, err = db.Query("select * from realm_signing_log order by serial")
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
