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

// Attempt to revoke a certificate. Return a status string: "revoked" or "unchanged".
func revoke(serial int, db *sql.DB) (string, error) {
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

	// If it is already revoked, do nothing. Else, set the revocation time to now.
	var status string
	if revoked.Valid {
		status = "unchanged"
	} else {
		status = "revoked"
		now := time.Now().Format(layoutISO)

		update, err := db.Prepare("update realm_signing_log set revoked = ? where serial = ?")
		if err != nil {
			return "", err
		}
		defer update.Close()

		_, err = update.Exec(now, serial)
		if err != nil {
			return "", err
		}
	}

	return status, nil
}
