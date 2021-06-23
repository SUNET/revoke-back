package main

import (
	"database/sql"
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
