package main

import (
	"bufio"
	"fmt"
	"os"
)

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
