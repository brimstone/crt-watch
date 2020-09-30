package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/brimstone/logger"
)

type CrtLog struct {
	Expired           bool
	IssuerCaID        int    `json:"issuer_ca_id"`
	IssuerName        string `json:"issuer_name"`
	MinCertID         int    `json:"min_cert_id"`
	MinEntryTimestamp string `json:"min_entry_timestamp"`
	NameValue         string `json:"name_value"`
	NotAfter          string `json:"not_after"`
	NotAfterTime      time.Time
	NotBefore         string `json:"not_before"`
	NotBeforeTime     time.Time
	TimeLeft          time.Duration
	Actual            string
}

var log = logger.New()

func fetchLog(domain string) ([]CrtLog, error) {
	var crtlog []CrtLog
	defer log.Profile(time.Now())

	resp, err := http.Get("https://crt.sh/json?q=" + domain)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(body, &crtlog)
	return crtlog, err

}

func main() {

	domain := os.Args[1]
	ValidSites := make(map[string]*CrtLog)
	var ValidSiteIndex []string
	now := time.Now()

	log.Debug("Getting certs",
		log.Field("domain", domain),
	)
	crtlog, err := fetchLog(domain)
	wildlog, err := fetchLog("%25." + domain)
	crtlog = append(crtlog, wildlog...)
	// Figure out which are expired
	for i := range crtlog {
		crtlog[i].NotAfterTime, err = time.Parse("2006-01-02T15:04:05", crtlog[i].NotAfter)
		if err != nil {
			log.Error("Unable to parse time",
				log.Field("NotAfter", crtlog[i].NotAfter),
			)
			continue
		}
		if now.After(crtlog[i].NotAfterTime) {
			crtlog[i].Expired = true
		}

		crtlog[i].NotBeforeTime, err = time.Parse("2006-01-02T15:04:05", crtlog[i].NotBefore)
		if err != nil {
			log.Error("Unable to parse time",
				log.Field("NotBefore", crtlog[i].NotBefore),
			)
			continue
		}
		if now.Before(crtlog[i].NotBeforeTime) {
			crtlog[i].Expired = true
		}

		crtlog[i].TimeLeft = crtlog[i].NotAfterTime.Sub(now)
	}

	// Filter out expired certs
	for _, site := range crtlog {
		name := strings.ReplaceAll(site.NameValue, "\n", ",")
		if now.Add(-time.Hour * 24 * 30).After(site.NotAfterTime) {
			continue
		}
		if p, ok := ValidSites[name]; ok {
			if p.NotAfterTime.Before(site.NotAfterTime) {
				*ValidSites[name] = site
			}
		} else {
			ValidSites[name] = &CrtLog{}
			*ValidSites[name] = site
		}
	}
	// Get a unique list of sites
	for site := range ValidSites {
		ValidSiteIndex = append(ValidSiteIndex, site)
	}

	// Try to connect to the site and verify the times on the cert match
	for _, site := range ValidSiteIndex {
		log.Debug("Checking TLS",
			log.Field("site", site),
		)
		conn, err := tls.DialWithDialer(&net.Dialer{
			Timeout: time.Second * 10,
		},
			"tcp",
			strings.Split(site, ",")[0]+":443",
			&tls.Config{
				InsecureSkipVerify: true,
				ServerName:         strings.Split(site, ",")[0],
				VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return nil
					}
					cert, err := x509.ParseCertificate(rawCerts[0])
					if err != nil {
						return nil // TODO save to Actual?
					}
					if cert.NotAfter != ValidSites[site].NotAfterTime {
						ValidSites[site].Actual = "NotAfter mismatch"
						return nil
					}
					if cert.NotBefore != ValidSites[site].NotBeforeTime {
						ValidSites[site].Actual = "NotBefore mismatch"
						return nil
					}
					//ValidSites[site].Actual = cert.Subject.String()
					//fmt.Printf("%q\n", cert.Subject)
					return nil
				},
			},
		)
		if err != nil {
			ValidSites[site].Actual = err.Error()
			continue
		}
		conn.Close()
	}

	// Sort by domain name
	sort.Strings(ValidSiteIndex)
	// Report
	for _, site := range ValidSiteIndex {
		base := []logger.FieldPair{
			log.Field("NotAfter", ValidSites[site].NotAfter),
			log.Field("NotBefore", ValidSites[site].NotBefore),
			log.Field("TimeLeft", ValidSites[site].TimeLeft),
			log.Field("Expired", ValidSites[site].Expired),
		}
		// Report
		if ValidSites[site].Expired {
			log.Warn(site, base...)
		} else if ValidSites[site].Actual != "" {
			log.Error(site,
				append(base, log.Field("Actual", ValidSites[site].Actual))...,
			)
		} else {
			log.Info(site, base...)
		}
	}

}
