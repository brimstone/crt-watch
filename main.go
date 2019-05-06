package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
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
	ValidSites := make(map[string]CrtLog)
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
			continue
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
			continue
		}

		crtlog[i].TimeLeft = crtlog[i].NotAfterTime.Sub(now)
	}

	// Filter out expired certs
	for _, site := range crtlog {
		if site.Expired {
			continue
		}
		if p, ok := ValidSites[site.NameValue]; ok {
			if p.NotAfterTime.Before(site.NotAfterTime) {
				ValidSites[site.NameValue] = site
			}
		} else {
			ValidSites[site.NameValue] = site
		}
	}
	// Get a unique list of sites
	for site := range ValidSites {
		ValidSiteIndex = append(ValidSiteIndex, site)
	}
	// Sort by domain name
	sort.Strings(ValidSiteIndex)
	// Report
	for _, site := range ValidSiteIndex {
		log.Info(site,
			log.Field("NotAfter", ValidSites[site].NotAfter),
			log.Field("NotBefore", ValidSites[site].NotBefore),
			log.Field("TimeLeft", ValidSites[site].TimeLeft),
		)
	}

}
