// Package intel provides offline, deterministic lookups into embedded EPSS and KEV snapshots.
// Data is parsed lazily on first use and cached for concurrent access.
package intel

import (
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"sync"

	_ "embed"
)

// EPSSModelVersion is the model version string embedded in the EPSS snapshot header.
const EPSSModelVersion = "v2026.06.15"

// SnapshotDate is the score_date day (YYYY-MM-DD) from the EPSS snapshot header.
const SnapshotDate = "2026-07-29"

//go:embed data/epss.csv.gz
var epssGZ []byte

//go:embed data/kev.json
var kevJSON []byte

// EPSSScore holds the probability score and percentile rank for a CVE.
type EPSSScore struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
}

// KEVEntry holds catalog fields for a CVE listed in the CISA Known Exploited Vulnerabilities catalog.
type KEVEntry struct {
	CVEID         string `json:"cveID"`
	DateAdded     string `json:"dateAdded"`
	DueDate       string `json:"dueDate"`
	VendorProject string `json:"vendorProject"`
	Product       string `json:"product"`
}

var (
	once    sync.Once
	epssMap map[string]EPSSScore
	kevMap  map[string]KEVEntry
)

func initOnce() {
	once.Do(func() {
		epssMap = parseEPSS()
		kevMap = parseKEV()
	})
}

// EPSS looks up the EPSS score for the first CVE-format id in ids.
// Callers may pass an advisory ID followed by its CVE aliases; the first
// matching CVE key wins. ids are normalised (trimmed, uppercased) before lookup.
// Safe for concurrent use.
func EPSS(ids ...string) (EPSSScore, bool) {
	initOnce()
	for _, id := range ids {
		key := normalise(id)
		if !isCVE(key) {
			continue
		}
		if s, ok := epssMap[key]; ok {
			return s, true
		}
	}
	return EPSSScore{}, false
}

// KEV looks up the KEV entry for the first CVE-format id in ids.
// Callers may pass an advisory ID followed by its CVE aliases; the first
// matching CVE key wins. ids are normalised (trimmed, uppercased) before lookup.
// Safe for concurrent use.
func KEV(ids ...string) (KEVEntry, bool) {
	initOnce()
	for _, id := range ids {
		key := normalise(id)
		if !isCVE(key) {
			continue
		}
		if e, ok := kevMap[key]; ok {
			return e, true
		}
	}
	return KEVEntry{}, false
}

// normalise trims whitespace and uppercases an advisory id.
func normalise(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

// isCVE reports whether the normalised id looks like a CVE identifier.
func isCVE(id string) bool {
	return strings.HasPrefix(id, "CVE-")
}

// parseEPSS reads and indexes the embedded gzip-compressed CSV.
// Line 1 is a comment (#…), line 2 is the header (cve,epss,percentile),
// remaining lines are data rows.
func parseEPSS() map[string]EPSSScore {
	gr, err := gzip.NewReader(bytes.NewReader(epssGZ))
	if err != nil {
		panic("intel: failed to open epss.csv.gz: " + err.Error())
	}
	defer gr.Close()

	cr := csv.NewReader(gr)
	cr.Comment = '#'
	// Skip the header row (cve,epss,percentile).
	if _, err := cr.Read(); err != nil {
		panic("intel: failed to read EPSS header: " + err.Error())
	}

	m := make(map[string]EPSSScore, 300_000)
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			panic("intel: EPSS parse error: " + err.Error())
		}
		if len(rec) < 3 {
			continue
		}
		score, _ := strconv.ParseFloat(rec[1], 64)
		pct, _ := strconv.ParseFloat(rec[2], 64)
		m[normalise(rec[0])] = EPSSScore{Score: score, Percentile: pct}
	}
	return m
}

// kevCatalog is the JSON envelope for kev.json.
type kevCatalog struct {
	Vulnerabilities []struct {
		CVEID         string `json:"cveID"`
		DateAdded     string `json:"dateAdded"`
		DueDate       string `json:"dueDate"`
		VendorProject string `json:"vendorProject"`
		Product       string `json:"product"`
	} `json:"vulnerabilities"`
}

// parseKEV reads and indexes the embedded KEV JSON.
func parseKEV() map[string]KEVEntry {
	var cat kevCatalog
	if err := json.Unmarshal(kevJSON, &cat); err != nil {
		panic("intel: failed to parse kev.json: " + err.Error())
	}
	m := make(map[string]KEVEntry, len(cat.Vulnerabilities))
	for _, v := range cat.Vulnerabilities {
		key := normalise(v.CVEID)
		m[key] = KEVEntry{
			CVEID:         v.CVEID,
			DateAdded:     v.DateAdded,
			DueDate:       v.DueDate,
			VendorProject: v.VendorProject,
			Product:       v.Product,
		}
	}
	return m
}
