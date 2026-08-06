//go:build live

// advisory_id_osv_live_test.go — do the advisory identifiers we ship actually EXIST?
//
// The existence half of advisory_id_format_test.go. Format is checkable offline; existence is not,
// so this layer is gated twice over:
//
//   - the `live` build tag, like the tree's other network/toolchain tests; AND
//   - ASSAY_OSV_EXISTENCE_CHECK=1, a dedicated env var (the same belt-and-braces idiom as
//     advisory_source_overlap_live_test.go's OPEN_TEGRON_OVERLAP_CORPUS).
//
// # Why two gates and not one
//
// ZERO-EGRESS POSTURE. This test sends our advisory identifiers to a third party. That is fine —
// they are ours, they are public, and OSV is the authority we are checking against — but it must be
// impossible for it to fire inside a customer's CI or in anyone's default `go test ./...`. It is a
// MAINTAINER check on OUR OWN corpus, run deliberately, never as a side effect of anything. A
// single tag would be enough to keep it out of the default suite; the second gate keeps it out of a
// blanket `-tags live` run too, which is the plausible accident.
//
// Run it:
//
//	ASSAY_OSV_EXISTENCE_CHECK=1 GOWORK=off go test -tags live ./pipeline/ -run OSV -v
//
// # On not reusing trigger.HTTPOSVClient
//
// The dispatch's instinct was right and the seam does not exist. trigger.HTTPOSVClient is the
// production OSV caller, but its only method is QueryBatch, which POSTs {ecosystem, name, version}
// package coordinates to /v1/querybatch and returns the advisories affecting them. There is no
// per-identifier lookup on it, and /v1/vulns/<id> is a different endpoint with a different verb and
// a different response shape. Reusing it would mean adding a production method that only a
// maintainer test calls — a wider production surface to avoid twenty lines of test-local HTTP.
// So this file does its own GET, and deliberately does not touch the production client.
package pipeline

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"testing"
	"time"
)

// osvVulnURL is the OSV.dev per-identifier lookup: 200 with the record, 404 when the identifier
// does not exist. https://google.github.io/osv.dev/get-v1-vulns/
const osvVulnURL = "https://api.osv.dev/v1/vulns/"

// osvExistenceEnv gates this file's network calls. Deliberately distinct from anything the CLI
// reads: pointing the scanner at OSV must never turn a maintainer audit on.
const osvExistenceEnv = "ASSAY_OSV_EXISTENCE_CHECK"

// osvPoliteDelay spaces the requests. There are on the order of a hundred identifiers and OSV is a
// free public service; a maintainer audit that takes fifteen seconds instead of two is a fine trade
// for not hammering it.
const osvPoliteDelay = 120 * time.Millisecond

// firstPartyNamespaces are the identifier namespaces WE mint. They are not registered with any
// issuing authority and by construction resolve nowhere, so querying OSV for them would assert
// nothing. Their well-formedness is checked hermetically in advisory_id_format_test.go; this is a
// scope statement, not an exemption from checking.
var firstPartyNamespaces = map[string]bool{"TEGRON": true, "FERRALON": true}

func requireOSVGate(t *testing.T) {
	t.Helper()
	if os.Getenv(osvExistenceEnv) != "1" {
		t.Skipf("set %s=1 to resolve our advisory identifiers against OSV.dev — this is a maintainer "+
			"audit of our own corpus and sends identifiers to a third party, so it never runs by default",
			osvExistenceEnv)
	}
}

// osvRecord is the slice of the OSV record this test reads.
type osvRecord struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
}

// fetchOSV resolves one identifier. found=false means a clean 404: OSV does not have this
// identifier. An error is a transport or protocol problem and is NOT evidence about the identifier.
func fetchOSV(t *testing.T, client *http.Client, id string) (rec osvRecord, found bool, err error) {
	t.Helper()
	resp, err := client.Get(osvVulnURL + id)
	if err != nil {
		return rec, false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return rec, false, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		if err := json.Unmarshal(body, &rec); err != nil {
			return rec, false, fmt.Errorf("decoding the OSV record for %s: %w", id, err)
		}
		return rec, true, nil
	case http.StatusNotFound:
		return rec, false, nil
	default:
		return rec, false, fmt.Errorf("OSV returned HTTP %d for %s: %s", resp.StatusCode, id, body)
	}
}

// shippedIdentifiers collects every advisory identifier in the built-in table, mapped to the
// advisory entry it is published under, so a failure can name where to go and fix it.
func shippedIdentifiers() map[string][]string {
	out := map[string][]string{}
	for id, facts := range AdvisoryTable {
		out[id] = append(out[id], "AdvisoryTable key")
		for _, alias := range idsFrom(facts) {
			out[alias] = append(out[alias], "identifier on AdvisoryTable["+id+"]")
		}
	}
	return out
}

// TestOSV_ShippedIdentifiersExist resolves every third-party identifier we ship. A 404 means we are
// citing an advisory that does not exist — the acute form of the defect advisory_id_format_test.go
// catches structurally, and the one a well-formed fabrication would slip past.
func TestOSV_ShippedIdentifiersExist(t *testing.T) {
	requireOSVGate(t)
	client := &http.Client{Timeout: 30 * time.Second}

	all := shippedIdentifiers()
	ids := make([]string, 0, len(all))
	for id := range all {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var resolved, skipped int
	for _, id := range ids {
		if ns, _, _ := cutNamespace(id); firstPartyNamespaces[ns] {
			skipped++
			continue
		}
		rec, found, err := fetchOSV(t, client, id)
		time.Sleep(osvPoliteDelay)
		if err != nil {
			t.Errorf("resolving %s: %v (transport problem — this says nothing about the identifier; re-run)", id, err)
			continue
		}
		if !found {
			sort.Strings(all[id])
			t.Errorf("%s does NOT exist at OSV (404). We ship it as: %v\n"+
				"  a customer who follows this citation finds nothing; either correct it to the real\n"+
				"  identifier or remove it — do not leave an unresolvable id in a published artifact",
				id, all[id])
			continue
		}
		if rec.ID != id {
			t.Errorf("%s resolves at OSV to a record whose id is %q — we are citing an alias as if it were "+
				"the canonical identifier", id, rec.ID)
		}
		resolved++
	}
	t.Logf("resolved %d identifiers at OSV; skipped %d first-party ids (%v — ours, registered nowhere)",
		resolved, skipped, sortedKeys(firstPartyNamespaces))
}

// TestOSV_AliasesAgreeWithOSV compares the alias set we publish for an advisory against the alias
// set OSV publishes for it.
//
// An alias we claim that OSV does not link is a claim we cannot back. It is worth distinguishing
// from a 404: the identifier may be perfectly real and simply belong to a DIFFERENT advisory, which
// is how a successor CVE ends up mis-filed as an alias of its predecessor. The failure prints both
// sets so the maintainer can see which it is.
func TestOSV_AliasesAgreeWithOSV(t *testing.T) {
	requireOSVGate(t)
	client := &http.Client{Timeout: 30 * time.Second}

	keys := make([]string, 0, len(AdvisoryTable))
	for id := range AdvisoryTable {
		keys = append(keys, id)
	}
	sort.Strings(keys)

	for _, id := range keys {
		ns, _, _ := cutNamespace(id)
		if firstPartyNamespaces[ns] {
			continue
		}
		ours := AdvisoryTable[id].Aliases
		if len(ours) == 0 {
			continue
		}
		rec, found, err := fetchOSV(t, client, id)
		time.Sleep(osvPoliteDelay)
		if err != nil || !found {
			// Existence is TestOSV_ShippedIdentifiersExist's job; do not report it twice.
			continue
		}
		theirs := map[string]bool{rec.ID: true}
		for _, a := range rec.Aliases {
			theirs[a] = true
		}
		for _, a := range ours {
			if aNS, _, _ := cutNamespace(a); firstPartyNamespaces[aNS] {
				continue
			}
			if !theirs[a] {
				sort.Strings(rec.Aliases)
				t.Errorf("we publish %q as an alias of %s; OSV does not link them\n"+
					"  OSV's aliases for %s: %v\n"+
					"  either it belongs to a different advisory (a successor CVE is not an alias) or the\n"+
					"  identifier is wrong; either way we are asserting a relationship no source states",
					a, id, id, rec.Aliases)
			}
		}
	}
}

// cutNamespace splits an identifier into its leading namespace and the rest.
func cutNamespace(id string) (ns, rest string, ok bool) {
	for i := 0; i < len(id); i++ {
		if id[i] == '-' {
			return id[:i], id[i+1:], true
		}
	}
	return id, "", false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
