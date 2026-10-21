package pipeline

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/intel"
)

// attributionSignals is a signals 1.x fixture shaped like the corpus's real file, which keys records
// by CVE, GO, PYSEC and RUSTSEC ids alike. Its records are the two shapes the join must not get
// wrong:
//
//   - The gogs chain. CISA lists only the successor CVE-2025-8110 and says nothing about its
//     predecessor CVE-2024-55947, which has no CVE record here at all. GO-2024-3356, the
//     predecessor's GO alias, is a roll-up record carrying a listing.
//   - The HTTP/2 rapid-reset siblings. GO-2023-2102 stands for CVE-2023-39325 AND CVE-2023-44487;
//     only CVE-2023-44487 is KEV-listed (EPSS 0.99999), and CVE-2023-39325 has no record of its
//     own. The GO roll-up carries the sibling's listing.
const attributionSignals = `{"signals_version": "1.0.0", "record_count": 4,
  "signals_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
  "records": [
    {"identifier": "CVE-2025-8110",
     "kev": {"listed": true, "date_added": "2025-07-28", "catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00Z"}},
    {"identifier": "GO-2024-3356", "epss": {"score": 0.75197, "percentile": 0.99463, "as_of": "2026-08-01"},
     "kev": {"listed": true, "date_added": "2025-07-28", "catalog_version": "2026.10.19", "date_released": "2026-10-19T18:00:00Z"}},
    {"identifier": "CVE-2023-44487", "epss": {"score": 0.99999, "percentile": 0.99997, "as_of": "2026-08-11"},
     "kev": {"listed": true, "date_added": "2023-10-10", "catalog_version": "2026.08.11", "date_released": "2026-08-11T18:59:43Z"}},
    {"identifier": "GO-2023-2102", "epss": {"score": 0.99999, "percentile": 0.99997, "as_of": "2026-08-11"},
     "kev": {"listed": true, "date_added": "2023-10-10", "catalog_version": "2026.08.11", "date_released": "2026-08-11T18:59:43Z"}}]}`

// KEV/EPSS score CVEs, and trigger's priorityFor attributes them to an advisory through
// intel.Signals.Attribute, which may follow an alias (a GO-/GHSA-keyed advisory has to match through
// its CVE alias). A join that takes the first record any of an advisory's identifiers has — what
// #167 shipped — hands one advisory another vulnerability's KEV listing two ways:
//
//   - through an alias another advisory also names (the gogs defect: AdvisoryTable merged both CVEs
//     of the chain under CVE-2024-55947, so the predecessor reported the successor's listing);
//   - through a roll-up record. A GO, PYSEC, RUSTSEC or GHSA record may stand for several CVEs, so a
//     CVE-keyed advisory reaching one through its GO alias can take a SIBLING CVE's listing:
//     CVE-2023-39325 → GO-2023-2102 → KEV-listed CVE-2023-44487. On the corpus's real signals file
//     seven CVE-keyed entries here took their KEV and EPSS from a GO record that way.
//
// Either is customer-visible: report.json's kev_listed, the SARIF properties block, report.html,
// the Tier-1 PR-comment KEV column, and finding ranking (findingRank sorts KEV-listed higher) all
// read it, and report.Priority documents the field as meaning CISA records active exploitation of
// THAT CVE.
//
// These two tests guard the join and the structural cause behind the first defect.

// tableClaims are the claims of a run asked about every AdvisoryTable entry. A run's claims are its
// work set: every advisory the run was asked about, by its id and the aliases its record lists, and
// every row its report holds, fresh or inherited. trigger's rankWith builds them that way, reading
// the records through the run's fact source; here the source is the table, and every row such a run
// holds is an entry the work set already names.
func tableClaims() *intel.Claims {
	ids := make([]string, 0, len(AdvisoryTable))
	for id := range AdvisoryTable {
		ids = append(ids, id)
	}
	claims := new(intel.Claims)
	LookupEach(NewTableSource(), ids, func(id string, facts AdvisoryFacts, _ bool) {
		claims.Add(id, facts.Aliases...)
	})
	return claims
}

// TestKEVAttributionFollowsListedCVE pins the join over a run whose work set is the whole advisory
// table (tableClaims):
//
//   - no entry takes a signals record whose identifier is the id or an alias of a DIFFERENT entry;
//   - an entry keyed by a CVE takes only the record under its own id — never a roll-up reached
//     through an alias, which may be a sibling CVE's.
func TestKEVAttributionFollowsListedCVE(t *testing.T) {
	sig, err := intel.Parse(strings.NewReader(attributionSignals))
	if err != nil {
		t.Fatal(err)
	}
	claims := tableClaims()
	// namedByOther is the invariant's own reading of the table, independent of intel.Claims.
	namedByOther := func(ident, id string) string {
		for other, facts := range AdvisoryTable {
			if other == id {
				continue
			}
			if strings.EqualFold(other, ident) {
				return other
			}
			for _, a := range facts.Aliases {
				if strings.EqualFold(a, ident) {
					return other
				}
			}
		}
		return ""
	}
	for id, facts := range AdvisoryTable {
		m, ok := sig.Attribute(id, facts.Aliases, claims)
		if !ok {
			continue
		}
		if other := namedByOther(m.Identifier, id); other != "" {
			t.Errorf("advisory %s takes its signals from %s, which advisory %s names: kev_listed/epss are "+
				"attributed to another vulnerability (aliases=%v)", id, m.Identifier, other, facts.Aliases)
		}
		if strings.HasPrefix(id, "CVE-") && m.Identifier != id {
			t.Errorf("advisory %s takes its signals from %s through an alias: a CVE's signal is its own "+
				"record, and %s may be a sibling CVE's (aliases=%v)", id, m.Identifier, m.Identifier, facts.Aliases)
		}
	}

	// The concrete cases, stated directly so a regression names itself.
	kev := func(id string) (intel.KEV, bool) {
		t.Helper()
		facts, ok := AdvisoryTable[id]
		if !ok {
			t.Fatalf("%s missing from AdvisoryTable", id)
		}
		m, ok := sig.Attribute(id, facts.Aliases, claims)
		return m.KEV, ok && m.HasKEV
	}
	if k, ok := kev("CVE-2024-55947"); ok && k.Listed {
		t.Errorf("CVE-2024-55947 (gogs predecessor) resolves a KEV listing from %s; CISA lists only its successor CVE-2025-8110", k.Identifier)
	}
	if k, ok := kev("CVE-2023-39325"); ok && k.Listed {
		t.Errorf("CVE-2023-39325 resolves a KEV listing from %s; CISA lists only its sibling CVE-2023-44487", k.Identifier)
	}
	k, ok := kev("CVE-2025-8110")
	if !ok || !k.Listed {
		t.Fatal("CVE-2025-8110 (gogs successor) resolves no KEV listing; the fixture lists it")
	}
	if k.Identifier != "CVE-2025-8110" {
		t.Errorf("gogs successor KEV listing attributed to %s, want CVE-2025-8110", k.Identifier)
	}
}

// TestNoEntryAliasesAnotherEntrysPrimaryID guards the structural cause rather than the symptom.
// Two advisories are two vulnerabilities; if one lists the other's primary id as an alias, then
// every CVE-keyed join downstream (KEV, EPSS, govulnMatchID's first GO- alias, aliasIndex work-set
// resolution) has one slot for two answers and must get at least one of them wrong.
func TestNoEntryAliasesAnotherEntrysPrimaryID(t *testing.T) {
	for id, facts := range AdvisoryTable {
		for _, a := range facts.Aliases {
			if a == id {
				continue
			}
			if _, isPrimary := AdvisoryTable[a]; isPrimary {
				t.Errorf("advisory %s lists %s in its Aliases, but %s is its own AdvisoryTable entry: "+
					"two vulnerabilities merged under one id — split them and join with Lineage",
					id, a, a)
			}
		}
	}
}
