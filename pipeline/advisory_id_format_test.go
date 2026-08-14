// advisory_id_format_test.go — every advisory identifier we ship is well-formed for its issuing
// authority.
//
// HERMETIC and always on: pure string checking over the built-in AdvisoryTable and the on-disk
// advisory corpus. No build, no exec, no network. It belongs in the default `go test ./...` because
// it costs nothing and because a malformed identifier is a fact about a string, knowable the moment
// the string is written.
//
// # What this is for
//
// The publication red-team found a FABRICATED advisory alias shipping in the built-in table:
// GHSA-vm622-x2cf-3blh. It cannot exist — a GHSA ID is three groups of exactly four characters and
// its first group here is five — and it 404s on OSV. Nothing in the tree noticed, because nothing
// in the tree had an opinion about what an advisory identifier looks like.
//
// An advisory ID is the customer's citation anchor: it is how they take our verdict to their own
// tracker, their own vendor, their own auditor. One that resolves nowhere converts a checkable
// claim into an unverifiable assertion, which is the opposite of what this tool sells.
//
// # Two layers, gated differently on purpose
//
//   - FORMAT (here): does the identifier obey its authority's published grammar? Hermetic, free,
//     always on. This layer alone catches the fabricated alias.
//   - EXISTENCE (advisory_id_osv_live_test.go): does the identifier actually resolve at OSV? That
//     needs the network, so it is opt-in and never fires in a customer's CI.
//
// # No silent skips
//
// An identifier whose prefix matches no known grammar FAILS. It is not skipped, and there is no
// exemption list. A skip is the same failure mode this test exists to close: a value nothing has an
// opinion about. Adding a new identifier namespace means adding its grammar here, with a citation.
package pipeline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// advisoryIDGrammar is one issuing authority's published identifier format.
type advisoryIDGrammar struct {
	// namespace is the first hyphen-separated segment, used to select the grammar.
	namespace string
	// pattern is the full-identifier grammar, anchored.
	pattern *regexp.Regexp
	// authority cites where the grammar comes from, so a future reader can check it rather than
	// trusting this file. Every one of these was read at the source, not recalled.
	authority string
}

// advisoryIDGrammars is the complete set of identifier namespaces this project ships. Anything
// outside it fails.
var advisoryIDGrammars = []advisoryIDGrammar{
	{
		// CVE Program ID syntax: "CVE" + 4-digit year + a sequence number of AT LEAST four digits.
		// The 2014 syntax change removed the fixed 4-digit cap precisely so the sequence could grow
		// (CVE-2014-0001 through CVE-2021-1234567 are all valid), so the grammar must not pin the
		// sequence to four — a 5+ digit CVE is correct, not a defect.
		namespace: "CVE",
		pattern:   regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`),
		authority: "CVE Program ID syntax (post-2014 syntax change): CVE-YYYY-NNNN with 4+ sequence digits",
	},
	{
		// GitHub Security Advisory ID. The grammar is published verbatim by the advisory database
		// itself: "The syntax of GHSA IDs follows this format: GHSA-xxxx-xxxx-xxxx where x is a
		// letter or a number from the following set: 23456789cfghjmpqrvwx", with the regex
		// /GHSA(-[23456789cfghjmpqrvwx]{4}){3}/. The alphabet excludes vowels and visually
		// confusable characters, which is why both the LENGTH and the ALPHABET are load-bearing:
		// GHSA-vm622-x2cf-3blh violates both (a five-character first group, and b/l in the third).
		namespace: "GHSA",
		pattern:   regexp.MustCompile(`^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$`),
		authority: "github/advisory-database README — GHSA-xxxx-xxxx-xxxx over the set 23456789cfghjmpqrvwx",
	},
	{
		// Go vulnerability database entry. "The id field is a unique identifier for the
		// vulnerability entry. It is a string of the format GO-<YEAR>-<ENTRYID>." Entry IDs are
		// sequential and zero-padded to four; they are not capped at four, so the grammar allows
		// more.
		namespace: "GO",
		pattern:   regexp.MustCompile(`^GO-[0-9]{4}-[0-9]{4,}$`),
		authority: "go.dev/doc/security/vuln/database — GO-<YEAR>-<ENTRYID>",
	},
	{
		// OUR OWN synthetic first-party identifiers. These are deliberately not CVEs: they name
		// house canaries and corpus fixtures that no issuing authority has ever assigned, and
		// minting a CVE-shaped ID for one would be the fabrication defect in its purest form. They
		// get a grammar of their own rather than an exemption, because "we made it up" is not the
		// same as "it may be shaped however".
		//
		// Form: <ORG>-<CLASSIFIER>(-<CLASSIFIER>)*-<4-digit ordinal>, uppercase.
		// e.g. TEGRON-JS-SSRF-0001, TEGRON-GO-GRAFANA-DUCKDB-0001, FERRALON-APP-DOS-0001.
		namespace: "TEGRON",
		pattern:   regexp.MustCompile(`^TEGRON(-[A-Z][A-Z0-9]*)+-[0-9]{4}$`),
		authority: "first-party synthetic advisory id (this project) — ORG-CLASSIFIER…-NNNN",
	},
	{
		namespace: "FERRALON",
		pattern:   regexp.MustCompile(`^FERRALON(-[A-Z][A-Z0-9]*)+-[0-9]{4}$`),
		authority: "first-party synthetic advisory id (this project) — ORG-CLASSIFIER…-NNNN",
	},
}

// checkAdvisoryID validates one identifier and returns "" when it is well-formed, or an explanation
// of what is wrong with it.
func checkAdvisoryID(id string) string {
	if id == "" {
		return "is an empty advisory identifier"
	}
	ns, _, ok := strings.Cut(id, "-")
	if !ok {
		return "carries no <namespace>-<id> structure"
	}
	for _, g := range advisoryIDGrammars {
		if g.namespace != ns {
			continue
		}
		if g.pattern.MatchString(id) {
			return ""
		}
		return "is malformed for its issuing authority\n    grammar:   " + g.pattern.String() +
			"\n    authority: " + g.authority + explainGHSA(id, ns)
	}
	known := make([]string, 0, len(advisoryIDGrammars))
	for _, g := range advisoryIDGrammars {
		known = append(known, g.namespace)
	}
	return "uses the unknown identifier namespace " + ns + "\n" +
		"    known namespaces: " + strings.Join(known, ", ") + "\n" +
		"    an unrecognized namespace fails deliberately — add its published grammar above (with a\n" +
		"    citation) rather than exempting it; a silent skip is the defect this test closes"
}

// explainGHSA points at the offending group, because "malformed" is much less useful than "group 1
// is five characters" when the identifier looks plausible at a glance.
func explainGHSA(id, ns string) string {
	if ns != "GHSA" {
		return ""
	}
	groups := strings.Split(id, "-")[1:]
	var notes []string
	if len(groups) != 3 {
		notes = append(notes, "has "+strconv.Itoa(len(groups))+" groups, not 3")
	}
	for i, g := range groups {
		if len(g) != 4 {
			notes = append(notes, "group "+strconv.Itoa(i+1)+" ("+g+") is "+strconv.Itoa(len(g))+" characters, not 4")
		}
		if bad := strings.Map(func(r rune) rune {
			if strings.ContainsRune("23456789cfghjmpqrvwx", r) {
				return -1
			}
			return r
		}, g); bad != "" {
			notes = append(notes, "group "+strconv.Itoa(i+1)+" ("+g+") uses "+bad+", outside the GHSA alphabet")
		}
	}
	if len(notes) == 0 {
		return ""
	}
	return "\n    specifically: " + strings.Join(notes, "; ")
}

// idsFrom collects every advisory identifier an AdvisoryFacts carries: its aliases and both lineage
// pointers. The entry's own key is collected by the caller, which knows it.
func idsFrom(f AdvisoryFacts) []string {
	out := append([]string(nil), f.Aliases...)
	if f.Lineage.IncompleteFixOf != "" {
		out = append(out, f.Lineage.IncompleteFixOf)
	}
	if f.Lineage.RefixedBy != "" {
		out = append(out, f.Lineage.RefixedBy)
	}
	return out
}

// TestAdvisoryIDs_BuiltInTableIsWellFormed checks the compiled-in advisory table: every key, every
// alias, and every lineage pointer.
func TestAdvisoryIDs_BuiltInTableIsWellFormed(t *testing.T) {
	if len(AdvisoryTable) == 0 {
		t.Fatal("AdvisoryTable is empty — this test is checking nothing")
	}
	keys := make([]string, 0, len(AdvisoryTable))
	for k := range AdvisoryTable {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var checked int
	for _, id := range keys {
		facts := AdvisoryTable[id]
		if why := checkAdvisoryID(id); why != "" {
			t.Errorf("AdvisoryTable key %q %s", id, why)
		}
		checked++
		for _, alias := range idsFrom(facts) {
			checked++
			if why := checkAdvisoryID(alias); why != "" {
				t.Errorf("AdvisoryTable[%q] carries the identifier %q, which %s\n"+
					"  we publish this identifier to the customer as a citation; one that cannot exist\n"+
					"  turns a checkable claim into an unverifiable assertion",
					id, alias, why)
			}
		}
	}
	t.Logf("checked %d identifiers across %d built-in advisories", checked, len(keys))
}

// advisoryCorpusFixtureDir is the on-disk advisory corpus shipped in the tree — the same root
// pipeline/advisory_corpus_test.go points ArtifactSource at, and the shape a real corpus install
// takes. Its facts reach the customer exactly as the built-in table's do, so it gets the same check.
const advisoryCorpusFixtureDir = "../corpus/testdata/advisories"

// TestAdvisoryIDs_ShippedCorpusIsWellFormed checks the on-disk corpus: the manifest's advisory keys,
// each per-advisory file's name, and the identifiers inside each file.
func TestAdvisoryIDs_ShippedCorpusIsWellFormed(t *testing.T) {
	entries, err := os.ReadDir(advisoryCorpusFixtureDir)
	if err != nil {
		t.Fatalf("reading the shipped advisory corpus at %s: %v", advisoryCorpusFixtureDir, err)
	}

	var manifest struct {
		Advisories map[string]struct {
			File string `json:"file"`
		} `json:"advisories"`
	}
	readJSON(t, filepath.Join(advisoryCorpusFixtureDir, "manifest.json"), &manifest)
	if len(manifest.Advisories) == 0 {
		t.Fatal("corpus manifest lists no advisories — this test is checking nothing")
	}
	manifestKeys := make([]string, 0, len(manifest.Advisories))
	for k := range manifest.Advisories {
		manifestKeys = append(manifestKeys, k)
	}
	sort.Strings(manifestKeys)
	for _, id := range manifestKeys {
		if why := checkAdvisoryID(id); why != "" {
			t.Errorf("corpus manifest advisory key %q %s", id, why)
		}
	}

	var files int
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || name == "manifest.json" || name == attributionStoreFile {
			continue
		}
		files++
		id := strings.TrimSuffix(name, ".json")
		if why := checkAdvisoryID(id); why != "" {
			t.Errorf("corpus advisory file %s names the identifier %q, which %s", name, id, why)
		}
		var facts AdvisoryFacts
		readJSON(t, filepath.Join(advisoryCorpusFixtureDir, name), &facts)
		for _, alias := range idsFrom(facts) {
			if why := checkAdvisoryID(alias); why != "" {
				t.Errorf("corpus advisory %s carries the identifier %q, which %s", name, alias, why)
			}
		}
	}
	if files == 0 {
		t.Fatalf("no advisory files under %s — the walk is broken, not the corpus", advisoryCorpusFixtureDir)
	}
	t.Logf("checked %d manifest keys and %d advisory files", len(manifestKeys), files)
}

// TestAdvisoryIDs_GrammarsRejectAndAccept pins the grammars themselves. Without it a typo that
// loosened a pattern (a stray `?`, a dropped anchor) would silently disarm every check above, and
// the suite would go green for the wrong reason.
func TestAdvisoryIDs_GrammarsRejectAndAccept(t *testing.T) {
	for _, tc := range []struct {
		id   string
		want bool
		why  string
	}{
		{"CVE-2024-55947", true, "ordinary CVE"},
		{"CVE-2021-1234567", true, "long-sequence CVE — valid since the 2014 syntax change"},
		{"CVE-2024-123", false, "sequence shorter than four digits"},
		{"CVE-24-1234", false, "two-digit year"},
		{"GHSA-ppp9-7jff-5vj2", true, "real GHSA"},
		{"GHSA-vm622-x2cf-3blh", false, "THE BLOCKER: five-character first group, and b/l are outside the alphabet"},
		{"GHSA-ppp9-7jff", false, "two groups"},
		{"GHSA-aaaa-bbbb-cccc", false, "vowels and out-of-alphabet letters"},
		{"GHSA-ppp9-7jff-5vj2-5vj2", false, "four groups"},
		{"GO-2021-0113", true, "real Go entry"},
		{"GO-2021-113", false, "three-digit entry id"},
		{"TEGRON-JS-SSRF-0001", true, "first-party synthetic"},
		{"TEGRON-GO-GRAFANA-DUCKDB-0001", true, "first-party synthetic, multi-classifier"},
		{"FERRALON-APP-DOS-0001", true, "first-party synthetic"},
		{"TEGRON-0001", false, "no classifier segment"},
		{"TEGRON-js-ssrf-0001", false, "lowercase classifier"},
		{"OSV-2020-111", false, "namespace we do not ship — must fail, not skip"},
		{"", false, "empty"},
		{"nonsense", false, "no namespace structure"},
	} {
		why := checkAdvisoryID(tc.id)
		if got := why == ""; got != tc.want {
			t.Errorf("checkAdvisoryID(%q) accepted=%v, want %v (%s)\n  %s", tc.id, got, tc.want, tc.why, why)
		}
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
}
