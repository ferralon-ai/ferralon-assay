package pythonanalysis

import (
	"crypto/sha256"
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const airflowVulnSrc = "../../../corpus/testdata/repros/TEGRON-PY-AIRFLOW-EXPAPI-0001-vulnerable/src"

// assembledMap builds the shipped mapping the way production assembly would: the six inline
// curated rows + the first-party declared derivation from the AIRFLOW repro + a declared-unknown
// for the malformed distribution. It is the fixture C2a/C5/C6 assert over.
func assembledMap(t *testing.T) DistImportMap {
	t.Helper()
	plan := checkout.WorkspacePlan{
		Root:     airflowVulnSrc,
		Projects: []checkout.Project{{Root: airflowVulnSrc, Language: checkout.LangPython}},
	}
	declared, err := DeriveFirstParty("tegron-corpus-app", plan)
	if err != nil {
		t.Fatalf("DeriveFirstParty: %v", err)
	}
	var all []Contribution
	all = append(all, CuratedContributions()...)
	all = append(all, declared...)
	all = append(all, DeclaredUnknown("tegron-test-malformed"))
	m := NewDistImportMap(all...)
	if err := m.Validate(); err != nil {
		t.Fatalf("assembled map fails Validate: %v", err)
	}
	return m
}

// --- C1: the mapping is many-to-many in both directions ---------------------------------

// c1Map covers the four required shapes: one-to-one, one-dist-to-many, many-dist-to-one
// (namespace), and lookup-by-import-returns->1-dist.
func c1Contributions() []Contribution {
	var c []Contribution
	// one-to-one
	c = append(c, Contribution{Distribution: "flask", ImportPackage: "flask", Provenance: ProvenanceDeclared})
	// one-dist-to-many: protobuf contributes two import packages
	c = append(c,
		Contribution{Distribution: "protobuf", ImportPackage: "google.protobuf", Provenance: ProvenanceDeclared},
		Contribution{Distribution: "protobuf", ImportPackage: "google._upb", Provenance: ProvenanceDeclared},
	)
	// many-dist-to-one (namespace): acme-foo/acme-bar under root acme
	c = append(c, NamespaceFixture()...)
	// lookup-by-import returns >1 dist: two distributions contribute the identical import "widget"
	c = append(c,
		Contribution{Distribution: "widget-a", ImportPackage: "widget", Provenance: ProvenanceDeclared},
		Contribution{Distribution: "widget-b", ImportPackage: "widget", Provenance: ProvenanceDeclared},
	)
	return c
}

func TestC1_ManyToManyBothDirections(t *testing.T) {
	m := NewDistImportMap(c1Contributions()...)

	tests := []struct {
		name string
		kind string // "forward" or "reverse"
		key  string
		want []string
	}{
		{"one-to-one", "forward", "flask", []string{"flask"}},
		{"one-dist-to-many", "forward", "protobuf", []string{"google._upb", "google.protobuf"}},
		{"many-dist-to-one namespace", "reverse", "acme", []string{"acme-bar", "acme-foo"}},
		{"lookup-by-import >1 dist", "reverse", "widget", []string{"widget-a", "widget-b"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			switch tc.kind {
			case "forward":
				got = m.Forward(tc.key)
			case "reverse":
				got = m.Reverse(tc.key)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("%s(%q) = %v, want %v", tc.kind, tc.key, got, tc.want)
			}
		})
	}
}

// TestC1_MapStringStringReductionFails is the mandated control: reduce the type to a
// map[distribution]importPackage and confirm at least two of the four rows break. A shape that
// still passes under this reduction is not testing the many-to-many shape.
func TestC1_MapStringStringReductionFails(t *testing.T) {
	m := NewDistImportMap(c1Contributions()...)

	// The reduction: one import package per distribution — last write wins.
	reduced := map[string]string{}
	for _, c := range m.Contributions {
		reduced[c.Distribution] = c.ImportPackage
	}
	// A reverse index the reduction can build is only by ranging the VALUES (no key access):
	// exact match, no dotted-prefix namespace rule.
	reducedReverse := func(imp string) []string {
		var out []string
		for dist, im := range reduced {
			if im == imp {
				out = append(out, dist)
			}
		}
		sort.Strings(out)
		return out
	}

	failures := 0

	// Row (one-dist-to-many): the reduction holds one package for protobuf; the real map holds two.
	if realN, redN := len(m.Forward("protobuf")), len([]string{reduced["protobuf"]}); realN <= redN {
		t.Fatalf("expected one-dist-to-many to lose a contribution under reduction (real=%d, reduced=1)", realN)
	} else {
		failures++
	}

	// Row (many-dist-to-one namespace): the reduction's values are the leaf paths acme.foo/acme.bar;
	// the namespace root "acme" is not a value, so the reverse lookup is unrecoverable (empty), while
	// the real map returns both via the dotted-prefix rule.
	if real, red := m.Reverse("acme"), reducedReverse("acme"); len(real) == 2 && len(red) == 0 {
		failures++
	} else {
		t.Fatalf("expected namespace reverse to be unrecoverable under reduction (real=%v, reduced=%v)", real, red)
	}

	if failures < 2 {
		t.Fatalf("map[string]string reduction must break >=2 rows; broke %d", failures)
	}
}

// --- C2: every entry carries provenance; observed exists before anything produces it ------

// TestC2a_EveryEntryHasNonZeroProvenance asserts every produced contribution has a non-zero,
// recognized provenance, and that a zero-value entry fails the validator.
func TestC2a_EveryEntryHasNonZeroProvenance(t *testing.T) {
	m := assembledMap(t)
	for i, c := range m.Contributions {
		if c.Provenance == "" || !knownProvenance[c.Provenance] {
			t.Fatalf("contribution %d (%q→%q) has invalid provenance %q", i, c.Distribution, c.ImportPackage, c.Provenance)
		}
	}
	// A zero-value entry must redden Validate.
	bad := DistImportMap{Contributions: []Contribution{{Distribution: "x", ImportPackage: "x"}}}
	if err := bad.Validate(); err == nil {
		t.Fatal("Validate accepted a zero-value Provenance entry (C2a)")
	}
}

// TestC2b_ObservedDistinguishableFromCurated constructs an observed entry BY HAND (nothing else
// produces one) and asserts it round-trips through JSON and is distinguishable from a curated
// entry with identical distribution and import names — if the two compare equal, PLAN-270's
// curated→observed upgrade would be invisible.
func TestC2b_ObservedDistinguishableFromCurated(t *testing.T) {
	observed := Contribution{Distribution: "airflow-provider-x", ImportPackage: "airflow.providers.x", Provenance: ProvenanceObserved}
	curated := Contribution{
		Distribution:  "airflow-provider-x",
		ImportPackage: "airflow.providers.x",
		Provenance:    ProvenanceCurated,
		Source:        "hand-built curated twin for C2b",
		Date:          "2026-08-10",
	}

	// Distinguishable at the identity level: same dist+import, different provenance ⇒ NOT equal.
	if sameIdentity(observed, curated) {
		t.Fatal("observed and curated with identical names share identity (C2b): upgrade would be invisible")
	}
	if reflect.DeepEqual(observed, curated) {
		t.Fatal("observed and curated compare fully equal (C2b)")
	}

	// Both survive canonicalization as DISTINCT contributions (not collapsed to one).
	m := NewDistImportMap(observed, curated)
	if len(m.Contributions) != 2 {
		t.Fatalf("canonicalize collapsed distinct-provenance twins: got %d, want 2", len(m.Contributions))
	}

	// Round-trip: the observed provenance is preserved through JSON.
	raw, err := json.Marshal(observed)
	if err != nil {
		t.Fatalf("marshal observed: %v", err)
	}
	var back Contribution
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal observed: %v", err)
	}
	if back.Provenance != ProvenanceObserved {
		t.Fatalf("observed did not round-trip: got provenance %q", back.Provenance)
	}
}

// --- C3: namespace packages do not collapse ----------------------------------------------

func TestC3_NamespaceDoesNotCollapse(t *testing.T) {
	m := NewDistImportMap(NamespaceFixture()...)

	// (a) forward per dist returns only its own contributed leaf.
	if got, want := m.Forward("acme-foo"), []string{"acme.foo"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Forward(acme-foo) = %v, want %v", got, want)
	}
	if got, want := m.Forward("acme-bar"), []string{"acme.bar"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Forward(acme-bar) = %v, want %v", got, want)
	}
	// (b) reverse on the namespace root returns BOTH, sorted.
	if got, want := m.Reverse("acme"), []string{"acme-bar", "acme-foo"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Reverse(acme) = %v, want %v", got, want)
	}
	// (c) neither forward result contains the bare root as an exclusively-owned entry.
	for _, dist := range []string{"acme-foo", "acme-bar"} {
		for _, imp := range m.Forward(dist) {
			if imp == "acme" {
				t.Fatalf("Forward(%q) contains the bare namespace root", dist)
			}
		}
	}
}

// TestC3_CollapseControlReddensBoth is the mandated control: collapsing the two leaves into a
// single owner of the bare root must redden BOTH (b) and (c). If only one reddened, one
// assertion would be redundant.
func TestC3_CollapseControlReddensBoth(t *testing.T) {
	collapsed := NewDistImportMap(Contribution{
		Distribution:  "acme-foo",
		ImportPackage: "acme", // one distribution now owns the bare root; leaves dropped
		Provenance:    ProvenanceCurated,
		Source:        namespaceFixtureSource,
		Date:          curatedTableDate,
	})

	// (b) reddens: Reverse("acme") returns only one owner, not both.
	if got := collapsed.Reverse("acme"); reflect.DeepEqual(got, []string{"acme-bar", "acme-foo"}) {
		t.Fatal("collapse control did not redden (b): Reverse(acme) still returns both")
	} else if !reflect.DeepEqual(got, []string{"acme-foo"}) {
		t.Fatalf("collapse control (b): got %v, want [acme-foo]", got)
	}

	// (c) reddens: Forward("acme-foo") now contains the bare root as an exclusively-owned entry.
	ownsRoot := false
	for _, imp := range collapsed.Forward("acme-foo") {
		if imp == "acme" {
			ownsRoot = true
		}
	}
	if !ownsRoot {
		t.Fatal("collapse control did not redden (c): Forward(acme-foo) does not own the bare root")
	}
}

// --- C4: an unknown distribution yields a declared unknown, never a name-identity guess ---

func TestC4_UnknownIsDeclaredNotGuessed(t *testing.T) {
	const absent = "tegron-test-malformed"
	m := NewDistImportMap(
		DeclaredUnknown(absent),
		// negative control: a distribution whose import name genuinely equals its dist name.
		Contribution{Distribution: "flask", ImportPackage: "flask", Provenance: ProvenanceCurated, Source: "PyPI flask", Date: "2026-08-10"},
		// the load-bearing non-identity row.
		Contribution{Distribution: "apache-airflow", ImportPackage: "airflow", Provenance: ProvenanceCurated, Source: "PyPI apache-airflow", Date: "2026-08-10"},
	)
	if err := m.Validate(); err != nil {
		t.Fatalf("map fails Validate: %v", err)
	}

	// The unknown distribution is PRESENT, marked unknown, empty import, with partiality.
	var found *Contribution
	for i := range m.Contributions {
		if m.Contributions[i].Distribution == absent {
			found = &m.Contributions[i]
		}
	}
	if found == nil {
		t.Fatalf("unknown distribution %q absent from the map (C4: present, not empty)", absent)
	}
	if found.Provenance != ProvenanceUnknown {
		t.Fatalf("unknown dist provenance = %q, want unknown", found.Provenance)
	}
	if found.ImportPackage != "" {
		t.Fatalf("unknown dist ImportPackage = %q, want empty", found.ImportPackage)
	}
	if found.Partiality == nil {
		t.Fatal("unknown dist carries no Partiality (C4)")
	}
	// Forward returns EMPTY — never the distribution name.
	if got := m.Forward(absent); len(got) != 0 {
		t.Fatalf("Forward(%q) = %v, want empty (no name-identity fallback)", absent, got)
	}

	// Negative control: identity and non-identity rows are classified by PROVENANCE, not by the
	// name coincidence. flask→flask is curated; apache-airflow→airflow is curated and NON-identity.
	if got, want := m.Forward("flask"), []string{"flask"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Forward(flask) = %v, want %v", got, want)
	}
	if got, want := m.Forward("apache-airflow"), []string{"airflow"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Forward(apache-airflow) = %v, want %v (non-identity, proves not strings.ToLower)", got, want)
	}
	for _, c := range m.Contributions {
		if c.Provenance == ProvenanceCurated && (c.Distribution == "flask" || c.Distribution == "apache-airflow") && c.Source == "" {
			t.Fatalf("curated row %q classified without a source (identity coincidence, not provenance)", c.Distribution)
		}
	}
}

// TestC4_IdentityFallbackMutationReddens is the mutation control: adding an
// import-name-equals-distribution-name fallback must redden the unknown assertion.
func TestC4_IdentityFallbackMutationReddens(t *testing.T) {
	const absent = "tegron-test-malformed"
	m := NewDistImportMap(DeclaredUnknown(absent))

	// The forbidden mutation: fall back to the distribution name when Forward is empty.
	forwardWithIdentityFallback := func(dist string) []string {
		if fwd := m.Forward(dist); len(fwd) > 0 {
			return fwd
		}
		return []string{dist} // <- the name-identity guess C4 forbids
	}

	// The real Forward returns empty (the assertion the honest path passes).
	if got := m.Forward(absent); len(got) != 0 {
		t.Fatalf("Forward(%q) unexpectedly non-empty: %v", absent, got)
	}
	// Under the mutation the same assertion reddens — proving it bites on the guess.
	if got := forwardWithIdentityFallback(absent); len(got) == 0 || got[0] != absent {
		t.Fatalf("identity-fallback mutation did not produce the guessed name: %v", got)
	}
}

// --- C5: the curated table is auditable row by row ----------------------------------------

func TestC5_CuratedRowsCarrySourceAndDate(t *testing.T) {
	rows := append(CuratedContributions(), NamespaceFixture()...)
	if len(rows) == 0 {
		t.Fatal("no curated rows")
	}
	for _, c := range rows {
		if c.Provenance != ProvenanceCurated {
			t.Fatalf("row %q is not curated: %q", c.Distribution, c.Provenance)
		}
		if c.Source == "" {
			t.Fatalf("curated row %q has empty Source (C5)", c.Distribution)
		}
		if c.Date == "" {
			t.Fatalf("curated row %q has empty Date (C5)", c.Distribution)
		}
	}
	// The validator also enforces C5; a curated row with an empty Source must redden.
	bad := DistImportMap{Contributions: []Contribution{{Distribution: "x", ImportPackage: "x", Provenance: ProvenanceCurated, Date: "2026-08-10"}}}
	if err := bad.Validate(); err == nil {
		t.Fatal("Validate accepted a curated row with empty Source (C5)")
	}
}

// TestC5_AirflowNonIdentityRowPresent pins the load-bearing non-identity row: apache-airflow
// contributes airflow (not apache-airflow). It is the only corpus row where the import name is
// not the distribution name, so it is what proves the map is a real lookup, not strings.ToLower.
func TestC5_AirflowNonIdentityRowPresent(t *testing.T) {
	var row *Contribution
	for _, c := range CuratedContributions() {
		if c.Distribution == "apache-airflow" {
			c := c
			row = &c
		}
	}
	if row == nil {
		t.Fatal("apache-airflow curated row missing")
	}
	if row.ImportPackage != "airflow" {
		t.Fatalf("apache-airflow import = %q, want airflow", row.ImportPackage)
	}
	if row.ImportPackage == row.Distribution {
		t.Fatal("apache-airflow is a name-identity row; the load-bearing non-identity case is gone")
	}
	if row.Source == "" || row.Date == "" {
		t.Fatal("apache-airflow row lacks a cited Source/Date")
	}
}

// --- C6: output is deterministic across processes and the module is green -----------------

// TestC6_SerializationDeterministic serializes the assembled map >=50 times in-process, asserts
// every run is byte-identical, and logs a sha256 for cross-process comparison. NO checked-in
// golden — a repeat-run is what the criterion requires.
func TestC6_SerializationDeterministic(t *testing.T) {
	m := assembledMap(t)

	first, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for i := 0; i < 60; i++ {
		next, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal run %d: %v", i, err)
		}
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("serialization not byte-identical on run %d", i)
		}
	}
	sum := sha256.Sum256(first)
	t.Logf("C6 assembled-map serialization sha256 = %x (compare across separate process runs)", sum)

	// Forward/Reverse are likewise stable across repeated calls.
	for _, dist := range []string{"apache-airflow", "tegron-corpus-app"} {
		want := m.Forward(dist)
		for i := 0; i < 60; i++ {
			if got := m.Forward(dist); !reflect.DeepEqual(got, want) {
				t.Fatalf("Forward(%q) non-deterministic on run %d: %v vs %v", dist, i, got, want)
			}
		}
	}
}

// TestFirstPartyDerivation checks the declared derivation from WorkspacePlan + source layout:
// import packages come from the top-level module names, provenance is declared (no source), and
// the distribution name is the supplied first-party identity.
func TestFirstPartyDerivation(t *testing.T) {
	plan := checkout.WorkspacePlan{
		Root:     airflowVulnSrc,
		Projects: []checkout.Project{{Root: airflowVulnSrc, Language: checkout.LangPython}},
	}
	got, err := DeriveFirstParty("tegron-corpus-app", plan)
	if err != nil {
		t.Fatalf("DeriveFirstParty: %v", err)
	}
	var imports []string
	for _, c := range got {
		if c.Provenance != ProvenanceDeclared {
			t.Fatalf("first-party contribution %q provenance = %q, want declared", c.ImportPackage, c.Provenance)
		}
		if c.Distribution != "tegron-corpus-app" {
			t.Fatalf("first-party distribution = %q, want tegron-corpus-app", c.Distribution)
		}
		if c.Source != "" || c.Date != "" || c.Partiality != nil {
			t.Fatalf("declared contribution %q carries curated/unknown fields", c.ImportPackage)
		}
		imports = append(imports, c.ImportPackage)
	}
	sort.Strings(imports)
	want := []string{"endpoints", "get_code", "init_views"}
	if !reflect.DeepEqual(imports, want) {
		t.Fatalf("derived import packages = %v, want %v", imports, want)
	}
	// A declared contribution must pass the validator (no source/date required for declared).
	if err := NewDistImportMap(got...).Validate(); err != nil {
		t.Fatalf("declared map fails Validate: %v", err)
	}
}

// TestValidatorInvariants exercises the D1 invariants directly.
func TestValidatorInvariants(t *testing.T) {
	p := plugin.Unsupported()
	cases := []struct {
		name    string
		contrib Contribution
		wantErr bool
	}{
		{"valid declared", Contribution{Distribution: "d", ImportPackage: "i", Provenance: ProvenanceDeclared}, false},
		{"valid unknown", Contribution{Distribution: "d", Provenance: ProvenanceUnknown, Partiality: &p}, false},
		{"unknown without partiality", Contribution{Distribution: "d", Provenance: ProvenanceUnknown}, true},
		{"unknown with import package", Contribution{Distribution: "d", ImportPackage: "i", Provenance: ProvenanceUnknown, Partiality: &p}, true},
		{"non-unknown with partiality", Contribution{Distribution: "d", ImportPackage: "i", Provenance: ProvenanceDeclared, Partiality: &p}, true},
		{"unrecognized provenance", Contribution{Distribution: "d", ImportPackage: "i", Provenance: Provenance("bogus")}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := DistImportMap{Contributions: []Contribution{tc.contrib}}.Validate()
			if tc.wantErr != (err != nil) {
				t.Fatalf("Validate err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}
