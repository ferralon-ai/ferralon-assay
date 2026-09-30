package pipeline

import (
	"reflect"
	"sort"
	"testing"
)

// TestArtifactSource_KnownIDs: the tree reader enumerates its manifest, sorted, and an unusable
// manifest enumerates nothing rather than erroring.
func TestArtifactSource_KnownIDs(t *testing.T) {
	src := NewArtifactSource(advisoryFixtureRoot)
	enum, ok := src.(AdvisoryEnumerator)
	if !ok {
		t.Fatal("artifactSource does not satisfy AdvisoryEnumerator")
	}
	got := enum.KnownIDs()
	want := []string{
		"TEGRON-TEST-0001", "TEGRON-TEST-ABSPATH", "TEGRON-TEST-BACKSLASH", "TEGRON-TEST-BADDIGEST",
		"TEGRON-TEST-DATED", "TEGRON-TEST-DOTDOT", "TEGRON-TEST-MALFORMED",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("KnownIDs() = %v, want %v", got, want)
	}
	if !sort.StringsAreSorted(got) {
		t.Errorf("KnownIDs() not sorted: %v", got)
	}

	for _, root := range []string{"testdata/advisory_source/does-not-exist", "testdata/advisory_source/badcount", "testdata/advisory_source/dupid"} {
		if ids := NewArtifactSource(root).(AdvisoryEnumerator).KnownIDs(); len(ids) != 0 {
			t.Errorf("KnownIDs() on unusable corpus %s = %v, want empty", root, ids)
		}
	}
}

// TestLookupEach_MatchesLookup: the bulk path returns, id for id and in order, exactly what Lookup
// returns — including every fail-open case in the fixture corpus and an id the corpus lacks — for
// the tree reader (which batches) and for a source that does not (the plain-Lookup fallback).
func TestLookupEach_MatchesLookup(t *testing.T) {
	ids := append(NewArtifactSource(advisoryFixtureRoot).(AdvisoryEnumerator).KnownIDs(), "TEGRON-TEST-ABSENT", "GO-2021-0113")

	for _, tc := range []struct {
		name string
		src  AdvisorySource
	}{
		{"tree reader", NewArtifactSource(advisoryFixtureRoot)},
		{"tree reader, missing manifest", NewArtifactSource("testdata/advisory_source/does-not-exist")},
		{"chain (plain Lookup)", NewChainSource(NewArtifactSource(advisoryFixtureRoot), NewTableSource())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var seen []string
			LookupEach(tc.src, ids, func(id string, facts AdvisoryFacts, ok bool) {
				seen = append(seen, id)
				wantFacts, wantOK := tc.src.Lookup(id)
				if ok != wantOK || !reflect.DeepEqual(facts, wantFacts) {
					t.Errorf("%s: LookupEach = (%v, ok=%v), Lookup = (%v, ok=%v)", id, facts, ok, wantFacts, wantOK)
				}
			})
			if !reflect.DeepEqual(seen, ids) {
				t.Errorf("LookupEach visited %v, want %v in order", seen, ids)
			}
		})
	}
}

// TestAffectedPackageKeys: the identities an advisory is matched to a codebase by are the ones
// codebase_inventory resolves a version by.
func TestAffectedPackageKeys(t *testing.T) {
	for _, tc := range []struct {
		name  string
		facts AdvisoryFacts
		want  []PackageKey
	}{
		{
			name:  "go module from the table (module field)",
			facts: AdvisoryFacts{Module: "golang.org/x/text", PURL: "pkg:golang/golang.org/x/text"},
			want:  []PackageKey{{"golang", "golang.org/x/text"}},
		},
		{
			name:  "go stdlib by go-toolchain scheme",
			facts: AdvisoryFacts{VersionScheme: "go-toolchain", PURL: "pkg:golang/stdlib"},
			want:  []PackageKey{{"golang", "stdlib"}},
		},
		{
			name:  "go stdlib by PURL alone",
			facts: AdvisoryFacts{PURL: "pkg:golang/stdlib"},
			want:  []PackageKey{{"golang", "stdlib"}},
		},
		{
			name:  "maven coordinate",
			facts: AdvisoryFacts{Coordinate: "org.example:lib", PURL: "pkg:maven/org.example/lib", VersionScheme: "maven"},
			want:  []PackageKey{{"maven", "org.example:lib"}},
		},
		{
			name:  "coordinate with no PURL keeps an unknown ecosystem",
			facts: AdvisoryFacts{Coordinate: "left-pad"},
			want:  []PackageKey{{"", "left-pad"}},
		},
		{
			name: "multi-package: every element, then the primary, deduplicated",
			facts: AdvisoryFacts{
				Coordinate: "a", PURL: "pkg:npm/a",
				AffectedPackages: []AffectedPackage{
					{Coordinate: "a", PURL: "pkg:npm/a"},
					{Coordinate: "b", PURL: "pkg:npm/b"},
				},
			},
			want: []PackageKey{{"npm", "a"}, {"npm", "b"}},
		},
		{
			name:  "no affected package",
			facts: AdvisoryFacts{Summary: "kernel bug", CWEs: []string{"CWE-416"}},
			want:  nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := AffectedPackageKeys(tc.facts); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("AffectedPackageKeys = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAffectedPackageKeys_CorpusGoCoordinate: a published-corpus Go record spells the module in
// `coordinate`; toFacts projects it onto Module, so it matches the go.mod require by module path.
func TestAffectedPackageKeys_CorpusGoCoordinate(t *testing.T) {
	doc := advisoryDoc{
		SchemaVersion: normalizedAdvisorySchemaVersionV3,
		VulnID:        "TEST-1",
		Coordinate:    "golang.org/x/crypto",
		PURL:          "pkg:golang/golang.org/x/crypto",
		VersionScheme: "gomod",
	}
	facts, ok := doc.toFacts("TEST-1")
	if !ok {
		t.Fatal("toFacts rejected a valid record")
	}
	want := []PackageKey{{"golang", "golang.org/x/crypto"}}
	if got := AffectedPackageKeys(facts); !reflect.DeepEqual(got, want) {
		t.Errorf("AffectedPackageKeys = %v, want %v", got, want)
	}
}
