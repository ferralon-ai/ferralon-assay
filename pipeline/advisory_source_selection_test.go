// advisory_source_selection_test.go
//
// Runtime-selection tests for the AdvisorySource seam: the process-wide swappable default
// (SetDefaultAdvisorySource / defaultAdvisorySource / LookupAdvisoryFacts), the exported
// NewArtifactSource constructor, and the startup-only Validate() preflight. The preflight is a
// SEPARATE gate from Lookup's per-advisory fail-open (inv.5): Validate returns the real error a
// wholly-unusable corpus produces, while Lookup on the SAME broken root still collapses to
// (zero, false) — proven together below.
package pipeline

import (
	"reflect"
	"strings"
	"testing"
)

// selectionStubSource is a distinctive AdvisorySource: it returns the same sentinel facts for every
// id, so a test can tell whether a read went through the injected/default-swapped source (sentinel
// module) or the built-in AdvisoryTable (the real module).
type selectionStubSource struct{ facts AdvisoryFacts }

func (s selectionStubSource) Lookup(string) (AdvisoryFacts, bool) { return s.facts, true }

// swapDefaultSource installs src as the process-wide default and restores the prior value in a
// t.Cleanup, so a test that mutates the global seam never leaks state into the next test.
func swapDefaultSource(t *testing.T, src AdvisorySource) {
	t.Helper()
	prev := defaultAdvisorySourceVar
	t.Cleanup(func() { defaultAdvisorySourceVar = prev })
	SetDefaultAdvisorySource(src)
}

// Unset (nil var) ⇒ defaultAdvisorySource() is tableSource: a known AdvisoryTable id resolves
// byte-identically to the built-in table, so an unconfigured process is unchanged.
func TestDefaultAdvisorySource_UnsetIsTableSource(t *testing.T) {
	// Guard against any leaked global state from another test in this package.
	prev := defaultAdvisorySourceVar
	defaultAdvisorySourceVar = nil
	t.Cleanup(func() { defaultAdvisorySourceVar = prev })

	if _, ok := defaultAdvisorySource().(tableSource); !ok {
		t.Fatalf("defaultAdvisorySource() = %T, want tableSource when unset", defaultAdvisorySource())
	}
	facts, ok := defaultAdvisorySource().Lookup("GO-2021-0113")
	if !ok {
		t.Fatal("defaultAdvisorySource().Lookup(GO-2021-0113) ok=false, want true (table hit)")
	}
	if facts.Module != "golang.org/x/text" {
		t.Fatalf("Module = %q, want golang.org/x/text (the AdvisoryTable value)", facts.Module)
	}
}

// SetDefaultAdvisorySource swaps what BOTH defaultAdvisorySource() and LookupAdvisoryFacts (the
// Prove-side read point) resolve through: after the swap a known table id returns the installed
// source's facts, not the table's.
func TestSetDefaultAdvisorySource_SwapsDefaultAndLookupAdvisoryFacts(t *testing.T) {
	const sentinel = "example.com/swapped/module"
	swapDefaultSource(t, selectionStubSource{facts: AdvisoryFacts{Module: sentinel}})

	if got := defaultAdvisorySource(); got.(selectionStubSource).facts.Module != sentinel {
		t.Fatalf("defaultAdvisorySource() did not return the installed source (got %T)", got)
	}
	// GO-2021-0113 is a real AdvisoryTable id (module golang.org/x/text). Through the swapped
	// default it must resolve to the sentinel instead — proving the swap reaches LookupAdvisoryFacts.
	if got := LookupAdvisoryFacts("GO-2021-0113"); got.Module != sentinel {
		t.Fatalf("LookupAdvisoryFacts(GO-2021-0113).Module = %q, want the swapped sentinel %q", got.Module, sentinel)
	}
}

// NewArtifactSource resolves a known fixture advisory from the schema-compatible corpus root.
func TestNewArtifactSource_ResolvesKnownFixture(t *testing.T) {
	src := NewArtifactSource(advisoryFixtureRoot)
	facts, ok := src.Lookup("TEGRON-TEST-0001")
	if !ok {
		t.Fatal("NewArtifactSource Lookup(TEGRON-TEST-0001) ok=false, want true")
	}
	if facts.Coordinate != "com.example.lib:widget" {
		t.Fatalf("Coordinate = %q, want com.example.lib:widget", facts.Coordinate)
	}
}

// inv.5 regression guard: an unknown id against a valid NewArtifactSource still fails open to
// (zero, false) — never a partial or laundered fact.
func TestNewArtifactSource_UnknownIDFailsOpen(t *testing.T) {
	src := NewArtifactSource(advisoryFixtureRoot)
	facts, ok := src.Lookup("TEGRON-TEST-NOPE")
	if ok {
		t.Fatal("NewArtifactSource Lookup(unknown) ok=true, want false (fail open)")
	}
	if !reflect.DeepEqual(facts, AdvisoryFacts{}) {
		t.Fatalf("unknown id returned non-zero facts %+v, want zero", facts)
	}
}

// Validate() passes on both schema-compatible valid roots — the source is usable, no preflight error.
// Exercised through the CorpusValidator interface the entrypoint type-asserts to.
func TestValidate_PassesOnValidRoots(t *testing.T) {
	for _, root := range []string{advisoryFixtureRoot, ferralonCorpusRoot} {
		v, ok := NewArtifactSource(root).(CorpusValidator)
		if !ok {
			t.Fatalf("NewArtifactSource(%q) does not implement CorpusValidator", root)
		}
		if err := v.Validate(); err != nil {
			t.Errorf("Validate(%q) = %v, want nil (valid corpus)", root, err)
		}
	}
}

// Validate() returns a DISTINCT, descriptive error for each wholly-unusable corpus (missing dir,
// record_count mismatch, duplicate identifier), AND a post-load Lookup on the same broken root STILL
// fails open — proving the startup gate is separate from the per-advisory fail-open (inv.5).
func TestValidate_ErrorsButLookupStillFailsOpen(t *testing.T) {
	tests := []struct {
		name        string
		root        string
		lookupID    string
		errContains string
	}{
		{"missing dir", "testdata/advisory_source/does-not-exist", "TEGRON-TEST-0001", "read advisory manifest"},
		{"record_count mismatch", "testdata/advisory_source/badcount", "TEGRON-TEST-BADCOUNT", "record_count"},
		{"duplicate identifier", "testdata/advisory_source/dupid", "TEGRON-TEST-DUP", "duplicate identifier"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := NewArtifactSource(tt.root)

			err := src.(CorpusValidator).Validate()
			if err == nil {
				t.Fatalf("Validate(%q) = nil, want an error (corpus is unusable)", tt.root)
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("Validate error %q does not mention %q", err.Error(), tt.errContains)
			}

			// The SPLIT: the same broken root, once handed to Lookup, still fails open — Validate's
			// error never leaks into a per-advisory read, never a fabricated not-affected.
			facts, ok := src.Lookup(tt.lookupID)
			if ok {
				t.Fatalf("Lookup(%q) ok=true against a corpus Validate rejected, want false (fail open)", tt.lookupID)
			}
			if !reflect.DeepEqual(facts, AdvisoryFacts{}) {
				t.Errorf("Lookup returned non-zero facts %+v against a broken corpus, want zero", facts)
			}
		})
	}
}

// The two errors for distinct failure modes must not collapse to the same message — each names its
// own cause so an operator can act on the preflight fatal.
func TestValidate_ErrorsAreDistinct(t *testing.T) {
	badcount := NewArtifactSource("testdata/advisory_source/badcount").(CorpusValidator).Validate()
	dupid := NewArtifactSource("testdata/advisory_source/dupid").(CorpusValidator).Validate()
	if badcount == nil || dupid == nil {
		t.Fatalf("expected both invalid corpora to error (badcount=%v dupid=%v)", badcount, dupid)
	}
	if badcount.Error() == dupid.Error() {
		t.Fatalf("record_count and duplicate-identifier errors are identical: %q", badcount.Error())
	}
}
