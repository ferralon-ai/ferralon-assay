// workset_test.go
//
// I-17(b): the scan path's work set is no longer 16 compiled-in ids. These tests pin the three
// properties that keep the widening honest — the compiled-in set is a floor that cannot be lost, a
// widening that did not happen is disclosed rather than rendered clean, and only ids the advisory
// source can actually answer for are admitted.
package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// fakeOSV is a scripted OSVClient: it returns ids for whatever packages it is handed, or an error.
type fakeOSV struct {
	ids  []string
	err  error
	seen []report.Package
}

func (f *fakeOSV) QueryBatch(_ context.Context, pkgs []report.Package) (trigger.OSVResult, error) {
	f.seen = pkgs
	if f.err != nil {
		return trigger.OSVResult{}, f.err
	}
	var res trigger.OSVResult
	for _, id := range f.ids {
		p := report.Package{}
		if len(pkgs) > 0 {
			p = pkgs[0]
		}
		res.Advisories = append(res.Advisories, trigger.OSVAdvisory{ID: id, Package: p})
	}
	return res, nil
}

// goFixture writes a minimal Go module tree and returns an *acquired for it.
func goFixture(t *testing.T, gomod string) *acquired {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	return &acquired{
		buildDir:   dir,
		language:   checkout.LangGo,
		repo:       "example.com/fixture",
		advisories: goAdvisoryCorpus(false),
	}
}

const fixtureGoMod = `module example.com/fixture

go 1.21.0

require (
	golang.org/x/crypto v0.30.0
	golang.org/x/text v0.3.6 // indirect
)
`

func ids(refs []assessment.VulnRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.ID)
	}
	return out
}

func hasID(refs []assessment.VulnRef, id string) bool {
	for _, r := range refs {
		if r.ID == id {
			return true
		}
	}
	return false
}

func hasReason(notes []report.PartialityNote, reason string) bool {
	for _, n := range notes {
		if n.Reason == reason {
			return true
		}
	}
	return false
}

// --- Property 1: the compiled-in set is a FLOOR --------------------------------------------

// TestWorkSet_FloorIsNeverLost is the acceptance gate the handoff states: no id that was evaluated
// before may stop being evaluated. It is asserted against the hostile cases — OSV returning nothing,
// OSV returning only junk, and OSV failing outright.
func TestWorkSet_FloorIsNeverLost(t *testing.T) {
	floor := goAdvisoryCorpus(false)

	for _, tc := range []struct {
		name string
		osv  *fakeOSV
	}{
		{"osv returns nothing", &fakeOSV{}},
		{"osv returns only ids we have no facts for", &fakeOSV{ids: []string{"GHSA-zzzz-zzzz-zzzz", "CVE-1999-0001"}}},
		{"osv fails", &fakeOSV{err: errors.New("dial tcp: no route to host")}},
		{"osv returns ids already in the floor", &fakeOSV{ids: []string{"CVE-2024-45337", "GO-2021-0113"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acq := goFixture(t, fixtureGoMod)
			ws := resolveWorkSet(context.Background(), acq, tc.osv, pipeline.NewTableSource())

			for _, want := range floor {
				if !hasID(ws.advisories, want.ID) {
					t.Errorf("floor id %q lost from the work set — the union must never narrow", want.ID)
				}
			}
			if len(ws.advisories) < len(floor) {
				t.Errorf("work set = %d ids, floor = %d: a widening cannot shrink the set", len(ws.advisories), len(floor))
			}
		})
	}
}

// TestWorkSet_NoDuplicateIDs proves the union de-duplicates: an OSV id already in the floor must not
// be evaluated twice (each evaluation is a full S1-S6 pass).
func TestWorkSet_NoDuplicateIDs(t *testing.T) {
	acq := goFixture(t, fixtureGoMod)
	osv := &fakeOSV{ids: []string{"CVE-2024-45337", "CVE-2024-45337", "GO-2021-0113"}}

	ws := resolveWorkSet(context.Background(), acq, osv, pipeline.NewTableSource())

	seen := map[string]int{}
	for _, id := range ids(ws.advisories) {
		seen[id]++
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("id %q appears %d times in the work set, want 1", id, n)
		}
	}
}

// --- Property 2: a widening that did not happen is DISCLOSED -------------------------------

// TestWorkSet_UnreachableOSVIsDisclosed is the I-03 contract at the work-set seam: a scan whose work
// set could not be determined is analysis that did not happen. It must not render as a clean scan.
func TestWorkSet_UnreachableOSVIsDisclosed(t *testing.T) {
	acq := goFixture(t, fixtureGoMod)
	ws := resolveWorkSet(context.Background(), acq, &fakeOSV{err: errors.New("network unreachable")}, pipeline.NewTableSource())

	if !hasReason(ws.partiality, reasonWorkSetNotWidened) {
		t.Fatalf("an unreachable OSV emitted no partiality note; notes = %+v", ws.partiality)
	}
	if ws.source != report.WorkSetBuiltinLanguageSet {
		t.Errorf("WorkSetSource = %q, want %q — only the floor actually ran", ws.source, report.WorkSetBuiltinLanguageSet)
	}
	if ws.widened != 0 {
		t.Errorf("widened = %d, want 0", ws.widened)
	}
}

// TestWorkSet_NoManifestIsDisclosed proves a repository whose dependencies could not be read says so
// rather than reporting a work set that silently covers nothing new.
func TestWorkSet_NoManifestIsDisclosed(t *testing.T) {
	acq := &acquired{
		buildDir:   t.TempDir(), // no go.mod
		language:   checkout.LangGo,
		advisories: goAdvisoryCorpus(false),
	}
	osv := &fakeOSV{ids: []string{"CVE-2023-39325"}}

	ws := resolveWorkSet(context.Background(), acq, osv, pipeline.NewTableSource())

	if !hasReason(ws.partiality, plugin.PartialReasonNoManifest) {
		t.Fatalf("missing go.mod emitted no partiality note; notes = %+v", ws.partiality)
	}
	if len(osv.seen) != 0 {
		t.Errorf("OSV was queried with %d packages despite no inventory; want no query at all", len(osv.seen))
	}
}

// TestWorkSet_UnresolvableIDsAreDisclosedNotDropped proves ids OSV says affect this repository, but
// which the advisory source cannot answer for, are surfaced as a coverage limit. Dropping them
// silently would be the same failure as a silently-empty scan: OSV said they apply and we did not
// assess them.
func TestWorkSet_UnresolvableIDsAreDisclosedNotDropped(t *testing.T) {
	acq := goFixture(t, fixtureGoMod)
	osv := &fakeOSV{ids: []string{"GHSA-nope-nope-nope", "CVE-1999-0001"}}

	ws := resolveWorkSet(context.Background(), acq, osv, pipeline.NewTableSource())

	if !hasReason(ws.partiality, reasonAdvisoryFactsUnavailable) {
		t.Fatalf("unresolvable OSV ids emitted no partiality note; notes = %+v", ws.partiality)
	}
	if hasID(ws.advisories, "GHSA-nope-nope-nope") {
		t.Error("an id with no facts was admitted; it would cost a full S1-S6 pass and produce nothing")
	}
}

// TestWorkSet_DisabledIsNotAPartiality proves a deliberately offline run is a supported
// configuration, not a degradation. Its Report says builtin_language_set plainly and carries no
// note — the distinction from a FAILED widening is intent.
func TestWorkSet_DisabledIsNotAPartiality(t *testing.T) {
	f := runFlagsFor(t, "-osv-work-set=false")
	acq := goFixture(t, fixtureGoMod)

	ws, err := f.scanWorkSet(context.Background(), acq)
	if err != nil {
		t.Fatalf("scanWorkSet err = %v", err)
	}
	if len(ws.partiality) != 0 {
		t.Errorf("a deliberately offline run emitted partiality %+v, want none", ws.partiality)
	}
	if ws.source != report.WorkSetBuiltinLanguageSet {
		t.Errorf("WorkSetSource = %q, want %q", ws.source, report.WorkSetBuiltinLanguageSet)
	}
	if len(ws.advisories) != len(acq.advisories) {
		t.Errorf("work set = %d, want the floor's %d", len(ws.advisories), len(acq.advisories))
	}
}

// TestWorkSet_EnvOptOut proves the env channel actually reaches the decision.
//
// The interesting direction inverted when the widening became opt-in: with the default now FALSE,
// asserting that TEGRON_OSV_WORK_SET=0 yields "disabled" would pass on a build that ignored the
// env var completely. So this asserts the direction that can only succeed by reading it.
func TestWorkSet_EnvOptOut(t *testing.T) {
	t.Setenv(envOSVWorkSet, "1")
	f := runFlagsFor(t)

	enabled, err := f.osvWorkSetEnabled()
	if err != nil {
		t.Fatalf("osvWorkSetEnabled err = %v", err)
	}
	if !enabled {
		t.Fatalf("%s=1 did not enable the widening — the flag default beat the env var", envOSVWorkSet)
	}
}

// TestWorkSet_ExplicitFlagBeatsEnv pins the system-wide precedence idiom (flag wins over env), in
// the direction that matters after the default flip: an operator whose orchestrator sets the env
// var must still be able to force a run offline from the command line. This is what the Visit in
// osvWorkSetEnabled buys — without it an unset flag is indistinguishable from one set to the
// default, and -osv-work-set=false could not beat TEGRON_OSV_WORK_SET=1.
func TestWorkSet_ExplicitFlagBeatsEnv(t *testing.T) {
	t.Setenv(envOSVWorkSet, "1")
	f := runFlagsFor(t, "-osv-work-set=false")

	enabled, err := f.osvWorkSetEnabled()
	if err != nil {
		t.Fatalf("osvWorkSetEnabled err = %v", err)
	}
	if enabled {
		t.Fatal("an explicit -osv-work-set=false was overridden by the env var")
	}
}

// TestWorkSet_UnparseableOptOutIsAnError proves a typo cannot silently change what the scan covers,
// matching the corpus requirement gate's reasoning.
func TestWorkSet_UnparseableOptOutIsAnError(t *testing.T) {
	t.Setenv(envOSVWorkSet, "nope")
	f := runFlagsFor(t)

	if _, err := f.osvWorkSetEnabled(); err == nil {
		t.Fatal("expected an error for an unparseable opt-out value, not a silent default")
	}
}

// --- Property 3: only ids with FACTS are admitted, and aliases join ------------------------

// TestWorkSet_AliasAdmission is the join that makes the widening reach anything at all. OSV answers
// in the upstream feed's namespace (GO-2023-2102, GHSA-4374-p667-p6c8); the advisory source keys the
// same vulnerability under CVE-2023-39325. Admission must resolve the alias AND admit under the
// PRIMARY id, because that is where the facts — and therefore the finding — live.
func TestWorkSet_AliasAdmission(t *testing.T) {
	acq := goFixture(t, fixtureGoMod)

	for _, alias := range []string{"GO-2023-2102", "GHSA-4374-p667-p6c8"} {
		t.Run(alias, func(t *testing.T) {
			ws := resolveWorkSet(context.Background(), acq, &fakeOSV{ids: []string{alias}}, pipeline.NewTableSource())

			if !hasID(ws.advisories, "CVE-2023-39325") {
				t.Fatalf("alias %q was not admitted under its primary id CVE-2023-39325; got %v", alias, ids(ws.advisories))
			}
			if hasID(ws.advisories, alias) {
				t.Errorf("alias %q was admitted under its OWN id; facts are keyed on the primary", alias)
			}
		})
	}
}

// TestWorkSet_AliasIndexIsDeterministic guards against Go's randomized map iteration leaking into
// the work set: two runs over the same table must produce the same index.
func TestWorkSet_AliasIndexIsDeterministic(t *testing.T) {
	first := aliasIndex()
	for i := 0; i < 20; i++ {
		next := aliasIndex()
		if len(next) != len(first) {
			t.Fatalf("aliasIndex size varies across calls: %d vs %d", len(next), len(first))
		}
		for k, v := range first {
			if next[k] != v {
				t.Fatalf("aliasIndex[%q] varies across calls: %q vs %q", k, v, next[k])
			}
		}
	}
}

// TestWorkSet_WidenedSetIsDeterministic proves the admitted order does not depend on the order OSV
// happened to answer in — two identical scans must produce identical Reports.
func TestWorkSet_WidenedSetIsDeterministic(t *testing.T) {
	acq := goFixture(t, fixtureGoMod)
	forward := []string{"CVE-2023-39325", "CVE-2023-45283", "CVE-2024-24790"}
	reverse := []string{"CVE-2024-24790", "CVE-2023-45283", "CVE-2023-39325"}

	a := resolveWorkSet(context.Background(), acq, &fakeOSV{ids: forward}, pipeline.NewTableSource())
	b := resolveWorkSet(context.Background(), acq, &fakeOSV{ids: reverse}, pipeline.NewTableSource())

	got, want := ids(a.advisories), ids(b.advisories)
	if len(got) != len(want) {
		t.Fatalf("work-set sizes differ by OSV answer order: %d vs %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("work set depends on OSV answer order at %d: %q vs %q", i, got[i], want[i])
		}
	}
}

// TestWorkSet_ProvenanceRecordsSourceAndSize is the handoff's acceptance criterion: the Report must
// record which work-set source was used and how many ids it contained.
func TestWorkSet_ProvenanceRecordsSourceAndSize(t *testing.T) {
	acq := goFixture(t, fixtureGoMod)
	ws := resolveWorkSet(context.Background(), acq, &fakeOSV{ids: []string{"CVE-2023-39325"}}, pipeline.NewTableSource())

	f := runFlagsFor(t)
	if _, err := f.advisoryCorpusOption(); err != nil {
		t.Fatalf("advisoryCorpusOption err = %v", err)
	}
	got := f.intelProvenance(ws)

	if got.WorkSetSource != workSetSourceBuiltinUnionOSV {
		t.Errorf("WorkSetSource = %q, want %q", got.WorkSetSource, workSetSourceBuiltinUnionOSV)
	}
	if got.WorkSetSize != len(ws.advisories) {
		t.Errorf("WorkSetSize = %d, want %d", got.WorkSetSize, len(ws.advisories))
	}
	if got.WorkSetSize <= len(goAdvisoryCorpus(false)) {
		t.Errorf("WorkSetSize = %d did not exceed the %d-id floor — nothing was widened",
			got.WorkSetSize, len(goAdvisoryCorpus(false)))
	}
}

// --- The dependency inventory ---------------------------------------------------------------

// TestGoInventory_ReadsRequiresAndStdlib proves the inventory is built from the MANIFEST, not from
// the advisory set. report.SBOM is advisory-keyed — built by walking the work set — so querying OSV
// with it would be circular and could never widen anything.
func TestGoInventory_ReadsRequiresAndStdlib(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(fixtureGoMod), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	pkgs, notes := goDependencyInventory(dir)
	if len(notes) != 0 {
		t.Errorf("unexpected partiality for a readable go.mod: %+v", notes)
	}

	want := map[string]string{
		"golang.org/x/crypto": "v0.30.0",
		"golang.org/x/text":   "v0.3.6", // indirect requires are real dependencies
		goStdlibPackage:       "1.21.0", // the toolchain, with the "go" prefix stripped
	}
	got := map[string]string{}
	for _, p := range pkgs {
		if p.Ecosystem != ecosystemGo {
			t.Errorf("package %q ecosystem = %q, want %q", p.Name, p.Ecosystem, ecosystemGo)
		}
		got[p.Name] = p.Version
	}
	for name, version := range want {
		if got[name] != version {
			t.Errorf("inventory[%q] = %q, want %q", name, got[name], version)
		}
	}
}

// TestToolchainVersion_StripsGoPrefix pins the measured OSV behaviour: "go1.21.0" is not a version
// OSV can parse, and it answers the query with EVERY stdlib advisory ever recorded (142 vs the 68
// that actually apply) instead of failing. An unfiltered firehose that reads like a real answer is
// worse than an error, so the normalization is load-bearing, not cosmetic.
func TestToolchainVersion_StripsGoPrefix(t *testing.T) {
	for _, tc := range []struct{ gomod, want string }{
		{"module m\n\ngo 1.21.0\n", "1.21.0"},
		{"module m\n\ngo 1.21\n", "1.21.0"}, // a two-element directive means the .0 release
		{"module m\n\ngo 1.22.0\n\ntoolchain go1.24.3\n", "1.24.3"},
		{"module m\n", ""},
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(tc.gomod), 0o600); err != nil {
			t.Fatalf("write go.mod: %v", err)
		}
		pkgs, _ := goDependencyInventory(dir)

		var got string
		for _, p := range pkgs {
			if p.Name == goStdlibPackage {
				got = p.Version
			}
		}
		if got != tc.want {
			t.Errorf("go.mod %q -> stdlib version %q, want %q", tc.gomod, got, tc.want)
		}
		if got != "" && got[0] == 'g' {
			t.Errorf("stdlib version %q kept its \"go\" prefix; OSV cannot range-compare it", got)
		}
	}
}

// TestInventory_UnknownLanguageQueriesNothing proves a language with no inventory path degrades to
// the floor rather than querying OSV with an empty or wrong-ecosystem package list.
func TestInventory_UnknownLanguageQueriesNothing(t *testing.T) {
	acq := &acquired{buildDir: t.TempDir(), language: checkout.LangUnknown, advisories: nil}
	osv := &fakeOSV{ids: []string{"CVE-2023-39325"}}

	ws := resolveWorkSet(context.Background(), acq, osv, pipeline.NewTableSource())

	if len(osv.seen) != 0 {
		t.Errorf("OSV queried for a language with no inventory path (%d packages)", len(osv.seen))
	}
	if ws.source != report.WorkSetBuiltinLanguageSet {
		t.Errorf("WorkSetSource = %q, want %q", ws.source, report.WorkSetBuiltinLanguageSet)
	}
}

// TestWorkSet_EveryLanguageFloorSurvives is the handoff's "Java, JS and Python scans produce at
// least what they produce today" gate, generalized to every language that has a floor.
//
// It matters most for the three non-Go ecosystems, whose floors are entirely first-party TEGRON-*
// fixtures that OSV.dev has never heard of and never will. Any design that REPLACED the compiled-in
// set with the OSV answer — rather than unioning with it — would silently delete all seven of them
// and turn those scans from demo-quality into nothing.
//
// The three non-Go floors are requested with the house canaries ON because that is now the only way
// they are non-empty: their corpora are house canaries in their entirety. The property under test is
// union-not-replace, which needs a non-empty floor to have anything to say.
func TestWorkSet_EveryLanguageFloorSurvives(t *testing.T) {
	for _, tc := range []struct {
		language string
		floor    []assessment.VulnRef
	}{
		{checkout.LangGo, goAdvisoryCorpus(false)},
		{checkout.LangJava, javaAdvisoryCorpus(true)},
		{checkout.LangJS, jsAdvisoryCorpus(true)},
		{checkout.LangPython, pythonAdvisoryCorpus(true)},
	} {
		t.Run(tc.language, func(t *testing.T) {
			if len(tc.floor) == 0 {
				t.Fatalf("%s floor is empty — the fixture is wrong, not the code", tc.language)
			}
			// plugin is nil: no manifest parser for this language in a hermetic test. The
			// inventory is therefore absent, which is the WORST case for floor preservation.
			acq := &acquired{buildDir: t.TempDir(), language: tc.language, advisories: tc.floor}

			ws := resolveWorkSet(context.Background(), acq, &fakeOSV{ids: []string{"CVE-2023-39325"}}, pipeline.NewTableSource())

			for _, want := range tc.floor {
				if !hasID(ws.advisories, want.ID) {
					t.Errorf("%s floor id %q lost", tc.language, want.ID)
				}
			}
			if len(ws.advisories) != len(tc.floor) {
				t.Errorf("%s work set = %d, want exactly the %d-id floor when no inventory resolves",
					tc.language, len(ws.advisories), len(tc.floor))
			}
		})
	}
}
