// workset_test.go
//
// These tests pin the three properties that keep the work-set widening honest: the opted-in house
// canaries are a floor that cannot be lost, a widening that did not happen is disclosed rather than
// rendered clean, and only ids the advisory source can actually answer for are admitted. The fixture
// runs opt the Go canaries in so the floor is non-empty, and resolve facts from the fixture
// advisories under corpus/testdata/advisories.
package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
		advisories: houseCanaries(checkout.LangGo, true),
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

// --- Property 1: the opted-in canaries are a FLOOR --------------------------------------------

// TestWorkSet_FloorIsNeverLost is the acceptance gate the handoff states: no id that was evaluated
// before may stop being evaluated. It is asserted against the hostile cases — OSV returning nothing,
// OSV returning only junk, and OSV failing outright.
func TestWorkSet_FloorIsNeverLost(t *testing.T) {
	floor := houseCanaries(checkout.LangGo, true)

	for _, tc := range []struct {
		name string
		osv  *fakeOSV
	}{
		{"osv returns nothing", &fakeOSV{}},
		{"osv returns only ids we have no facts for", &fakeOSV{ids: []string{"GHSA-zzzz-zzzz-zzzz", "CVE-1999-0001"}}},
		{"osv fails", &fakeOSV{err: errors.New("dial tcp: no route to host")}},
		{"osv returns ids already in the floor", &fakeOSV{ids: []string{"FERRALON-APP-DOS-0001", "GO-2021-0113"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acq := goFixture(t, fixtureGoMod)
			ws := resolveWorkSet(context.Background(), acq, tc.osv, fixtureSource())

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
	osv := &fakeOSV{ids: []string{"CVE-2024-45337", "CVE-2024-45337", "GO-2021-0113", "FERRALON-APP-DOS-0001"}}

	ws := resolveWorkSet(context.Background(), acq, osv, fixtureSource())

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
	ws := resolveWorkSet(context.Background(), acq, &fakeOSV{err: errors.New("network unreachable")}, fixtureSource())

	if !hasReason(ws.partiality, reasonWorkSetNotWidened) {
		t.Fatalf("an unreachable OSV emitted no partiality note; notes = %+v", ws.partiality)
	}
	if ws.source != report.WorkSetHouseCanaries {
		t.Errorf("WorkSetSource = %q, want %q — only the floor actually ran", ws.source, report.WorkSetHouseCanaries)
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
		advisories: houseCanaries(checkout.LangGo, true),
	}
	osv := &fakeOSV{ids: []string{"CVE-2023-39325"}}

	ws := resolveWorkSet(context.Background(), acq, osv, fixtureSource())

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

	ws := resolveWorkSet(context.Background(), acq, osv, fixtureSource())

	if !hasReason(ws.partiality, reasonAdvisoryFactsUnavailable) {
		t.Fatalf("unresolvable OSV ids emitted no partiality note; notes = %+v", ws.partiality)
	}
	if hasID(ws.advisories, "GHSA-nope-nope-nope") {
		t.Error("an id with no facts was admitted; it would cost a full S1-S6 pass and produce nothing")
	}
}

// TestWorkSet_DisabledIsNotAPartiality proves a deliberately offline run is a supported
// configuration, not a degradation. Its Report says house_canaries plainly and carries no
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
	if ws.source != report.WorkSetHouseCanaries {
		t.Errorf("WorkSetSource = %q, want %q", ws.source, report.WorkSetHouseCanaries)
	}
	if len(ws.advisories) != len(acq.advisories) {
		t.Errorf("work set = %d, want the floor's %d", len(ws.advisories), len(acq.advisories))
	}
}

// TestWorkSet_EnvOptOut proves the env channel actually reaches the decision.
//
// The interesting direction inverted when the widening became opt-in: with the default now FALSE,
// asserting that ASSAY_OSV_WORK_SET=0 yields "disabled" would pass on a build that ignored the
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
// default, and -osv-work-set=false could not beat ASSAY_OSV_WORK_SET=1.
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

// --- Property 3: only ids with FACTS are admitted ------------------------------------------

// TestWorkSet_AdmitsUnderTheAnsweredID pins admission to a bare Lookup on the id OSV answered with.
// The fixture source keys the HTTP/2 rapid-reset advisory under CVE-2023-39325; OSV's GO- and GHSA-
// ids for it resolve nothing there, so they are disclosed as unresolved, never admitted, and never
// rewritten to another id.
func TestWorkSet_AdmitsUnderTheAnsweredID(t *testing.T) {
	acq := goFixture(t, fixtureGoMod)
	osv := &fakeOSV{ids: []string{"CVE-2023-39325", "GO-2023-2102", "GHSA-4374-p667-p6c8"}}

	ws := resolveWorkSet(context.Background(), acq, osv, fixtureSource())

	if !hasID(ws.advisories, "CVE-2023-39325") {
		t.Fatalf("CVE-2023-39325 was not admitted; got %v", ids(ws.advisories))
	}
	for _, alias := range []string{"GO-2023-2102", "GHSA-4374-p667-p6c8"} {
		if hasID(ws.advisories, alias) {
			t.Errorf("%q was admitted with no facts keyed under it", alias)
		}
		if !slices.Contains(ws.unresolved, alias) {
			t.Errorf("%q is not disclosed as unresolved; unresolved = %v", alias, ws.unresolved)
		}
	}
}

// TestWorkSet_WidenedSetIsDeterministic proves the admitted order does not depend on the order OSV
// happened to answer in — two identical scans must produce identical Reports.
func TestWorkSet_WidenedSetIsDeterministic(t *testing.T) {
	acq := goFixture(t, fixtureGoMod)
	forward := []string{"CVE-2023-39325", "CVE-2023-45283", "CVE-2024-24790"}
	reverse := []string{"CVE-2024-24790", "CVE-2023-45283", "CVE-2023-39325"}

	a := resolveWorkSet(context.Background(), acq, &fakeOSV{ids: forward}, fixtureSource())
	b := resolveWorkSet(context.Background(), acq, &fakeOSV{ids: reverse}, fixtureSource())

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
	ws := resolveWorkSet(context.Background(), acq, &fakeOSV{ids: []string{"CVE-2023-39325"}}, fixtureSource())

	f := runFlagsFor(t)
	if _, err := f.advisoryCorpusOption(); err != nil {
		t.Fatalf("advisoryCorpusOption err = %v", err)
	}
	got := f.intelProvenance(ws)

	if got.WorkSetSource != workSetSourceCanariesUnionOSV {
		t.Errorf("WorkSetSource = %q, want %q", got.WorkSetSource, workSetSourceCanariesUnionOSV)
	}
	if got.WorkSetSize != len(ws.advisories) {
		t.Errorf("WorkSetSize = %d, want %d", got.WorkSetSize, len(ws.advisories))
	}
	if got.WorkSetSize <= len(houseCanaries(checkout.LangGo, true)) {
		t.Errorf("WorkSetSize = %d did not exceed the %d-id floor — nothing was widened",
			got.WorkSetSize, len(houseCanaries(checkout.LangGo, true)))
	}
}

// --- The dependency inventory ---------------------------------------------------------------

// TestGoInventory_ReadsRequiresAndStdlib proves the inventory is built from the MANIFEST, not from
// the advisory set. report.SBOM is advisory-keyed — built by walking the work set — so querying OSV
// with it would be circular and could never widen anything.
func TestGoInventory_ReadsRequiresAndStdlib(t *testing.T) {
	acq := goFixture(t, fixtureGoMod)

	resolved, unresolved, notes := goDependencyInventory(context.Background(), acq)
	if len(notes) != 0 {
		t.Errorf("unexpected partiality for a readable go.mod: %+v", notes)
	}

	want := map[string]string{
		"golang.org/x/crypto": "v0.30.0",
		"golang.org/x/text":   "v0.3.6", // indirect requires are real dependencies
	}
	got := map[string]string{}
	for _, p := range resolved {
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
	if len(unresolved) != 1 || unresolved[0] != (report.Package{Ecosystem: ecosystemGo, Name: goStdlibPackage}) {
		t.Errorf("unresolved = %+v, want only the standard library, named with no version", unresolved)
	}
}

// TestGoInventory_ReadsTheAnalyzedModule pins the inventory to the go.mod the pipeline analyzes:
// checkout.FindGoModuleRoot's pick under the checkout root, which is the root go.mod when there is
// one, otherwise the shallowest nested one, lexicographically first among equals. The requires, the
// stdlib query point's build manifest and the project's own identity all come from that module.
func TestGoInventory_ReadsTheAnalyzedModule(t *testing.T) {
	gomod := func(module string) string {
		return "module " + module + "\n\ngo 1.21\n\nrequire " + module + "dep v1.0.0\n"
	}
	for _, tc := range []struct {
		name    string
		modules map[string]string // dir relative to the checkout root -> its go.mod
		want    string            // module dir the inventory reads, relative to the checkout root
	}{
		{name: "root module", modules: map[string]string{".": gomod("example.com/root")}, want: "."},
		{name: "nested only", modules: map[string]string{"service": gomod("example.com/service")}, want: "service"},
		{name: "root and nested", modules: map[string]string{
			".":       gomod("example.com/root"),
			"service": gomod("example.com/service"),
		}, want: "."},
		{name: "nested siblings", modules: map[string]string{
			"b": gomod("example.com/b"),
			"a": gomod("example.com/a"),
		}, want: "a"},
		{name: "shallower nested wins", modules: map[string]string{
			"a/deep": gomod("example.com/deep"),
			"z":      gomod("example.com/z"),
		}, want: "z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, content := range tc.modules {
				if err := os.MkdirAll(filepath.Join(dir, rel), 0o755); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				if err := os.WriteFile(filepath.Join(dir, rel, "go.mod"), []byte(content), 0o600); err != nil {
					t.Fatalf("write go.mod: %v", err)
				}
			}
			wantDir := filepath.Join(dir, tc.want)
			if got, ok := checkout.FindGoModuleRoot(dir); !ok || got != wantDir {
				t.Fatalf("FindGoModuleRoot = %q, %v; the pipeline analyzes %q", got, ok, wantDir)
			}
			build := &buildToolchainAnalyzer{unsearchingAnalyzer: unsearchingAnalyzer{language: "go"}, resolved: "go1.20.14"}
			acq := &acquired{
				buildDir:    dir,
				language:    checkout.LangGo,
				plugin:      build,
				goToolchain: subjectGoToolchain{trustObserved: true},
			}

			resolved, unresolved, notes := goDependencyInventory(context.Background(), acq)
			if len(notes) != 0 {
				t.Errorf("notes = %+v, want none", notes)
			}
			if len(unresolved) != 0 {
				t.Errorf("unresolved = %+v, want none", unresolved)
			}
			module := strings.Fields(tc.modules[tc.want])[1]
			want := []report.Package{
				{Ecosystem: ecosystemGo, Name: module + "dep", Version: "v1.0.0"},
				{Ecosystem: ecosystemGo, Name: goStdlibPackage, Version: "1.20.14"},
			}
			if len(resolved) != len(want) || resolved[0] != want[0] || resolved[1] != want[1] {
				t.Errorf("resolved = %+v, want %+v", resolved, want)
			}
			if len(build.dirs) != 1 || build.dirs[0] != wantDir {
				t.Errorf("BuildManifest read at %q, want [%q]", build.dirs, wantDir)
			}
			isRoot := rootMatcher(context.Background(), acq)
			if isRoot == nil || !isRoot(pipeline.PackageKey{Ecosystem: "golang", Name: module}) {
				t.Errorf("rootMatcher does not recognise %s as the project", module)
			}
		})
	}
}

// TestGoInventory_NoModuleIsNoManifest pins the disclosure for a tree with no go.mod within the
// module search.
func TestGoInventory_NoModuleIsNoManifest(t *testing.T) {
	acq := &acquired{buildDir: t.TempDir(), language: checkout.LangGo}

	resolved, unresolved, notes := goDependencyInventory(context.Background(), acq)
	if len(resolved) != 0 || len(unresolved) != 0 {
		t.Errorf("inventory = %+v / %+v, want empty", resolved, unresolved)
	}
	if len(notes) != 1 || notes[0].Reason != plugin.PartialReasonNoManifest || notes[0].Ecosystem != ecosystemGo {
		t.Errorf("notes = %+v, want one %s note", notes, plugin.PartialReasonNoManifest)
	}
}

// TestWorkSet_StdlibQueryPoint pins where the OSV widening asks about the Go standard library. Only
// an EXACT toolchain is a query point, in OSV's bare-semver form: "go1.21.0" is not a version OSV
// can parse, and it answers such a query with every stdlib advisory ever recorded, which reads like
// a real answer. Anything short of exact — every go.mod directive — is queried by name, so the
// version axis adjudicates each advisory against the resolved toolchain fact; a directive taken as
// the query point drops the advisories of every other release the build may run.
func TestWorkSet_StdlibQueryPoint(t *testing.T) {
	const byName = ""
	for _, tc := range []struct {
		name  string
		gomod string
		tc    subjectGoToolchain
		want  string
	}{
		{name: "two-part go line", gomod: "module m\n\ngo 1.21\n", want: byName},
		{name: "three-part go line", gomod: "module m\n\ngo 1.21.0\n", want: byName},
		{name: "toolchain line", gomod: "module m\n\ngo 1.22.0\n\ntoolchain go1.24.3\n", want: byName},
		{name: "no directive", gomod: "module m\n", want: byName},
		{name: "declared exact", gomod: "module m\n\ngo 1.21.0\n", tc: subjectGoToolchain{declared: "go1.22.7"}, want: "1.22.7"},
		{name: "declared exact, no directive", gomod: "module m\n", tc: subjectGoToolchain{declared: "go1.22.7"}, want: "1.22.7"},
		{name: "declared below the go line", gomod: "module m\n\ngo 1.22.0\n", tc: subjectGoToolchain{declared: "go1.21.5"}, want: byName},
		{name: "declared unparseable", gomod: "module m\n\ngo 1.21.0\n", tc: subjectGoToolchain{declared: "latest"}, want: byName},
		{name: "observed, trusted", gomod: "module m\n\ngo 1.21.0\n", tc: subjectGoToolchain{observed: "go1.23.4", trustObserved: true}, want: "1.23.4"},
		{name: "observed, untrusted", gomod: "module m\n\ngo 1.21.0\n", tc: subjectGoToolchain{observed: "go1.23.4"}, want: byName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acq := goFixture(t, tc.gomod)
			acq.goToolchain = tc.tc
			osv := &fakeOSV{}

			ws := resolveWorkSet(context.Background(), acq, osv, fixtureSource())

			var queried []report.Package
			for _, p := range osv.seen {
				if p.Name == goStdlibPackage {
					queried = append(queried, p)
				}
			}
			if len(queried) != 1 {
				t.Fatalf("stdlib queried %d times (%+v), want once", len(queried), queried)
			}
			if got := queried[0].Version; got != tc.want {
				t.Errorf("stdlib query point = %q, want %q (\"\" is by name)", got, tc.want)
			}
			for _, u := range ws.unversioned {
				if u == goStdlibPackage {
					t.Errorf("stdlib disclosed as unversioned and not asked about; it is queried by name")
				}
			}
		})
	}
}

// TestWorkSet_StdlibQueryPointBazel pins that a Bazel workspace at or above the module root leaves
// go.mod's directives no floor, so a declared exact toolchain below the go line stands: the query
// point is the one a module with no go line gets, not the by-name query a binding go line forces.
func TestWorkSet_StdlibQueryPointBazel(t *testing.T) {
	const byName = ""
	for _, tc := range []struct {
		name   string
		gomod  string
		marker string // directory, relative to the temp root, holding MODULE.bazel; "-" for none
		top    string // directory, relative to the temp root, that is the git top-level
		want   string
	}{
		{name: "binding go line, no workspace", gomod: "module m\n\ngo 1.22.0\n", marker: "-", top: ".", want: byName},
		{name: "binding go line, workspace at the module root", gomod: "module m\n\ngo 1.22.0\n", marker: "svc", top: ".", want: "1.21.5"},
		{name: "binding go line, workspace above the module root", gomod: "module m\n\ngo 1.22.0\n", marker: ".", top: ".", want: "1.21.5"},
		{name: "toolchain line, workspace above the module root", gomod: "module m\n\ngo 1.22.0\n\ntoolchain go1.24.3\n", marker: ".", top: ".", want: "1.21.5"},
		{name: "no go line, workspace above the module root", gomod: "module m\n", marker: ".", top: ".", want: "1.21.5"},
		{name: "binding go line, workspace above the git top-level", gomod: "module m\n\ngo 1.22.0\n", marker: ".", top: "svc", want: byName},
		{name: "no go line, no workspace", gomod: "module m\n", marker: "-", top: ".", want: "1.21.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			mod := filepath.Join(root, "svc")
			if err := os.MkdirAll(mod, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(mod, "go.mod"), []byte(tc.gomod), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.marker != "-" {
				if err := os.WriteFile(filepath.Join(root, tc.marker, "MODULE.bazel"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			gitT(t, filepath.Join(root, tc.top), "init", "-q")
			acq := goFixture(t, tc.gomod)
			acq.buildDir = mod
			acq.goToolchain = subjectGoToolchain{declared: "go1.21.5"}
			osv := &fakeOSV{}

			resolveWorkSet(context.Background(), acq, osv, fixtureSource())

			var queried []report.Package
			for _, p := range osv.seen {
				if p.Name == goStdlibPackage {
					queried = append(queried, p)
				}
			}
			if len(queried) != 1 {
				t.Fatalf("stdlib queried %d times (%+v), want once", len(queried), queried)
			}
			if got := queried[0].Version; got != tc.want {
				t.Errorf("stdlib query point = %q, want %q (\"\" is by name)", got, tc.want)
			}
		})
	}
}

// TestWorkSet_StdlibQueryPointFromBuildToolchain pins the analyzer-resolved build toolchain as a
// stdlib query point: exact only under trust, consulted only under trust, and ignored when go.mod's
// directives bind the toolchain.
func TestWorkSet_StdlibQueryPointFromBuildToolchain(t *testing.T) {
	const byName = ""
	for _, tc := range []struct {
		name      string
		gomod     string
		trust     bool
		want      string
		wantCalls int
	}{
		{name: "two-part go line, trusted", gomod: "module m\n\ngo 1.21\n", trust: true, want: "1.20.14", wantCalls: 1},
		{name: "two-part go line, untrusted", gomod: "module m\n\ngo 1.21\n", want: byName, wantCalls: 0},
		{name: "binding go line, trusted", gomod: "module m\n\ngo 1.21.0\n", trust: true, want: byName, wantCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			acq := goFixture(t, tc.gomod)
			acq.goToolchain = subjectGoToolchain{trustObserved: tc.trust}
			build := &buildToolchainAnalyzer{unsearchingAnalyzer: unsearchingAnalyzer{language: "go"}, resolved: "go1.20.14"}
			acq.plugin = build
			osv := &fakeOSV{}

			resolveWorkSet(context.Background(), acq, osv, fixtureSource())

			var queried []report.Package
			for _, p := range osv.seen {
				if p.Name == goStdlibPackage {
					queried = append(queried, p)
				}
			}
			if len(queried) != 1 {
				t.Fatalf("stdlib queried %d times (%+v), want once", len(queried), queried)
			}
			if got := queried[0].Version; got != tc.want {
				t.Errorf("stdlib query point = %q, want %q (\"\" is by name)", got, tc.want)
			}
			if build.calls != tc.wantCalls {
				t.Errorf("BuildManifest called %d times, want %d", build.calls, tc.wantCalls)
			}
		})
	}
}

// buildToolchainAnalyzer is an unsearchingAnalyzer whose build manifest reports one Go runtime the
// build environment resolves to resolved, counting the calls.
type buildToolchainAnalyzer struct {
	unsearchingAnalyzer
	resolved string
	calls    int
	dirs     []string
}

func (a *buildToolchainAnalyzer) BuildManifest(_ context.Context, req plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	a.calls++
	a.dirs = append(a.dirs, req.BuildDir)
	return plugin.BuildManifestResult{Runtimes: []plugin.RuntimeSpec{{Name: "go", Resolved: a.resolved}}}, nil
}

// TestScanWorkSet_DeclaredToolchainReachesStdlibQuery proves -subject-go-version reaches the OSV
// widening's stdlib query point on the scan path, at the transport.
func TestScanWorkSet_DeclaredToolchainReachesStdlibQuery(t *testing.T) {
	body := &osvBodyTrap{}
	prev := http.DefaultTransport
	http.DefaultTransport = body
	t.Cleanup(func() { http.DefaultTransport = prev })

	f := runFlagsFor(t, "-osv-work-set=true", "-subject-go-version=go1.22.7")
	if _, err := f.scanWorkSet(context.Background(), goFixture(t, fixtureGoMod)); err != nil {
		t.Fatalf("scanWorkSet err = %v", err)
	}
	if !strings.Contains(body.body, `{"version":"1.22.7","package":{"ecosystem":"Go","name":"stdlib"}}`) {
		t.Errorf("OSV request does not query stdlib at the declared toolchain: %s", body.body)
	}
}

// osvBodyTrap records the last request body and refuses the request.
type osvBodyTrap struct{ body string }

func (b *osvBodyTrap) RoundTrip(req *http.Request) (*http.Response, error) {
	data, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	b.body = string(data)
	return nil, errors.New("osvBodyTrap: refusing outbound request")
}

// TestInventory_UnknownLanguageQueriesNothing proves a language with no inventory path degrades to
// the floor rather than querying OSV with an empty or wrong-ecosystem package list.
func TestInventory_UnknownLanguageQueriesNothing(t *testing.T) {
	acq := &acquired{buildDir: t.TempDir(), language: checkout.LangUnknown, advisories: nil}
	osv := &fakeOSV{ids: []string{"CVE-2023-39325"}}

	ws := resolveWorkSet(context.Background(), acq, osv, fixtureSource())

	if len(osv.seen) != 0 {
		t.Errorf("OSV queried for a language with no inventory path (%d packages)", len(osv.seen))
	}
	if ws.source != report.WorkSetNone {
		t.Errorf("WorkSetSource = %q, want %q", ws.source, report.WorkSetNone)
	}
}

// TestWorkSet_EveryLanguageFloorSurvives pins union-not-replace for every language with house
// canaries. The canaries are first-party FERRALON-* fixtures that OSV.dev has never heard of, so a
// design that REPLACED the floor with the OSV answer would silently delete them all.
func TestWorkSet_EveryLanguageFloorSurvives(t *testing.T) {
	for _, tc := range []struct {
		language string
		floor    []assessment.VulnRef
	}{
		{checkout.LangGo, houseCanaries(checkout.LangGo, true)},
		{checkout.LangJava, houseCanaries(checkout.LangJava, true)},
		{checkout.LangJS, houseCanaries(checkout.LangJS, true)},
		{checkout.LangPython, houseCanaries(checkout.LangPython, true)},
	} {
		t.Run(tc.language, func(t *testing.T) {
			if len(tc.floor) == 0 {
				t.Fatalf("%s floor is empty — the fixture is wrong, not the code", tc.language)
			}
			// plugin is nil: no manifest parser for this language in a hermetic test. The
			// inventory is therefore absent, which is the WORST case for floor preservation.
			acq := &acquired{buildDir: t.TempDir(), language: tc.language, advisories: tc.floor}

			ws := resolveWorkSet(context.Background(), acq, &fakeOSV{ids: []string{"CVE-2023-39325"}}, fixtureSource())

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
