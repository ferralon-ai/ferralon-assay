package trigger

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
)

// forbiddenSignals are the advisory-prioritization signals that gate SCHEDULING only and
// must NEVER appear on a pipeline/verdict struct or in the evidence path (inv.5). If any
// of these leaks into a struct a stage can read, the stage could conclude on it — exactly
// what this tripwire exists to prevent.
var forbiddenSignals = []string{"band", "severity", "epss", "kev"}

// TestBandQuarantine_NoForbiddenFieldOnPipelineStructs is the structural half of the
// inv.5 tripwire: it reflects over the structs that carry a case through the pipeline —
// assessment.Assessment (the durable record every stage receives), assessment.Request
// (c.Request), and pipeline.AdvisoryFacts (the normalized_advisory shape) — and FAILS if
// any (recursively-reached) exported field name carries a scheduling-only signal. Band is
// deliberately declared in the trigger/scheduler package alone; if a future change adds a
// Band/Severity/EPSS/KEV field to any of these, this test breaks loudly.
func TestBandQuarantine_NoForbiddenFieldOnPipelineStructs(t *testing.T) {
	roots := []reflect.Type{
		reflect.TypeOf(assessment.Assessment{}),
		reflect.TypeOf(assessment.Request{}),
		reflect.TypeOf(pipeline.AdvisoryFacts{}),
	}
	for _, root := range roots {
		seen := map[reflect.Type]bool{}
		assertNoForbiddenField(t, root, root.Name(), seen)
	}
}

func assertNoForbiddenField(t *testing.T, typ reflect.Type, path string, seen map[reflect.Type]bool) {
	t.Helper()
	for typ.Kind() == reflect.Ptr || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || seen[typ] {
		return
	}
	seen[typ] = true
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath != "" { // unexported (e.g. time.Time internals) — skip
			continue
		}
		lower := strings.ToLower(f.Name)
		for _, sig := range forbiddenSignals {
			if strings.Contains(lower, sig) {
				t.Errorf("inv.5 quarantine breach: field %s.%s carries scheduling-only signal %q — it must not live on a pipeline/verdict struct", path, f.Name, sig)
			}
		}
		assertNoForbiddenField(t, f.Type, path+"."+f.Name, seen)
	}
}

// TestBandQuarantine_NoBandSymbolInPipelineSource is the source-level half of the tripwire
// (RFC §4b): no PRODUCTION file under a pipeline package may reference the band symbol.
// Band is a scheduler concept; a pipeline source referencing it is a leak even if it never
// reached a struct field. Test files are excluded (they legitimately use "band" as prose,
// e.g. "fault band").
func TestBandQuarantine_NoBandSymbolInPipelineSource(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test file path")
	}
	triggerDir := filepath.Dir(thisFile)            // .../ferralon-assay/trigger
	openTegronDir := filepath.Dir(triggerDir)       // .../ferralon-assay
	repoRoot := filepath.Dir(openTegronDir)         // .../<repo>

	pipelineDirs := []string{
		filepath.Join(openTegronDir, "pipeline"),
		filepath.Join(repoRoot, "service", "internal", "pipeline"), // scanned only if present
	}

	// \bband\b, case-insensitive: the band identifier as a whole word, not a substring of
	// an unrelated word (so "bandwidth" would not trip, but a Band field/type/var would).
	bandRe := regexp.MustCompile(`(?i)\bband\b`)

	scanned := 0
	for _, dir := range pipelineDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Logf("pipeline dir not present, skipping: %s", dir)
			continue
		}
		err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			scanned++
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if loc := bandRe.FindIndex(data); loc != nil {
				rel, _ := filepath.Rel(repoRoot, p)
				t.Errorf("inv.5 quarantine breach: pipeline source %s references the band symbol (offset %d) — band gates scheduling only and must not enter the pipeline", rel, loc[0])
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no pipeline source files — tripwire would be vacuous")
	}
}

// TestAdmit_FailsOpenOnUnknownBand proves the gate never drops a case on an absent or
// unrecognized band: unknown and off-enum values admit.
func TestAdmit_FailsOpenOnUnknownBand(t *testing.T) {
	for _, band := range []Band{BandUnknown, Band("nonsense"), BandImmediate, BandStandard} {
		if got := admit(band); got != AdmitNow {
			t.Errorf("admit(%q) = %q, want %q (fail-open)", band, got, AdmitNow)
		}
	}
	if got := admit(BandDeferred); got != AdmitDefer {
		t.Errorf("admit(deferred) = %q, want %q", got, AdmitDefer)
	}
	if got := admit(BandExcluded); got != AdmitSkip {
		t.Errorf("admit(excluded) = %q, want %q", got, AdmitSkip)
	}
}

// TestAdmitAdvisories_GatesSchedulingAndStripsBand proves the admission pass admits/defers/
// skips by band, strips band from the admitted output (the admitted type is a plain VulnRef
// that structurally cannot carry a band), and orders immediate ahead of standard.
func TestAdmitAdvisories_GatesSchedulingAndStripsBand(t *testing.T) {
	sched := []ScheduledAdvisory{
		{Vuln: assessment.VulnRef{ID: "A", Source: "osv"}, Band: BandStandard},
		{Vuln: assessment.VulnRef{ID: "B", Source: "osv"}, Band: BandDeferred},
		{Vuln: assessment.VulnRef{ID: "C", Source: "osv"}, Band: BandExcluded},
		{Vuln: assessment.VulnRef{ID: "D", Source: "osv"}, Band: BandImmediate},
		{Vuln: assessment.VulnRef{ID: "E", Source: "osv"}, Band: BandUnknown},
	}
	res := admitAdvisories(sched)

	gotAdmit := ids(res.Admitted)
	// Immediate (D) first; A and E (standard/unknown, same rank) keep input order.
	want := []string{"D", "A", "E"}
	if strings.Join(gotAdmit, ",") != strings.Join(want, ",") {
		t.Errorf("admitted = %v, want %v", gotAdmit, want)
	}
	if strings.Join(res.Deferred, ",") != "B" {
		t.Errorf("deferred = %v, want [B]", res.Deferred)
	}
	if strings.Join(res.Skipped, ",") != "C" {
		t.Errorf("skipped = %v, want [C]", res.Skipped)
	}

	// The admitted element type has no band-shaped field: band is structurally dropped.
	vt := reflect.TypeOf(res.Admitted).Elem()
	for i := 0; i < vt.NumField(); i++ {
		if strings.Contains(strings.ToLower(vt.Field(i).Name), "band") {
			t.Fatalf("admitted VulnRef carries a band-shaped field %q — band leaked past the gate", vt.Field(i).Name)
		}
	}
}

// TestScheduleFor_NilBandsAdmitsAll proves the fail-open default at the request seam: with
// no bands supplied every case is BandUnknown, admitted, in the original order.
func TestScheduleFor_NilBandsAdmitsAll(t *testing.T) {
	advs := []assessment.VulnRef{
		{ID: "X", Source: "osv"}, {ID: "Y", Source: "osv"}, {ID: "Z", Source: "osv"},
	}
	res := admitAdvisories(scheduleFor(advs, nil))
	if strings.Join(ids(res.Admitted), ",") != "X,Y,Z" {
		t.Errorf("nil-bands admitted = %v, want [X Y Z] in order", ids(res.Admitted))
	}
	if len(res.Deferred) != 0 || len(res.Skipped) != 0 {
		t.Errorf("nil-bands held back cases: deferred=%v skipped=%v", res.Deferred, res.Skipped)
	}
}

func ids(vs []assessment.VulnRef) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.ID)
	}
	return out
}
