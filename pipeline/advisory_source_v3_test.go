// advisory_source_v3_test.go
//
// Unit tests for the ferralon.normalized_advisory.v3 wire foundation (cycle
// 2026-07-14-enable-enrichment-support, dispatch E-V3A): the {v2,v3} schema recognizer, the three
// new closed-set validators (sink_kind / ingress_kind / failed_fix_class), the v3 field mapping in
// toFacts, the OSV withdrawn honoring (T1), and the sink_kind route-selection resolver (row 2).
//
// Every validator fails OPEN on an unrecognized member (the operand drops to its zero, never a
// silent wrong route) — the same discipline as schemeRecognized/trustTierRecognized (inv.5).
package pipeline

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/vulnclass"
)

// --- schema recognition: the closed set {v2, v3} ---------------------------------------------

func TestSchemaVersionRecognized_Set(t *testing.T) {
	tests := []struct {
		v    string
		want bool
	}{
		{"ferralon.normalized_advisory.v2", true},
		{"ferralon.normalized_advisory.v3", true},
		{"", false},
		{"tegron.normalized_advisory.v2", false},   // pre-rename tag stays rejected
		{"ferralon.normalized_advisory.v4", false}, // an unseen major is not silently accepted
		{"ferralon.normalized_advisory.v2.1", false},
	}
	for _, tt := range tests {
		if got := schemaVersionRecognized(tt.v); got != tt.want {
			t.Errorf("schemaVersionRecognized(%q) = %v, want %v", tt.v, got, tt.want)
		}
	}
}

// A v3-tagged document decodes and leaves un-declared v3 fields zero (fail-open, inv.5).
func TestToFacts_V3TagDecodes(t *testing.T) {
	doc := advisoryDoc{SchemaVersion: normalizedAdvisorySchemaVersionV3, VulnID: "CVE-X"}
	facts, ok := doc.toFacts("CVE-X")
	if !ok {
		t.Fatal("toFacts(v3 minimal doc) ok=false, want true")
	}
	if !facts.Trigger.Zero() || facts.Fix != (FixHint{}) || facts.PocSummary != "" || facts.Withdrawn {
		t.Errorf("undeclared v3 fields not zero: %+v", facts)
	}
}

// A v2-tagged document still decodes (rollout non-breaking), leaving the v3 additive fields zero.
func TestToFacts_V2TagStillDecodes(t *testing.T) {
	doc := advisoryDoc{SchemaVersion: normalizedAdvisorySchemaVersion, VulnID: "CVE-Y", SinkKind: "ssrf"}
	facts, ok := doc.toFacts("CVE-Y")
	if !ok {
		t.Fatal("toFacts(v2 doc) ok=false, want true (v2 must keep validating)")
	}
	if facts.SinkKind != "ssrf" || !facts.Trigger.Zero() {
		t.Errorf("v2 decode wrong: %+v", facts)
	}
}

// --- classFromSinkKind / sinkKindRecognized (upstream sink-kind vocabulary reconcile) ----------

// Native back-compat: every vulnclass.Class value still resolves 1:1, cwe[] irrelevant to this path.
func TestClassFromSinkKind_NativeEnumBackCompat(t *testing.T) {
	for _, c := range vulnclass.KnownClasses() {
		got, ok := classFromSinkKind(string(c), nil)
		if !ok || got != c {
			t.Errorf("classFromSinkKind(%q, nil) = (%q,%v), want (%q,true)", c, got, ok, c)
		}
		// A cwe[] that would (if consulted) point elsewhere must NOT override an already-native kind.
		got, ok = classFromSinkKind(string(c), []string{"CWE-918"})
		if !ok || got != c {
			t.Errorf("classFromSinkKind(%q, [CWE-918]) = (%q,%v), want (%q,true) (native kind wins)", c, got, ok, c)
		}
	}
}

// Intel's 1:1 vocabulary members (distinct strings from the vulnclass.Class enum) map onto the
// agreed class regardless of cwe[].
func TestClassFromSinkKind_IntelVocabDirect(t *testing.T) {
	tests := []struct {
		intelKind string
		want      vulnclass.Class
	}{
		{"memory_corruption", vulnclass.ClassMemorySafety},
		{"resource_exhaustion", vulnclass.ClassDoS},
		// path_traversal and ssrf are Intel-vocabulary-identical to the native enum strings; they
		// resolve via the native-enum branch, exercised in TestClassFromSinkKind_NativeEnumBackCompat.
	}
	for _, tt := range tests {
		got, ok := classFromSinkKind(tt.intelKind, nil)
		if !ok || got != tt.want {
			t.Errorf("classFromSinkKind(%q, nil) = (%q,%v), want (%q,true)", tt.intelKind, got, ok, tt.want)
		}
	}
}

// code_execution fans out by cwe[]: each branch, the ambiguous case (→ honest-absent), and the
// zero-CWE / no-recognized-CWE cases (→ honest-absent).
func TestClassFromSinkKind_CodeExecutionCWEFanout(t *testing.T) {
	tests := []struct {
		name   string
		cwes   []string
		want   vulnclass.Class
		wantOK bool
	}{
		{"CWE-502 deserialization", []string{"CWE-502"}, vulnclass.ClassDeserialize, true},
		{"CWE-1336 SSTI", []string{"CWE-1336"}, vulnclass.ClassTemplateInj, true},
		{"CWE-94 (SSTI convention)", []string{"CWE-94"}, vulnclass.ClassTemplateInj, true},
		{"CWE-77 command injection", []string{"CWE-77"}, vulnclass.ClassInjection, true},
		{"CWE-78 command injection", []string{"CWE-78"}, vulnclass.ClassInjection, true},
		{"lowercase/no-prefix CWE normalizes", []string{"78"}, vulnclass.ClassInjection, true},
		{"two CWEs agreeing on one class", []string{"CWE-77", "CWE-78"}, vulnclass.ClassInjection, true},
		{"ambiguous: deserialization + injection", []string{"CWE-502", "CWE-78"}, vulnclass.ClassUnknown, false},
		{
			// Documented ignore-out-of-set / pin-in-set: a single in-set fan-out CWE (CWE-502)
			// pins even when an out-of-set CWE (CWE-918/SSRF) rides along — the out-of-set CWE is
			// ignored for the fan-out, so this is a pin, not ambiguity.
			"in-set pins despite out-of-set CWE riding along", []string{"CWE-502", "CWE-918"}, vulnclass.ClassDeserialize, true,
		},
		{"unrecognized CWE only", []string{"CWE-9999"}, vulnclass.ClassUnknown, false},
		{"empty cwe list", nil, vulnclass.ClassUnknown, false},
		{
			// A fan-out-irrelevant CWE (SSRF) riding along on a code_execution advisory does not
			// pin a fan-out class; it is simply ignored, not treated as ambiguity.
			"non-fanout CWE ignored, no other signal", []string{"CWE-918"}, vulnclass.ClassUnknown, false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := classFromSinkKind("code_execution", tt.cwes)
			if ok != tt.wantOK || (ok && got != tt.want) {
				t.Errorf("classFromSinkKind(code_execution, %v) = (%q,%v), want (%q,%v)", tt.cwes, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// Empty and genuinely unrecognized values fail open (ok=false), so the classifier stands.
func TestClassFromSinkKind_UnrecognizedFailsOpen(t *testing.T) {
	for _, s := range []string{"", "totally-made-up", "SSRF", "ssrf "} {
		if got, ok := classFromSinkKind(s, nil); ok {
			t.Errorf("classFromSinkKind(%q, nil) = (%q,true), want ok=false (fail open)", s, got)
		}
	}
}

func TestSinkKindRecognized(t *testing.T) {
	// Empty, native-enum members, Intel-vocab members, and "code_execution" itself are all
	// recognized vocabulary — even though "code_execution" only conditionally PINS a class.
	for _, ok := range []string{"", "ssrf", "memory_corruption", "resource_exhaustion", "code_execution"} {
		if !sinkKindRecognized(ok) {
			t.Errorf("sinkKindRecognized(%q) = false, want true", ok)
		}
	}
	if sinkKindRecognized("nonsense") {
		t.Error("sinkKindRecognized accepted a non-enum, non-Intel-vocab value")
	}
}

// --- ingressKindRecognized / failedFixClassRecognized -----------------------------------------

func TestIngressKindRecognized(t *testing.T) {
	for _, ok := range []string{"", "http", "grpc", "cli", "library"} {
		if !ingressKindRecognized(ok) {
			t.Errorf("ingressKindRecognized(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"HTTP", "websocket", "tcp", "http "} {
		if ingressKindRecognized(bad) {
			t.Errorf("ingressKindRecognized(%q) = true, want false", bad)
		}
	}
}

func TestFailedFixClassRecognized(t *testing.T) {
	for _, ok := range []string{"", "naive-dep-bump-insufficient", "guard-keyed-away-from-sink"} {
		if !failedFixClassRecognized(ok) {
			t.Errorf("failedFixClassRecognized(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"naive_dep_bump", "unknown-class", "guard-keyed-away"} {
		if failedFixClassRecognized(bad) {
			t.Errorf("failedFixClassRecognized(%q) = true, want false", bad)
		}
	}
}

// An unrecognized ingress_kind / failed_fix_class fails open in toFacts: the operand drops to "",
// the rest of the descriptor still decodes (never rejecting the whole document).
func TestToFacts_UnrecognizedEnumsFailOpen(t *testing.T) {
	doc := advisoryDoc{
		SchemaVersion: normalizedAdvisorySchemaVersionV3,
		VulnID:        "CVE-Z",
		Trigger:       &docTrigger{IngressKind: "carrier-pigeon", Route: "/x", Param: "p", MalformedToken: "shape"},
		Fix:           &docFix{UpstreamCommit: "c1", FailedFixClass: "not-a-real-class"},
	}
	facts, ok := doc.toFacts("CVE-Z")
	if !ok {
		t.Fatal("toFacts ok=false, want true (unrecognized enum must fail open, not reject the doc)")
	}
	if facts.Trigger.IngressKind != "" {
		t.Errorf("IngressKind = %q, want \"\" (failed open)", facts.Trigger.IngressKind)
	}
	if facts.Trigger.Route != "/x" || facts.Trigger.Param != "p" {
		t.Errorf("rest of trigger dropped: %+v", facts.Trigger)
	}
	if facts.Fix.FailedFixClass != "" {
		t.Errorf("FailedFixClass = %q, want \"\" (failed open)", facts.Fix.FailedFixClass)
	}
	if facts.Fix.UpstreamCommit != "c1" {
		t.Errorf("rest of fix dropped: %+v", facts.Fix)
	}
}

// --- resolveVulnClass: row 2 override + withdrawn (T1) -----------------------------------------

func TestResolveVulnClass(t *testing.T) {
	tests := []struct {
		name  string
		facts AdvisoryFacts
		want  vulnclass.Class
	}{
		{
			// Declared sink_kind supersedes a misleading CWE (CWE-125 → memory_safety classifier).
			name:  "sink_kind overrides misleading CWE",
			facts: AdvisoryFacts{SinkKind: "ssrf", CWEs: []string{"CWE-125"}},
			want:  vulnclass.ClassSSRF,
		},
		{
			// code_execution's cwe[] doesn't pin a fan-out class (CWE-918 isn't in the fan-out
			// set) → honest-absent, the classifier result stands (zero-regressions invariant).
			name:  "unpinned code_execution falls back to classifier",
			facts: AdvisoryFacts{SinkKind: "code_execution", CWEs: []string{"CWE-918"}},
			want:  vulnclass.ClassSSRF, // from CWE-918, not from sink_kind
		},
		{
			// code_execution's cwe[] DOES pin exactly one fan-out class → sink_kind resolves.
			name:  "code_execution pinned by CWE-502 resolves to deserialization",
			facts: AdvisoryFacts{SinkKind: "code_execution", CWEs: []string{"CWE-502"}},
			want:  vulnclass.ClassDeserialize,
		},
		{
			// code_execution's cwe[] is ambiguous (two distinct fan-out classes) → honest-absent;
			// the classifier's first-recognized-CWE result stands (here, deserialization from
			// CWE-502, since ClassifyAdvisory scans CWEs in order and returns the first hit).
			name:  "ambiguous code_execution falls back to classifier",
			facts: AdvisoryFacts{SinkKind: "code_execution", CWEs: []string{"CWE-502", "CWE-78"}},
			want:  vulnclass.ClassDeserialize,
		},
		{
			// Intel's own vocabulary member (distinct from the native enum string) resolves.
			name:  "Intel vocab memory_corruption maps to memory_safety",
			facts: AdvisoryFacts{SinkKind: "memory_corruption", CWEs: []string{"CWE-400"}},
			want:  vulnclass.ClassMemorySafety,
		},
		{
			// No sink_kind: pure classifier.
			name:  "no sink_kind uses classifier",
			facts: AdvisoryFacts{CWEs: []string{"CWE-400"}},
			want:  vulnclass.ClassDoS,
		},
		{
			// Withdrawn forces ClassUnknown even with a declared sink_kind (never a live route).
			name:  "withdrawn supersedes sink_kind",
			facts: AdvisoryFacts{Withdrawn: true, SinkKind: "ssrf", CWEs: []string{"CWE-918"}},
			want:  vulnclass.ClassUnknown,
		},
		{
			// Unclassifiable, no sink_kind → ClassUnknown (honest not-assessed).
			name:  "unclassifiable stays unknown",
			facts: AdvisoryFacts{Summary: "a benign note"},
			want:  vulnclass.ClassUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVulnClass(tt.facts); got != tt.want {
				t.Errorf("resolveVulnClass = %q, want %q", got, tt.want)
			}
		})
	}
}

// Zero-override regression guard: for every recognized class, a matching sink_kind must NOT change a
// correct classifier result (they agree), and must never silently produce a DIFFERENT class than the
// declared kind.
func TestResolveVulnClass_NoRegressionOnAgreement(t *testing.T) {
	for _, c := range vulnclass.KnownClasses() {
		facts := AdvisoryFacts{SinkKind: string(c)}
		if got := resolveVulnClass(facts); got != c {
			t.Errorf("resolveVulnClass(sink_kind=%q) = %q, want %q", c, got, c)
		}
	}
}

// --- v3 affected_packages[] multi-package block ------------------------------------------------

// A v3 doc WITH affected_packages[] decodes and carries EVERY element through toFacts, while the
// scalar-primary mapping (v2 fields) is unchanged.
func TestToFacts_V3AffectedPackages_CarriesAll(t *testing.T) {
	doc := advisoryDoc{
		SchemaVersion: normalizedAdvisorySchemaVersionV3,
		VulnID:        "CVE-MP-1",
		// scalar primary (v2 back-compat) = the first package.
		Module:        "example.com/a",
		VersionScheme: "gomod",
		FixedVersion:  "v2.0.0",
		AffectedRanges: []docRange{
			{Fixed: "v2.0.0", FixedVersion: "v2.0.0"},
		},
		AffectedPackages: []docAffectedPackage{
			{
				Module:         "example.com/a",
				VersionScheme:  "gomod",
				FixedVersion:   "v2.0.0",
				AffectedRanges: []docRange{{Fixed: "v2.0.0", FixedVersion: "v2.0.0"}},
				Symbols:        []string{"example.com/a.Sink"},
			},
			{
				Module:         "example.com/b",
				VersionScheme:  "gomod",
				FixedVersion:   "v3.1.0",
				AffectedRanges: []docRange{{Introduced: "v3.0.0", Fixed: "v3.1.0", FixedVersion: "v3.1.0"}},
				Symbols:        []string{"example.com/b.Reset"},
			},
		},
	}
	facts, ok := doc.toFacts("CVE-MP-1")
	if !ok {
		t.Fatal("toFacts(v3 multi-package doc) ok=false, want true")
	}
	// scalar-lift unchanged: yields the primary.
	if facts.Module != "example.com/a" || facts.FixedVersion != "v2.0.0" {
		t.Errorf("scalar primary lift = (%q,%q), want (example.com/a, v2.0.0)", facts.Module, facts.FixedVersion)
	}
	if len(facts.AffectedPackages) != 2 {
		t.Fatalf("AffectedPackages = %d, want 2", len(facts.AffectedPackages))
	}
	if facts.AffectedPackages[0].Module != "example.com/a" || facts.AffectedPackages[1].Module != "example.com/b" {
		t.Errorf("AffectedPackages modules = [%q,%q], want [example.com/a, example.com/b]",
			facts.AffectedPackages[0].Module, facts.AffectedPackages[1].Module)
	}
	b := facts.AffectedPackages[1]
	if len(b.AffectedRanges) != 1 || b.AffectedRanges[0] != (Range{Introduced: "v3.0.0", Fixed: "v3.1.0", FixedVersion: "v3.1.0"}) {
		t.Errorf("secondary ranges = %+v, want one {v3.0.0,v3.1.0}", b.AffectedRanges)
	}
	if len(b.Symbols) != 1 || b.Symbols[0] != "example.com/b.Reset" {
		t.Errorf("secondary symbols = %v, want [example.com/b.Reset]", b.Symbols)
	}
}

// Per-element fail-open (inv.5): an element with an unrecognized version_scheme, and one with a
// boundless range, each DROP that element — never the whole document. A good element survives.
func TestToFacts_V3AffectedPackages_PerElementFailOpen(t *testing.T) {
	doc := advisoryDoc{
		SchemaVersion: normalizedAdvisorySchemaVersionV3,
		VulnID:        "CVE-MP-2",
		Module:        "example.com/good",
		VersionScheme: "gomod",
		AffectedPackages: []docAffectedPackage{
			{Module: "example.com/good", VersionScheme: "gomod", AffectedRanges: []docRange{{Fixed: "v1.2.0"}}},
			{Module: "example.com/badscheme", VersionScheme: "cargo", AffectedRanges: []docRange{{Fixed: "v1.0.0"}}}, // unrecognized scheme → dropped
			{Module: "example.com/badrange", VersionScheme: "gomod", AffectedRanges: []docRange{{}}},                 // boundless range → dropped
		},
	}
	facts, ok := doc.toFacts("CVE-MP-2")
	if !ok {
		t.Fatal("toFacts must NOT reject the doc for a bad element (per-element fail-open)")
	}
	if len(facts.AffectedPackages) != 1 {
		t.Fatalf("AffectedPackages = %d, want 1 (only the good element survives)", len(facts.AffectedPackages))
	}
	if facts.AffectedPackages[0].Module != "example.com/good" {
		t.Errorf("surviving element = %q, want example.com/good", facts.AffectedPackages[0].Module)
	}
}

// A v2 doc (no affected_packages[]) decodes exactly as today: AffectedPackages is nil.
func TestToFacts_V2NoArray_NilAffectedPackages(t *testing.T) {
	doc := advisoryDoc{
		SchemaVersion:  normalizedAdvisorySchemaVersion,
		VulnID:         "CVE-V2",
		Module:         "example.com/only",
		VersionScheme:  "gomod",
		AffectedRanges: []docRange{{Fixed: "v1.0.0"}},
	}
	facts, ok := doc.toFacts("CVE-V2")
	if !ok {
		t.Fatal("toFacts(v2 doc) ok=false, want true")
	}
	if facts.AffectedPackages != nil {
		t.Errorf("AffectedPackages = %+v, want nil (v2 doc carries no array)", facts.AffectedPackages)
	}
}
