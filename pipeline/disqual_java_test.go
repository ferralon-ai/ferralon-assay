// internal/pipeline/disqual_java_test.go
//
// Hermetic proof of the Java Increment-2 disqualification path: pom/gradle-derived dependency
// versions drive the version-range axis with MAVEN ordering. codebase_inventory reads the
// declared version via the plugin (ResolveDependencyVersions) and folds it into resolved_version;
// disqualification_discovery then compares it against the advisory's Maven upper-exclusive bound.
//
// The pipeline never imports javaanalysis (inv.8), so these stubs carry the resolver's output
// (proven real by TestResolveVersions_CorpusRepros at the javaanalysis layer) across the boundary.
// patched → DISQUALIFIED; vulnerable → PROCEEDS; UNRESOLVED → PROCEEDS (fail open, never a false
// not-affected).
package pipeline

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// javaVersionStub mimics the live Java plugin's ResolveDependencyVersions for the
// TEGRON-JAVA-DEP-0001 repro: it returns the declared widget version the real pom resolver
// produces. Resolved=false models the UNRESOLVED (BOM-managed) repro.
type javaVersionStub struct {
	plugin.StubPlugin
	version  string
	resolved bool
}

func (javaVersionStub) Language() string { return "java" }

func (s javaVersionStub) ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	part := plugin.Complete()
	if !s.resolved {
		part = plugin.Partial(plugin.PartialReasonToolFailure)
	}
	return plugin.DependencyVersionResult{
		Partiality: part,
		Found:      true,
		Match: plugin.ResolvedDependency{
			Coordinate: req.Coordinate,
			Version:    s.version,
			Resolved:   s.resolved,
			Source:     "pom",
		},
	}, nil
}

// runJavaDisqual drives the two stages the Java disqualification path needs (advisory_intake to
// seed the Maven range, codebase_inventory to resolve the version via the stub, then
// disqualification_discovery) against the named vendored repro, and returns the discovery result.
func runJavaDisqual(t *testing.T, repro string, stub plugin.LanguagePlugin) DisqualResult {
	t.Helper()
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-" + repro, Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "TEGRON-JAVA-DEP-0001", Source: "corpus"},
		Codebase: assessment.CodebaseRef{
			Repo:     "com.example/dep-repro",
			Revision: "v1",
			Acquisition: assessment.Acquisition{
				Mode: "vendored_repro",
				Path: "../corpus/testdata/repros/" + repro,
			},
		},
	}}
	if err := (advisoryIntake{}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	if err := (codebaseInventory{plugin: stub}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("codebase_inventory: %v", err)
	}
	return runDisqual(t, store, c.ID)
}

// PATCHED: widget declared at 1.4.0 == fixed (affects < 1.4.0) → provably outside → DISQUALIFIED.
func TestJavaDisqual_PatchedVersion_Disqualifies(t *testing.T) {
	res := runJavaDisqual(t, "TEGRON-JAVA-DEP-0001-patched", javaVersionStub{version: "1.4.0", resolved: true})
	if !res.Disqualified {
		t.Fatalf("patched (widget 1.4.0 >= fixed 1.4.0) must DISQUALIFY, got %+v", res)
	}
	if res.Reason != ReasonVersionNotInRange {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonVersionNotInRange)
	}
}

// VULNERABLE: widget declared at 1.3.9 < fixed 1.4.0 → inside affected range → PROCEEDS.
func TestJavaDisqual_VulnerableVersion_Proceeds(t *testing.T) {
	res := runJavaDisqual(t, "TEGRON-JAVA-DEP-0001-vulnerable", javaVersionStub{version: "1.3.9", resolved: true})
	if res.Disqualified {
		t.Fatalf("vulnerable (widget 1.3.9 < fixed 1.4.0) must PROCEED, got %+v", res)
	}
	if res.Reason != ReasonInsufficient {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonInsufficient)
	}
}

// UNRESOLVED: the resolver could not determine the declared version (BOM-managed). The version
// axis must FAIL OPEN — PROCEED, never a false not-affected (inv.5). This is the honesty guard.
func TestJavaDisqual_UnresolvedVersion_FailsOpen(t *testing.T) {
	res := runJavaDisqual(t, "TEGRON-JAVA-DEP-0001-unresolved", javaVersionStub{version: "", resolved: false})
	if res.Disqualified {
		t.Fatalf("UNRESOLVED version must FAIL OPEN (proceed), got disqualified %+v", res)
	}
	if res.Reason != ReasonInsufficient {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonInsufficient)
	}
}

// A numeric-ordering trap at the pipeline layer: had the comparator been lexical, "1.4.10"
// would sort BELOW "1.4.9" and wrongly fail to disqualify. With Maven numeric ordering the
// patched 1.4.10 (>= a hypothetical fixed 1.4.9) disqualifies. This guards the integration of
// the Maven comparator into the disqualification decision, not just the comparator in isolation.
func TestJavaDisqual_NumericOrdering_NotLexical(t *testing.T) {
	store := artifact.NewMemStore()
	caseID := "case-numeric"
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id":         "TEGRON-JAVA-DEP-0001",
		"affected_ranges": []map[string]string{{"upper_exclusive": "1.4.9", "scheme": "maven"}},
		"trust_tier":      "first_party", // curated-corpus provenance intake would stamp (inv.5 gate)
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{
		"resolved_version": "1.4.10",
	})
	res := runDisqual(t, store, caseID)
	if !res.Disqualified {
		t.Fatalf("1.4.10 >= 1.4.9 (numeric) must DISQUALIFY; a lexical compare would wrongly proceed: %+v", res)
	}
	if res.Reason != ReasonVersionNotInRange {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonVersionNotInRange)
	}
}
