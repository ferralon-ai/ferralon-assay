// internal/pipeline/disqual_js_test.go
//
// Hermetic proof of the JS/TS Increment-2 disqualification path: lockfile-derived
// installed versions drive the version-range axis with NPM (node-semver) ordering.
// codebase_inventory reads the resolved version via the plugin
// (ResolveDependencyVersions) and folds it into resolved_version; disqualification_discovery
// then compares it against the advisory's npm upper-exclusive bound.
//
// The pipeline never imports jsanalysis (inv.8), so these stubs carry the resolver's output
// (proven real by the lockfile-fixture tests at the jsanalysis layer) across the boundary.
// patched → DISQUALIFIED; vulnerable → PROCEEDS; UNRESOLVED → PROCEEDS (fail open, never a
// false not-affected).
package pipeline

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// jsVersionStub mimics the live JS plugin's ResolveDependencyVersions for the
// TEGRON-JS-DEP-0001 repro: it returns the installed left-pad version the real lockfile
// resolver produces. Resolved=false models an UNRESOLVED (unparseable lockfile) repro.
type jsVersionStub struct {
	plugin.StubPlugin
	version  string
	resolved bool
}

func (jsVersionStub) Language() string { return "js" }

func (s jsVersionStub) ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
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
			Source:     "npm",
		},
	}, nil
}

// runJSDisqual drives advisory_intake (seeds the npm range), codebase_inventory (resolves
// the version via the stub) and disqualification_discovery against a fabricated JS case,
// returning the discovery result. It points at the existing JS SSRF repro's source tree
// only so codebase_inventory has a real build dir to detect as JS; the resolved version is
// supplied by the stub (the lockfile parse is proven separately at the analysis layer).
func runJSDisqual(t *testing.T, version string, resolved bool) DisqualResult {
	t.Helper()
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-js-dep", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "TEGRON-JS-DEP-0001", Source: "corpus"},
		Codebase: assessment.CodebaseRef{
			Repo:     "tegron/js-dep-repro",
			Revision: "v1",
			Acquisition: assessment.Acquisition{
				Mode: "vendored_repro",
				Path: "../corpus/testdata/repros/TEGRON-JS-SSRF-0001-vulnerable",
			},
		},
	}}
	stub := jsVersionStub{version: version, resolved: resolved}
	if err := (advisoryIntake{}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	if err := (codebaseInventory{plugin: stub}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("codebase_inventory: %v", err)
	}
	return runDisqual(t, store, c.ID)
}

// PATCHED: left-pad installed at 1.4.0 == fixed (affects < 1.4.0) → provably outside → DISQUALIFIED.
func TestJSDisqual_PatchedVersion_Disqualifies(t *testing.T) {
	res := runJSDisqual(t, "1.4.0", true)
	if !res.Disqualified {
		t.Fatalf("patched (left-pad 1.4.0 >= fixed 1.4.0) must DISQUALIFY, got %+v", res)
	}
	if res.Reason != ReasonVersionNotInRange {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonVersionNotInRange)
	}
}

// VULNERABLE: left-pad installed at 1.3.9 < fixed 1.4.0 → inside affected range → PROCEEDS.
func TestJSDisqual_VulnerableVersion_Proceeds(t *testing.T) {
	res := runJSDisqual(t, "1.3.9", true)
	if res.Disqualified {
		t.Fatalf("vulnerable (left-pad 1.3.9 < fixed 1.4.0) must PROCEED, got %+v", res)
	}
	if res.Reason != ReasonInsufficient {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonInsufficient)
	}
}

// UNRESOLVED: the resolver could not determine the installed version. The version axis must
// FAIL OPEN — PROCEED, never a false not-affected (inv.5). This is the honesty guard.
func TestJSDisqual_UnresolvedVersion_FailsOpen(t *testing.T) {
	res := runJSDisqual(t, "", false)
	if res.Disqualified {
		t.Fatalf("UNRESOLVED version must FAIL OPEN (proceed), got disqualified %+v", res)
	}
	if res.Reason != ReasonInsufficient {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonInsufficient)
	}
}

// A numeric-ordering trap at the pipeline layer: had the npm comparator been lexical,
// "1.10.0" would sort BELOW "1.9.0" and wrongly fail to disqualify. With node-semver numeric
// ordering the installed 1.10.0 (>= a hypothetical fixed 1.9.0) disqualifies.
func TestJSDisqual_NumericOrdering_NotLexical(t *testing.T) {
	store := artifact.NewMemStore()
	caseID := "case-js-numeric"
	putJSON(t, store, caseID, artifact.TypeNormalizedAdvisory, map[string]any{
		"vuln_id":         "TEGRON-JS-DEP-0001",
		"affected_ranges": []map[string]string{{"upper_exclusive": "1.9.0", "scheme": "npm"}},
		"trust_tier":      "first_party", // curated-corpus provenance intake would stamp (inv.5 gate)
	})
	putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{
		"resolved_version": "1.10.0",
	})
	res := runDisqual(t, store, caseID)
	if !res.Disqualified {
		t.Fatalf("1.10.0 >= 1.9.0 (numeric) must DISQUALIFY; a lexical compare would wrongly proceed: %+v", res)
	}
	if res.Reason != ReasonVersionNotInRange {
		t.Fatalf("reason = %q, want %q", res.Reason, ReasonVersionNotInRange)
	}
}
