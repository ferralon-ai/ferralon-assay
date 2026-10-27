// disqual_gotoolchain_realstage_test.go
//
// The real-stage end-to-end for the go-toolchain version axis, with NO hand-written inventory
// artifact.
//
// The existing "U7 end-to-end proof" (disqual_gotoolchain_u7_test.go) declares the span
// advisory_intake → inventory → disqualification_discovery, but its helper hand-writes the inventory
// artifact at the middle seam (disqual_versionscheme_u5_test.go:87) — and the middle seam is exactly
// where the defect lived. It executes A and C and fakes B. So these cases run all three stages for
// real over a real go.mod on disk, seed nothing between them, and assert the U7 comparator ADJUDICATED
// the version the pipeline itself produced.
//
// M1's integration test proves the toolchain fact is RECORDED. This one proves it is CONSUMED.
package pipeline

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// runRealGoToolchainAxis runs advisory_intake → codebase_inventory → disqualification_discovery with
// nothing seeded between them, and returns the toolchain fact the inventory stage produced, the
// resolved_version it wrote, and the discovery verdict the version axis reached.
func runRealGoToolchainAxis(t *testing.T, vulnID, goMod, declared, observed string, trustObserved bool, plug goManifestPlugin) (ToolchainFact, string, DisqualResult) {
	t.Helper()
	buildDir := writeGoModFixture(t, goMod)
	store := artifact.NewMemStore()
	caseID := "case-realstage-" + vulnID
	c := &assessment.Assessment{ID: caseID, Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: vulnID, Source: "corpus"},
		Codebase: assessment.CodebaseRef{
			Repo:        "example.com/target",
			Revision:    "v1",
			Acquisition: assessment.Acquisition{Mode: "git"},
		},
	}}
	if err := (advisoryIntake{}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	stage := codebaseInventory{
		checkout:         dirCheckout{dir: buildDir, lang: "go"},
		plugin:           plug,
		subjectGoVersion: declared,
		ciGoVersion:      observed,
		trustCIGoVersion: trustObserved,
	}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("codebase_inventory: %v", err)
	}
	fact, ok := Toolchain(store, caseID)
	if !ok {
		t.Fatal("no inventory artifact")
	}
	ver, _ := extractResolvedVersion(store, caseID)
	return fact, ver, runDisqual(t, store, caseID)
}

// TestGoToolchainAxis_RealStagesEndToEnd is the test whose absence let the U7 comparator merge with
// no input. Every case runs the real stages over a real go.mod; the assertion is on the ADJUDICATION,
// not on an intermediate value.
//
// The floor cases are the soundness argument in executable form: goToolchainVersionOutsideRange
// is monotone non-decreasing in its version argument, so a floor already past every branch fix proves
// the true toolchain is past it — disqualifying on `go 1.21.0` for a CVE fixed at go1.20.10/go1.21.3 is
// sound even though the build may have used any go1.21.x or later. The converse never disqualifies: a
// floor BELOW a fix proves nothing and must fail OPEN.
func TestGoToolchainAxis_RealStagesEndToEnd(t *testing.T) {
	tests := []struct {
		name     string
		vulnID   string
		goMod    string
		declared string
		observed string
		trust    bool
		// pinBuild replaces the toolchain the build's environment resolves (reported only when the
		// directives do not bound it) with buildToolchain; "" stands for one that is not established.
		pinBuild       bool
		buildToolchain string
		wantFact       ToolchainFact
		wantVersion    string
		wantDisqual    bool
		wantReason     string
		wantRationale  string
	}{
		{
			// CVE-2023-39325 is fixed go1.20.10 on the 1.20.x branch AND go1.21.3 on mainline. A
			// go1.22 floor is at or past BOTH, so it is provably outside the whole disjoint set.
			name:          "a floor past every branch fix disqualifies",
			vulnID:        "CVE-2023-39325",
			goMod:         "module example.com/target\n\ngo 1.22.0\n",
			wantFact:      ToolchainFact{Version: "go1.22.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
			wantVersion:   "go1.22.0",
			wantDisqual:   true,
			wantReason:    ReasonVersionNotInRange,
			wantRationale: "monotonicity: outside(floor) implies outside(true toolchain)",
		},
		{
			// go1.21.0 is INSIDE the mainline range (fixed go1.21.3), so the set is not wholly
			// outside — the axis must proceed, never disqualify.
			name:          "a floor inside a branch range proceeds",
			vulnID:        "CVE-2023-39325",
			goMod:         "module example.com/target\n\ngo 1.21.0\n",
			wantFact:      ToolchainFact{Version: "go1.21.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
			wantVersion:   "go1.21.0",
			wantDisqual:   false,
			wantReason:    ReasonInsufficient,
			wantRationale: "a floor below a fix proves nothing about the true toolchain",
		},
		{
			// The toolchain directive supplies the tighter floor and it reaches the axis — but a
			// PATCHED 1.20.x floor still fails open on a backport, and that is correct. go1.20.14 is
			// past the 1.20 branch fix and below the mainline range's introduced go1.21.0, so as an
			// exact version it would sit in the gap. As a floor it does not: the true toolchain may be
			// go1.21.1, inside the mainline range. Being below a lower bound does not carry from a
			// floor to the versions above it, so a floor is read against upper bounds only.
			name:          "the tighter floor reaches the axis; a patched branch floor still fails open",
			vulnID:        "CVE-2023-39325",
			goMod:         "module example.com/target\n\ngo 1.20\n\ntoolchain go1.20.14\n",
			wantFact:      ToolchainFact{Version: "go1.20.14", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective},
			wantVersion:   "go1.20.14",
			wantDisqual:   false,
			wantReason:    ReasonInsufficient,
			wantRationale: "a floor in the gap may be any later toolchain, including one inside the mainline range",
		},
		{
			// The same version declared EXACTLY sits in the backport's gap: past go1.20.10 and below
			// the mainline range's introduced go1.21.0. buildAffectedRanges carries Introduced, so it
			// is outside both ranges.
			name:          "an exact patched branch toolchain in the backport gap disqualifies",
			vulnID:        "CVE-2023-39325",
			goMod:         "module example.com/target\n\ngo 1.20\n",
			declared:      "go1.20.14",
			wantFact:      ToolchainFact{Version: "go1.20.14", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
			wantVersion:   "go1.20.14",
			wantDisqual:   true,
			wantReason:    ReasonVersionNotInRange,
			wantRationale: "go1.20.14 >= go1.20.10 and < go1.21.0: outside both branch ranges",
		},
		{
			// An EXACT bound reaches the axis on exactly the same terms — Bound gates reachability
			// (M4), not the version axis, because the axis's only conclusion is "past the fix".
			name:          "an exact TRUSTED observed toolchain disqualifies on the same axis",
			vulnID:        "CVE-2024-24790",
			goMod:         "module example.com/target\n\ngo 1.19\n",
			observed:      "go1.22.4",
			trust:         true,
			wantFact:      ToolchainFact{Version: "go1.22.4", Bound: ToolchainBoundExact, Source: ToolchainSourceCIObserved},
			wantVersion:   "go1.22.4",
			wantDisqual:   true,
			wantReason:    ReasonVersionNotInRange,
			wantRationale: "exact and minimum are both admissible inputs to a disqualification",
		},
		{
			// THE SHIPPED NO-CONFIG DEFAULT, all the way to the adjudication. A recent Go is observed
			// on the runner (as it is on every hosted scan) but nobody asserted it describes the
			// subject, so the axis adjudicates the go.mod FLOOR instead. go1.21.0 is inside the
			// affected range, so the advisory is NOT disqualified — where the trusted go1.22.4
			// observation above disqualifies it.
			//
			// This is the case reviewer-07's major was about: on a dedicated scan job the observation
			// is the runner image's Go, past every backport fix, and treating it as exact fabricated a
			// not-affected for a build still exposed. The default now declines to conclude.
			name:          "the no-config default adjudicates the FLOOR, not the observed runner Go",
			vulnID:        "CVE-2024-24790",
			goMod:         "module example.com/target\n\ngo 1.21.0\n",
			observed:      "go1.22.4",
			wantFact:      ToolchainFact{Version: "go1.21.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
			wantVersion:   "go1.21.0",
			wantDisqual:   false,
			wantReason:    ReasonInsufficient,
			wantRationale: "an untrusted observation may not license a not-affected (inv.5, ruling 7)",
		},
		{
			// A subject that declares a toolchain still inside an affected range must NOT be
			// disqualified — the whole point is that this case now reaches reachability instead of
			// being silently green.
			name:          "an exact toolchain inside the affected range proceeds",
			vulnID:        "CVE-2024-24790",
			goMod:         "module example.com/target\n\ngo 1.19\n",
			declared:      "go1.21.5",
			wantFact:      ToolchainFact{Version: "go1.21.5", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
			wantVersion:   "go1.21.5",
			wantDisqual:   false,
			wantReason:    ReasonInsufficient,
			wantRationale: "go1.21.5 < go1.21.11 is still affected",
		},
		{
			// GO-2021-0264 is fixed go1.16.10 and go1.17.3; a go 1.21.0 floor is past both.
			name:          "a stdlib advisory with toolchain ranges disqualifies on a floor past its fixes",
			vulnID:        "GO-2021-0264",
			goMod:         "module example.com/target\n\ngo 1.21.0\n",
			wantFact:      ToolchainFact{Version: "go1.21.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
			wantVersion:   "go1.21.0",
			wantDisqual:   true,
			wantReason:    ReasonVersionNotInRange,
			wantRationale: "go1.21.0 is at or past go1.17.3",
		},
		{
			name:          "a stdlib advisory proceeds on a floor inside a branch range",
			vulnID:        "GO-2021-0264",
			goMod:         "module example.com/target\n\ngo 1.17\n\ntoolchain go1.17.0\n",
			wantFact:      ToolchainFact{Version: "go1.17.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective},
			wantVersion:   "go1.17.0",
			wantDisqual:   false,
			wantReason:    ReasonInsufficient,
			wantRationale: "go1.17.0 < go1.17.3 is still affected",
		},

		// GO-2021-0264's go1.16.x branch: affected below go1.16.10, not at or after it, up to the
		// mainline range's introduced go1.17.0.
		{
			name:          "GO-2021-0264: go1.16.5 is inside the go1.16 branch range",
			vulnID:        "GO-2021-0264",
			goMod:         "module example.com/target\n\ngo 1.16\n",
			declared:      "go1.16.5",
			wantFact:      ToolchainFact{Version: "go1.16.5", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
			wantVersion:   "go1.16.5",
			wantDisqual:   false,
			wantReason:    ReasonInsufficient,
			wantRationale: "go1.16.5 < go1.16.10 is affected",
		},
		{
			name:          "GO-2021-0264: go1.16.9 is the last affected go1.16 release",
			vulnID:        "GO-2021-0264",
			goMod:         "module example.com/target\n\ngo 1.16\n",
			declared:      "go1.16.9",
			wantFact:      ToolchainFact{Version: "go1.16.9", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
			wantVersion:   "go1.16.9",
			wantDisqual:   false,
			wantReason:    ReasonInsufficient,
			wantRationale: "go1.16.9 < go1.16.10 is affected",
		},
		{
			name:          "GO-2021-0264: go1.16.10 is the go1.16 branch fix",
			vulnID:        "GO-2021-0264",
			goMod:         "module example.com/target\n\ngo 1.16\n",
			declared:      "go1.16.10",
			wantFact:      ToolchainFact{Version: "go1.16.10", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
			wantVersion:   "go1.16.10",
			wantDisqual:   true,
			wantReason:    ReasonVersionNotInRange,
			wantRationale: "go1.16.10 is the fix and below the mainline range's introduced go1.17.0",
		},
		{
			name:          "GO-2021-0264: a later go1.16 release is past the branch fix",
			vulnID:        "GO-2021-0264",
			goMod:         "module example.com/target\n\ngo 1.16\n",
			declared:      "go1.16.15",
			wantFact:      ToolchainFact{Version: "go1.16.15", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
			wantVersion:   "go1.16.15",
			wantDisqual:   true,
			wantReason:    ReasonVersionNotInRange,
			wantRationale: "go1.16.15 >= go1.16.10 and < go1.17.0: outside both ranges",
		},

		// A go directive below 1.21 is advisory to the go commands that build such modules: `go 1.17`
		// is legally built by go1.16.5. It is no floor, and the toolchain the build's environment
		// resolves stands in for it only under the observation's trust.
		{
			name:          "a pre-1.21 go directive is no floor: the stdlib advisory fails open",
			vulnID:        "GO-2021-0264",
			goMod:         "module example.com/target\n\ngo 1.17\n",
			wantFact:      ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
			wantVersion:   "",
			wantDisqual:   false,
			wantReason:    ReasonInsufficient,
			wantRationale: "go 1.17 may have been built by go1.16.5, inside the go1.16 branch range",
		},
		{
			name:           "a pre-1.21 go directive under trust adjudicates the build toolchain: inside",
			vulnID:         "GO-2021-0264",
			goMod:          "module example.com/target\n\ngo 1.17\n",
			trust:          true,
			pinBuild:       true,
			buildToolchain: "go1.16.5",
			wantFact:       ToolchainFact{Version: "go1.16.5", Bound: ToolchainBoundExact, Source: ToolchainSourceBuildResolved},
			wantVersion:    "go1.16.5",
			wantDisqual:    false,
			wantReason:     ReasonInsufficient,
			wantRationale:  "the build toolchain go1.16.5 is affected whatever the go line says",
		},
		{
			name:           "a pre-1.21 go directive under trust adjudicates the build toolchain: past",
			vulnID:         "GO-2021-0264",
			goMod:          "module example.com/target\n\ngo 1.17\n",
			trust:          true,
			pinBuild:       true,
			buildToolchain: "go1.17.3",
			wantFact:       ToolchainFact{Version: "go1.17.3", Bound: ToolchainBoundExact, Source: ToolchainSourceBuildResolved},
			wantVersion:    "go1.17.3",
			wantDisqual:    true,
			wantReason:     ReasonVersionNotInRange,
			wantRationale:  "the build toolchain go1.17.3 is the mainline fix",
		},
		{
			name:          "a pre-1.21 go directive under trust with no established toolchain fails open",
			vulnID:        "GO-2021-0264",
			goMod:         "module example.com/target\n\ngo 1.17\n",
			trust:         true,
			pinBuild:      true,
			wantFact:      ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
			wantVersion:   "",
			wantDisqual:   false,
			wantReason:    ReasonInsufficient,
			wantRationale: "an unestablished build toolchain may never produce a not-affected",
		},
		{
			name:           "a pre-1.21 go directive without trust ignores the build toolchain",
			vulnID:         "GO-2021-0264",
			goMod:          "module example.com/target\n\ngo 1.17\n",
			pinBuild:       true,
			buildToolchain: "go1.17.3",
			wantFact:       ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
			wantVersion:    "",
			wantDisqual:    false,
			wantReason:     ReasonInsufficient,
			wantRationale:  "the analyzer's go command describes the subject only under trust",
		},
		{
			name:           "a two-part 1.21 go directive without trust is no floor",
			vulnID:         "GO-2021-0264",
			goMod:          "module example.com/target\n\ngo 1.21\n",
			pinBuild:       true,
			buildToolchain: "go1.16.5",
			wantFact:       ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
			wantVersion:    "",
			wantDisqual:    false,
			wantReason:     ReasonInsufficient,
			wantRationale:  "a go command before 1.21 builds a two-part go 1.21 module",
		},
		{
			name:           "a three-part 1.21.0 go directive is trusted over the build toolchain",
			vulnID:         "GO-2021-0264",
			goMod:          "module example.com/target\n\ngo 1.21.0\n",
			trust:          true,
			pinBuild:       true,
			buildToolchain: "go1.16.5",
			wantFact:       ToolchainFact{Version: "go1.21.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective},
			wantVersion:    "go1.21.0",
			wantDisqual:    true,
			wantReason:     ReasonVersionNotInRange,
			wantRationale:  "a go command before 1.21 rejects a three-part go line, so it binds",
		},
		{
			name:           "a two-part 1.22 go directive under trust adjudicates the build toolchain",
			vulnID:         "GO-2021-0264",
			goMod:          "module example.com/target\n\ngo 1.22\n",
			trust:          true,
			pinBuild:       true,
			buildToolchain: "go1.16.5",
			wantFact:       ToolchainFact{Version: "go1.16.5", Bound: ToolchainBoundExact, Source: ToolchainSourceBuildResolved},
			wantVersion:    "go1.16.5",
			wantDisqual:    false,
			wantReason:     ReasonInsufficient,
			wantRationale:  "go1.16.5 builds a two-part go 1.22 module and is affected",
		},
		{
			name:          "a declaration below a two-part 1.21 go directive is not refuted",
			vulnID:        "GO-2021-0264",
			goMod:         "module example.com/target\n\ngo 1.21\n",
			declared:      "go1.20.5",
			wantFact:      ToolchainFact{Version: "go1.20.5", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared},
			wantVersion:   "go1.20.5",
			wantDisqual:   true,
			wantReason:    ReasonVersionNotInRange,
			wantRationale: "the declared go1.20.5 stands and is past both fixes",
		},
		{
			name:           "a pre-1.21 go directive with a toolchain line is trusted over the build toolchain",
			vulnID:         "GO-2021-0264",
			goMod:          "module example.com/target\n\ngo 1.17\n\ntoolchain go1.17.3\n",
			trust:          true,
			pinBuild:       true,
			buildToolchain: "go1.16.5",
			wantFact:       ToolchainFact{Version: "go1.17.3", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective},
			wantVersion:    "go1.17.3",
			wantDisqual:    true,
			wantReason:     ReasonVersionNotInRange,
			wantRationale:  "a go command before 1.21 rejects a toolchain line, so the directives bind",
		},
		{
			// No directive, no declaration, no observation: the fact resolves nothing, resolved_version
			// stays empty, verKnown is false and the version axis fails OPEN. This fail-open is the
			// correct one — declining to assert safety, rather than failing open INTO a safety claim.
			name:          "an unresolved toolchain fails the axis OPEN",
			vulnID:        "CVE-2023-45283",
			goMod:         "module example.com/target\n",
			wantFact:      ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved},
			wantVersion:   "",
			wantDisqual:   false,
			wantReason:    ReasonInsufficient,
			wantRationale: "an unestablished fact may never produce a not-affected (inv.5)",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fact, ver, res := runRealGoToolchainAxis(t, tc.vulnID, tc.goMod, tc.declared, tc.observed, tc.trust,
				goManifestPlugin{pinBuildToolchain: tc.pinBuild, buildToolchain: tc.buildToolchain})
			if fact != tc.wantFact {
				t.Errorf("toolchain fact = %+v, want %+v", fact, tc.wantFact)
			}
			if ver != tc.wantVersion {
				t.Errorf("resolved_version = %q, want %q — the fact must flow into the axis's input", ver, tc.wantVersion)
			}
			if res.Disqualified != tc.wantDisqual || res.Reason != tc.wantReason {
				t.Errorf("disqualification = %+v, want {Disqualified:%v Reason:%q} (%s)",
					res, tc.wantDisqual, tc.wantReason, tc.wantRationale)
			}
		})
	}
}

// TestGoToolchainAxis_ToolchainSubjectRecognizesBothSpellings pins the recognizer the scan-level
// disclosure keys on. The corpus carries "the subject is the toolchain" two ways and a recognizer
// that saw only one would silently leave a quarter of the affected advisories emitting an
// unestablished not_exploitable: an explicit go-toolchain version scheme, or a pkg:golang/stdlib PURL
// whose scheme derives to gomod.
func TestGoToolchainAxis_ToolchainSubjectRecognizesBothSpellings(t *testing.T) {
	tests := []struct {
		vulnID string
		want   bool
		why    string
	}{
		{"CVE-2023-39325", true, "explicit go-toolchain version scheme"},
		{"CVE-2023-45283", true, "explicit go-toolchain version scheme"},
		{"CVE-2024-24790", true, "explicit go-toolchain version scheme"},
		{"GO-2021-0264", true, "explicit go-toolchain version scheme on a pkg:golang/stdlib PURL"},
		{"GO-2021-0113", false, "a real module dependency (golang.org/x/text)"},
		{"CVE-2024-55947", false, "a first-party application advisory"},
		{"FERRALON-JS-DEP-0001", false, "an npm dependency"},
	}
	for _, tc := range tests {
		t.Run(tc.vulnID, func(t *testing.T) {
			store := artifact.NewMemStore()
			caseID := "case-subject-" + tc.vulnID
			c := &assessment.Assessment{ID: caseID, Request: assessment.Request{
				Vulnerability: assessment.VulnRef{ID: tc.vulnID, Source: "corpus"},
			}}
			if err := (advisoryIntake{}).Run(context.Background(), c, store); err != nil {
				t.Fatalf("advisory_intake: %v", err)
			}
			if got := ToolchainSubject(store, caseID); got != tc.want {
				t.Errorf("ToolchainSubject(%s) = %v, want %v (%s)", tc.vulnID, got, tc.want, tc.why)
			}
		})
	}
}

// TestIsGoStdlibPURL covers reviewer minor 1: the recognizer was exact string equality against
// "pkg:golang/stdlib", which fails in BOTH directions and both are harmful.
//
// A MISS restores the unestablished not_exploitable (ToolchainSubject is what withheldNote keys on)
// AND stops advisoryFromArtifacts suppressing the SBOM coordinate, so a nonexistent
// golang.org/x/net@go1.x.y reaches the SBOM and the OpenVEX product id. An OVER-match withholds a
// genuinely resolved module finding. The in-repo fixtures pin the bare spelling, so nothing else would
// catch an upstream feed changing it.
func TestIsGoStdlibPURL(t *testing.T) {
	tests := []struct {
		purl string
		want bool
		why  string
	}{
		// The bare form the corpus emits today.
		{"pkg:golang/stdlib", true, "the canonical spelling"},

		// Spellings the PURL grammar permits for the SAME package. Each of these silently missed
		// under exact equality, and a miss fails unsafe.
		{"pkg:golang/stdlib@go1.20", true, "a pinned version is still the stdlib"},
		{"pkg:golang/stdlib@go1.20.14", true, "a three-segment pinned version"},
		{"pkg:golang/stdlib?os=linux", true, "qualifiers do not change the package"},
		{"pkg:golang/stdlib#net/http", true, "a subpath names a package WITHIN the stdlib"},
		{"pkg:golang/stdlib@go1.20?os=linux#net/http", true, "version + qualifiers + subpath together"},
		{"pkg:golang/stdlib@", true, "an empty version separator"},
		{"pkg:golang/stdlib?", true, "an empty qualifier separator"},
		{"pkg:golang/stdlib#", true, "an empty subpath separator"},
		{"pkg:GOLANG/stdlib", true, "the PURL type is case-insensitive"},
		{"pkg:golang/StdLib", true, "a non-lowercased name is a non-conformant spelling of the same package"},

		// Over-match guards. These are real modules, not the standard library, and withholding them
		// would suppress a finding whose version WAS genuinely resolved.
		{"pkg:golang/stdlib-helper", false, "a different module that merely starts with stdlib"},
		{"pkg:golang/example.com/stdlib", false, "a namespaced module named stdlib is not THE stdlib"},
		{"pkg:golang/golang.org/x/net", false, "an ordinary module dependency"},
		{"pkg:npm/stdlib", false, "the npm package named stdlib is unrelated"},
		{"pkg:pypi/stdlib", false, "likewise on PyPI"},

		// Malformed input fails closed on this predicate's own terms (it is not the stdlib), which is
		// the same direction purlEcosystem already fails.
		{"", false, "empty"},
		{"pkg:", false, "no type"},
		{"pkg:golang", false, "no name segment"},
		{"pkg:golang/", false, "empty name"},
		{"golang/stdlib", false, "missing the pkg: scheme"},
	}
	for _, tc := range tests {
		t.Run(tc.purl, func(t *testing.T) {
			if got := isGoStdlibPURL(tc.purl); got != tc.want {
				t.Errorf("isGoStdlibPURL(%q) = %v, want %v (%s)", tc.purl, got, tc.want, tc.why)
			}
		})
	}
}

// TestToolchainSubject_RecognizesAQualifiedStdlibPURL is the consequence of the fix at the level the
// verdict path actually consumes. A corpus feed that starts pinning the stdlib PURL's version must not
// silently turn the withholding off — under exact equality this advisory (no go-toolchain scheme, so
// the PURL arm is the only recognizer) would have gone back to emitting the claim this axis removed.
func TestToolchainSubject_RecognizesAQualifiedStdlibPURL(t *testing.T) {
	for _, purl := range []string{"pkg:golang/stdlib", "pkg:golang/stdlib@go1.20.14", "pkg:golang/stdlib?os=linux"} {
		t.Run(purl, func(t *testing.T) {
			if !toolchainSubject(purl, nil) {
				t.Errorf("toolchainSubject(%q, no ranges) = false: the stdlib PURL is the ONLY recognizer for an advisory that declares no go-toolchain scheme, so a miss here restores the unestablished not_exploitable", purl)
			}
		})
	}
	// The other direction, at the same seam: a module PURL with no go-toolchain range is not a
	// toolchain subject, and withholding it would suppress a real finding.
	if toolchainSubject("pkg:golang/golang.org/x/text", nil) {
		t.Error("toolchainSubject(x/text) = true: a module advisory must stay reportable")
	}
}

// TestGoToolchainAxis_ModuleMatchOutranksTheToolchainElement is the multi-package case that keeps the
// disclosure honest in the other direction. CVE-2023-39325 affects golang.org/x/net AND the stdlib; a
// target that actually requires x/net is adjudicated as an x/net MODULE case with a genuinely resolved
// module version, so it is NOT a toolchain subject and must NOT be withheld. Select-by-target picks
// the first element the codebase depends on, and the toolchain element is the fallback, not the
// default.
func TestGoToolchainAxis_ModuleMatchOutranksTheToolchainElement(t *testing.T) {
	buildDir := writeGoModFixture(t,
		"module example.com/target\n\ngo 1.20\n\nrequire golang.org/x/net v0.15.0\n")
	store := artifact.NewMemStore()
	caseID := "case-module-outranks-toolchain"
	src := gotoolchainGuardSource{}
	c := &assessment.Assessment{ID: caseID, Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "CVE-2023-39325", Source: "corpus"},
		Codebase: assessment.CodebaseRef{
			Repo:        "example.com/target",
			Revision:    "v1",
			Acquisition: assessment.Acquisition{Mode: "git"},
		},
	}}
	if err := (advisoryIntake{src: src}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	stage := codebaseInventory{
		checkout: dirCheckout{dir: buildDir, lang: "go"},
		plugin:   goManifestPlugin{},
		src:      src,
	}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("codebase_inventory: %v", err)
	}

	ver, ok := extractResolvedVersion(store, caseID)
	if !ok || ver != "v0.15.0" {
		t.Fatalf("resolved_version = %q (ok=%v), want v0.15.0 — the module the target actually requires", ver, ok)
	}
	if ToolchainSubject(store, caseID) {
		t.Error("ToolchainSubject = true, want false: the adjudicated element is the x/net module, whose version was genuinely resolved — withholding it would suppress a real finding")
	}
}
