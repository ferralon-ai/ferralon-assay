// guard_sufficiency_test.go
//
// B-guardsuff guard-sufficiency annotation (RFC §4.2). Three levels of pin, cheapest first:
//   - guardSufficiencyFor: the total, fail-quiet builder — annotates ONLY guards already on the
//     candidate path, in MitigatingGuards order; empty/unmatched ⇒ nil (honest-absent).
//   - advisoryGuardSufficiency: the S1 reader (absent/unreadable ⇒ nil).
//   - finding(): the wiring — a reachable_candidate whose on-path guards carry declared sufficiency is
//     annotated with it; a candidate whose guards carry no declared sufficiency is byte-identical to
//     today; and (the honest-absent heart) a NON-candidate never carries the annotation.
package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/report"
)

func TestGuardSufficiencyFor(t *testing.T) {
	suff := []guardSufficiencyVariant{
		{Symbol: "IsSymlink", ForBypass: "CVE-2025-8110", Sufficient: false},
		{Symbol: "hasSymlinkInPath", ForBypass: "CVE-2025-8110", Sufficient: true},
	}
	cases := []struct {
		name     string
		onPath   []string
		declared []guardSufficiencyVariant
		want     []report.GuardSufficiencyNote
	}{
		{"no on-path guards ⇒ nil", nil, suff, nil},
		{"no declared sufficiency ⇒ nil", []string{"IsSymlink"}, nil, nil},
		{
			"on-path guard, declared sufficient",
			[]string{"hasSymlinkInPath"}, suff,
			[]report.GuardSufficiencyNote{{Symbol: "hasSymlinkInPath", ForBypass: "CVE-2025-8110", Sufficiency: report.GuardSufficiencySufficient}},
		},
		{
			"on-path guard, declared insufficient",
			[]string{"IsSymlink"}, suff,
			[]report.GuardSufficiencyNote{{Symbol: "IsSymlink", ForBypass: "CVE-2025-8110", Sufficiency: report.GuardSufficiencyInsufficient}},
		},
		{
			"both on path ⇒ annotated in MitigatingGuards order",
			[]string{"IsSymlink", "hasSymlinkInPath"}, suff,
			[]report.GuardSufficiencyNote{
				{Symbol: "IsSymlink", ForBypass: "CVE-2025-8110", Sufficiency: report.GuardSufficiencyInsufficient},
				{Symbol: "hasSymlinkInPath", ForBypass: "CVE-2025-8110", Sufficiency: report.GuardSufficiencySufficient},
			},
		},
		{
			// A guard is on the path but the advisory declares sufficiency for a DIFFERENT guard ⇒ the
			// on-path guard is not annotated (never widen the guard set past guardsOnPath).
			"on-path guard with no declared variant ⇒ nil",
			[]string{"someOtherGuard"}, suff, nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := guardSufficiencyFor(tc.onPath, tc.declared)
			if len(got) != len(tc.want) {
				t.Fatalf("guardSufficiencyFor(%v) = %+v, want %+v", tc.onPath, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("note %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestAdvisoryGuardSufficiency(t *testing.T) {
	cases := []struct {
		name    string
		advJSON string
		want    []guardSufficiencyVariant
	}{
		{
			"present",
			`{"guard_sufficiency":[{"symbol":"isRepositoryGitPath","version":"0.13.1","for_bypass":"CVE-2024-55947","sufficient":true}]}`,
			[]guardSufficiencyVariant{{Symbol: "isRepositoryGitPath", Version: "0.13.1", ForBypass: "CVE-2024-55947", Sufficient: true}},
		},
		{"absent key ⇒ nil", `{"vuln_id":"CVE-X"}`, nil},
		{"empty array ⇒ nil", `{"guard_sufficiency":[]}`, nil},
		{"unreadable ⇒ nil", `not json`, nil},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assessmentID := "01900000-0000-7000-8000-0000000000c" + string(rune('0'+i))
			store := artifact.NewMemStore()
			if _, err := store.Put(&artifact.Artifact{AssessmentID: assessmentID, Type: artifact.TypeNormalizedAdvisory, Payload: []byte(tc.advJSON)}); err != nil {
				t.Fatalf("Put: %v", err)
			}
			got := advisoryGuardSufficiency(store, assessmentID)
			if len(got) != len(tc.want) {
				t.Fatalf("advisoryGuardSufficiency = %+v, want %+v", got, tc.want)
			}
			for j := range got {
				if got[j] != tc.want[j] {
					t.Errorf("variant %d = %+v, want %+v", j, got[j], tc.want[j])
				}
			}
		})
	}
	// No artifact at all ⇒ nil (honest-absent, not an error).
	if got := advisoryGuardSufficiency(artifact.NewMemStore(), "missing"); got != nil {
		t.Errorf("advisoryGuardSufficiency(empty store) = %+v, want nil", got)
	}
}

// seedGuardCandidate seeds the artifacts finding() reads to take the reachable_candidate arm with the given
// on-path frame and a call graph in which that frame calls each guard in callees. The normalized
// advisory declares advisoryGuardsJSON + guardSufficiencyJSON.
func seedGuardCandidate(t *testing.T, store artifact.Store, assessmentID, frameSym string, guardSCIPs []string, advJSON string) {
	t.Helper()
	put := func(typ artifact.Type, payload string) {
		if _, err := store.Put(&artifact.Artifact{AssessmentID: assessmentID, Type: typ, Payload: []byte(payload)}); err != nil {
			t.Fatalf("Put %s: %v", typ, err)
		}
	}
	put(artifact.TypeCandidatePair, `{}`) // makes hasCandidate true
	// One TypeReachability artifact carries BOTH the path-presence trace (firstReachPath → frames) and
	// the call graph (callGraphEdges → guard-on-path intersection).
	edges := ""
	for i, g := range guardSCIPs {
		if i > 0 {
			edges += ","
		}
		edges += `{"caller":{"scip":"` + frameSym + `"},"callee":{"scip":"` + g + `"}}`
	}
	put(artifact.TypeReachability, `{"reachability":{"paths":[{"trace":[{"scip":"`+frameSym+`"}]}]},"call_graph":{"edges":[`+edges+`]}}`)
	put(artifact.TypeNormalizedAdvisory, advJSON)
}

// TestFinding_CandidateArm_SetsGuardSufficiency drives the real finding() over a seeded store: the gogs
// symlink lineage (CVE-2025-8110), where IsSymlink is present-but-declared-insufficient and
// hasSymlinkInPath is declared-sufficient — both on the path. It asserts the candidate carries both
// MitigatingGuards and the matching declared-sufficiency annotation, and that a candidate whose on-path
// guards declare NO sufficiency is byte-identical to today (annotation nil).
func TestFinding_CandidateArm_SetsGuardSufficiency(t *testing.T) {
	const frameSym = "scip-go gomod m . pkg/UpdateRepoFile()."
	const isSymlink = "scip-go gomod m . pkg/IsSymlink()."
	const hasSymlinkInPath = "scip-go gomod m . pkg/hasSymlinkInPath()."

	t.Run("declared sufficiency ⇒ annotated", func(t *testing.T) {
		const assessmentID = "01900000-0000-7000-8000-0000000000d0"
		store := artifact.NewMemStore()
		seedGuardCandidate(t, store, assessmentID, frameSym,
			[]string{isSymlink, hasSymlinkInPath},
			`{"advisory_guards":["IsSymlink","hasSymlinkInPath"],`+
				`"guard_sufficiency":[`+
				`{"symbol":"IsSymlink","version":"0.13.3","for_bypass":"CVE-2025-8110","sufficient":false},`+
				`{"symbol":"hasSymlinkInPath","version":"0.13.4","for_bypass":"CVE-2025-8110","sufficient":true}]}`)

		f := finding(store, assessmentID, report.Advisory{ID: "CVE-2025-8110", Source: "osv"}, nil)
		if f.Verdict != report.VerdictReachableCandidate {
			t.Fatalf("verdict = %q, want reachable_candidate", f.Verdict)
		}
		wantGuards := []string{"IsSymlink", "hasSymlinkInPath"}
		if len(f.Evidence.MitigatingGuards) != len(wantGuards) {
			t.Fatalf("MitigatingGuards = %v, want %v", f.Evidence.MitigatingGuards, wantGuards)
		}
		want := []report.GuardSufficiencyNote{
			{Symbol: "IsSymlink", ForBypass: "CVE-2025-8110", Sufficiency: report.GuardSufficiencyInsufficient},
			{Symbol: "hasSymlinkInPath", ForBypass: "CVE-2025-8110", Sufficiency: report.GuardSufficiencySufficient},
		}
		got := f.Evidence.GuardSufficiency
		if len(got) != len(want) {
			t.Fatalf("GuardSufficiency = %+v, want %+v", got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("note %d = %+v, want %+v", i, got[i], want[i])
			}
		}
	})

	t.Run("on-path guard, no declared sufficiency ⇒ nil (as today)", func(t *testing.T) {
		const assessmentID = "01900000-0000-7000-8000-0000000000d1"
		store := artifact.NewMemStore()
		seedGuardCandidate(t, store, assessmentID, frameSym,
			[]string{isSymlink},
			`{"advisory_guards":["IsSymlink"]}`) // guard on path, but no guard_sufficiency declared

		f := finding(store, assessmentID, report.Advisory{ID: "CVE-2025-8110", Source: "osv"}, nil)
		if f.Verdict != report.VerdictReachableCandidate {
			t.Fatalf("verdict = %q, want reachable_candidate", f.Verdict)
		}
		if len(f.Evidence.MitigatingGuards) != 1 {
			t.Fatalf("MitigatingGuards = %v, want [IsSymlink]", f.Evidence.MitigatingGuards)
		}
		if f.Evidence.GuardSufficiency != nil {
			t.Errorf("GuardSufficiency = %+v, want nil (absent sufficiency ⇒ candidate reported exactly as today)", f.Evidence.GuardSufficiency)
		}
	})
}

// TestFinding_NonCandidate_NeverCarriesGuardSufficiency is the honest-absent heart: an advisory that
// declares guard sufficiency but resolves to a NON-candidate verdict must carry NONE — proving the
// annotation is read only inside the candidate arm and can never touch a refutation (the guard-driven
// PoNE flip is structurally impossible). Here no candidate pair is seeded, so finding() falls to its
// default (not_exploitable) arm.
func TestFinding_NonCandidate_NeverCarriesGuardSufficiency(t *testing.T) {
	const assessmentID = "01900000-0000-7000-8000-0000000000e0"
	store := artifact.NewMemStore()
	if _, err := store.Put(&artifact.Artifact{AssessmentID: assessmentID, Type: artifact.TypeNormalizedAdvisory,
		Payload: []byte(`{"advisory_guards":["isRepositoryGitPath"],"guard_sufficiency":[{"symbol":"isRepositoryGitPath","for_bypass":"CVE-2024-55947","sufficient":true}]}`)}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	f := finding(store, assessmentID, report.Advisory{ID: "CVE-2024-55947", Source: "osv"}, nil)
	if f.Verdict == report.VerdictReachableCandidate {
		t.Fatalf("fixture unexpectedly produced a candidate; want a non-candidate verdict, got %q", f.Verdict)
	}
	if f.Evidence.GuardSufficiency != nil {
		t.Errorf("non-candidate finding carries GuardSufficiency %+v — it must never reach a non-candidate verdict (inv.5)", f.Evidence.GuardSufficiency)
	}
}
