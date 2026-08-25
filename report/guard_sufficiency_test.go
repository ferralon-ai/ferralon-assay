// guard_sufficiency_test.go
//
// B-guardsuff (RFC §4.2): GuardSufficiency annotates a reachable_candidate's on-path guards with the
// advisory's DECLARED sufficiency. These pin the STRUCTURAL honest-absent guarantee at the report
// boundary — the annotation may appear on nothing but a reachable_candidate, and every note must carry
// a real guard + a recognized label — so Validate() rejects it on any verdict that could rest on
// absence, and rejects a malformed (empty) annotation that would be a claim resting on nothing. This is
// the structural wall against the presence→sufficiency laundering a guard-driven PoNE verdict would be.
package report

import "testing"

func TestGuardSufficiencyLabel_Valid(t *testing.T) {
	cases := []struct {
		l    GuardSufficiencyLabel
		want bool
	}{
		{GuardSufficiencySufficient, true},
		{GuardSufficiencyInsufficient, true},
		{"", false},        // empty is NOT valid: absence is omitting the note, never an empty label
		{"partial", false}, // not a defined label
		{"sufficient!", false},
	}
	for _, tc := range cases {
		if got := tc.l.Valid(); got != tc.want {
			t.Errorf("GuardSufficiencyLabel(%q).Valid() = %v, want %v", tc.l, got, tc.want)
		}
	}
}

func TestSufficiencyLabel(t *testing.T) {
	if got := SufficiencyLabel(true); got != GuardSufficiencySufficient {
		t.Errorf("SufficiencyLabel(true) = %q, want %q", got, GuardSufficiencySufficient)
	}
	if got := SufficiencyLabel(false); got != GuardSufficiencyInsufficient {
		t.Errorf("SufficiencyLabel(false) = %q, want %q", got, GuardSufficiencyInsufficient)
	}
}

// TestValidateRejectsGuardSufficiencyOnNonCandidate is the structural inv.5 gate: a declared-
// sufficiency annotation on anything but a reachable_candidate is rejected, so guard_sufficiency can
// never annotate — let alone drive — a disqualification, not_exploitable, or undetermined verdict. This
// is precisely what makes the guard-driven PoNE flip (the presence→sufficiency laundering) impossible.
func TestValidateRejectsGuardSufficiencyOnNonCandidate(t *testing.T) {
	for _, v := range []Verdict{VerdictNotExploitable, VerdictDisqualified, VerdictUndetermined} {
		f := AdvisoryFinding{
			Advisory: Advisory{ID: "X", Source: "osv"},
			Verdict:  v,
			Evidence: EvidenceSummary{GuardSufficiency: []GuardSufficiencyNote{{Symbol: "isRepositoryGitPath", Sufficiency: GuardSufficiencySufficient}}},
		}
		if v == VerdictUndetermined {
			f.UndeterminedReason = ReasonAnalysisDidNotRun
		}
		r := NewBuilder(Subject{ResolvedCommit: "c"}).AddFinding(f).Build()
		if err := r.Validate(); err == nil {
			t.Errorf("verdict %q: expected Validate to reject a guard-sufficiency annotation on a non-candidate verdict (inv.5, strength-not-admission)", v)
		}
	}
}

// TestValidateRejectsMalformedGuardSufficiencyNote pins that an annotation resting on nothing — an
// empty guard symbol or an unrecognized/empty label — is rejected even on a candidate. Absence is
// expressed by omitting the note entirely, never by an empty one (mirror of the non-nil-but-empty
// ExploitPreconditions rejection).
func TestValidateRejectsMalformedGuardSufficiencyNote(t *testing.T) {
	cases := []struct {
		name string
		note GuardSufficiencyNote
	}{
		{"empty symbol", GuardSufficiencyNote{Symbol: "", Sufficiency: GuardSufficiencySufficient}},
		{"empty label", GuardSufficiencyNote{Symbol: "isRepositoryGitPath", Sufficiency: ""}},
		{"unknown label", GuardSufficiencyNote{Symbol: "isRepositoryGitPath", Sufficiency: "maybe"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := NewBuilder(Subject{ResolvedCommit: "c"}).
				AddFinding(AdvisoryFinding{
					Advisory: Advisory{ID: "X", Source: "osv"},
					Verdict:  VerdictReachableCandidate,
					Evidence: EvidenceSummary{ReachablePath: "a → b", GuardSufficiency: []GuardSufficiencyNote{tc.note}},
				}).Build()
			if err := r.Validate(); err == nil {
				t.Fatalf("expected Validate to reject a malformed guard-sufficiency note %+v", tc.note)
			}
		})
	}
}

// TestValidateAcceptsGuardSufficiencyOnCandidate is the mirror: a candidate carrying well-formed
// annotations validates and the annotations survive Build.
func TestValidateAcceptsGuardSufficiencyOnCandidate(t *testing.T) {
	notes := []GuardSufficiencyNote{
		{Symbol: "IsSymlink", ForBypass: "CVE-2025-8110", Sufficiency: GuardSufficiencyInsufficient},
		{Symbol: "hasSymlinkInPath", ForBypass: "CVE-2025-8110", Sufficiency: GuardSufficiencySufficient},
	}
	r := NewBuilder(Subject{ResolvedCommit: "c"}).
		AddFinding(AdvisoryFinding{
			Advisory: Advisory{ID: "CVE-2025-8110", Source: "osv"},
			Verdict:  VerdictReachableCandidate,
			Evidence: EvidenceSummary{
				ReachablePath:    "main.handler → db.UpdateRepoFile",
				MitigatingGuards: []string{"IsSymlink", "hasSymlinkInPath"},
				GuardSufficiency: notes,
			},
		}).Build()
	if err := r.Validate(); err != nil {
		t.Fatalf("a candidate carrying well-formed guard-sufficiency annotations should validate, got: %v", err)
	}
	if len(r.Advisories[0].Evidence.GuardSufficiency) != 2 {
		t.Fatalf("guard-sufficiency annotations lost through Build: %+v", r.Advisories[0].Evidence)
	}
}
