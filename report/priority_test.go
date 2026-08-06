package report

import "testing"

// candidate is a tiny constructor for a reachable_candidate finding with the given
// id, grade, and optional priority, used by the ranking tests below.
func gradedCandidate(id string, grade ReachabilityGrade, p *Priority) AdvisoryFinding {
	return AdvisoryFinding{
		Advisory: Advisory{ID: id, Source: "osv"},
		Verdict:  VerdictReachableCandidate,
		Evidence: EvidenceSummary{Grade: grade},
		Priority: p,
	}
}

func TestBuildRanksActionableFindingsFirst(t *testing.T) {
	// Intentionally added out of priority order; Build must sort them.
	b := NewBuilder(Subject{Repo: "r", ResolvedCommit: "c"})
	b.AddFinding(AdvisoryFinding{Advisory: Advisory{ID: "DISQ-1", Source: "osv"}, Verdict: VerdictDisqualified})
	b.AddFinding(gradedCandidate("CAND-cfo", GradeControlFlowOnly, &Priority{EPSSScore: 0.10}))
	b.AddFinding(gradedCandidate("CAND-kev", GradeControlFlowOnly, &Priority{KEVListed: true, EPSSScore: 0.01}))
	b.AddFinding(gradedCandidate("CAND-tainted", GradeAttackerTainted, &Priority{EPSSScore: 0.20}))
	b.AddFinding(AdvisoryFinding{Advisory: Advisory{ID: "NE-1", Source: "osv"}, Verdict: VerdictNotExploitable})
	b.AddFinding(gradedCandidate("CAND-highepss", GradeControlFlowOnly, &Priority{EPSSScore: 0.90}))

	got := b.Build().Advisories
	want := []string{
		"CAND-kev",      // KEV beats everything among candidates
		"CAND-tainted",  // attacker-tainted beats control-flow-only
		"CAND-highepss", // among control-flow-only, higher EPSS first
		"CAND-cfo",      // lower EPSS
		"DISQ-1",        // non-candidates sink below all candidates (stable by id)
		"NE-1",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].Advisory.ID != id {
			t.Errorf("rank %d: got %q, want %q", i, got[i].Advisory.ID, id)
		}
	}
}

func TestValidateRejectsGradeOnNonCandidate(t *testing.T) {
	r := NewBuilder(Subject{ResolvedCommit: "c"}).
		AddFinding(AdvisoryFinding{
			Advisory: Advisory{ID: "X", Source: "osv"},
			Verdict:  VerdictNotExploitable,
			Evidence: EvidenceSummary{Grade: GradeAttackerTainted},
		}).Build()
	if err := r.Validate(); err == nil {
		t.Fatal("expected Validate to reject a reachability grade on a non-candidate verdict (inv. 5)")
	}
}

func TestValidateRejectsUnknownGrade(t *testing.T) {
	r := NewBuilder(Subject{ResolvedCommit: "c"}).
		AddFinding(AdvisoryFinding{
			Advisory: Advisory{ID: "X", Source: "osv"},
			Verdict:  VerdictReachableCandidate,
			Evidence: EvidenceSummary{Grade: ReachabilityGrade("definitely_exploitable")},
		}).Build()
	if err := r.Validate(); err == nil {
		t.Fatal("expected Validate to reject an unknown reachability grade")
	}
}

func TestValidateAcceptsGradedCandidate(t *testing.T) {
	r := NewBuilder(Subject{ResolvedCommit: "c"}).
		ReachableCandidateGraded(
			Advisory{ID: "X", Source: "osv"}, nil,
			GradeAttackerTainted,
			&EntryPoint{Symbol: "GET /fetch", Kind: "http_route", AttackerControllable: true},
			[]CallFrame{{Symbol: "main.handler"}, {Symbol: "pkg.Vuln"}},
			"main.handler → pkg.Vuln", "",
		).Build()
	if err := r.Validate(); err != nil {
		t.Fatalf("graded candidate should validate, got: %v", err)
	}
	f := r.Advisories[0]
	if f.Evidence.Grade != GradeAttackerTainted || f.Evidence.EntryPoint == nil || len(f.Evidence.CallPath) != 2 {
		t.Fatalf("graded candidate lost evidence: %+v", f.Evidence)
	}
}
