package trigger

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// splitVerdictSource is siblingSource with a symbol per instance, so each instance's verdict rests on
// its own reachability.
type splitVerdictSource struct{}

func (splitVerdictSource) Lookup(id string) (pipeline.AdvisoryFacts, bool) {
	facts, ok := siblingSource{}.Lookup(id)
	if !ok {
		return facts, false
	}
	facts.Symbols = []string{"example.com/lib.Parse"}
	facts.AffectedPackages[0].Symbols = []string{"example.com/lib.Parse"}
	facts.AffectedPackages[1].Symbols = []string{"example.com/lib/v2.Parse"}
	return facts, true
}

// splitVerdictPlugin reaches example.com/lib/v2's symbol and neither instance's otherwise: the v2
// sibling is a reachable_candidate and the example.com/lib parent not_exploitable, neither a limit
// verdict, so each row carries the package the run labels it with.
type splitVerdictPlugin struct{ refutingGoPlugin }

func (splitVerdictPlugin) Reachability(_ context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	const v2 = "example.com/lib/v2"
	if strings.HasPrefix(req.Package, "pkg:golang/"+v2+"@") {
		return plugin.ReachabilityResult{
			Partiality: plugin.Complete(),
			Paths: []plugin.ReachPath{{
				Ingress: plugin.Symbol{SCIP: "scip-go gomod example.com/target . example.com/target/main()."},
				Sink:    plugin.Symbol{SCIP: "scip-go gomod " + v2 + " . " + v2 + "/Parse().", Package: v2},
			}},
		}, nil
	}
	return plugin.ReachabilityResult{
		Partiality: plugin.Complete(),
		Refutations: []plugin.Refutation{
			{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/example.com/lib", Detail: "no symbol reached"},
			{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/" + v2, Detail: "no symbol reached"},
		},
	}, nil
}

// TestCVEWatch_RetryLabelsTheInstanceItAssessed: a sibling's reachable_candidate row stored above the
// parent's not_exploitable row. A not-fetched or restated retry of the key assesses the parent, and
// whether it completes, stops or fails, its fresh row replaces the parent's under the parent's
// coordinate and the sibling's row stays as stored. Seeding the retry from the first stored row
// labeled the parent's result with the sibling's coordinate and dropped the sibling's verdict.
func TestCVEWatch_RetryLabelsTheInstanceItAssessed(t *testing.T) {
	complete := splitVerdictPlugin{refutingGoPlugin{inventory: plugin.Complete()}}
	store := &memStore{}
	if _, err := RunBaseline(context.Background(), store, BaselineRequest{
		Subject:       Subject{Repo: "r", Revision: "main", ResolvedCommit: "base-sha"},
		Codebase:      assessment.CodebaseRef{Repo: "r", Revision: "main"},
		Advisories:    passAdvisories("GO-S-1"),
		AssessOptions: siblingAssessOpts(t, complete, splitVerdictSource{}),
	}); err != nil {
		t.Fatalf("RunBaseline: %v", err)
	}
	var parent, sibling report.AdvisoryFinding
	for _, f := range store.state.Report.Advisories {
		switch {
		case f.Package != nil && f.Package.Name == "example.com/lib/v2":
			sibling = f
		case f.Package != nil && f.Package.Name == "example.com/lib":
			parent = f
		}
	}
	if parent.Verdict != report.VerdictNotExploitable || sibling.Verdict != report.VerdictReachableCandidate {
		t.Fatalf("baseline rows = %+v, want a not_exploitable parent and a reachable_candidate sibling", store.state.Report.Advisories)
	}
	base := store.state

	for _, lane := range []string{"not fetched", "restated"} {
		for _, outcome := range []string{"completes", "stops", "fails"} {
			t.Run(fmt.Sprintf("%s/%s", lane, outcome), func(t *testing.T) {
				st := *base
				rep := *base.Report
				rep.Advisories = []report.AdvisoryFinding{sibling, parent}
				st.Report = &rep
				store := &memStore{state: &st}

				var p plugin.LanguagePlugin = complete
				analysis := context.Background()
				switch outcome {
				case "stops":
					ctx, cancel := context.WithCancelCause(context.Background())
					t.Cleanup(func() { cancel(nil) })
					p = stopOnNthPlugin{refutingGoPlugin: complete.refutingGoPlugin, stop: func() { cancel(errTestStop) }, calls: &atomic.Int32{}, n: 1}
					analysis = ctx
				case "fails":
					p = failFirstPlugin{refutingGoPlugin: complete.refutingGoPlugin, calls: &atomic.Int32{}}
				}
				res := retryStoredFrom(t, store, lane, p, splitVerdictSource{}, analysis)
				rows := rowsByID(res.Report)["GO-S-1"]
				if len(rows) != 2 {
					t.Fatalf("rows = %+v, want the sibling's and the parent's fresh row", rows)
				}
				if !slices.ContainsFunc(rows, func(f report.AdvisoryFinding) bool { return reflect.DeepEqual(f, sibling) }) {
					t.Errorf("the sibling's reachable_candidate row changed or was dropped: %+v", rows)
				}
				fresh := rows[slices.IndexFunc(rows, func(f report.AdvisoryFinding) bool { return !reflect.DeepEqual(f, sibling) })]
				switch outcome {
				case "completes":
					// The not-fetched lane's run reads no more code, so the parent's refuting verdict
					// stays withheld.
					verdict := fresh.Verdict
					if lane == "not fetched" && fresh.UndeterminedReason == report.ReasonDependencyNotFetched {
						verdict = report.VerdictNotExploitable
					}
					if verdict != report.VerdictNotExploitable || fresh.Package == nil || fresh.Package.Name != "example.com/lib" || fresh.Package.Version != parent.Package.Version {
						t.Errorf("fresh row = %+v, want the parent's not_exploitable verdict under example.com/lib@%s", fresh, parent.Package.Version)
					}
				case "stops":
					if fresh.UndeterminedReason != report.ReasonScanCutShort {
						t.Errorf("fresh row = %+v, want the parent's cut row", fresh)
					}
				case "fails":
					if fresh.UndeterminedReason != report.ReasonAnalysisDidNotRun {
						t.Errorf("fresh row = %+v, want the parent's failure row", fresh)
					}
				}
			})
		}
	}
}

// TestCVEWatch_RetryStoppedBeforeItsFirstPassKeepsEveryRow: a retry stopped before its first pass
// adjudicated anything names no instance, so beside two packaged rows it can tell neither as the
// parent's and keeps both beside its cut row, in either stored order.
func TestCVEWatch_RetryStoppedBeforeItsFirstPassKeepsEveryRow(t *testing.T) {
	for _, lane := range []string{"not fetched", "restated"} {
		for _, siblingFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/sibling first=%v", lane, siblingFirst), func(t *testing.T) {
				store := completedSiblingBaseline(t, false, siblingFirst)
				storedRows := slices.Clone(store.state.Report.Advisories)
				analysis, cancel := context.WithCancelCause(context.Background())
				cancel(errTestStop)
				res := retryStored(t, store, lane, refutingGoPlugin{inventory: plugin.Complete()}, analysis)
				rows := rowsByID(res.Report)["GO-S-1"]
				if len(rows) != 3 || len(cutIDs(res.Report)) != 1 {
					t.Fatalf("rows = %+v, want both stored rows and the fresh cut row", rows)
				}
				for _, k := range storedRows {
					if !slices.ContainsFunc(rows, func(f report.AdvisoryFinding) bool { return reflect.DeepEqual(f, k) }) {
						t.Errorf("stored row %s changed or was dropped: %+v", rowKind(k), rows)
					}
				}
			})
		}
	}
}
