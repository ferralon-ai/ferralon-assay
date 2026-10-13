package trigger

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// ranged adds a declared affected range to a normalized-advisory fixture, for tests whose subject
// is a reachable_candidate and not the range axis.
func ranged(t *testing.T, advJSON string) string {
	t.Helper()
	var adv map[string]any
	if err := json.Unmarshal([]byte(advJSON), &adv); err != nil {
		t.Fatalf("advisory fixture: %v", err)
	}
	adv["affected_ranges"] = []map[string]string{{"upper_exclusive": "99.0.0"}}
	b, err := json.Marshal(adv)
	if err != nil {
		t.Fatalf("advisory fixture: %v", err)
	}
	return string(b)
}

const (
	raIngress = "scip-python python app . app/views.fetch()."
	raSink    = "scip-python python requests 2.32.3 requests/sessions.Session.resolve_redirects()."
	raGuard   = "scip-python python app . app/guards/is_safe()."
)

// seedRangeCandidate seeds one advisory that formed a candidate path ingress → sink, with an on-path
// declared guard and the candidate-only annotations (provenance, preconditions, guard sufficiency) the
// advisory can carry.
func seedRangeCandidate(t *testing.T, advisory map[string]any, inv map[string]any) (*artifact.MemStore, string) {
	t.Helper()
	store := artifact.NewMemStore()
	const aid = "range-absent"
	adv := map[string]any{
		"advisory_guards":   []string{"is_safe"},
		"symbol_provenance": "osv-declared",
		"trigger_condition": "follows a redirect",
		"guard_sufficiency": []map[string]any{{"symbol": "is_safe", "for_bypass": "PYSEC-2015-17", "sufficient": false}},
	}
	for k, v := range advisory {
		adv[k] = v
	}
	putJSON(t, store, aid, artifact.TypeNormalizedAdvisory, adv)
	if inv != nil {
		seedInventory(t, store, aid, inv)
	}
	putJSON(t, store, aid, artifact.TypeIngressMap, plugin.IngressResult{
		Partiality: plugin.Complete(),
		Ingresses:  []plugin.Ingress{{Symbol: plugin.Symbol{SCIP: raIngress}, Kind: "http_route", Selector: "/fetch"}},
	})
	seedReachArtifact(t, store, aid, plugin.CallGraphResult{
		Partiality: plugin.Complete(),
		Edges:      []plugin.CallEdge{depEdge(raIngress, raGuard), depEdge(raIngress, raSink)},
	}, plugin.ReachabilityResult{
		Partiality: plugin.Complete(),
		Paths: []plugin.ReachPath{{
			Ingress: plugin.Symbol{SCIP: raIngress},
			Trace:   []plugin.Symbol{{SCIP: raIngress}, {SCIP: raSink}},
		}},
	})
	putJSON(t, store, aid, artifact.TypeCandidatePair, artifact.CandidatePair{Ingress: &artifact.Ref{}})
	return store, aid
}

var requestsPkg = &report.Package{Ecosystem: "PyPI", Name: "requests", Version: "2.32.3", PURL: "pkg:pypi/requests@2.32.3"}

// TestFinding_RangeAbsentCandidate: a candidate on an advisory that declares no affected range for
// the admitted package is admitted at every version, so it is reported undetermined with the path
// kept as evidence. Each "undetermined" row is a reachable_candidate without the policy.
func TestFinding_RangeAbsentCandidate(t *testing.T) {
	requests := map[string]any{"coordinate": "requests", "purl": "pkg:pypi/requests"}
	with := func(base map[string]any, extra map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	cases := []struct {
		name          string
		advisory      map[string]any
		inv           map[string]any
		pkg           *report.Package
		wantCandidate bool
	}{
		{
			// requests PYSEC-2015-17 against 2.32.3: the corpus strips PyPI ranges today.
			name:     "pypi: no range at all",
			advisory: requests,
			pkg:      requestsPkg,
		},
		{
			name:     "npm: no range at all",
			advisory: map[string]any{"coordinate": "json5", "purl": "pkg:npm/json5"},
			pkg:      &report.Package{Ecosystem: "npm", Name: "json5", Version: "2.2.3", PURL: "pkg:npm/json5@2.2.3"},
		},
		{
			name:     "go: no range at all",
			advisory: map[string]any{"module": "golang.org/x/net", "purl": "pkg:golang/golang.org/x/net"},
			pkg:      &report.Package{Ecosystem: "Go", Name: "golang.org/x/net", Version: "v0.20.0", PURL: "pkg:golang/golang.org/x/net@v0.20.0"},
		},
		{
			name:          "ranged: a fixed bound",
			advisory:      with(requests, map[string]any{"affected_ranges": []map[string]string{{"upper_exclusive": "2.33.0", "scheme": "pypi"}}}),
			pkg:           requestsPkg,
			wantCandidate: true,
		},
		{
			// An unfixed range is declared ("every version from here on"), not absent.
			name:          "ranged: unfixed range with no upper bound",
			advisory:      with(requests, map[string]any{"affected_ranges": []map[string]string{{"upper_exclusive": "", "scheme": "pypi"}}}),
			pkg:           requestsPkg,
			wantCandidate: true,
		},
		{
			name: "multi-package: admitted package ranged, another absent",
			advisory: with(requests, map[string]any{"affected_packages": []map[string]any{
				{"coordinate": "requests", "purl": "pkg:pypi/requests", "affected_ranges": []map[string]string{{"upper_exclusive": "2.33.0", "scheme": "pypi"}}},
				{"coordinate": "requests-toolbelt", "purl": "pkg:pypi/requests-toolbelt"},
			}}),
			inv:           map[string]any{"language": "python", "resolved_version": "2.32.3", "selected_coordinate": "requests"},
			pkg:           requestsPkg,
			wantCandidate: true,
		},
		{
			name: "multi-package: admitted package absent, another ranged",
			advisory: with(requests, map[string]any{
				"affected_ranges": []map[string]string{{"upper_exclusive": "2.33.0", "scheme": "pypi"}},
				"affected_packages": []map[string]any{
					{"coordinate": "requests", "purl": "pkg:pypi/requests", "affected_ranges": []map[string]string{{"upper_exclusive": "2.33.0", "scheme": "pypi"}}},
					{"coordinate": "requests-toolbelt", "purl": "pkg:pypi/requests-toolbelt"},
				},
			}),
			inv: map[string]any{"language": "python", "resolved_version": "1.0.0", "selected_coordinate": "requests-toolbelt"},
			pkg: &report.Package{Ecosystem: "PyPI", Name: "requests-toolbelt", Version: "1.0.0", PURL: "pkg:pypi/requests-toolbelt@1.0.0"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, aid := seedRangeCandidate(t, tc.advisory, tc.inv)
			f := finding(store, aid, report.Advisory{ID: "PYSEC-2015-17", Source: "corpus"}, tc.pkg)

			// The candidate this advisory forms with a declared range: the evidence the
			// undetermined row must keep.
			rstore, raid := seedRangeCandidate(t, with(tc.advisory, map[string]any{
				"affected_ranges": []map[string]string{{"upper_exclusive": "99.0.0"}}, "affected_packages": nil,
			}), nil)
			cand := finding(rstore, raid, report.Advisory{ID: "PYSEC-2015-17", Source: "corpus"}, tc.pkg)
			if cand.Verdict != report.VerdictReachableCandidate || cand.Evidence.ReachablePath == "" ||
				len(cand.Evidence.CallPath) == 0 || cand.Evidence.EntryPoint == nil || len(cand.Evidence.MitigatingGuards) == 0 {
				t.Fatalf("fixture does not form a full candidate: %+v", cand)
			}

			rep := report.Report{SchemaVersion: report.SchemaVersion, Advisories: []report.AdvisoryFinding{f}}
			if err := rep.Validate(); err != nil {
				t.Fatalf("report invalid: %v", err)
			}
			if tc.wantCandidate {
				if f.Verdict != report.VerdictReachableCandidate || f.UndeterminedReason != "" {
					t.Fatalf("got %s/%q, want reachable_candidate", f.Verdict, f.UndeterminedReason)
				}
				return
			}
			if f.Verdict != report.VerdictUndetermined || f.UndeterminedReason != report.ReasonAdvisoryRangeAbsent {
				t.Fatalf("got %s/%q, want undetermined/%q", f.Verdict, f.UndeterminedReason, report.ReasonAdvisoryRangeAbsent)
			}
			want := report.EvidenceSummary{
				Detail:           report.UndeterminedDetail(report.ReasonAdvisoryRangeAbsent),
				ReachablePath:    cand.Evidence.ReachablePath,
				EntryPoint:       cand.Evidence.EntryPoint,
				CallPath:         cand.Evidence.CallPath,
				MitigatingGuards: cand.Evidence.MitigatingGuards,
			}
			if !reflect.DeepEqual(f.Evidence, want) {
				t.Errorf("evidence = %+v\nwant       %+v", f.Evidence, want)
			}
			note, ok := limitNoteFor(f)
			if !ok || note.Reason != report.ReasonAdvisoryRangeAbsent || note.Ecosystem != tc.pkg.Ecosystem {
				t.Errorf("limit note = %+v, ok=%v; want %q scoped to %s", note, ok, report.ReasonAdvisoryRangeAbsent, tc.pkg.Ecosystem)
			}
		})
	}
}

// TestFinding_RangeAbsentNotExploitableUnchanged: a package the lane refuted as never loaded is safe
// at any version, so a not_exploitable on an advisory with no declared range stands.
func TestFinding_RangeAbsentNotExploitableUnchanged(t *testing.T) {
	fx := yamlSearched()
	fx.advisorySymbols = nil
	fx.reach.Searched = nil
	fx.reach.Refutation = refutation("pkg:pypi/PyYAML")
	f := fx.finding(t) // the fixture's advisory declares no affected range
	if f.Verdict != report.VerdictNotExploitable || f.UndeterminedReason != "" {
		t.Fatalf("got %s/%q, want not_exploitable", f.Verdict, f.UndeterminedReason)
	}
	if f.Evidence.Basis != verdict.BasisSymbolAbsent {
		t.Errorf("basis = %q, want %q", f.Evidence.Basis, verdict.BasisSymbolAbsent)
	}
}
