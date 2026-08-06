// gotoolchain_m4_test.go
//
// Stdlib reachability may run under the SUBJECT's Go toolchain, and only then does its empty
// path set license a verdict.
//
// The table below is the honesty boundary, stated as one matrix over
// (flag, bound, fetch-outcome). One arm — and exactly one — emits `not_exploitable` with basis
// `vulnerable_symbol_absent`: the arm where the subject's toolchain was actually scanned. Every other
// arm, including "the flag is on and the fact is exact but the toolchain could not be run", stays
// `undetermined` and disclosed. An arm that emitted a safety claim without a subject scan would be
// the original defect wearing the fix's clothes.
//
// These run the REAL baseline path (buildBaselineReport → assess → S1–S6) over a real go.mod on disk.
// The one seam faked is the analyzer's answer about which toolchain it ran under, because that is the
// half whose real form is a network toolchain fetch; the DECISION logic on both sides of it —
// reachability_ingress's request gate and undeterminedReason's lift — is the production code.
package trigger

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// toolchainReachPlugin is goManifestPlugin plus a controllable answer to "which toolchain did you
// actually run under". It stands in for the toolchain fetch, which is the only part of M4 that needs
// a network; honored=true models a switch that worked, honored=false the fallback to the analyzer's
// own toolchain (unfetchable release, or one that could not build the module).
//
// It also records the request, so the table can assert what the pipeline ASKED for and not merely
// what came back — a stage that stopped requesting would otherwise look identical to a fetch that
// always failed.
type toolchainReachPlugin struct {
	goManifestPlugin
	honored bool
	// analyzerToolchain is what the fallback reports having run under. Deliberately a real-looking
	// value rather than empty: a fallback that reported "" would be trivially unequal to the request,
	// so the match has to be tested against a plausible near-miss.
	analyzerToolchain string
	seen              *plugin.ReachabilityRequest
}

func (p toolchainReachPlugin) Reachability(_ context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	if p.seen != nil {
		*p.seen = req
	}
	res := plugin.ReachabilityResult{Partiality: plugin.Complete()}
	if req.GoToolchain != "" {
		if p.honored {
			res.ScanToolchain = req.GoToolchain
		} else {
			res.ScanToolchain = p.analyzerToolchain
		}
	}
	return res, nil
}

// stdlibNoRangeAdvisory is GO-2021-0264: a pkg:golang/stdlib advisory that declares NO affected
// range. That makes it the clean probe for this matrix — the version axis can never disqualify it, so
// its disposition is decided by the reachability licence alone and by nothing else.
var stdlibNoRangeAdvisory = []assessment.VulnRef{{ID: "GO-2021-0264", Source: "corpus"}}

const (
	// The exact fact the shipped Action surface produces WHEN THE CALLER VOUCHES FOR IT: action.yml
	// samples `go env GOVERSION` before installing the scanner's toolchain, and the in-repo dogfood
	// workflow runs setup-go with 1.26.4 first and sets trust-observed-go, so this is the value M4
	// meets on that surface. Untrusted — the shipped default — the same observation resolves NOTHING
	// (ruling 7: dropped, not demoted to a floor).
	dogfoodObservedToolchain = "go1.26.4"
	// declaredToolchain drives exactness through tier 1 (subject-go-version), which no trust flag
	// gates. Most of the matrix below uses it deliberately: M4's gate keys on Bound == exact and is
	// indifferent to which tier produced it, so routing exactness through tier 1 tests the gate
	// instead of re-testing ruling 7's trust plumbing. The two rows that ARE about tier 2 say so.
	declaredToolchain = "go1.26.4"
	// A different release, to stand in for the analyzer's own toolchain on the fallback path.
	analyzerToolchain = "go1.26.3"
)

func TestGoToolchainM4_UndeterminedLiftMatrix(t *testing.T) {
	const (
		goFloor       = "module example.com/target\n\ngo 1.20\n"
		goNoDirective = "module example.com/target\n"
	)

	cases := []struct {
		name  string
		goMod string
		// flagOn opts into subject-toolchain reachability (the release gate).
		flagOn bool
		// declared is the tier-1 subject-go-version source: exact, and not trust-gated.
		declared string
		// observed is the tier-2 ci_observed measurement, and trustObserved is the caller's
		// assertion that it describes the subject. Untrusted, the observation does not participate
		// in resolution at all — so an observation WITHOUT trust is not a weaker bound, it is no
		// bound (ruling 7).
		observed      string
		trustObserved bool
		// honored models whether the analyzer could run under the requested toolchain.
		honored bool
		// wantRequested is the toolchain reachability_ingress must ask the analyzer for.
		wantRequested string
		// wantVerdict is the ESTABLISHED verdict, or "" when the advisory must be undetermined.
		wantVerdict report.Verdict
		// wantReason is the reason code on the undetermined row (and on its scan-level limit).
		wantReason string
	}{
		{
			name:       "flag off, exact fact: undetermined — reachability still ran on the analyzer's Go",
			goMod:      goFloor,
			declared:   declaredToolchain,
			wantReason: report.ReasonGoToolchainNotScanned,
		},
		{
			name:       "flag off, floor: undetermined",
			goMod:      goFloor,
			wantReason: report.ReasonGoToolchainNotScanned,
		},
		{
			name:       "flag off, unresolved: undetermined under the weaker code",
			goMod:      goNoDirective,
			wantReason: report.ReasonGoToolchainUnresolved,
		},
		{
			name:          "flag on, exact fact, toolchain ran: VERDICT — the absence is finally about the subject",
			goMod:         goFloor,
			flagOn:        true,
			declared:      declaredToolchain,
			honored:       true,
			wantRequested: declaredToolchain,
			wantVerdict:   report.VerdictNotExploitable,
		},
		{
			name:          "flag on, exact fact, toolchain could NOT run: undetermined — a fallback is not a subject scan",
			goMod:         goFloor,
			flagOn:        true,
			declared:      declaredToolchain,
			honored:       false,
			wantRequested: declaredToolchain,
			wantReason:    report.ReasonGoToolchainNotScanned,
		},
		{
			// THE SHIPPED DEFAULT (ruling 7). Every unconfigured caller is in this row: the Action
			// samples the runner's Go and passes it, nobody vouches for it, so it drops out of
			// resolution and the fact falls to the go.mod floor. M4 asks for nothing and the
			// advisory stays disclosed. Without this row the matrix does not enumerate the one
			// configuration most scans actually run in.
			name:       "flag on, observation present but UNTRUSTED: no request — an unvouched observation is not a bound",
			goMod:      goFloor,
			flagOn:     true,
			observed:   dogfoodObservedToolchain,
			honored:    true,
			wantReason: report.ReasonGoToolchainNotScanned,
		},
		{
			// The dogfood surface: same observation, caller vouches for it, so tier 2 yields exact
			// and M4 behaves exactly as it does on a tier-1 declaration. This is the row that keeps
			// ruling 7 and M4 wired together from the other direction.
			name:          "flag on, observation TRUSTED, toolchain ran: VERDICT",
			goMod:         goFloor,
			flagOn:        true,
			observed:      dogfoodObservedToolchain,
			trustObserved: true,
			honored:       true,
			wantRequested: dogfoodObservedToolchain,
			wantVerdict:   report.VerdictNotExploitable,
		},
		{
			name:       "flag on, floor only: no request at all — a floor licenses no refutation by absence",
			goMod:      goFloor,
			flagOn:     true,
			wantReason: report.ReasonGoToolchainNotScanned,
		},
		{
			name:       "flag on, unresolved: no request at all",
			goMod:      goNoDirective,
			flagOn:     true,
			wantReason: report.ReasonGoToolchainUnresolved,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var seen plugin.ReachabilityRequest
			opts := []pipeline.AssessOption{
				pipeline.WithPlugin(toolchainReachPlugin{
					honored:           c.honored,
					analyzerToolchain: analyzerToolchain,
					seen:              &seen,
				}),
				pipeline.WithSubjectToolchainReachability(c.flagOn),
			}
			if c.declared != "" || c.observed != "" {
				opts = append(opts, pipeline.WithSubjectToolchain(c.declared, c.observed, c.trustObserved))
			}
			rep := runGoBaseline(t, c.goMod, stdlibNoRangeAdvisory, opts...)

			if seen.GoToolchain != c.wantRequested {
				t.Errorf("reachability request GoToolchain = %q, want %q", seen.GoToolchain, c.wantRequested)
			}

			verdicts := verdictByID(rep)
			got, reported := verdicts["GO-2021-0264"]
			if !reported {
				t.Fatalf("GO-2021-0264 absent from advisories[]; every advisory evaluated gets a row under v2, undetermined included")
			}
			// wantVerdict == "" is the no-verdict-established state. Under v1 it meant the row was
			// WITHHELD; under v2 it is an `undetermined` row carrying wantReason.
			if c.wantVerdict == "" {
				assertUndetermined(t, rep, "GO-2021-0264", c.wantReason)
				if ids := undeterminedByReason(rep)[c.wantReason]; len(ids) != 1 || ids[0] != "GO-2021-0264" {
					t.Errorf("undetermined under %s = %v, want [GO-2021-0264]", c.wantReason, ids)
				}
				return
			}

			if got != c.wantVerdict {
				t.Errorf("GO-2021-0264 verdict = %q, want %q", got, c.wantVerdict)
			}
			for _, n := range rep.Partiality {
				if len(n.Advisories) > 0 {
					t.Errorf("disclosure %+v emitted alongside a real verdict — a reported advisory must not also be disclosed as withheld", n)
				}
				if n.Reason == report.ReasonGoToolchainNotScanned || n.Reason == report.ReasonGoToolchainUnresolved {
					t.Errorf("limit %q emitted alongside an established verdict — the limit and the undetermined row must appear together or not at all", n.Reason)
				}
			}
		})
	}
}

// TestGoToolchainM4_SymbolAbsentBasisRequiresASubjectScan is the inv.5 assertion stated directly,
// independent of the matrix's bookkeeping: for a stdlib advisory, the ONLY way basis
// `vulnerable_symbol_absent` can reach a report is a run in which the subject's toolchain was
// actually scanned. It is written as a sweep over the same states so that a future arm which starts
// emitting the basis cannot slip through by not being in the matrix.
func TestGoToolchainM4_SymbolAbsentBasisRequiresASubjectScan(t *testing.T) {
	states := []struct {
		name string
		// flagOn is the release gate; declared is tier 1 (exact, never trust-gated); observed +
		// trustObserved are tier 2. Exactness runs through tier 1 except where the case name says
		// otherwise, so each arm exercises the state it claims to and not ruling 7's plumbing.
		flagOn        bool
		declared      string
		observed      string
		trustObserved bool
		honored       bool
		// subjectScanned is the ground truth: did the analysis run under the subject's toolchain?
		subjectScanned bool
	}{
		{name: "flag off, exact", declared: declaredToolchain, honored: true},
		{name: "flag off, floor", honored: true},
		{name: "flag on, floor", flagOn: true, honored: true},
		// The arm that matters most in this sweep: a request IS made and declined. Threading trust
		// away from it (or dropping the exact source) would make the request never happen, and the
		// fallback path — "a fallback is not a subject scan" — would stop being exercised here at all
		// while the assertion kept passing.
		{name: "flag on, exact, fallback", flagOn: true, declared: declaredToolchain, honored: false},
		{name: "flag on, exact, honored", flagOn: true, declared: declaredToolchain, honored: true, subjectScanned: true},
		// Ruling 7's shipped default, swept for the basis directly: an observation nobody vouched for
		// cannot put vulnerable_symbol_absent on the wire.
		{name: "flag on, observation untrusted", flagOn: true, observed: dogfoodObservedToolchain, honored: true},
		{name: "flag on, observation trusted, honored", flagOn: true, observed: dogfoodObservedToolchain, trustObserved: true, honored: true, subjectScanned: true},
	}

	for _, s := range states {
		t.Run(s.name, func(t *testing.T) {
			opts := []pipeline.AssessOption{
				pipeline.WithPlugin(toolchainReachPlugin{
					honored:           s.honored,
					analyzerToolchain: analyzerToolchain,
				}),
				pipeline.WithSubjectToolchainReachability(s.flagOn),
			}
			if s.declared != "" || s.observed != "" {
				opts = append(opts, pipeline.WithSubjectToolchain(s.declared, s.observed, s.trustObserved))
			}
			rep := runGoBaseline(t, "module example.com/target\n\ngo 1.20\n", stdlibNoRangeAdvisory, opts...)

			var sawBasis bool
			for _, f := range rep.Advisories {
				if f.Evidence.Basis == verdict.BasisSymbolAbsent {
					sawBasis = true
				}
			}
			if sawBasis != s.subjectScanned {
				t.Errorf("basis %q present = %t, want %t: this basis is a claim about the SUBJECT's toolchain and may only be emitted when that toolchain was scanned",
					verdict.BasisSymbolAbsent, sawBasis, s.subjectScanned)
			}
		})
	}
}

// TestGoToolchainM4_ModuleAdvisoriesGetNoToolchainRequest is the blast-radius fence on the request
// side. The subject's toolchain is a property of the scan, so the request is made whenever the flag
// and the bound allow it — but a NON-Go subject resolves no fact at all (M1 gates resolution on
// language=="go"), so it must never be asked to run under a Go toolchain.
//
// Exactness comes from tier 1 here on purpose. Tier 1 is not trust-gated, so the LANGUAGE gate is the
// only thing left that can suppress the request — the assertion therefore cannot pass because ruling
// 7 refused an untrusted observation upstream, which is precisely how this guard would go quietly
// unexercised while still looking green.
func TestGoToolchainM4_ModuleAdvisoriesGetNoToolchainRequest(t *testing.T) {
	var seen plugin.ReachabilityRequest
	opts := []pipeline.AssessOption{
		pipeline.WithCheckout(fixedCheckout{dir: writeGoMod(t, "module example.com/target\n\ngo 1.20\n"), lang: "javascript"}),
		pipeline.WithPlugin(toolchainReachPlugin{honored: true, analyzerToolchain: analyzerToolchain, seen: &seen}),
		pipeline.WithSubjectToolchainReachability(true),
		pipeline.WithSubjectToolchain(declaredToolchain, "", false),
	}
	runGoBaseline(t, "module example.com/target\n\ngo 1.20\n", stdlibNoRangeAdvisory, opts...)

	if seen.GoToolchain != "" {
		t.Errorf("a javascript subject was asked to run under Go toolchain %q; the fact is Go-only by construction", seen.GoToolchain)
	}
}

// TestGoToolchainM4_SubjectToolchainFactStaysTruthfulAcrossTheSwitch guards the M1 record against the
// most natural M4 mistake: writing the toolchain that RAN over the fact that describes the SUBJECT.
// They are different quantities — the whole ADR turns on not conflating them — and the switch must
// leave the inventory fact byte-identical to the flag-off run.
func TestGoToolchainM4_SubjectToolchainFactStaysTruthfulAcrossTheSwitch(t *testing.T) {
	run := func(flagOn, honored bool) pipeline.ToolchainFact {
		t.Helper()
		store, id := assessOneForToolchain(t, flagOn, honored)
		fact, ok := pipeline.Toolchain(store, id)
		if !ok {
			t.Fatal("no inventory toolchain fact recorded")
		}
		return fact
	}

	off := run(false, false)
	on := run(true, true)
	fallback := run(true, false)

	want := pipeline.ToolchainFact{
		Version: dogfoodObservedToolchain,
		Bound:   pipeline.ToolchainBoundExact,
		Source:  pipeline.ToolchainSourceCIObserved,
	}
	if off != want {
		t.Fatalf("flag-off fact = %+v, want %+v", off, want)
	}
	if on != want {
		t.Errorf("fact after a HONORED switch = %+v, want %+v — the fact describes the subject, not the run", on, want)
	}
	if fallback != want {
		t.Errorf("fact after a FALLBACK = %+v, want %+v — a fallback changes what ran, never what the subject is", fallback, want)
	}
}

// assessOneForToolchain runs the S1–S6 assess pipeline once and returns its store, so a test can read
// back the artifacts the report projection hides.
//
// This helper drives exactness through a TRUSTED tier-2 observation (trust-observed-go), unlike the
// matrix above: its callers assert the fact's Source is ci_observed, so the tier is the subject of the
// test rather than incidental to it. Trust is passed explicitly true — with it false the observation
// would drop out of resolution entirely, the bound would become minimum, and both callers would be
// asserting something other than what their names say.
func assessOneForToolchain(t *testing.T, flagOn, honored bool) (store artifact.Store, assessmentID string) {
	t.Helper()
	buildDir := writeGoMod(t, "module example.com/target\n\ngo 1.20\n")
	st, id, err := assess(context.Background(), assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "GO-2021-0264", Source: "corpus"},
		Codebase:      assessment.CodebaseRef{Repo: "example.com/target", Revision: "main"},
	},
		pipeline.WithCheckout(fixedCheckout{dir: buildDir, lang: "go"}),
		pipeline.WithPlugin(toolchainReachPlugin{honored: honored, analyzerToolchain: analyzerToolchain}),
		pipeline.WithSubjectToolchainReachability(flagOn),
		pipeline.WithSubjectToolchain("", dogfoodObservedToolchain, true),
	)
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	return st, id
}

// TestGoToolchainM4_ScanToolchainRecordIsHonest pins the artifact the lift reads. A fallback must be
// recorded as a fallback: the requested and actual toolchains both present, Subject false. The
// "fallback" and "flag off" subtests only mean anything while a request is actually made, which is why
// assessOneForToolchain vouches for its observation.
func TestGoToolchainM4_ScanToolchainRecordIsHonest(t *testing.T) {
	t.Run("honored", func(t *testing.T) {
		store, id := assessOneForToolchain(t, true, true)
		if !pipeline.SubjectToolchainScanned(store, id) {
			t.Error("SubjectToolchainScanned = false after the analyzer confirmed it ran under the requested toolchain")
		}
	})
	t.Run("fallback", func(t *testing.T) {
		store, id := assessOneForToolchain(t, true, false)
		if pipeline.SubjectToolchainScanned(store, id) {
			t.Errorf("SubjectToolchainScanned = true after a fallback to %s — a near-miss version must not satisfy the match", analyzerToolchain)
		}
	})
	t.Run("flag off", func(t *testing.T) {
		store, id := assessOneForToolchain(t, false, true)
		if pipeline.SubjectToolchainScanned(store, id) {
			t.Error("SubjectToolchainScanned = true with the gate off")
		}
	})
}

// TestGoToolchainM4_RefutedExactClaimCannotLicenseARefutation is the contradiction guard seen from
// M4's end of the seam, and it is the assertion the guard exists for.
//
// A caller vouches for an observation of go1.20.5 while the subject's own go.mod requires
// `toolchain go1.24.0`. Pre-guard, that resolved EXACT: M4 would have asked the analyzer to run under
// go1.20.5, the analyzer would have honored it, ToolchainScan would have matched request against
// actual and reported Subject:true, and the undetermined verdict would have lifted — emitting
// `not_exploitable` / `vulnerable_symbol_absent` (and OpenVEX `not_affected`) off a call graph over a
// stdlib the subject provably does not build with. `GOTOOLCHAIN=auto` only switches UP, so go1.20.5 is
// the bootstrap, not the build.
//
// Post-guard the repo's own directive refutes the claim, the bound is `minimum`, and M4's gate is
// denied STRUCTURALLY — no special case anywhere in M4, and no request is made at all. The flag being
// on changes nothing, which is the whole point.
func TestGoToolchainM4_RefutedExactClaimCannotLicenseARefutation(t *testing.T) {
	const goModAboveTheClaim = "module example.com/target\n\ngo 1.20\n\ntoolchain go1.24.0\n"

	for _, tc := range []struct {
		name     string
		declared string
		observed string
		trust    bool
	}{
		{name: "trusted observation below the manifest floor", observed: "go1.20.5", trust: true},
		{name: "declaration below the manifest floor", declared: "go1.20.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var seen plugin.ReachabilityRequest
			rep := runGoBaseline(t, goModAboveTheClaim, stdlibNoRangeAdvisory,
				pipeline.WithPlugin(toolchainReachPlugin{
					honored:           true, // the analyzer WOULD have honored it — that is the danger
					analyzerToolchain: analyzerToolchain,
					seen:              &seen,
				}),
				pipeline.WithSubjectToolchainReachability(true),
				pipeline.WithSubjectToolchain(tc.declared, tc.observed, tc.trust),
			)

			if seen.GoToolchain != "" {
				t.Errorf("reachability was asked to run under %q, a toolchain the subject's own go.mod refutes", seen.GoToolchain)
			}
			for _, f := range rep.Advisories {
				if f.Verdict != report.VerdictUndetermined {
					t.Errorf("emitted %s verdict %q basis %q off a refuted exact claim — inv.5 admits no ESTABLISHED verdict here",
						f.Advisory.ID, f.Verdict, f.Evidence.Basis)
				}
			}
			if ids := undeterminedByReason(rep)[report.ReasonGoToolchainNotScanned]; len(ids) != 1 || ids[0] != "GO-2021-0264" {
				t.Errorf("undetermined under %s = %v, want [GO-2021-0264]", report.ReasonGoToolchainNotScanned, ids)
			}
			// The refuted claim must not reach the supply-chain wire as an attestation. It reaches it
			// as `under_investigation`, which asserts nothing — that is the distinction the bump buys.
			assertNoNotAffected(t, rep, "GO-2021-0264")
		})
	}
}
