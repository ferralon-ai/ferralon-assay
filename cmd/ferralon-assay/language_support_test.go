// language_support_test.go — every language this release claims to support must actually complete a
// scan of a repository written in it.
//
// # What went wrong, and why a test is the fix
//
// The scanner shipped analyzer plugins for Go, Java, JavaScript, Python and .NET, and only Go could
// complete a run. The compiled-in advisory table held no Maven, npm, PyPI or NuGet facts at all —
// the only entries in those ecosystems were TEGRON-* house canaries, gated off the default surface
// because they carry no CVE — so the default advisory floor for four of the five languages was
// empty, and scanWorkSet halts a run whose work set resolves to zero. A default Java, JS, Python or
// .NET scan exited non-zero.
//
// Nothing failed when that happened. Every unit test passed, the plugins built, the binaries went
// into the release tarball, and the gap was visible only to someone who ran the shipped scanner
// against a repository of each language. It was ultimately DOCUMENTED — in README.md and action.yml,
// telling users to scope the action to Go — rather than fixed, twice.
//
// This file is the check that would have caught it. It is table-driven over the five supported
// languages and it fails if any one of them stops being able to complete a scan.
//
// # Completing a scan is half the property; the other half is what the scan says
//
// Making all five languages complete a run immediately produced a worse failure than halting:
// four of them completed by emitting `not_exploitable / vulnerable_symbol_absent` for advisories
// nothing had searched for. TestNoLanguageRefutesWithoutASearch is the other half of the lock —
// an analyzer that resolves no dependency version and searches no call graph may not produce a
// refuting verdict for any language, today or after a future analyzer lands.
//
// # Altitude: why the completion half stops at the work set
//
// A full S1–S6 baseline against the REAL per-language analyzer is not hermetic — it wants the
// plugin binaries on PATH, a git binary, and (for Go) the govulncheck database over the network.
// The completion table therefore asserts everything decidable in-process, which is precisely the
// layer that defect lived in: per-language wiring, a non-empty default floor, and a work set that
// resolves without halting. The verdict-honesty table below runs the real baseline path with the
// analyzer seam filled by a double, which is how the pipeline's own hermetic tests carry a
// measured analyzer shape across the inv.8 boundary (see pipeline/disqual_java_test.go).
//
// The end-to-end half — the shipped scanner run against a real tree of each language, exit 0, a
// Report on disk — was performed by hand against all five and is recorded in the cycle deposit
// (execution/42-bake-all-five.md).
package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
	"github.com/ferralon-ai/ferralon-assay/verdict"
)

// supportedLanguages is every language the release claims. A language belongs here exactly when the
// tarball bakes an analyzer plugin for it (scripts/build-release.sh BAKED_TARGETS) — the two lists
// are the same claim made in two places, and this file is where the claim is tested.
var supportedLanguages = []string{
	checkout.LangGo,
	checkout.LangJava,
	checkout.LangKotlin,
	checkout.LangJS,
	checkout.LangPython,
	checkout.LangDotNet,
}

// TestEverySupportedLanguageCompletesAScan is the regression lock.
//
// For each supported language it acquires a real one-file source tree through the production
// acquisition path and resolves the work set through the production gate, with DEFAULT flags — no
// -include-house-canaries, no -osv-work-set, no corpus. That is the configuration a user gets, and
// the configuration that was broken.
func TestEverySupportedLanguageCompletesAScan(t *testing.T) {
	for _, language := range supportedLanguages {
		t.Run(language, func(t *testing.T) {
			trapEgress(t)

			acq := treeFor(t, language, false)

			// 1. A language-matched analyzer plugin. selectPlugin has no fallback arm: a language it
			//    does not know hard-fails the run, so this is the wiring half of "supported".
			if acq.plugin == nil {
				t.Fatal("no analyzer plugin was selected")
			}
			if acq.plugin.Language() != language {
				t.Fatalf("plugin language = %q, want %q — the pipeline only runs a plugin whose "+
					"Language() matches the tree, so a mismatch silently disables analysis",
					acq.plugin.Language(), language)
			}

			// 2. A dependency ecosystem. Without one the OSV widening has nothing to query and
			//    dependencyInventory returns early, so the language can never widen past its floor.
			if ecosystemForLanguage(language) == "" {
				t.Fatal("no dependency ecosystem is mapped for this language")
			}

			// 3. A NON-EMPTY DEFAULT FLOOR. This is the line the defect crossed.
			if len(acq.advisories) == 0 {
				t.Fatal("the default advisory floor is empty, so scanWorkSet will halt the run and " +
					"a default scan of this language cannot complete — this is the exact defect " +
					"this file exists to catch")
			}

			// 4. The gate does not fire. The property in full: a default scan of this language
			//    resolves a work set and proceeds.
			f := runFlagsFor(t)
			ws, err := f.scanWorkSet(context.Background(), acq)
			if err != nil {
				t.Fatalf("a default scan of a %s tree halts: %v", language, err)
			}
			if len(ws.advisories) == 0 {
				t.Fatal("scanWorkSet returned an empty work set without erroring")
			}
		})
	}
}

// unsearchingAnalyzer is an analyzer that ran and searched nothing: it resolves no dependency
// version, resolves no symbol, and returns an empty call graph it declines to call complete.
//
// That is not a strawman. It is the measured shape of the Java, JS, Python and .NET analyzers
// facing a dependency advisory: each is source-lexical over FIRST-PARTY code, so it never opens
// the dependency, and the version it does sometimes read off a manifest is the only axis it can
// contribute. Every method is overridden because plugin.StubPlugin's live ops return canned
// symbols and a canned two-edge graph — inheriting any of them would fabricate the very evidence
// this test is asserting the absence of.
type unsearchingAnalyzer struct {
	plugin.StubPlugin
	language string
}

func (a unsearchingAnalyzer) Language() string { return a.language }

func (unsearchingAnalyzer) IndexSymbols(context.Context, plugin.IndexSymbolsRequest) (plugin.SymbolIndexResult, error) {
	return plugin.SymbolIndexResult{Partiality: plugin.Complete()}, nil
}

func (unsearchingAnalyzer) ResolveDependencySymbols(context.Context, plugin.ResolveSymbolsRequest) (plugin.SymbolResolutionResult, error) {
	return plugin.SymbolResolutionResult{Partiality: plugin.Complete()}, nil
}

func (unsearchingAnalyzer) ResolveDependencyVersions(context.Context, plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	return plugin.DependencyVersionResult{Partiality: plugin.Partial(plugin.PartialReasonNoManifest)}, nil
}

func (unsearchingAnalyzer) CallGraph(context.Context, plugin.CallGraphRequest) (plugin.CallGraphResult, error) {
	return plugin.CallGraphResult{
		Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch),
		Algorithm:  "source-lexical",
	}, nil
}

func (unsearchingAnalyzer) FindIngresses(context.Context, plugin.FindIngressesRequest) (plugin.IngressResult, error) {
	return plugin.IngressResult{Partiality: plugin.Complete()}, nil
}

func (unsearchingAnalyzer) Reachability(context.Context, plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	return plugin.ReachabilityResult{Partiality: plugin.Partial(plugin.PartialReasonDynamicDispatch)}, nil
}

func (unsearchingAnalyzer) BuildManifest(context.Context, plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	return plugin.BuildManifestResult{Partiality: plugin.Unsupported()}, nil
}

// TestNoLanguageRefutesWithoutASearch is the verdict half of this file's claim.
//
// A refutation — `not_exploitable`, or any Evidence.Basis at all — states that a comparison ran
// against this codebase and cleared it. When no dependency version was resolved and no call graph
// was searched, no comparison ran, and the row must land on the OPEN verdict instead. Before the
// fix this table records, a Java repository whose servlet called the exact method CVE-2020-36518
// names was reported not exploitable, which is the worst thing this scanner can say.
//
// It runs the real baseline path (trigger.RunBaseline → assess → S1–S6 → the verdict rule) over a
// real tree of each language and each language's real default advisory floor. The one seam filled
// by a double is the analyzer, because the real one is a separate binary; trapEgress proves the
// pass reaches no network.
//
// The property is stated over the finding's own basis, never over the language: the row is only
// required to be open when the finding carries NO resolved SBOM package. An analyzer that starts
// resolving versions and symbols is free to refute, and passes this test by doing so.
func TestNoLanguageRefutesWithoutASearch(t *testing.T) {
	for _, language := range supportedLanguages {
		t.Run(language, func(t *testing.T) {
			trapEgress(t)

			dir := t.TempDir()
			file, content := languageFixture(t, language)
			if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o600); err != nil {
				t.Fatalf("write %s: %v", file, err)
			}

			rep, err := trigger.RunBaseline(context.Background(), statestore.NewMemStore(), trigger.BaselineRequest{
				Subject: trigger.Subject{Repo: "specimen", Revision: "HEAD"},
				Codebase: assessment.CodebaseRef{
					Repo:        "specimen",
					Revision:    "HEAD",
					Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: dir},
				},
				Advisories:    advisoryCorpus(language, false),
				AssessOptions: []pipeline.AssessOption{pipeline.WithPlugin(unsearchingAnalyzer{language: language})},
			})
			if err != nil {
				t.Fatalf("baseline over a %s tree: %v", language, err)
			}
			if len(rep.Advisories) == 0 {
				t.Fatal("the run produced no findings, so this table asserted nothing")
			}

			for _, f := range rep.Advisories {
				if f.Package != nil {
					continue // a version WAS resolved: this row is free to refute.
				}
				if f.Verdict == report.VerdictNotExploitable {
					t.Errorf("%s: %s is not_exploitable with no resolved SBOM package — nothing "+
						"resolved a version and nothing searched a call graph, so there is no "+
						"comparison for that refutation to rest on", language, f.Advisory.ID)
				}
				if f.Evidence.Basis != verdict.BasisNone {
					t.Errorf("%s: %s carries refutation basis %q with no resolved SBOM package; "+
						"the honest landing spot is the open verdict", language, f.Advisory.ID, f.Evidence.Basis)
				}
			}
		})
	}
}

// TestDefaultFloorResolvesFacts pins the other way a floor can be hollow: membership without facts.
//
// An id in the work set that no fact source can resolve spends a full S1–S6 pass to produce an empty
// finding — it is work-set membership that assesses nothing, which reads to a user exactly like
// coverage. So every id in every default floor must resolve through the built-in table, and must
// carry a version axis or a reachability axis to resolve it ON.
func TestDefaultFloorResolvesFacts(t *testing.T) {
	src := pipeline.NewTableSource()
	for _, language := range supportedLanguages {
		t.Run(language, func(t *testing.T) {
			for _, ref := range advisoryCorpus(language, false) {
				facts, ok := src.Lookup(ref.ID)
				if !ok {
					t.Errorf("%s floor names %s, which the built-in advisory table cannot resolve",
						language, ref.ID)
					continue
				}
				if len(facts.AffectedRanges) == 0 && facts.UpperExclusive == "" && len(facts.Symbols) == 0 {
					t.Errorf("%s floor advisory %s carries neither a version range nor a symbol: it "+
						"can only ever fail open, so it is membership that assesses nothing",
						language, ref.ID)
				}
			}
		})
	}
}

// TestDefaultFloorCarriesNoHouseCanary is the standing ruling, re-asserted against the new floors.
//
// The house canaries are synthetic first-party advisories over packages that do not exist
// (com.example.*, tegron-corpus-*). They carry no CVE, so a finding naming one reads as noise at
// best and as a fabricated result at worst, and they were deliberately gated off the default surface.
// Populating the floors is not a licence to reopen that: every default-floor advisory must be a real
// published one, identified by carrying a CVE or GHSA identifier as its id or an alias.
func TestDefaultFloorCarriesNoHouseCanary(t *testing.T) {
	src := pipeline.NewTableSource()
	for _, language := range supportedLanguages {
		t.Run(language, func(t *testing.T) {
			for _, ref := range advisoryCorpus(language, false) {
				if strings.HasPrefix(ref.ID, "TEGRON-") || strings.HasPrefix(ref.ID, "FERRALON-") {
					t.Errorf("%s default floor names the house canary %s", language, ref.ID)
					continue
				}
				facts, ok := src.Lookup(ref.ID)
				if !ok {
					continue // reported by TestDefaultFloorResolvesFacts
				}
				public := strings.HasPrefix(ref.ID, "CVE-") || strings.HasPrefix(ref.ID, "GHSA-") ||
					strings.HasPrefix(ref.ID, "GO-")
				for _, a := range facts.Aliases {
					if strings.HasPrefix(a, "CVE-") || strings.HasPrefix(a, "GHSA-") || strings.HasPrefix(a, "GO-") {
						public = true
					}
				}
				if !public {
					t.Errorf("%s default floor names %s, which carries no CVE/GHSA/GO identifier: "+
						"the default findings surface takes real published advisories only",
						language, ref.ID)
				}
			}
		})
	}
}

// TestHouseCanariesStillOptIn pins the other half of that ruling: the canaries are ADDED by
// -include-house-canaries, never removed by it, and every ecosystem that has one still honours the
// flag. A floor that stopped growing under the flag would mean the demo path had been silently
// unwired while populating the default surface.
func TestHouseCanariesStillOptIn(t *testing.T) {
	for _, language := range supportedLanguages {
		t.Run(language, func(t *testing.T) {
			off := advisoryCorpus(language, false)
			on := advisoryCorpus(language, true)
			if len(on) <= len(off) {
				t.Fatalf("%s corpus is %d with canaries off and %d with them on: the opt-in must ADD",
					language, len(off), len(on))
			}
			// The floor is a prefix of the opted-in set: the flag adds, it never reorders or drops.
			for i, ref := range off {
				if on[i] != ref {
					t.Fatalf("%s corpus index %d is %v with canaries off but %v with them on: the "+
						"opt-in must leave the default floor untouched", language, i, ref, on[i])
				}
			}
		})
	}
}

// TestBakedTargetsCoverEverySupportedLanguage ties the release payload to this file's claim.
//
// The release bakes one analyzer plugin per supported language into the tarball. If a language is
// supported here but not baked there, the release ships a scanner that selects a plugin binary the
// tarball does not contain, and the run dies on PATH lookup at the customer's runner. Reading the
// shell script is crude, and it is exactly the right crudeness: it is the artifact that decides what
// ships.
//
// It reads scripts/build-release.sh — the ONE target table — and not the operator's publish script.
// Both surfaces that cut this release (this repository's release workflow, and the private cut
// script) build through that table, so this is the only file that can be wrong. Pointing at the cut
// script instead would have tested the wrong artifact on the surface that has it, and SKIPPED on the
// published repo, where it does not exist and never will.
func TestBakedTargetsCoverEverySupportedLanguage(t *testing.T) {
	// In-module, so it is present on every surface this test runs on: an unreadable table is a
	// failure, never a skip.
	path := filepath.Join("..", "..", "scripts", "build-release.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the release target table at %s: %v", path, err)
	}
	script := string(data)
	for _, language := range supportedLanguages {
		want := "./cmd/tegron-plugin-" + language
		if !strings.Contains(script, want) {
			t.Errorf("build-release.sh BAKED_TARGETS does not build %s, but %s is a supported language: "+
				"the release would ship a scanner whose plugin binary is missing from the tarball",
				want, language)
		}
	}
}
