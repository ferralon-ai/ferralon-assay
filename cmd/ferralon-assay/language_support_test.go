// language_support_test.go — every language this release claims to support must be able to complete
// a scan of a repository written in it, and must say nothing it did not establish.
//
// # Completing a scan
//
// The scanner carries no advisories of its own, so a scan's work set comes from a corpus policy, the
// OSV widening, or the opted-in house canaries. TestEverySupportedLanguageCompletesAScan asserts, per
// language, the wiring a scan needs (a language-matched analyzer plugin and a dependency ecosystem),
// that a default acquisition has no work set and halts at the empty-work-set gate, and that the same
// tree with a work set of its ecosystem's advisories proceeds.
//
// # What the scan says
//
// TestNoLanguageRefutesWithoutASearch is the other half: an analyzer that resolves no dependency
// version and searches no call graph may not produce a refuting verdict for any language.
//
// # Altitude
//
// A full S1–S6 baseline against the REAL per-language analyzer is not hermetic — it wants the
// plugin binaries on PATH, a git binary, and (for Go) the govulncheck database over the network.
// The completion table therefore stops at the work set, and the verdict-honesty table runs the real
// baseline path with the analyzer seam filled by a double, which is how the pipeline's own hermetic
// tests carry a measured analyzer shape across the inv.8 boundary (see pipeline/disqual_java_test.go).
// Advisory facts come from the fixture corpus under corpus/testdata/advisories.
package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
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

// fixtureFloors is a per-language work set of real published advisories from the fixture corpus
// (corpus/testdata/advisories). The scanner has no default work set; these stand in for what a
// corpus policy or the OSV widening would choose, so each language is exercised against advisories
// in its own ecosystem.
var fixtureFloors = map[string][]string{
	checkout.LangGo:     {"GO-2021-0113", "GO-2021-0264", "CVE-2024-45337"},
	checkout.LangJava:   {"CVE-2019-14540", "CVE-2020-36518", "CVE-2024-22243"},
	checkout.LangKotlin: {"CVE-2019-14540", "CVE-2020-36518", "CVE-2024-22243"},
	checkout.LangJS:     {"CVE-2022-46175", "CVE-2023-26136", "CVE-2024-29041"},
	checkout.LangPython: {"CVE-2024-22195", "CVE-2024-23334", "CVE-2024-3772"},
	checkout.LangDotNet: {"CVE-2019-0820", "CVE-2020-5234", "CVE-2024-21907"},
}

// fixtureFloor returns language's fixture work set, failing the test if any id is missing from the
// fixture corpus or carries neither a version axis nor a symbol axis — an advisory that can only
// fail open would let the tables below pass while assessing nothing.
func fixtureFloor(t *testing.T, language string) []assessment.VulnRef {
	t.Helper()
	ids, ok := fixtureFloors[language]
	if !ok {
		t.Fatalf("no fixture floor for language %q", language)
	}
	src := fixtureSource()
	refs := make([]assessment.VulnRef, 0, len(ids))
	for _, id := range ids {
		facts, ok := src.Lookup(id)
		if !ok {
			t.Fatalf("%s fixture floor names %s, which the fixture corpus does not hold", language, id)
		}
		if len(facts.AffectedRanges) == 0 && facts.UpperExclusive == "" && len(facts.Symbols) == 0 {
			t.Fatalf("%s fixture advisory %s carries neither a version range nor a symbol", language, id)
		}
		refs = append(refs, assessment.VulnRef{ID: id, Source: "ghsa"})
	}
	return refs
}

// TestEverySupportedLanguageCompletesAScan is the regression lock.
//
// For each supported language it acquires a real one-file source tree through the production
// acquisition path with DEFAULT flags and asserts the two halves of the contract: with no work-set
// input the acquisition carries no advisories and the gate halts the run, and with a work set of
// that ecosystem's advisories the same tree resolves and proceeds.
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

			// 2. A dependency ecosystem. Without one neither a corpus policy nor the OSV widening
			//    can choose advisories against this tree.
			if ecosystemForLanguage(language) == "" {
				t.Fatal("no dependency ecosystem is mapped for this language")
			}

			// 3. No default work set: with no input the gate halts the run.
			if len(acq.advisories) != 0 {
				t.Fatalf("a default acquisition carries advisories %v; the scanner carries none of its own",
					ids(acq.advisories))
			}
			f := runFlagsFor(t)
			if _, err := f.scanWorkSet(context.Background(), acq); err == nil {
				t.Fatal("a scan with no work-set input did not halt")
			}

			// 4. With a work set and facts for it, the gate does not fire.
			acq.advisories = fixtureFloor(t, language)
			f.resolvedSource = fixtureSource()
			ws, err := f.scanWorkSet(context.Background(), acq)
			if err != nil {
				t.Fatalf("a %s scan with a work set halts: %v", language, err)
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
// real tree of each language and a fixture work set of that ecosystem's advisories. The one seam filled
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
				Advisories: fixtureFloor(t, language),
				AssessOptions: []pipeline.AssessOption{
					pipeline.WithPlugin(unsearchingAnalyzer{language: language}),
					pipeline.WithAdvisorySource(fixtureSource()),
				},
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

// TestHouseCanariesOnlyByFlag pins that -include-house-canaries is the only thing that puts an
// advisory into an acquisition: off, every language acquires none; on, each acquires exactly its
// house canaries.
func TestHouseCanariesOnlyByFlag(t *testing.T) {
	for _, language := range supportedLanguages {
		t.Run(language, func(t *testing.T) {
			if got := treeFor(t, language, false).advisories; len(got) != 0 {
				t.Fatalf("canaries off: acquisition carries %v, want none", ids(got))
			}
			want := houseCanaries(language, true)
			if len(want) == 0 {
				t.Fatalf("%s has no house canary to opt in", language)
			}
			if got := treeFor(t, language, true).advisories; !slices.Equal(got, want) {
				t.Fatalf("canaries on: acquisition carries %v, want %v", ids(got), ids(want))
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
		want := "./cmd/" + plugin.BinaryName(language)
		if !strings.Contains(script, want) {
			t.Errorf("build-release.sh BAKED_TARGETS does not build %s, but %s is a supported language: "+
				"the release would ship a scanner whose plugin binary is missing from the tarball",
				want, language)
		}
	}
}
