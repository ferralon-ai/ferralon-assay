package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// --- The work set -------------------------------------------------------------------------
//
// THE WORK SET IS THE SET OF ADVISORY IDS A SCAN PASS EVALUATES. It is a different thing from the
// advisory FACT source, and conflating the two is the mistake this file exists to correct.
//
// Historically the scan path's work set was a compiled-in, language-scoped slice of 16 ids
// (advisoryCorpus in acquire.go). That set is the same for every repository on earth: pointing
// -advisory-corpus at a 72-record corpus does NOT cause 72 advisories to be evaluated, because a
// corpus is a fact LOOKUP (AdvisorySource.Lookup(id)), not a work LIST. Nothing walked it.
//
// The widening here is the mechanism cve-watch has always used, brought to the scan path: ask
// OSV.dev which advisories affect the repository's REAL dependencies, and evaluate those.
//
//	OSV supplies the QUESTIONS.  The advisory source supplies the ANSWERS.
//
// Three properties are load-bearing, in descending order of how badly their loss would hurt:
//
//  1. THE COMPILED-IN SET IS A FLOOR, NEVER A CEILING. The widened work set is a UNION with it, so
//     no id that was evaluated before can stop being evaluated — whatever OSV says, whatever the
//     network does. Java/JS/Python carry first-party TEGRON-* fixtures OSV has never heard of;
//     replace-by instead of union-with would silently delete them.
//
//  2. A WORK SET THAT COULD NOT BE DETERMINED IS ANALYSIS THAT DID NOT HAPPEN. When OSV is
//     unreachable the pass still runs the floor, but it emits a PartialityNote saying the widening
//     did not happen. A narrower-than-intended scan must never render as a clean one. This is the
//     same doctrine as the corpus require-gate in run.go, applied at the other end of the pipe.
//
//  3. ONLY IDS WE HAVE FACTS FOR ARE ADMITTED. OSV answers a package query with every advisory it
//     has ever recorded against that package — 68 for the Go 1.21 standard library alone. An id
//     with no facts in the advisory source resolves nothing and analyzes nothing; admitting it
//     would spend a full S1–S6 pass (a whole call graph, per advisory) to produce an empty finding.
//     So the OSV answer is intersected with what the source can actually resolve, and the ids that
//     fall out are DISCLOSED as a PartialityNote rather than dropped silently — OSV said they apply
//     to this repository and we could not assess them, which is exactly a limit on coverage.
//
// The intersection is also what makes coverage grow the RIGHT way: it is bounded by the fact
// source, so publishing more advisory facts (a richer corpus) widens the scan, while an OSV outage
// or a noisy OSV answer cannot.

// Partiality reason codes this file declares. The PartialityNote.Reason vocabulary is explicitly
// OPEN (see report.PartialityNote), so these extend it without touching the report schema.
const (
	// reasonWorkSetNotWidened: the OSV work-set query did not complete, so the pass evaluated only
	// the compiled-in floor. The scan is narrower than the configuration asked for.
	reasonWorkSetNotWidened = "work_set_not_widened"
	// reasonWorkSetNoInventory: the repository's dependency coordinates could not be read, so there
	// was nothing to ask OSV about. Distinct from "OSV said nothing affects you".
	reasonWorkSetNoInventory = "work_set_no_inventory"
	// reasonAdvisoryFactsUnavailable: OSV reported advisories affecting this repository that the
	// advisory source has no facts for. They were NOT evaluated.
	reasonAdvisoryFactsUnavailable = "advisory_facts_unavailable"
)

// workSetSourceBuiltinUnionOSV names a work set that is the compiled-in language floor UNIONED with
// the ids an OSV.dev query over the repository's real dependencies returned. It extends the open
// report.WorkSet* vocabulary; report.WorkSetBuiltinLanguageSet still names a floor-only pass and
// report.WorkSetOSVQuery is reserved for a pass driven by OSV ALONE, which this is deliberately not
// (see property 1 above).
const workSetSourceBuiltinUnionOSV = "builtin_language_set_union_osv_query"

// workSet is the resolved set of advisory ids one scan pass will evaluate, together with the
// disclosure of how it was chosen and what it could not cover.
type workSet struct {
	// advisories is the evaluated set: the compiled-in floor first, in its original order, then the
	// OSV-derived additions sorted for determinism.
	advisories []assessment.VulnRef
	// source is the report.IntelProvenance.WorkSetSource value describing how the set was chosen.
	source string
	// partiality is the set of limits to disclose on the Report. Never nil-checked by callers; an
	// empty slice means the work set is exactly what the configuration asked for.
	partiality []report.PartialityNote
	// widened is how many ids OSV contributed beyond the floor. Reporting-only.
	widened int
	// unresolved is every id OSV reported against this repository's dependencies that no fact
	// source could resolve, sorted. These advisories were NOT evaluated by this pass.
	//
	// It exists so the number and the identities survive to a surface instead of dying inside
	// resolveWorkSet. It is rendered at the terminal by describe(), and carried into the Report —
	// and from there to every sink — by the Detail slot of the reasonAdvisoryFactsUnavailable entry
	// in partiality.
	unresolved []string
	// ecosystem is the dependency ecosystem the widening queried, for the CLI summary line.
	ecosystem string
}

// floorWorkSet returns the compiled-in language-scoped work set with no widening attempted. It is
// what cve-watch uses (that mode does its own OSV query against the stored SBOM and must not be
// changed) and what the scan path uses BY DEFAULT, the widening being opt-in (osvWorkSetDefault),
// as well as what a widening that was asked for and failed degrades to.
func floorWorkSet(advisories []assessment.VulnRef) workSet {
	return workSet{advisories: advisories, source: report.WorkSetBuiltinLanguageSet}
}

// resolveWorkSet widens the compiled-in floor with the advisories OSV.dev reports against the
// repository's real dependencies.
//
// It NEVER returns an error. Every failure — no dependency manifest, an unreachable OSV, a plugin
// that cannot enumerate — degrades to the floor plus a PartialityNote. A scan that fails to widen is
// a narrower scan, not a failed one; the caller must still produce a Report, and that Report must
// say so. (Contrast the corpus require-gate in run.go, which DOES hard-fail: there the operator
// declared an expectation, and silently substituting stale built-in intel would misrepresent which
// facts were used. Here nothing is misrepresented as long as the note is emitted.)
// src is the SAME AdvisorySource the pass will resolve facts through — the corpus-then-table chain
// when a corpus is configured, the table alone otherwise. Passing it in rather than rebuilding a
// table-only source here is what lets a richer corpus widen the scan: admission asks the real fact
// source whether it can answer for an id.
func resolveWorkSet(ctx context.Context, acq *acquired, osv trigger.OSVClient, src pipeline.AdvisorySource) workSet {
	ws := floorWorkSet(acq.advisories)
	ws.ecosystem = ecosystemForLanguage(acq.language)

	pkgs, notes := dependencyInventory(ctx, acq)
	ws.partiality = append(ws.partiality, notes...)
	if len(pkgs) == 0 {
		return ws
	}

	res, err := osv.QueryBatch(ctx, pkgs)
	if err != nil {
		ws.partiality = append(ws.partiality, report.PartialityNote{
			Reason:    reasonWorkSetNotWidened,
			Ecosystem: ws.ecosystem,
		})
		return ws
	}

	admitted, unresolved := admitByFacts(res.IDs(), acq.advisories, src)
	ws.unresolved = unresolved
	if len(unresolved) > 0 {
		// Detail carries the IDENTITIES of the advisories this pass did not assess into the Report,
		// and from there into every sink that renders Detail (projection/report_sarif.go,
		// resultsink/github/tier0_summary.go). Without it the note fires with a bare reason code:
		// still not a silent clean scan, but a reader is told that something went unassessed
		// without being told what, which is the question they will actually ask.
		//
		// Class is left unset on purpose. Builder.AddPartiality stamps it from Reason
		// (report.ClassifyPartialityReason), which is the single place the taxonomy is applied —
		// and an unrecognized reason lands in the LOUD arm, which is where every code this file
		// mints belongs. Setting it here would fork the taxonomy.
		ws.partiality = append(ws.partiality, report.PartialityNote{
			Reason:    reasonAdvisoryFactsUnavailable,
			Ecosystem: ws.ecosystem,
			Detail:    unresolvedDetail(unresolved),
		})
	}
	if len(admitted) == 0 {
		// The widening RAN and added nothing. That is a real, complete answer — this repository's
		// dependencies carry no advisory we hold facts for beyond the floor — so it is reported as
		// a widened pass with zero additions, not as a floor-only pass.
		ws.source = workSetSourceBuiltinUnionOSV
		return ws
	}

	ws.advisories = append(append([]assessment.VulnRef{}, acq.advisories...), admitted...)
	ws.source = workSetSourceBuiltinUnionOSV
	ws.widened = len(admitted)
	return ws
}

// admitByFacts intersects the ids OSV returned with the ids the advisory source can actually
// resolve facts for, and returns the additions (sorted, floor-deduplicated) plus THE IDS in the OSV
// answer that no fact source could resolve — sorted, so both halves of the return are deterministic.
//
// The unresolved half is ids rather than a count on purpose. These are advisories OSV says affect
// this repository and that this pass therefore did NOT evaluate; a user who asks "which ones did
// you not assess?" is asking for exactly this list, and a count cannot answer them. A caller that
// needs only the count takes len(). Discarding it is the silent-unassessed-advisory defect, so it
// is threaded onto workSet rather than consumed here.
//
// ALIAS RESOLUTION IS THE POINT. OSV answers in whatever id namespace the upstream feed uses —
// "GO-2023-2102" and "GHSA-4374-p667-p6c8" are the same vulnerability the advisory source keys under
// "CVE-2023-39325". A bare Lookup on the OSV id misses all three of the Go standard-library
// advisories we hold facts for. Aliases are already an established join key here: trigger's
// priorityFor() matches KEV/EPSS on `append([]string{adv.ID}, adv.Aliases...)` for exactly this
// reason. An alias hit is admitted under the PRIMARY id, because that is the key the facts — and
// therefore the finding — are stored under.
func admitByFacts(osvIDs []string, floor []assessment.VulnRef, src pipeline.AdvisorySource) (additions []assessment.VulnRef, unresolvable []string) {
	inFloor := make(map[string]struct{}, len(floor))
	for _, a := range floor {
		inFloor[a.ID] = struct{}{}
	}

	if src == nil {
		src = pipeline.NewTableSource()
	}
	aliases := aliasIndex()

	seen := make(map[string]struct{})
	var ids []string
	for _, id := range osvIDs {
		primary := id
		if _, ok := src.Lookup(id); !ok {
			p, ok := aliases[id]
			if !ok {
				unresolvable = append(unresolvable, id)
				continue
			}
			primary = p
		}
		if _, ok := inFloor[primary]; ok {
			continue
		}
		if _, ok := seen[primary]; ok {
			continue
		}
		seen[primary] = struct{}{}
		ids = append(ids, primary)
	}

	sort.Strings(ids)
	for _, id := range ids {
		additions = append(additions, assessment.VulnRef{ID: id, Source: "osv"})
	}
	sort.Strings(unresolvable)
	return additions, unresolvable
}

// aliasIndex maps every alias of every compiled-in advisory to that advisory's primary id.
//
// It reads pipeline.AdvisoryTable directly rather than going through the AdvisorySource seam
// because the seam deliberately exposes only Lookup(id) — it can answer "what do you know about
// this id" but not "what ids do you know". Selecting a work set needs the latter. The seam is still
// the ONLY path facts flow through (see admitByFacts); this index decides membership, never content.
//
// The consequence is that alias-only matches resolve against the compiled-in table but not against
// a filesystem corpus, so a corpus record reachable only by one of its aliases is not admitted. That
// is a coverage limit, not a soundness one, and closing it means giving AdvisorySource an
// enumeration method — a wider change than this one, and the natural home for corpus-driven work-set
// selection generally.
func aliasIndex() map[string]string {
	idx := make(map[string]string)
	for id, facts := range pipeline.AdvisoryTable {
		for _, a := range facts.Aliases {
			if a == "" || a == id {
				continue
			}
			// First writer wins, so the map is deterministic despite Go's randomized map
			// iteration order: a collision is two primaries claiming one alias, which would
			// otherwise make the admitted set differ run to run.
			if prior, ok := idx[a]; !ok || id < prior {
				idx[a] = id
			}
		}
	}
	return idx
}

// dependencyInventory reads the repository's REAL dependency coordinates — every package it
// declares, not merely the ones some advisory already names.
//
// This is the piece the scan path did not have. report.SBOM is ADVISORY-KEYED: trigger.ResolveSBOM
// walks the work set and asks the pipeline which package each advisory resolves to, so a dependency
// no advisory mentions contributes nothing. Querying OSV with that SBOM would be circular — it could
// only ever return advisories about packages the existing work set already named, which is precisely
// the set we are trying to grow beyond. Widening needs an inventory built from the manifest instead.
//
// Go is read here from go.mod (the Go analyzer plugin declares resolve_versions Unsupported — Go
// dependency versions are resolved in-pipeline from go.mod). Every other language reuses its
// plugin's existing whole-manifest parse: ResolveDependencyVersions already parses every
// manifest/lockfile under the build dir into DependencyVersionResult.All and only then selects the
// requested coordinate, so an EMPTY coordinate returns the full inventory with no plugin change.
func dependencyInventory(ctx context.Context, acq *acquired) ([]report.Package, []report.PartialityNote) {
	eco := ecosystemForLanguage(acq.language)
	if eco == "" {
		return nil, nil
	}

	if acq.language == checkout.LangGo {
		return goDependencyInventory(acq.buildDir)
	}

	// No analyzer plugin means no manifest parser for this language. That is an absent inventory,
	// not a crash: the pass degrades to the floor and discloses it, like every other failure here.
	if acq.plugin == nil {
		return nil, []report.PartialityNote{{Reason: reasonWorkSetNoInventory, Ecosystem: eco}}
	}

	res, err := acq.plugin.ResolveDependencyVersions(ctx, plugin.ResolveVersionsRequest{BuildDir: acq.buildDir})
	if err != nil {
		return nil, []report.PartialityNote{{Reason: reasonWorkSetNoInventory, Ecosystem: eco}}
	}

	seen := make(map[report.Package]struct{}, len(res.All))
	var pkgs []report.Package
	for _, d := range res.All {
		// An UNRESOLVED dependency carries no version by design (inv.5 — a version is never
		// guessed). OSV needs one to decide whether a range applies, so it is skipped here rather
		// than queried with an empty version, which OSV would answer with every advisory ever
		// recorded against the package.
		if !d.Resolved || d.Version == "" || d.Coordinate == "" {
			continue
		}
		p := report.Package{Ecosystem: eco, Name: d.Coordinate, Version: d.Version}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		pkgs = append(pkgs, p)
	}

	var notes []report.PartialityNote
	if len(pkgs) == 0 {
		notes = append(notes, report.PartialityNote{Reason: reasonWorkSetNoInventory, Ecosystem: eco})
	}
	sortPackages(pkgs)
	return pkgs, notes
}

// goDependencyInventory reads every module go.mod requires, plus the Go standard library keyed to
// the toolchain version.
//
// Indirect requires are INCLUDED: a transitive dependency is a real dependency, and on a modern go
// directive the indirect block is the resolved build list — the closest thing to a true SBOM the
// module graph offers without a network fetch.
//
// The standard library is a dependency too, and OSV tracks it as the "stdlib" package of the Go
// ecosystem. It matters disproportionately here: the compiled-in table's go-toolchain advisories
// (the net/http, path/filepath and net/netip backport pairs) are the clearest advisories we hold
// real facts for that no repository's go.mod will ever name, so without this the widening cannot
// reach them.
func goDependencyInventory(buildDir string) ([]report.Package, []report.PartialityNote) {
	data, err := os.ReadFile(filepath.Join(buildDir, "go.mod"))
	if err != nil {
		return nil, []report.PartialityNote{{Reason: plugin.PartialReasonNoManifest, Ecosystem: ecosystemGo}}
	}
	mf, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return nil, []report.PartialityNote{{Reason: plugin.PartialReasonNoManifest, Ecosystem: ecosystemGo}}
	}

	seen := make(map[report.Package]struct{}, len(mf.Require)+1)
	var pkgs []report.Package
	add := func(name, version string) {
		if name == "" || version == "" {
			return
		}
		p := report.Package{Ecosystem: ecosystemGo, Name: name, Version: version}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		pkgs = append(pkgs, p)
	}

	for _, r := range mf.Require {
		if r == nil {
			continue
		}
		add(r.Mod.Path, r.Mod.Version)
	}
	if v := toolchainVersion(mf); v != "" {
		add(goStdlibPackage, v)
	}

	var notes []report.PartialityNote
	if len(pkgs) == 0 {
		notes = append(notes, report.PartialityNote{Reason: plugin.PartialReasonNoManifest, Ecosystem: ecosystemGo})
	}
	sortPackages(pkgs)
	return pkgs, notes
}

// toolchainVersion returns the Go toolchain version go.mod pins, in the form OSV's Go ecosystem
// expects for the "stdlib" package: a bare semver, NO "go" prefix.
//
// The prefix is not cosmetic. OSV cannot parse "go1.21.0" as a version and answers the query with
// every stdlib advisory it has ever recorded (142 at the time of writing) instead of the 68 that
// actually affect that release — an unfiltered firehose that reads exactly like a real answer.
// Measured against api.osv.dev, 2026-07-29.
func toolchainVersion(mf *modfile.File) string {
	var raw string
	if mf.Toolchain != nil && mf.Toolchain.Name != "" {
		raw = mf.Toolchain.Name
	} else if mf.Go != nil {
		raw = mf.Go.Version
	}
	raw = strings.TrimPrefix(raw, "go")
	if raw == "" {
		return ""
	}
	// A two-element go directive ("1.21") is not a version OSV can range-compare; normalize it to
	// the release's .0 patch, which is what the directive means.
	if strings.Count(raw, ".") == 1 {
		raw += ".0"
	}
	return raw
}

// Ecosystem tags, matching both report.Package.Ecosystem and OSV.dev's ecosystem vocabulary (they
// agree, which is why the same strings serve the SBOM and the query).
const (
	ecosystemGo    = "Go"
	ecosystemMaven = "Maven"
	ecosystemNPM   = "npm"
	ecosystemPyPI  = "PyPI"
	ecosystemNuGet = "NuGet"

	// goStdlibPackage is OSV's package name for the Go standard library.
	goStdlibPackage = "stdlib"
)

// ecosystemForLanguage maps a detected source language to its dependency ecosystem, or "" for a
// language with no inventory path.
func ecosystemForLanguage(language string) string {
	switch language {
	case checkout.LangGo:
		return ecosystemGo
	case checkout.LangJava:
		return ecosystemMaven
	case checkout.LangKotlin:
		return ecosystemMaven // Kotlin/JVM artifacts are Maven-keyed in OSV regardless of source language (A2).
	case checkout.LangJS:
		return ecosystemNPM
	case checkout.LangPython:
		return ecosystemPyPI
	case checkout.LangDotNet:
		return ecosystemNuGet
	default:
		return ""
	}
}

// sortPackages orders an inventory deterministically, so the OSV request body — and therefore the
// positional response mapping — is reproducible for a given tree.
func sortPackages(pkgs []report.Package) {
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})
}

// describe renders a one-line human summary of how the work set was chosen, for the CLI's run
// output. The Report carries the machine-readable form (report.IntelProvenance + Partiality).
//
// A DEGRADED run says so here too. The Report's PartialityNote is the durable disclosure, but the
// terminal is where an operator actually looks, and "9 advisories" reads like a complete answer
// unless the line admits the widening did not happen.
func (w workSet) describe() string {
	return w.describeSet() + w.describeUnassessed()
}

// describeUnassessed appends the unassessed-advisory disclosure to the terminal line, or "" when
// every id OSV named was resolvable.
//
// It is a SEPARATE clause from describeSet because the two answer different questions and can both
// be true at once: describeSet says how wide the pass was, this says what the pass was told about
// and skipped anyway. Folding it into the switch would let one suppress the other.
func (w workSet) describeUnassessed() string {
	if len(w.unresolved) == 0 {
		return ""
	}
	return "\n  " + unresolvedDetail(w.unresolved)
}

func (w workSet) describeSet() string {
	switch {
	case hasNote(w.partiality, reasonWorkSetNotWidened):
		return fmt.Sprintf("%d advisories (built-in language set only — OSV.dev unreachable, so the work set was NOT widened; this scan is narrower than configured)", len(w.advisories))
	case hasNote(w.partiality, reasonWorkSetNoInventory), hasNote(w.partiality, plugin.PartialReasonNoManifest):
		return fmt.Sprintf("%d advisories (built-in language set only — no dependency manifest resolved, so there was nothing to widen from)", len(w.advisories))
	case w.source == report.WorkSetBuiltinLanguageSet:
		return fmt.Sprintf("%d advisories (built-in language set)", len(w.advisories))
	case w.widened == 0:
		return fmt.Sprintf("%d advisories (built-in language set; OSV reported nothing further we hold facts for)", len(w.advisories))
	default:
		return fmt.Sprintf("%d advisories (%d built-in + %d from OSV over %s dependencies)",
			len(w.advisories), len(w.advisories)-w.widened, w.widened, w.ecosystem)
	}
}

// unresolvedDetailCap bounds how many ids unresolvedDetail names before it summarizes. A Report
// note is read by a human in a job summary or a SARIF property; 12 ids is about as much as one
// sentence can carry, and the count that precedes them is exact regardless.
const unresolvedDetailCap = 12

// unresolvedDetail renders the unassessed-advisory disclosure: the exact count always, plus as many
// of the identities as a single note can reasonably carry.
//
// The count is never elided, because the count is what makes the gap auditable — a user who sees
// "102 not assessed" knows to ask for the rest even when the note names only twelve of them. It
// returns "" for an empty input so a caller can assign it unconditionally.
func unresolvedDetail(unresolved []string) string {
	if len(unresolved) == 0 {
		return ""
	}
	shown := unresolved
	suffix := ""
	if len(shown) > unresolvedDetailCap {
		shown = shown[:unresolvedDetailCap]
		suffix = fmt.Sprintf(", and %d more", len(unresolved)-unresolvedDetailCap)
	}
	return fmt.Sprintf("%d advisory id(s) reported against this repository's dependencies had no facts available and were NOT assessed: %s%s",
		len(unresolved), strings.Join(shown, ", "), suffix)
}

// hasNote reports whether the given partiality reason was declared.
func hasNote(notes []report.PartialityNote, reason string) bool {
	for _, n := range notes {
		if n.Reason == reason {
			return true
		}
	}
	return false
}
