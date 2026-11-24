package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// A version is provably outside an advisory's affected range only when no source for that advisory
// places it inside. The corpus serves each advisory id as its own record, so a GO record and its GHSA
// alias may disagree, and the analyzer's own database is another source again. rangeDispute is
// consulted after the version axis disqualifies, and only ever withdraws that disqualification:
// a dispute sends the row on to analysis and asserts nothing about it.

// disputeTarget is one package the version axis judged outside: its identity, the versions the
// build resolved for it, and the projection the row applied to its own ranges, which an alias
// record's ranges for the package must pass through too before they are compared.
type disputeTarget struct {
	module, coordinate string
	versions           []string
	project            func(purl string, rngs []affectedRange) []affectedRange
}

// aliasRangeDispute returns the first alias record that names a judged package with a usable range
// set placing one of that package's versions inside it. A record that does not name the package, or
// whose ranges are absent or unusable, says nothing about the version and disputes nothing. A record
// that places a version outside only under an assumption about a pseudo-version's ancestry agrees
// under that assumption, which is returned with the record's id so the clear states it.
func aliasRangeDispute(src AdvisorySource, aliases []string, targets []disputeTarget) (dispute string, assumptions []aliasAssumption, disputed bool) {
	if src == nil {
		return "", nil, false
	}
	for _, id := range aliases {
		facts, ok := src.Lookup(id)
		if !ok {
			continue
		}
		for _, t := range targets {
			purl, rngs, ok := factsRangesFor(facts, t.module, t.coordinate)
			if !ok {
				continue
			}
			if t.project != nil {
				rngs = t.project(purl, rngs)
			}
			for _, v := range t.versions {
				outside, as, known := versionOutsideRangesAssuming(v, rngs)
				if !known || !outside {
					return fmt.Sprintf("advisory %s does not place %s outside its affected range", id, v), nil, true
				}
				for _, line := range as {
					if a := (aliasAssumption{advisory: id, line: line}); !slices.Contains(assumptions, a) {
						assumptions = append(assumptions, a)
					}
				}
			}
		}
	}
	return "", assumptions, false
}

// aliasAssumption is an assumption line an alias record's agreement rests on, with that record's id:
// the line names the record's bound, which the row's own record may not carry.
type aliasAssumption struct {
	advisory, line string
}

// statedFor is the line as the row states it: unqualified when the row's own placement already
// rests on it, else attributed to the alias record that carries the bound it names.
func (a aliasAssumption) statedFor(own []string) string {
	if slices.Contains(own, a.line) {
		return a.line
	}
	return "per " + a.advisory + ": " + a.line
}

// factsRangesFor projects a record's ranges for one package exactly as advisory_intake projects the
// row's own: the matching affected_packages elements, unioned, else the scalar block when the record
// carries none and names the package. purl is the matched package's. ok is false when the record does
// not name the package or its range set is not wholly usable.
func factsRangesFor(facts AdvisoryFacts, module, coordinate string) (string, []affectedRange, bool) {
	scheme := facts.VersionScheme
	if scheme == "" {
		scheme = schemeFromPURL(facts.PURL)
	}
	if len(facts.AffectedPackages) == 0 {
		if !namesPackage(facts.Module, facts.Coordinate, module, coordinate) {
			return "", nil, false
		}
		rngs, ok := validAffectedRanges(buildAffectedRanges(facts.AffectedRanges, facts.UpperExclusive, scheme))
		return facts.PURL, rngs, ok
	}
	pkgs := make([]advisoryAffectedPackage, 0, len(facts.AffectedPackages))
	for _, p := range facts.AffectedPackages {
		pkgScheme := p.VersionScheme
		if pkgScheme == "" {
			pkgScheme = schemeFromPURL(p.PURL)
		}
		pkgs = append(pkgs, advisoryAffectedPackage{
			Module:         goModulePath(p.Module, p.Coordinate, pkgScheme),
			Coordinate:     p.Coordinate,
			PURL:           p.PURL,
			AffectedRanges: withDisagreeingLegacyRanges(buildAffectedRanges(p.AffectedRanges, p.UpperExclusive, pkgScheme), p, facts, scheme),
		})
	}
	sel, ok := affectedPackageNamed(pkgs, module, coordinate)
	if !ok {
		return "", nil, false
	}
	rngs, ok := validAffectedRanges(sel.AffectedRanges)
	return sel.PURL, rngs, ok
}

func namesPackage(recModule, recCoordinate, module, coordinate string) bool {
	return (module != "" && recModule == module) || (coordinate != "" && recCoordinate == coordinate)
}

// analyzerRangeDispute asks the language plugin whether its own vulnerability database matches the
// advisory against the build. A match disputes the range, over a partial run too: a run that left
// part of the build out proves no absence, but a match it reports is still the database placing a
// build module version in range, and the dispute discloses the partial run. A plugin that could not
// answer, or answered no match over part of the build, disputes nothing, and the returned note says
// why in a fixed vocabulary, for the row to disclose; a run's own error text, which names the
// build's directory, goes to the log only.
func analyzerRangeDispute(ctx context.Context, p plugin.LanguagePlugin, req plugin.ReachabilityRequest) (dispute, note string) {
	req.MatchOnly = true
	res, err := p.Reachability(ctx, req)
	switch {
	case err != nil:
		log.Printf("pipeline: disqualification_discovery: %s: govulncheck database cross-check: %v", req.VulnID, err)
		return "", "govulncheck's database could not be consulted: govulncheck_failed"
	case res.AnalyzerMatched && !res.Partiality.Complete:
		return fmt.Sprintf("govulncheck's database matches %s against the build, over a partial run: %s", req.VulnID, strings.Join(res.Partiality.Reasons, ", ")), ""
	case res.AnalyzerMatched:
		return fmt.Sprintf("govulncheck's database matches %s against the build", req.VulnID), ""
	case !res.Partiality.Complete:
		return "", "govulncheck's database could not be consulted over the whole build: " + strings.Join(res.Partiality.Reasons, ", ")
	}
	return "", ""
}

// rangeDispute withdraws a version-axis disqualification that another source contradicts: an alias
// record of the same advisory, then the Go analyzer's own database. It returns the contradicting
// source, or, when the analyzer could not be consulted, a note the cleared row discloses.
// assumptions are the alias records' own assumption lines when they agree only under one; they are
// meaningful only when dispute is empty.
func (s disqualificationDiscovery) rangeDispute(ctx context.Context, c *assessment.Assessment, store artifact.Store, buildDir, goWork string, axis versionAxis, rngs []affectedRange, others []presentRanges) (dispute, note string, assumptions []aliasAssumption) {
	module, coordinate := disputedPackage(store, c.ID)
	src := s.src
	if src == nil {
		src = defaultAdvisorySource()
	}
	targets := []disputeTarget{{module: module, coordinate: coordinate, versions: axis.Versions,
		project: func(_ string, r []affectedRange) []affectedRange { return rangesForFloorVersion(store, c.ID, r) }}}
	for _, o := range others {
		targets = append(targets, disputeTarget{module: o.Module, coordinate: o.Coordinate, versions: o.Versions,
			project: func(purl string, r []affectedRange) []affectedRange {
				if toolchainSubject(purl, r) {
					return rangesForToolchainFloor(store, c.ID, r)
				}
				return r
			}})
	}
	d, assumptions, ok := aliasRangeDispute(src, extractAliases(store, c.ID), targets)
	if ok {
		return d, "", nil
	}
	if s.plugin == nil || s.plugin.Language() != "go" {
		return "", "", assumptions
	}
	// The analyzer matches the toolchain against the one it scanned with, so a toolchain row asks
	// it only about the other modules the version axis judged.
	toolchain := toolchainSubject(admittedPackagePURL(store, c.ID), rngs)
	if toolchain && !slices.ContainsFunc(others, func(o presentRanges) bool { return o.Module != "" }) || !toolchain && module == "" {
		return "", "", assumptions
	}
	dispute, note = analyzerRangeDispute(ctx, s.plugin, plugin.ReachabilityRequest{
		MatchOutsideToolchain: toolchain,
		BuildDir:              buildDir,
		GoWork:                goWork,
		VulnID:                govulnMatchID(store, c.ID, c.Request.Vulnerability.ID),
		GoToolchain:           requestedToolchain(s.subjectToolchain, store, c.ID),
		GoToolchainFloor:      inventoryGoFloor(store, c.ID),
		Package:               admittedPackagePURL(store, c.ID),
	})
	if dispute != "" {
		return dispute, note, nil
	}
	return "", note, assumptions
}

// disputedPackage is the package the version axis judged: the one select-by-target chose, else the
// advisory's own module and coordinate.
func disputedPackage(store artifact.Store, caseID string) (module, coordinate string) {
	if sel, ok := extractSelectedPackage(store, caseID); ok {
		return sel.Module, sel.Coordinate
	}
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return "", ""
	}
	var adv struct {
		Module     string `json:"module"`
		Coordinate string `json:"coordinate"`
	}
	if json.Unmarshal(arts[0].Payload, &adv) != nil {
		return "", ""
	}
	return adv.Module, adv.Coordinate
}

func extractAliases(store artifact.Store, caseID string) []string {
	arts, err := store.Query(caseID, artifact.TypeNormalizedAdvisory)
	if err != nil || len(arts) == 0 {
		return nil
	}
	var adv struct {
		Aliases []string `json:"aliases"`
	}
	if json.Unmarshal(arts[0].Payload, &adv) != nil {
		return nil
	}
	return adv.Aliases
}
