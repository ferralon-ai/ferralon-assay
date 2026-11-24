package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
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

// aliasRangeDispute returns the first alias record that names the adjudicated package with a usable
// range set placing one of the axis versions inside it. A record that does not name the package, or
// whose ranges are absent or unusable, says nothing about the version and disputes nothing.
func aliasRangeDispute(src AdvisorySource, aliases []string, module, coordinate string, axis versionAxis) (string, bool) {
	if src == nil {
		return "", false
	}
	for _, id := range aliases {
		facts, ok := src.Lookup(id)
		if !ok {
			continue
		}
		rngs, ok := factsRangesFor(facts, module, coordinate)
		if !ok {
			continue
		}
		for _, v := range axis.Versions {
			if outside, known := versionOutsideRanges(v, rngs); !known || !outside {
				return fmt.Sprintf("advisory %s does not place %s outside its affected range", id, v), true
			}
		}
	}
	return "", false
}

// factsRangesFor projects a record's ranges for one package exactly as advisory_intake projects the
// row's own: the matching affected_packages elements, unioned, else the scalar block when the record
// carries none and names the package. ok is false when the record does not name the package or its
// range set is not wholly usable.
func factsRangesFor(facts AdvisoryFacts, module, coordinate string) ([]affectedRange, bool) {
	scheme := facts.VersionScheme
	if scheme == "" {
		scheme = schemeFromPURL(facts.PURL)
	}
	if len(facts.AffectedPackages) == 0 {
		if !namesPackage(facts.Module, facts.Coordinate, module, coordinate) {
			return nil, false
		}
		return validAffectedRanges(buildAffectedRanges(facts.AffectedRanges, facts.UpperExclusive, scheme))
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
			AffectedRanges: withDisagreeingLegacyRanges(buildAffectedRanges(p.AffectedRanges, p.UpperExclusive, pkgScheme), p, facts, scheme),
		})
	}
	sel, ok := affectedPackageNamed(pkgs, module, coordinate)
	if !ok {
		return nil, false
	}
	return validAffectedRanges(sel.AffectedRanges)
}

func namesPackage(recModule, recCoordinate, module, coordinate string) bool {
	return (module != "" && recModule == module) || (coordinate != "" && recCoordinate == coordinate)
}

// analyzerRangeDispute asks the language plugin whether its own vulnerability database matches the
// advisory against the build. A match disputes the range. A plugin that could not answer over the
// whole build disputes nothing, and the returned note says why, for the row to disclose.
func analyzerRangeDispute(ctx context.Context, p plugin.LanguagePlugin, req plugin.ReachabilityRequest) (dispute, note string) {
	req.MatchOnly = true
	res, err := p.Reachability(ctx, req)
	switch {
	case err != nil:
		return "", "govulncheck's database could not be consulted: " + firstLine(err.Error())
	case !res.Partiality.Complete:
		return "", "govulncheck's database could not be consulted over the whole build: " + strings.Join(res.Partiality.Reasons, ", ")
	case res.AnalyzerMatched:
		return fmt.Sprintf("govulncheck's database matches %s against the build", req.VulnID), ""
	}
	return "", ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	const max = 200
	if r := []rune(s); len(r) > max {
		return string(r[:max]) + "…"
	}
	return s
}

// rangeDispute withdraws a version-axis disqualification that another source contradicts: an alias
// record of the same advisory, then the Go analyzer's own database. It returns the contradicting
// source, or, when the analyzer could not be consulted, a note the cleared row discloses.
func (s disqualificationDiscovery) rangeDispute(ctx context.Context, c *assessment.Assessment, store artifact.Store, buildDir, goWork string, axis versionAxis, rngs []affectedRange) (dispute, note string) {
	module, coordinate := disputedPackage(store, c.ID)
	src := s.src
	if src == nil {
		src = defaultAdvisorySource()
	}
	if d, ok := aliasRangeDispute(src, extractAliases(store, c.ID), module, coordinate, axis); ok {
		return d, ""
	}
	if s.plugin == nil || s.plugin.Language() != "go" || module == "" || toolchainSubject(admittedPackagePURL(store, c.ID), rngs) {
		return "", ""
	}
	return analyzerRangeDispute(ctx, s.plugin, plugin.ReachabilityRequest{
		BuildDir:         buildDir,
		GoWork:           goWork,
		VulnID:           govulnMatchID(store, c.ID, c.Request.Vulnerability.ID),
		GoToolchain:      requestedToolchain(s.subjectToolchain, store, c.ID),
		GoToolchainFloor: inventoryGoFloor(store, c.ID),
		Package:          admittedPackagePURL(store, c.ID),
	})
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
