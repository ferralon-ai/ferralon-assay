package javaanalysis

import (
	"slices"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// withUnlistedInstall adds to part the limit of an inventory that omits what g's modules install
// unlisted (PartialReasonUnlistedInstall). When every unlisted install names the coordinates it
// installs (buildgraph.Module.UnlistedTargets), the limit is bounded to them, one scoped limit per
// module: the inventory misses those packages and no other. Any install that names none leaves the
// limit unbounded, as it holds for every package.
func withUnlistedInstall(g *buildgraph.Graph, part plugin.Partiality) plugin.Partiality {
	if !unlisted(g) {
		return part
	}
	unbounded := plugin.Partiality{Reasons: append(slices.Clone(part.Reasons), PartialReasonUnlistedInstall), Scoped: part.Scoped}
	var scoped []plugin.ScopedReason
	for _, m := range g.Modules {
		var targets []string
		for _, u := range m.Unlisted {
			coords := m.UnlistedTargets[u]
			if len(coords) == 0 {
				return unbounded
			}
			for _, c := range coords {
				purl := mavenPURLNoVersion(c)
				if purl == "" {
					return unbounded
				}
				targets = append(targets, purl)
			}
		}
		if len(targets) > 0 {
			slices.Sort(targets)
			scoped = append(scoped, plugin.ScopedReason{Reason: PartialReasonUnlistedInstall, Path: m.Path, Targets: slices.Compact(targets)})
		}
	}
	return plugin.Partiality{Reasons: part.Reasons, Scoped: append(slices.Clone(part.Scoped), scoped...)}
}
