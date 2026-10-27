package dotnetanalysis

import (
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis/assembly"
)

// runtimeTarget is the restore graph a build runs. Restore writes a "<tfm>/<rid>" target
// beside the portable "<tfm>" one for each runtime the project names, and that graph can
// differ: a runtime.json adds packages only it lists, and can resolve a different version
// of a package the portable graph also has. A build produced for one of those runtimes
// runs the runtime target's packages, not the portable target's.
type runtimeTarget struct {
	// load is the assets target whose packages run ("" for an unbound build, which reads
	// every target and is never searched).
	load string
	// misses are runtime-target packages the portable graph lacks or resolves at another
	// version, when the build's runtime does not pick out which runtime target runs.
	misses []assembly.DepMiss
	// shadowed are load's package keys some runtime target resolves at another version:
	// their bytes may not be the ones that run, so they are not read in place of the miss.
	shadowed map[string]bool
	// absent are the "<tfm>/<rid>" targets the build's runtimes need and restore did not
	// write: what those graphs add or re-version is unknown, and nothing bounds it.
	absent []string
}

// resolveRuntimeTarget picks the restore target the build runs. When the build's runtime is
// known and restore wrote a target for it, that target runs. Otherwise every package a
// runtime target adds or re-versions is a named miss, never a silent skip: which of them
// run is unknown. A portable build that also restored runtime targets is treated the same
// way, since its outputs record no runtime to tell it from an unknown one. A runtime the
// build's outputs record (rids) with no target of its own is listed in absent.
func resolveRuntimeTarget(g *assetsGraph, target string, rt assembly.Runtime, rids []string, locator *assembly.AssetsLocator) runtimeTarget {
	out := runtimeTarget{load: target}
	if g == nil || target == "" {
		return out
	}
	for _, rid := range rids {
		if _, ok := g.targets[target+"/"+rid]; !ok {
			out.absent = append(out.absent, target+"/"+rid)
		}
	}
	var ridTargets []string
	for k := range g.targets {
		if strings.HasPrefix(k, target+"/") {
			ridTargets = append(ridTargets, k)
		}
	}
	if len(ridTargets) == 0 {
		return out
	}
	if !rt.Ambiguous && rt.RID != "" {
		if _, ok := g.targets[target+"/"+rt.RID]; ok {
			out.load = target + "/" + rt.RID
			return out
		}
	}
	reason := assembly.MissRIDUnknown
	if rt.Ambiguous {
		reason = assembly.MissRIDAmbiguous
	}
	portable := map[string]string{} // lower id -> portable package key
	for key, lib := range g.targets[target] {
		if strings.EqualFold(lib.Type, "project") {
			continue
		}
		id, _ := splitPkgKey(key)
		portable[strings.ToLower(id)] = key
	}
	sort.Strings(ridTargets)
	for _, ridKey := range ridTargets {
		keys := make([]string, 0, len(g.targets[ridKey]))
		for key := range g.targets[ridKey] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if strings.EqualFold(g.targets[ridKey][key].Type, "project") {
				continue
			}
			id, _ := splitPkgKey(key)
			plainKey, inPortable := portable[strings.ToLower(id)]
			if inPortable && strings.EqualFold(plainKey, key) {
				continue
			}
			if locator.HasNoAssemblies(ridKey, key) {
				continue // restore recorded no assembly for it: no code to read, so the portable bytes stay
			}
			if inPortable {
				if out.shadowed == nil {
					out.shadowed = map[string]bool{}
				}
				out.shadowed[plainKey] = true
			}
			out.misses = append(out.misses, assembly.DepMiss{
				Dep:    assembly.DepRef{Target: ridKey, PkgKey: key, Runtime: rt},
				Reason: reason,
			})
		}
	}
	return out
}
