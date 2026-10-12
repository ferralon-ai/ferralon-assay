package cfamilyanalysis

import (
	"context"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// BuildManifest emits the C/C++ tree's build context (deriveBuildContext): one RuntimeSpec per
// distinct toolchain the compilation database uses, Source compile_db, or ambient compilers from
// a CMake cache; the detected generators as Resolvers. With neither a database nor a cache there
// are no Runtimes and the result declares no_manifest. No toolchain is fabricated (inv.5).
func BuildManifest(_ context.Context, req plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	bc, err := deriveBuildContext(req.BuildDir)
	if err != nil {
		return plugin.BuildManifestResult{}, err
	}
	return buildManifestResult(bc), nil
}

var runtimeSources = map[string]plugin.RuntimeSource{
	sourceDeclared:  plugin.RuntimeSourceDeclared,
	sourceAmbient:   plugin.RuntimeSourceAmbient,
	sourceCompileDB: plugin.RuntimeSourceCompileDB,
}

// buildManifestResult is the one place the lane's build context meets the plugin contract.
func buildManifestResult(bc buildContext) plugin.BuildManifestResult {
	res := plugin.BuildManifestResult{Partiality: bc.Partiality}
	for _, t := range bc.Runtimes {
		res.Runtimes = append(res.Runtimes, plugin.RuntimeSpec{
			Name:      t.Name,
			Toolchain: t.Toolchain,
			Source:    runtimeSources[t.Source],
			Target:    t.Target,
			Lang:      t.Lang,
			StdLevel:  t.StdLevel,
		})
	}
	for _, g := range bc.Resolvers {
		res.Resolvers = append(res.Resolvers, plugin.ResolverSpec{Name: g.Name, Command: g.Command, Source: plugin.RuntimeSourceDeclared})
	}
	return res
}
