package goanalysis

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/mod/modfile"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// BuildManifest parses the go.mod in req.BuildDir into a minimal build manifest:
// module path, Go version, the `toolchain` directive when present, and the build
// command (`go build ./...`). It is a single-module parse, not a build orchestrator.
//
// The two version directives are reported separately and neither is a pin: `go X.Y`
// is a minimum LANGUAGE version and `toolchain goX.Y.Z` a minimum TOOLCHAIN, and
// GOTOOLCHAIN=auto only ever switches UP from them. Ordering them into one fact
// about the subject's toolchain is the caller's job (pipeline.ToolchainFact).
//
// Partiality is declared, never overclaimed (inv.5): no go.mod (not a module) is
// Partial with no fabricated build command; replace/exclude directives that
// complicate the build degrade to Partial while still reporting what is known; a
// clean single-module go.mod is Complete. A missing build dir is a hard error
// (inv.4); a malformed go.mod surfaces as Partial (tool_failure), never a silent
// empty result.
func BuildManifest(_ context.Context, req plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	if fi, err := os.Stat(req.BuildDir); err != nil || !fi.IsDir() {
		return plugin.BuildManifestResult{}, err
	}

	modPath := filepath.Join(req.BuildDir, "go.mod")
	data, err := os.ReadFile(modPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Not a module: declare the gap, do NOT fabricate a build command.
			return plugin.BuildManifestResult{
				Partiality: plugin.Partial(plugin.PartialReasonToolFailure),
			}, nil
		}
		return plugin.BuildManifestResult{}, err
	}

	mf, err := modfile.Parse(modPath, data, nil)
	if err != nil {
		return plugin.BuildManifestResult{
			Partiality: plugin.Partial(plugin.PartialReasonToolFailure),
		}, nil
	}

	res := plugin.BuildManifestResult{}
	if mf.Module != nil {
		res.Module = mf.Module.Mod.Path
	}
	if mf.Go != nil {
		res.GoVersion = mf.Go.Version
	}
	if mf.Toolchain != nil {
		res.ToolchainVersion = mf.Toolchain.Name
	}

	// replace/exclude directives mean the on-disk module is not buildable with a
	// plain `go build ./...` in isolation — declare the gap rather than overclaim.
	complicated := len(mf.Replace) > 0 || len(mf.Exclude) > 0
	if res.Module == "" || res.GoVersion == "" {
		complicated = true
	}

	if complicated {
		res.Partiality = plugin.Partial(plugin.PartialReasonToolFailure)
		return res, nil
	}

	res.BuildCommand = "go build ./..."
	res.Partiality = plugin.Complete()
	return res, nil
}
