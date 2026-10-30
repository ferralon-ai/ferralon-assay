package goanalysis

import (
	"context"
	"os"
	"path/filepath"
	"strings"

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
// Those bounds hold only for a go command from Go 1.21 on; an older one does not
// enforce the `go` line. When the directives do not exclude such a go command (no
// `toolchain` line, and no three-part `go` line at 1.21.0 or later), the runtime
// also carries Resolved: the release the analyzer's go command resolves for the
// build directory under the build's environment (buildToolchain), an ambient
// observation that never establishes the build's release for the load.
//
// Partiality is declared, never overclaimed (inv.5): no go.mod (not a module) is
// Partial with no fabricated build command; replace/exclude directives that
// complicate the build degrade to Partial while still reporting what is known; a
// clean single-module go.mod is Complete. A missing build dir is a hard error
// (inv.4); a malformed go.mod surfaces as Partial (tool_failure), never a silent
// empty result.
func BuildManifest(ctx context.Context, req plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	ctx, err := withGoWork(ctx, req.GoWork)
	if err != nil {
		return plugin.BuildManifestResult{}, err
	}
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

	rt := plugin.RuntimeSpec{Name: "go", Source: plugin.RuntimeSourceDeclared}
	if mf.Go != nil {
		rt.Version = mf.Go.Version
	}
	if mf.Toolchain != nil {
		rt.Toolchain = mf.Toolchain.Name
	}
	if !directivesBindToolchain(rt.Version, rt.Toolchain) {
		rt.Resolved = buildToolchain(ctx, req.BuildDir)
	}
	res := plugin.BuildManifestResult{Runtimes: []plugin.RuntimeSpec{rt}}
	if mf.Module != nil {
		res.ProjectRoot = mf.Module.Mod.Path
	}

	// replace/exclude directives mean the on-disk module is not buildable with a
	// plain `go build ./...` in isolation — declare the gap rather than overclaim.
	complicated := len(mf.Replace) > 0 || len(mf.Exclude) > 0
	if res.ProjectRoot == "" || rt.Version == "" {
		complicated = true
	}

	if complicated {
		res.Partiality = plugin.Partial(plugin.PartialReasonToolFailure)
		return res, nil
	}

	res.Resolvers = []plugin.ResolverSpec{{Name: "go", Command: "go build ./...", Source: plugin.RuntimeSourceDeclared}}
	res.Partiality = plugin.Complete()
	return res, nil
}

// directivesBindToolchain reports whether go.mod's directives bound the toolchain that builds the
// module from below, which they do only when no go command before Go 1.21 can build it. A `toolchain`
// line does whatever it names: those go commands reject it as an unknown directive. So does a
// three-part `go` line at 1.21.0 or later ("1.21.0"), which they reject at parse. A two-part `go` line
// ("1.21") does not, whatever its version: those go commands do not enforce it. goVersion is the raw
// `go` directive, toolchain the `toolchain` name ("go1.21.3"). Kept in step with the pipeline's
// predicate of the same name.
func directivesBindToolchain(goVersion, toolchain string) bool {
	if toolchain != "" {
		return true
	}
	if strings.Count(goVersion, ".") != 2 {
		return false
	}
	r, ok := parseGoRelease("go" + goVersion)
	return ok && (r.major > 1 || r.minor >= 21)
}
