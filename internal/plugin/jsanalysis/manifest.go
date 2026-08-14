package jsanalysis

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// packageJSON is the subset of package.json fields the manifest parse reads. Only
// name, engines.node, scripts.build, and workspaces are consulted; everything else
// is ignored.
type packageJSON struct {
	Name       string            `json:"name"`
	Engines    map[string]string `json:"engines"`
	Scripts    map[string]string `json:"scripts"`
	Workspaces json.RawMessage   `json:"workspaces"`
}

// lockfiles are the npm/yarn/pnpm lockfile names whose presence selects a
// reproducible install command (`npm ci`) over `npm install`.
var lockfiles = []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}

// BuildManifest parses the package.json in req.BuildDir into a minimal build
// manifest: module name, Node version (engines.node), and the install/build
// command. It is a single-package parse, not a build orchestrator.
//
// Partiality is declared, never overclaimed (inv.5): no package.json (not a
// package) is Partial with no fabricated command; a workspaces/monorepo layout or a
// missing name degrades to Partial while still reporting what is known; a clean
// single-package package.json is Complete. A missing build dir is a hard error
// (inv.4); malformed JSON surfaces as Partial (tool_failure), never a silent empty
// result.
func BuildManifest(_ context.Context, req plugin.BuildManifestRequest) (plugin.BuildManifestResult, error) {
	if fi, err := os.Stat(req.BuildDir); err != nil || !fi.IsDir() {
		return plugin.BuildManifestResult{}, err
	}

	pkgPath := filepath.Join(req.BuildDir, "package.json")
	data, err := os.ReadFile(pkgPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Not a package: declare the gap, do NOT fabricate a build command.
			return plugin.BuildManifestResult{
				Partiality: plugin.Partial(plugin.PartialReasonToolFailure),
			}, nil
		}
		return plugin.BuildManifestResult{}, err
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return plugin.BuildManifestResult{
			Partiality: plugin.Partial(plugin.PartialReasonToolFailure),
		}, nil
	}

	// ProjectRoot carries the package identity (pkg.Name); the declared Node engine
	// constraint (engines.node) goes to the ecosystem-neutral Runtime{Name:"node"}
	// descriptor — no longer overloaded onto the retired Go-named "go_version" field.
	res := plugin.BuildManifestResult{ProjectRoot: pkg.Name}
	if v := pkg.Engines["node"]; v != "" {
		res.Runtime = plugin.RuntimeSpec{Name: "node", Version: v}
	}

	// A workspaces/monorepo layout is not installable/buildable with a single
	// package-root command, and a missing name means we cannot identify the
	// package — declare the gap rather than overclaim.
	complicated := hasWorkspaces(pkg.Workspaces) || res.ProjectRoot == ""

	if complicated {
		res.Partiality = plugin.Partial(plugin.PartialReasonToolFailure)
		return res, nil
	}

	command := installCommand(req.BuildDir)
	if pkg.Scripts["build"] != "" {
		command += " && npm run build"
	}
	res.Resolver = plugin.ResolverSpec{Name: "npm", Command: command}
	res.Partiality = plugin.Complete()
	return res, nil
}

// installCommand selects `npm ci` when a lockfile is present (reproducible install)
// and `npm install` otherwise. It never fabricates a build step — the build script,
// if any, is appended by the caller.
func installCommand(dir string) string {
	for _, name := range lockfiles {
		if fi, err := os.Stat(filepath.Join(dir, name)); err == nil && !fi.IsDir() {
			return "npm ci"
		}
	}
	return "npm install"
}

// hasWorkspaces reports whether package.json declares a non-empty workspaces field
// (array form or object form), marking a monorepo the single-package parse cannot
// speak for. A null/absent/empty field is not a monorepo.
func hasWorkspaces(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		return len(arr) > 0
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return len(obj.Packages) > 0
	}
	return false
}
