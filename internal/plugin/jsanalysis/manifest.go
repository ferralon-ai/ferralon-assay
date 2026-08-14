package jsanalysis

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// packageJSON is the subset of package.json fields the manifest parse reads. Only
// name, engines.node, scripts.build, and the os/cpu platform-restriction arrays are
// consulted; everything else is ignored.
type packageJSON struct {
	Name    string            `json:"name"`
	Engines map[string]string `json:"engines"`
	Scripts map[string]string `json:"scripts"`
	OS      []string          `json:"os"`  // npm platform restriction: OS names ("linux", "darwin", "!win32")
	CPU     []string          `json:"cpu"` // npm platform restriction: CPU architectures ("x64", "arm64")
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
	// §4.6 target: the ecosystem-neutral target platform/architecture, sourced from
	// package.json's npm `os`/`cpu` platform-restriction arrays (the only declared,
	// statically readable target information a package.json carries). Left zero when
	// neither is present — never guessed from the analyzer's own host.
	//
	// §4.6 configuration is deliberately left zero: package.json has no build-profile /
	// configuration field, and reading the analyzer's own NODE_ENV would fabricate the
	// customer's build configuration with wrong provenance and defeat determinism.
	res.Target = platformTarget(pkg.OS, pkg.CPU)

	// A missing name means we cannot identify the package — declare the gap rather
	// than overclaim. A workspaces/monorepo layout NO LONGER declines here (PLAN-160
	// C4): detecting a monorepo in order to return Partial(tool_failure) was the
	// behaviour that criterion removes — the whole-graph resolver (ResolveInventory)
	// now speaks for per-member subgraphs, and `npm ci` at the root installs the
	// workspace, so a named root remains a Complete, buildable manifest.
	if res.ProjectRoot == "" {
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

// platformTarget renders package.json's npm `os`/`cpu` platform-restriction arrays as
// a neutral "os/cpu" target string (analogous to "linux/amd64"). Each side is sorted
// and comma-joined for a deterministic, byte-stable value regardless of declaration
// order. Returns "" when neither side is declared — the target is never inferred from
// the analyzer's host.
func platformTarget(oses, cpus []string) string {
	o := joinSorted(oses)
	c := joinSorted(cpus)
	switch {
	case o != "" && c != "":
		return o + "/" + c
	case o != "":
		return o
	default:
		return c
	}
}

// joinSorted returns the non-empty values of vs, sorted, de-duplicated, comma-joined.
// Target is a canonical build-context value, so repeated os/cpu entries must collapse
// to one (a package.json may declare a value more than once).
func joinSorted(vs []string) string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		if v != "" {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	uniq := out[:0]
	for _, v := range out {
		if len(uniq) == 0 || v != uniq[len(uniq)-1] {
			uniq = append(uniq, v)
		}
	}
	return strings.Join(uniq, ",")
}
