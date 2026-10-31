package pythonanalysis

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- script installs ---------------------------------------------------------------
//
// A pip install a script surface runs (scriptRun) installs what its arguments name, read as
// the lines of a requirements file: each requirement, editable and URL argument is one line,
// and a -r file the walk does not already read as a manifest is read in place. Its packages
// join the inventory scoped to the surface, or to the -r file, so a build script that changes
// what it installs changes the inventory. A run whose arguments this cannot read names
// nothing, and the scan-level partiality says so.

// pipValueFlags are the pip install (and uv pip install) options that take the next argument
// as their value, so it is not read as a requirement.
var pipValueFlags = map[string]bool{
	"-c": true, "--constraint": true, "-t": true, "--target": true, "--platform": true,
	"--python-version": true, "--implementation": true, "--abi": true, "--root": true,
	"--prefix": true, "--src": true, "--upgrade-strategy": true, "-C": true,
	"--config-settings": true, "--global-option": true, "--no-binary": true, "--only-binary": true,
	"--progress-bar": true, "--root-user-action": true, "--report": true, "-i": true,
	"--index-url": true, "--extra-index-url": true, "-f": true, "--find-links": true,
	"--trusted-host": true, "--cert": true, "--client-cert": true, "--cache-dir": true,
	"--log": true, "--proxy": true, "--retries": true, "--timeout": true, "--exists-action": true,
	"--python": true, "-p": true, "--keyring-provider": true, "--use-feature": true,
	"--use-deprecated": true, "--group": true, "--index": true, "--default-index": true,
	"--index-strategy": true, "--extra": true, "--resolution": true, "--prerelease": true,
	"--override": true, "--exclude-newer": true, "--link-mode": true, "--python-platform": true,
}

// scriptInstallReqs returns, by scope, the requirements a pip install a script surface runs
// names. discovered holds the manifests the inventory already reads, whose packages a -r of
// one adds nothing to.
func scriptInstallReqs(root string, run scriptRun, discovered map[string]bool, env map[string]string, selection []string) map[string][]pyReq {
	out := map[string][]pyReq{}
	var lines []string
	for i := 0; i < len(run.args); i++ {
		a := run.args[i]
		switch {
		case (a == "-r" || a == "--requirement") && i+1 < len(run.args):
			i++
			scriptRequirementFile(root, run.surface, run.args[i], discovered, env, selection, out)
		case strings.HasPrefix(a, "--requirement="):
			scriptRequirementFile(root, run.surface, strings.TrimPrefix(a, "--requirement="), discovered, env, selection, out)
		case (a == "-e" || a == "--editable") && i+1 < len(run.args):
			i++
			lines = append(lines, "-e "+run.args[i])
		case strings.HasPrefix(a, "--editable="):
			lines = append(lines, "-e "+strings.TrimPrefix(a, "--editable="))
		case strings.HasPrefix(a, "-"):
			if pipValueFlags[a] {
				i++
			}
		default:
			lines = append(lines, a)
		}
	}
	if len(lines) > 0 {
		reqs := resolveRequirements([]byte(strings.Join(lines, "\n")+"\n"), env, selection)
		out[relScope(root, run.surface)] = append(out[relScope(root, run.surface)], reqs...)
	}
	return out
}

// scriptRequirementFile reads a -r file a script surface names, from the surface's directory
// or else the build root, into out under its own scope. A file that is not an in-tree regular
// file names nothing here: the run that names it is withheld, so the scan is partial.
func scriptRequirementFile(root, surface, p string, discovered map[string]bool, env map[string]string, selection []string, out map[string][]pyReq) {
	if filepath.IsAbs(p) {
		return
	}
	for _, dir := range []string{filepath.Dir(surface), root} {
		f := filepath.Join(dir, p)
		rel, err := filepath.Rel(root, f)
		if err != nil || !filepath.IsLocal(rel) {
			continue
		}
		data, err := readRegular(f)
		if err != nil {
			continue
		}
		if !discovered[f] {
			out[rel] = append(out[rel], resolveRequirements(data, env, selection)...)
		}
		return
	}
}

func relScope(root, p string) string {
	if rel, err := filepath.Rel(root, p); err == nil {
		return rel
	}
	return p
}

// scriptInventory returns the inventory nodes the pip installs script surfaces run name, with
// no ID the manifest nodes already hold, and whether a script surface may install a package
// none of them names.
func scriptInventory(req plugin.ResolveInventoryRequest, manifests []string, have map[string]bool) ([]plugin.DependencyNode, bool) {
	var runs []scriptRun
	_, _, withheld, _, _ := scanSurfaces(req.BuildDir, &runs)
	discovered := make(map[string]bool, len(manifests))
	for _, m := range manifests {
		discovered[m] = true
	}
	var nodes []plugin.DependencyNode
	for _, run := range runs {
		for scope, reqs := range scriptInstallReqs(req.BuildDir, run, discovered, req.TargetEnv, req.Selection) {
			for _, r := range reqs {
				if !r.Selected && !r.Unresolved {
					continue
				}
				// Two runs in one surface may install one name at two versions: each is a node.
				id := scope + "#" + r.Name
				for n := 2; have[id]; n++ {
					id = fmt.Sprintf("%s#%s#%d", scope, r.Name, n)
				}
				have[id] = true
				nodes = append(nodes, buildNode(id, r, req))
			}
		}
	}
	return nodes, withheld
}
