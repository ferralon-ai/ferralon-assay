package pythonanalysis

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// --- script installs ---------------------------------------------------------------
//
// A pip install a script surface runs (scriptRun) installs what its arguments name: each
// requirement argument is one requirements line, and each -r file the lane does not already
// read is read in place. Its packages join the inventory scoped to the surface, or to the -r
// file, so a build script that changes what it installs changes the inventory. An argument
// this cannot read as a package name (a path, a URL, an editable, an expansion the rule
// withholds on) names nothing.

// pipBoolFlags are the pip install (and uv pip install) long options that take no value. Any
// other long option without "=" is read as taking the next argument, so an option's value is
// never read as a requirement.
var pipBoolFlags = map[string]bool{
	"--break-system-packages": true, "--check-build-dependencies": true, "--compile": true,
	"--debug": true, "--disable-pip-version-check": true, "--dry-run": true,
	"--force-reinstall": true, "--ignore-requires-python": true, "--isolated": true,
	"--no-build-isolation": true, "--no-cache-dir": true, "--no-clean": true, "--no-color": true,
	"--no-compile": true, "--no-deps": true, "--no-index": true, "--no-input": true,
	"--no-warn-conflicts": true, "--no-warn-script-location": true, "--pre": true,
	"--prefer-binary": true, "--require-hashes": true, "--require-virtualenv": true,
	"--user": true, "--help": true, "--ignore-installed": true, "--quiet": true,
	"--upgrade": true, "--verbose": true, "--version": true, "--system": true,
	"--reinstall": true, "--strict": true, "--compile-bytecode": true, "--no-build": true,
	"--offline": true, "--refresh": true, "--native-tls": true, "--all-extras": true,
	"--no-sources": true, "--no-config": true, "--no-progress": true, "--exact": true,
}

// pipShortValueFlags are the short options that take a value, attached or as the next
// argument; -r's is a requirements file.
const pipShortValueFlags = "bcefiprtCP"

// pipArgs splits pip install's arguments into the -r files and the requirement arguments
// they name.
func pipArgs(args []string) (files, reqs []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, bool) {
			if i+1 < len(args) {
				i++
				return args[i], true
			}
			return "", false
		}
		switch {
		case a == "--requirement" || a == "--requirements":
			if v, ok := next(); ok {
				files = append(files, v)
			}
		case strings.HasPrefix(a, "--requirement=") || strings.HasPrefix(a, "--requirements="):
			files = append(files, a[strings.IndexByte(a, '=')+1:])
		case strings.HasPrefix(a, "--"):
			if !strings.Contains(a, "=") && !pipBoolFlags[a] && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
			}
		case strings.HasPrefix(a, "-") && len(a) > 1:
			for j := 1; j < len(a); j++ {
				if !strings.ContainsRune(pipShortValueFlags, rune(a[j])) {
					continue
				}
				v, ok := a[j+1:], j+1 < len(a)
				if !ok {
					v, ok = next()
				}
				if ok && a[j] == 'r' {
					files = append(files, v)
				}
				break
			}
		case pipRequirementArg(a):
			reqs = append(reqs, a)
		}
	}
	return files, reqs
}

// pipRequirementFiles returns the -r files pip install's arguments name.
func pipRequirementFiles(args []string) []string {
	files, _ := pipArgs(args)
	return files
}

// pipRequirementArg reports whether a, a pip install argument, names a package by name: not a
// local path, archive or URL, which installs from a source rather than the index.
func pipRequirementArg(a string) bool {
	if a == "" || !isASCIIAlnum(a[0]) || strings.ContainsAny(a, `/\:@`) {
		return false
	}
	lower := strings.ToLower(a)
	for _, ext := range []string{".whl", ".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar"} {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	return true
}

func isASCIIAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func relScope(root, p string) string {
	if rel, err := filepath.Rel(root, p); err == nil {
		return rel
	}
	return p
}

// scriptInventory returns the inventory nodes the pip installs script surfaces run name, with
// no ID the manifest nodes already hold. Each -r file is read once, and only when it resolves,
// through every symlink, inside the build.
func scriptInventory(req plugin.ResolveInventoryRequest, have map[string]bool) []plugin.DependencyNode {
	var runs []scriptRun
	scanSurfaces(req.BuildDir, &runs)
	realRoot, rootErr := filepath.EvalSymlinks(req.BuildDir)
	readFile := map[string]bool{}
	seen := map[string]bool{}
	var nodes []plugin.DependencyNode
	add := func(scope string, reqs []pyReq) {
		for _, r := range reqs {
			if !r.Selected && !r.Unresolved {
				continue
			}
			n := buildNode(scope+"#"+r.Name, r, req)
			if key := scope + " " + n.PURL; seen[key] {
				continue
			} else {
				seen[key] = true
			}
			// Two runs in one surface may install one name at two versions: each is a node.
			for i := 2; have[n.ID]; i++ {
				n.ID = fmt.Sprintf("%s#%s#%d", scope, r.Name, i)
			}
			have[n.ID] = true
			nodes = append(nodes, n)
		}
	}
	for _, run := range runs {
		if _, args := pipArgs(run.args); len(args) > 0 {
			add(relScope(req.BuildDir, run.surface), resolveRequirements([]byte(strings.Join(args, "\n")+"\n"), req.TargetEnv, req.Selection))
		}
		for _, f := range run.files {
			if readFile[f] || rootErr != nil || !buildtree.Inside(realRoot, f) {
				continue
			}
			readFile[f] = true
			if data, err := readRegular(f); err == nil {
				add(relScope(req.BuildDir, f), requirementFileReqs(f, data, req))
			}
		}
	}
	return nodes
}

// requirementFileReqs reads a -r file the way uv reads it by name: a pylock.toml (PEP 751) as
// a lock, another TOML, setup.cfg or setup.py as project metadata this does not read (it names
// nothing), and any other file as requirements lines.
func requirementFileReqs(path string, data []byte, req plugin.ResolveInventoryRequest) []pyReq {
	lower := strings.ToLower(filepath.Base(path))
	switch ext := filepath.Ext(lower); {
	case lower == "pylock.toml" || strings.HasPrefix(lower, "pylock.") && ext == ".toml":
		return parsePyLockTOML(data, req.TargetEnv, req.Selection)
	case ext == ".toml", ext == ".cfg", ext == ".py":
		return nil
	}
	return resolveRequirements(data, req.TargetEnv, req.Selection)
}

type pyLockTOML struct {
	Packages []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
		Marker  string `toml:"marker"`
	} `toml:"packages"`
}

// parsePyLockTOML returns each package a PEP 751 lock records, its marker evaluated against
// the declared environment. A lock that does not decode names nothing.
func parsePyLockTOML(data []byte, env map[string]string, selection []string) []pyReq {
	var lock pyLockTOML
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil
	}
	var out []pyReq
	for _, p := range lock.Packages {
		name := normalizePyCoordinate(p.Name)
		if name == "" {
			continue
		}
		v := strings.TrimSpace(p.Version)
		r := pyReq{Name: name, Version: v, Resolved: v != "", Source: "pylock.toml", Kind: reqNormal, Marker: strings.TrimSpace(p.Marker)}
		applyMarker(&r, env, selection)
		out = append(out, r)
	}
	return out
}
