package pythonanalysis

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
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
	"--use-pep517": true, "--no-use-pep517": true, "--verify-hashes": true, "--no-verify-hashes": true,
	"--no-cache": true,
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
		case a == "--":
			for _, a := range args[i+1:] {
				if pipRequirementArg(a) {
					reqs = append(reqs, a)
				}
			}
			return files, reqs
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

// pipArchiveExts are the archive suffixes pip installs a local file from.
var pipArchiveExts = []string{".whl", ".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tbz2",
	".tar.xz", ".txz", ".tar.lz", ".tlz", ".tar.lzma"}

// pipRequirementArg reports whether a, a pip install argument, names a package by name: not a
// local path, archive or URL, which installs from a source rather than the index, nor a name
// that is a glob the shell expands to paths (a wildcard version, ==4.*, is a requirement).
func pipRequirementArg(a string) bool {
	name := a
	if i := strings.IndexAny(a, "=<>!~;[ "); i >= 0 {
		name = a[:i]
	}
	if a == "" || !isASCIIAlnum(a[0]) || strings.ContainsAny(a, `/\:@`) || strings.ContainsAny(name, "*?") {
		return false
	}
	lower := strings.ToLower(a)
	for _, ext := range pipArchiveExts {
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
				add(relScope(req.BuildDir, f), requirementFileReqs(f, data, run, req))
			}
		}
	}
	return nodes
}

// requirementFileReqs reads a -r file the way the installer running it reads it by name: uv
// reads a pylock.toml (PEP 751) as a lock, which pip cannot install from, and another TOML,
// setup.cfg or setup.py as project metadata this does not read. Those name nothing; any other
// file is requirements lines.
func requirementFileReqs(path string, data []byte, run scriptRun, req plugin.ResolveInventoryRequest) []pyReq {
	lower := strings.ToLower(filepath.Base(path))
	switch ext := filepath.Ext(lower); {
	case lower == "pylock.toml" || strings.HasPrefix(lower, "pylock.") && ext == ".toml":
		if !run.uv {
			return nil
		}
		return parsePyLockTOML(data, run.args, req.TargetEnv, req.Selection)
	case ext == ".toml", ext == ".cfg", ext == ".py":
		return nil
	}
	return resolveRequirements(data, req.TargetEnv, req.Selection)
}

type pyLockTOML struct {
	Extras        []string `toml:"extras"`
	DefaultGroups []string `toml:"default-groups"`
	Groups        []string `toml:"dependency-groups"`
	Packages      []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
		Marker  string `toml:"marker"`
		VCS     *struct {
			URL string `toml:"url"`
		} `toml:"vcs"`
		Directory *struct {
			Path     string `toml:"path"`
			Editable bool   `toml:"editable"`
		} `toml:"directory"`
		Archive *struct {
			URL  string `toml:"url"`
			Path string `toml:"path"`
		} `toml:"archive"`
	} `toml:"packages"`
}

// parsePyLockTOML returns each package a PEP 751 lock records, its marker evaluated against
// the declared environment and the extras and dependency groups uv pip install's arguments
// select (pyLockSelection). An editable directory is the project itself and is not a node; a
// package from a VCS, a directory or an archive is unpinned (source_unpinned), as in a
// requirements file. A lock that does not decode names nothing.
func parsePyLockTOML(data []byte, args []string, env map[string]string, selection []string) []pyReq {
	var lock pyLockTOML
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil
	}
	env = pyLockSelection(lock, args, env)
	var out []pyReq
	for _, p := range lock.Packages {
		name := normalizePyCoordinate(p.Name)
		if name == "" || p.Directory != nil && p.Directory.Editable {
			continue
		}
		v := strings.TrimSpace(p.Version)
		r := pyReq{Name: name, Version: v, Resolved: v != "", Source: "pylock.toml", Kind: reqNormal, Marker: strings.TrimSpace(p.Marker)}
		switch {
		case p.VCS != nil:
			r.Kind, r.Raw = reqVCS, p.VCS.URL
		case p.Directory != nil:
			r.Kind, r.Raw = reqURL, p.Directory.Path
		case p.Archive != nil:
			r.Kind, r.Raw = reqURL, p.Archive.URL+p.Archive.Path
		}
		if r.Kind != reqNormal {
			r.Version, r.Resolved = "", false
			r.Partial = []string{plugin.PartialReasonSourceUnpinned}
		}
		applyMarker(&r, env, selection)
		out = append(out, r)
	}
	return out
}

// pyLockSelection is env with PEP 751's extras and dependency_groups marker variables bound to
// what uv pip install's arguments select from lock: the --extra names (every extra with
// --all-extras, none without), and the --group names with the lock's default groups. An
// argument this does not read as a selection (another group option, a group from a named
// file) leaves the variable unbound, so a marker naming it stays unresolved.
func pyLockSelection(lock pyLockTOML, args []string, env map[string]string) map[string]string {
	extras, groups := []string{}, slices.Clone(lock.DefaultGroups)
	extrasOK, groupsOK := true, true
	for i := 0; i < len(args); i++ {
		flag, v, attached := strings.Cut(args[i], "=")
		if !attached && (flag == "--extra" || flag == "--group") && i+1 < len(args) {
			i++
			v = args[i]
		}
		switch {
		case flag == "--extra":
			extras = append(extras, v)
		case flag == "--all-extras":
			extras = append(extras, lock.Extras...)
		case !strings.HasPrefix(flag, "--") || flag == "--extra-index-url":
		case strings.Contains(flag, "extra"):
			extrasOK = false
		case flag == "--group" && !strings.Contains(v, ":"):
			groups = append(groups, v)
		case strings.Contains(flag, "group"):
			groupsOK = false
		}
	}
	out := maps.Clone(env)
	if out == nil {
		out = map[string]string{}
	}
	bind := func(name string, ok bool, values []string) {
		if !ok {
			return
		}
		for i, v := range values {
			values[i] = normalizePyCoordinate(v)
		}
		out[name] = strings.Join(values, "\n")
	}
	bind("extras", extrasOK, extras)
	bind("dependency_groups", groupsOK, groups)
	return out
}
