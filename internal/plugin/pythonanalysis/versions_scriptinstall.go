package pythonanalysis

import (
	"errors"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/scriptsurface"
)

// --- script installs: Python forms --------------------------------------------------
//
// A build can install a Python package with a command in a Dockerfile, a shell script, a
// Makefile, a CI or platform file or a package.json script, at a version no manifest read here
// records. Version resolution therefore withholds every pin (Resolved=false for the whole
// build, since a named install also pulls its own dependencies) when a script surface runs a
// Python installer in any form other than the few that install exactly what a manifest or lock
// read here says:
//
//	pip install -r <file>          <file> a literal path, from the command's directory, to a
//	                               requirements file read here; pip may be pipN, pipN.M or
//	                               pythonN.M -m pip, and -r may repeat
//	uv sync --locked | --frozen    --locked refuses a lock pyproject.toml has moved past;
//	                               --frozen installs the lock as written
//	poetry install                 refuses a lock pyproject.toml has moved past
//	pdm sync                       installs the lock as written, where no pre_invoke,
//	                               pre_install or post_install hook in tool.pdm.scripts
//	                               runs around it
//	pipenv install --deploy        refuses a Pipfile.lock the Pipfile has moved past
//	pipenv sync                    installs Pipfile.lock as written
//	poetry|pdm|pipenv run <argv>   run without syncing; <argv> passes the same gate, and pdm
//	                               and pipenv run only where no script table can name <argv>
//
// with only --no-cache-dir, --user and -q added (and, to pip, --no-deps and --require-hashes,
// which only narrow what it installs), and with the manifest each binds to (the
// nearest pyproject.toml or Pipfile at or above the command's directory) and the lock it
// installs (the nearest at or above that) read here; and, for uv sync, poetry install and pdm
// sync, with a root project, and every local source the lock names, whose build runs no code
// from the tree and loads no plugin (rootBuildClean). Anything
// else that names an installer withholds: a package argument, another flag, pipx, uvx, uv run
// (it syncs), a bare uv sync or pdm install (both re-lock), conda, mamba, easy_install, and
// every other tool laneToken names, run wrappers whose argv names one included. A
// PIP_*, UV_* or PDM_* variable set in any script surface withholds, since every pip, uv or pdm
// the build runs reads it, unless laneEnvKeeps keeps it. How a surface is read, and what binds
// a command to a file, is lane-neutral, in scriptsurface.
//
// One more pip form installs nothing but pip itself, so it withholds the pip coordinate alone
// (pipSelfUpgrade):
//
//	pip install [flags] pip[<specifier>]   the one target pip, bare or with a version
//	                                       specifier and no extras, marker, URL or path; the
//	                                       flags only from selfUpgradeFlags
//
// No published pip release declares a dependency outside its testing extra, so the target
// installs pip and nothing else. That holds for the distribution PyPI serves: an index,
// extra index or find-links location may serve a different one, so a flag naming one is not
// in selfUpgradeFlags and the command withholds every pin. pip reads every install option
// from its config files as well, and a build can COPY a pip.conf or pip.ini from the tree to
// where pip reads one, so a tree that holds either allows no self-upgrade (pipConfigInTree).
// pip reads a config where it lands, not by the name it had in the tree, and a build can also
// fetch or mount one, so a script surface that names a pip config path, PIP_CONFIG_FILE or
// pip config allows none either (pipConfigNamedRE). A config the base image already holds is
// not observed, as for hash-checking mode (pipConfigMatches).
// A PIP_* variable falls under the lane-wide rule above. setuptools and wheel are not
// targets: wheel requires packaging.

// newScriptSpec is the Python lane's part of the rule, recording into installs every pip
// install -r it allows, and into tooling the distribution each allowed self-upgrade installs:
// a caller that allows a self-upgrade must withhold what tooling names. A nil tooling allows
// no self-upgrade.
func newScriptSpec(installs pipInstalls, tooling map[string]bool) scriptsurface.Spec {
	return scriptsurface.Spec{
		Token:    laneToken,
		Env:      laneEnvRE,
		EnvKeeps: laneEnvKeeps,
		Allowed: func(words []string, b scriptsurface.Binder) bool {
			return installs.allowed(words, b, tooling)
		},
		RunWrapper:  laneRunWrapper,
		RunBinds:    laneRunBinds,
		ReadRegular: readRegular,
		Absent:      absent,
	}
}

// pipInstall is how one allowed pip install -r installs a requirements file.
type pipInstall struct {
	noDeps        bool // --no-deps: only the requirements the files list
	requireHashes bool // --require-hashes: hash-checking mode
}

// pipInstalls records, by build-tree path, every allowed pip install -r of a requirements file
// the script surfaces run. A nil pipInstalls records nothing.
type pipInstalls map[string][]pipInstall

// laneEnvRE matches a PIP_*, UV_* or PDM_* name that is not a $, ${ or attribute reference, so is
// being set.
var laneEnvRE = regexp.MustCompile(`(?:^|[^$A-Za-z0-9_{.])(?:PIP|UV|PDM)_[A-Z0-9_]+`)

// laneEnvKeeps reports whether name, which laneEnvRE matched, installs nothing a lock read here
// does not record: PDM_CHECK_UPDATE only turns pdm's own update check off, and
// PDM_BUILD_SCM_VERSION only sets the version pdm-backend gives the project it builds.
func laneEnvKeeps(name string) bool {
	return name == "PDM_CHECK_UPDATE" || name == "PDM_BUILD_SCM_VERSION"
}

// laneToken reports whether word is a Python installer: uv, uvx, poetry, pdm, easy_install,
// mamba, micromamba, pixi, rye, hatch, flit, setup.py (install and develop fetch
// install_requires), any word starting pip or conda, and an interpreter option that runs one
// as a module with its name attached (-mpip, -Impip); or a task runner that runs commands a
// file not read here defines, or installs into the environments it makes (poe and its module
// poethepoet, invoke and its inv, tox). nox is not one: every noxfile imports it, and the noxfile.py it runs is a
// candidate whenever a session installs.
func laneToken(word string) bool {
	switch word {
	case "uv", "uvx", "poetry", "pdm", "easy_install", "mamba", "micromamba", "pixi", "rye",
		"hatch", "flit", "setup.py", "poe", "poethepoet", "invoke", "inv", "tox":
		return true
	}
	if m := attachedModuleRE.FindStringSubmatch(word); m != nil && laneToken(m[1]) {
		return true
	}
	return strings.HasPrefix(word, "pip") || strings.HasPrefix(word, "conda")
}

// attachedModuleRE matches a cluster of interpreter short options ending in -m with the
// module name attached, which CPython reads as -m <name>.
var attachedModuleRE = regexp.MustCompile(`^-[A-Za-z]*m(.+)$`)

var (
	pipHeadRE    = regexp.MustCompile(`^pip(?:\d+(?:\.\d+)?)?$`)
	pythonHeadRE = regexp.MustCompile(`^python(?:\d+(?:\.\d+)?)?$`)
)

// selfUpgradeFlags are the flags a pip self-upgrade may carry: none changes what pip installs
// or where it finds it.
var selfUpgradeFlags = map[string]bool{
	"-U": true, "--upgrade": true, "-q": true, "--quiet": true, "--no-cache-dir": true,
	"--disable-pip-version-check": true, "--user": true, "--no-warn-script-location": true,
	"--root-user-action=ignore": true,
}

// pipTargetRE matches the requirement pip, bare or with a PEP 440 version specifier.
var pipTargetRE = regexp.MustCompile(`^[Pp][Ii][Pp](?:(?:===|==|~=|!=|<=|>=|<|>)[0-9][0-9A-Za-z.*+!_-]*(?:,(?:===|==|~=|!=|<=|>=|<|>)[0-9][0-9A-Za-z.*+!_-]*)*)?$`)

// pipSelfUpgrade reports whether pip install's arguments, after install, are flags from
// selfUpgradeFlags and the one target pip.
func pipSelfUpgrade(args []string) bool {
	targets := 0
	for _, a := range args {
		switch {
		case selfUpgradeFlags[a]:
		case pipTargetRE.MatchString(a):
			targets++
		default:
			return false
		}
	}
	return targets == 1
}

// pipConfigNamedRE matches, in a script surface's text, a pip config file or directory
// (pip.conf, pip.ini, /etc/pip..., /etc/xdg/pip, .config/pip), PIP_CONFIG_FILE, or a pip
// config subcommand.
var pipConfigNamedRE = regexp.MustCompile(`(?i)pip\.conf|pip\.ini|pip_config_file|\bpip[0-9.]*\s+config\b|/etc/xdg/pip|\.config/pip|/etc/pip`)

// laneFlags are the flags every allowed form may carry.
var laneFlags = map[string]bool{"--no-cache-dir": true, "--user": true, "-q": true}

// laneRunWrapper returns the command a run wrapper runs, and whether words is one.
func laneRunWrapper(words []string) ([]string, bool) {
	if len(words) < 2 || words[1] != "run" {
		return nil, false
	}
	switch head, _ := scriptsurface.CommandName(words[0]); head {
	case "poetry", "pdm", "pipenv":
		return words[2:], true
	}
	return nil, false
}

// pdmSyncNoHooks reports whether pyprojects, the manifests a pdm sync binds to, are there and
// name no pre_invoke, pre_install or post_install script, which pdm sync runs around the
// install. A manifest this cannot decode names one.
func pdmSyncNoHooks(pyprojects []string) bool {
	if len(pyprojects) == 0 {
		return false
	}
	for _, m := range pyprojects {
		data, err := readRegular(m)
		if err != nil {
			return false
		}
		scripts, err := pdmScripts(data)
		if err != nil {
			return false
		}
		for _, hook := range []string{"pre_invoke", "pre_install", "post_install"} {
			if _, ok := scripts[hook]; ok {
				return false
			}
		}
	}
	return true
}

// pdmScripts decodes a pyproject.toml's tool.pdm.scripts table, failing when it is there but
// not a table.
func pdmScripts(data []byte) (map[string]any, error) {
	var doc struct {
		Tool struct {
			PDM struct {
				Scripts any `toml:"scripts"`
			} `toml:"pdm"`
		} `toml:"tool"`
	}
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return nil, err
	}
	switch scripts := doc.Tool.PDM.Scripts.(type) {
	case nil:
		return nil, nil
	case map[string]any:
		return scripts, nil
	}
	return nil, errors.New("tool.pdm.scripts is not a table")
}

// rootProject is what rootBuildClean reads from a pyproject.toml.
type rootProject struct {
	BuildSystem *struct {
		Backend     string `toml:"build-backend"`
		BackendPath any    `toml:"backend-path"`
	} `toml:"build-system"`
	Project *struct {
		Dynamic []string `toml:"dynamic"`
	} `toml:"project"`
	Tool struct {
		Poetry struct {
			Build           any `toml:"build"`
			RequiresPlugins any `toml:"requires-plugins"`
		} `toml:"poetry"`
		Setuptools struct {
			Cmdclass any            `toml:"cmdclass"`
			Dynamic  map[string]any `toml:"dynamic"`
		} `toml:"setuptools"`
		PDM struct {
			PackageType  *string `toml:"package-type"`
			Distribution *bool   `toml:"distribution"`
			Build        struct {
				CustomHook    any `toml:"custom-hook"`
				RunSetuptools any `toml:"run-setuptools"`
			} `toml:"build"`
			Version struct {
				Source        any `toml:"source"`
				VersionFormat any `toml:"version_format"`
			} `toml:"version"`
			Workspace any `toml:"workspace"`
		} `toml:"pdm"`
		Hatch map[string]any `toml:"hatch"`
		UV    struct {
			Package   *bool `toml:"package"`
			Workspace any   `toml:"workspace"`
		} `toml:"uv"`
	} `toml:"tool"`
}

// rootBuildClean reports whether tool's allowed install (poetry, pdm or uv) of the root
// project its nearest pyproject.toml declares runs no code from the tree, and loads no
// plugin, that could install a package the lock does not name. A manifest this cannot decode
// fails.
//
// poetry installs the root with a builder of its own, not the PEP 517 backend, and the only
// tree code that runs is a tool.poetry.build script. Any poetry command loads plugins from a
// .poetry/plugins directory beside the manifest, and poetry install installs
// tool.poetry.requires-plugins there from the index. pdm loads plugins from a .pdm-plugins
// directory there (releases before 2.27; the release a build runs is not known here). pdm
// builds the root through its PEP 517 backend when tool.pdm.package-type is "library" or,
// with none, unless tool.pdm.distribution is false; uv does when tool.uv.package is true or,
// with none, when the manifest has a build-system table. That build is clean only for a
// backend that runs nothing from the tree but what tool tables or files named here ask it to
// (backendClean). Every local source the lock names, a uv workspace member included, must
// build clean as well (localBuildsClean).
func rootBuildClean(tool string, b scriptsurface.Binder) bool {
	pyprojects := b.Nearest("pyproject.toml")
	if pyprojects == nil {
		return false
	}
	for _, m := range pyprojects {
		data, err := readRegular(m)
		if err != nil {
			return false
		}
		var doc rootProject
		if _, err := toml.Decode(string(data), &doc); err != nil {
			return false
		}
		switch tool {
		case "poetry":
			if doc.Tool.Poetry.Build != nil || doc.Tool.Poetry.RequiresPlugins != nil || !b.Clear("pyproject.toml", ".poetry/plugins") {
				return false
			}
		case "pdm":
			if !b.Clear("pyproject.toml", ".pdm-plugins") {
				return false
			}
			builds := doc.Tool.PDM.Distribution == nil || *doc.Tool.PDM.Distribution
			if t := doc.Tool.PDM.PackageType; t != nil {
				builds = *t == "library"
			}
			if builds && !backendClean(doc, b, "") {
				return false
			}
		case "uv":
			if uvBuilds(doc) && !backendClean(doc, b, "") {
				return false
			}
		default:
			return false
		}
	}
	return localBuildsClean(tool, b)
}

// uvBuilds reports whether uv builds the project a manifest declares: when tool.uv.package is
// true or, with none, when the manifest has a build-system table.
func uvBuilds(doc rootProject) bool {
	if p := doc.Tool.UV.Package; p != nil {
		return *p
	}
	return doc.BuildSystem != nil
}

// toolLocks names the lock each allowed install reads.
var toolLocks = map[string]string{"uv": "uv.lock", "poetry": "poetry.lock", "pdm": "pdm.lock"}

// localBuildsClean reports whether every local directory or file the lock beside the nearest
// pyproject.toml names (a path dependency, or a uv workspace member) builds, when tool builds
// it, through a backend that runs no code from the tree (backendClean). uv builds an editable
// or directory source, and a virtual one whose own manifest asks to be built (uvBuilds); poetry
// and pdm build every directory source. A local file is clean only as a wheel, which installs
// without a build. A path this cannot resolve to a manifest read here fails: one outside the
// build or written with a variable, a lock that is not beside the manifest (uv then installs
// the workspace that lock is for), or a source of a kind this does not know.
func localBuildsClean(tool string, b scriptsurface.Binder) bool {
	if !standalone(tool, b) {
		return false
	}
	locks := b.Beside("pyproject.toml", toolLocks[tool])
	if locks == nil {
		return false
	}
	for _, l := range locks {
		data, err := readRegular(l)
		if err != nil {
			return false
		}
		srcs, ok := localSources(tool, data)
		if !ok {
			return false
		}
		for _, src := range srcs {
			if !localBuildClean(tool, src, b) {
				return false
			}
		}
	}
	return true
}

// standalone reports whether no pyproject.toml above the nearest one declares a uv or pdm
// workspace. uv or pdm run inside a workspace member installs from the workspace's lock, not
// the one beside the member's manifest.
func standalone(tool string, b scriptsurface.Binder) bool {
	if tool == "poetry" {
		return true
	}
	above, ok := b.Enclosing("pyproject.toml")
	if !ok {
		return false
	}
	for _, m := range above {
		data, err := readRegular(m)
		if err != nil {
			return false
		}
		var doc rootProject
		if _, err := toml.Decode(string(data), &doc); err != nil ||
			tool == "uv" && doc.Tool.UV.Workspace != nil || tool == "pdm" && doc.Tool.PDM.Workspace != nil {
			return false
		}
	}
	return true
}

// localSource is a local directory or file a lock names, as written there.
type localSource struct {
	path    string
	file    bool // an archive, not a directory
	virtual bool // a uv source uv installs without building unless its manifest asks
}

// localSources returns the local sources a lock names. ok is false for a lock this cannot
// decode, or a package source of a kind it does not know.
func localSources(tool string, data []byte) ([]localSource, bool) {
	var lock struct {
		Package []map[string]any `toml:"package"`
	}
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil, false
	}
	var srcs []localSource
	for _, pkg := range lock.Package {
		switch tool {
		case "uv":
			src, ok := pkg["source"].(map[string]any)
			if !ok {
				return nil, false
			}
			// A remote source may carry other keys (a git subdirectory); a local one is its
			// path alone.
			var kinds []string
			for _, k := range []string{"registry", "git", "url", "editable", "directory", "virtual", "path"} {
				if _, ok := src[k]; ok {
					kinds = append(kinds, k)
				}
			}
			if len(kinds) != 1 {
				return nil, false
			}
			kind := kinds[0]
			if kind == "registry" || kind == "git" || kind == "url" {
				continue
			}
			p, ok := src[kind].(string)
			if !ok || len(src) != 1 {
				return nil, false
			}
			srcs = append(srcs, localSource{path: p, file: kind == "path", virtual: kind == "virtual"})
		case "poetry":
			src, ok := pkg["source"]
			if !ok {
				continue
			}
			t, ok := src.(map[string]any)
			if !ok {
				return nil, false
			}
			kind, _ := t["type"].(string)
			url, _ := t["url"].(string)
			switch kind {
			case "legacy", "git", "url":
			case "directory":
				srcs = append(srcs, localSource{path: url})
			case "file":
				srcs = append(srcs, localSource{path: url, file: true})
			default:
				return nil, false
			}
		case "pdm":
			if u, ok := pkg["url"].(string); ok && !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
				return nil, false
			}
			v, ok := pkg["path"]
			if !ok {
				continue
			}
			p, ok := v.(string)
			if !ok {
				return nil, false
			}
			if sub, there := pkg["subdirectory"]; there {
				s, ok := sub.(string)
				if !ok || isArchive(p) {
					return nil, false
				}
				p += "/" + s
			}
			srcs = append(srcs, localSource{path: p, file: isArchive(p)})
		default:
			return nil, false
		}
	}
	return srcs, true
}

// isArchive reports whether a pdm path names a wheel or source archive rather than a directory.
func isArchive(p string) bool {
	l := strings.ToLower(p)
	for _, ext := range []string{".whl", ".tar.gz", ".zip", ".tar.bz2", ".tgz"} {
		if strings.HasSuffix(l, ext) {
			return true
		}
	}
	return false
}

// localBuildClean reports whether tool's build of one local source runs no code from the tree.
// The project itself (".") is rootBuildClean's for uv; poetry and pdm never lock it, so for
// them a source there is a dependency built through the backend like any other.
func localBuildClean(tool string, src localSource, b scriptsurface.Binder) bool {
	p := strings.TrimSuffix(filepath.ToSlash(src.path), "/")
	if src.file {
		return strings.HasSuffix(strings.ToLower(p), ".whl")
	}
	if p == "." {
		return tool == "uv"
	}
	m := b.Beside("pyproject.toml", p+"/pyproject.toml")
	if m == nil {
		return false
	}
	for _, f := range m {
		data, err := readRegular(f)
		if err != nil {
			return false
		}
		var doc rootProject
		if _, err := toml.Decode(string(data), &doc); err != nil {
			return false
		}
		if src.virtual && !uvBuilds(doc) {
			continue
		}
		if !backendClean(doc, b, p) {
			return false
		}
	}
	return true
}

// backendClean reports whether the PEP 517 backend a manifest names runs no code from the
// tree when it builds the project: setuptools (also the backend when none is named) with no
// setup.py or setup.cfg beside the manifest, either of which can name command classes in the
// tree, no tool.setuptools.cmdclass, and no tool.setuptools.dynamic attr, which setuptools
// imports when it cannot read the value statically; pdm-backend with no pdm_build.py, no
// custom-hook or run-setuptools, and a version source of file or scm with no version_format,
// since a call source or a version_format calls a function in the tree; hatchling with no
// hooks table anywhere in tool.hatch, a version source of regex or none (the code source runs
// a file), and no hatch_build.py or hatch.toml, which hatchling merges into tool.hatch;
// poetry-core with no tool.poetry.build; flit_core with a project table whose dynamic names
// neither version nor description, which flit imports the module for when it cannot read them
// statically; or uv_build. A backend-path, which loads the backend itself from the tree, or
// any other backend fails.
func backendClean(doc rootProject, b scriptsurface.Binder, dir string) bool {
	clear := func(f string) bool {
		if dir != "" {
			f = dir + "/" + f
		}
		return b.Clear("pyproject.toml", f)
	}
	backend := ""
	if bs := doc.BuildSystem; bs != nil {
		if bs.BackendPath != nil {
			return false
		}
		backend = strings.TrimSpace(bs.Backend)
	}
	switch backend {
	case "", "setuptools.build_meta", "setuptools.build_meta:__legacy__":
		return doc.Tool.Setuptools.Cmdclass == nil && !hasKey(doc.Tool.Setuptools.Dynamic, "attr") &&
			clear("setup.py") && clear("setup.cfg")
	case "pdm.backend":
		v := doc.Tool.PDM.Version
		return doc.Tool.PDM.Build.CustomHook == nil && doc.Tool.PDM.Build.RunSetuptools == nil &&
			(v.Source == nil || v.Source == "file" || v.Source == "scm") && v.VersionFormat == nil && clear("pdm_build.py")
	case "hatchling.build":
		return !hasKey(doc.Tool.Hatch, "hooks") && hatchVersionStatic(doc.Tool.Hatch["version"]) &&
			clear("hatch_build.py") && clear("hatch.toml")
	case "poetry.core.masonry.api":
		return doc.Tool.Poetry.Build == nil
	case "flit_core.buildapi":
		return doc.Project != nil && !slices.Contains(doc.Project.Dynamic, "version") && !slices.Contains(doc.Project.Dynamic, "description")
	case "uv_build":
		return true
	}
	return false
}

// hatchVersionStatic reports whether a tool.hatch.version table, if there is one, reads the
// version with hatchling's regex source rather than running code.
func hatchVersionStatic(v any) bool {
	if v == nil {
		return true
	}
	t, ok := v.(map[string]any)
	if !ok {
		return false
	}
	src, there := t["source"]
	return !there || src == "regex"
}

// hasKey reports whether key names a table or value anywhere in v.
func hasKey(v any, key string) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, sub := range t {
			if k == key || hasKey(sub, key) {
				return true
			}
		}
	case []map[string]any:
		for _, sub := range t {
			if hasKey(sub, key) {
				return true
			}
		}
	case []any:
		for _, sub := range t {
			if hasKey(sub, key) {
				return true
			}
		}
	}
	return false
}

// laneRunBinds reports whether a run wrapper's argv is the command it runs rather than a
// script a manifest names: pdm run and pipenv run look a name up in pyproject.toml's
// tool.pdm.scripts and a Pipfile's scripts table first, pdm runs that table's pre_run and
// post_run hooks around any command, and those values are not read here. So any entry in the
// table, or a manifest this cannot decode, withholds.
func laneRunBinds(words []string, b scriptsurface.Binder) bool {
	var name string
	var scripts func(data []byte) (map[string]any, error)
	switch head, _ := scriptsurface.CommandName(words[0]); head {
	case "pdm":
		name = "pyproject.toml"
		scripts = pdmScripts
	case "pipenv":
		name = "Pipfile"
		scripts = func(data []byte) (map[string]any, error) {
			var doc struct {
				Scripts map[string]any `toml:"scripts"`
			}
			_, err := toml.Decode(string(data), &doc)
			return doc.Scripts, err
		}
	default:
		return true
	}
	for _, m := range b.Nearest(name) {
		data, err := readRegular(m)
		if err != nil {
			return false
		}
		if table, err := scripts(data); err != nil || len(table) > 0 {
			return false
		}
	}
	return true
}

// allowed reports whether a command holding an installer token, already free of
// expansions and redirects, is one of the allowed forms and binds to files read here.
func (installs pipInstalls) allowed(words []string, b scriptsurface.Binder, tooling map[string]bool) bool {
	head, ok := scriptsurface.CommandName(words[0])
	if !ok {
		return false
	}
	switch {
	case pipHeadRE.MatchString(head):
		return installs.pip(words[1:], b, tooling)
	case pythonHeadRE.MatchString(head) && len(words) >= 3 && words[1] == "-m" && pipHeadRE.MatchString(words[2]):
		return installs.pip(words[3:], b, tooling)
	case len(words) < 2:
		return false
	case head == "uv" && words[1] == "sync":
		return scriptsurface.FlagsOnly(words[2:], laneFlags, "--locked", "--frozen") && b.Nearest("pyproject.toml", "uv.lock") != nil && rootBuildClean(head, b)
	case head == "poetry" && words[1] == "install":
		return scriptsurface.FlagsOnly(words[2:], laneFlags) && b.Nearest("pyproject.toml", "poetry.lock") != nil && rootBuildClean(head, b)
	case head == "pdm" && words[1] == "sync":
		return scriptsurface.FlagsOnly(words[2:], laneFlags) && pdmSyncNoHooks(b.Nearest("pyproject.toml", "pdm.lock")) && rootBuildClean(head, b)
	case head == "pipenv" && words[1] == "install":
		return scriptsurface.FlagsOnly(words[2:], laneFlags, "--deploy") && b.Nearest("Pipfile", "Pipfile.lock") != nil
	case head == "pipenv" && words[1] == "sync":
		return scriptsurface.FlagsOnly(words[2:], laneFlags) && b.Nearest("Pipfile", "Pipfile.lock") != nil
	}
	return false
}

// pip reports whether pip's arguments are install, the shared flags, --no-deps,
// --require-hashes, and one or more -r naming a requirements file read here, and records the
// install of each file; or, when tooling is not nil, a self-upgrade (pipSelfUpgrade), recorded
// in tooling.
func (installs pipInstalls) pip(args []string, b scriptsurface.Binder, tooling map[string]bool) bool {
	if len(args) == 0 || args[0] != "install" {
		return false
	}
	if pipSelfUpgrade(args[1:]) {
		if tooling == nil {
			return false
		}
		tooling["pip"] = true
		return true
	}
	var (
		how   pipInstall
		files []string
	)
	for i := 1; i < len(args); i++ {
		var p string
		switch a := args[i]; {
		case laneFlags[a]:
			continue
		case a == "--no-deps":
			how.noDeps = true
			continue
		case a == "--require-hashes":
			how.requireHashes = true
			continue
		case (a == "-r" || a == "--requirement") && i+1 < len(args):
			p = args[i+1]
			i++
		case strings.HasPrefix(a, "--requirement="):
			p = strings.TrimPrefix(a, "--requirement=")
		default:
			return false
		}
		if name := filepath.Base(p); isManifest(name) && !isRequirementsName(name) {
			return false // a lock or build definition is not a requirements file
		}
		hosts := b.Hosts(p)
		if hosts == nil {
			return false
		}
		files = append(files, hosts...)
	}
	if len(files) == 0 {
		return false
	}
	if installs != nil {
		for _, f := range files {
			f = filepath.Clean(f)
			installs[f] = append(installs[f], how)
		}
	}
	return true
}
