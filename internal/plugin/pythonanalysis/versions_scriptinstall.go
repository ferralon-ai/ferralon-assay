package pythonanalysis

import (
	"errors"
	"path/filepath"
	"regexp"
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
//	uv venv [<dir>]                creates an empty environment; only -p, --python and
//	                               --prompt may be added (--seed installs pip into it)
//	poetry|pdm|pipenv run <argv>   run without syncing; <argv> passes the same gate, and pdm
//	                               and pipenv run only where no script table can name <argv>
//
// with only --no-cache-dir, --user and -q added (and, to pip, --no-deps and --require-hashes,
// which only narrow what it installs), and with the manifest each binds to (the
// nearest pyproject.toml or Pipfile at or above the command's directory) and the lock it
// installs (the nearest at or above that) read here; and, for uv sync, poetry install and pdm
// sync, with a root project whose build runs no code from the tree and loads no plugin
// (rootBuildClean). Anything
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
//
// ensurepip installs the pip its interpreter bundles, and before Python 3.12 setuptools too, so
// under the same config rules it withholds those two coordinates alone (ensurepipFlags):
//
//	python -m ensurepip [flags]            the flags only from ensurepipFlags
//
// mypy --install-types runs pip on the stub packages mypy finds missing, which can pull in
// runtime dependencies. Its parser accepts any unambiguous prefix of a long flag, so a word
// from --install- up to --install-types is a token wherever it appears, and so is any script
// surface whose text holds one, wherever it sits in that text: a ${FLAGS:-} default, or a line
// a printf writes into an @ file (installTypesTextRE). A shorter prefix, --ins to --install,
// is a flag helm and others use too, so it withholds every pin only in a surface whose text
// names mypy (installTypesAbbrevRE). A mypy config can set install_types as well, and mypy
// reads a config where it lands and by any name --config-file gives it, so a file under the
// build dir whose head names mypy and an install_types key, however it is set, withholds
// every pin (mypyConfigInstalls). mypy also reads arguments one per line from a
// file an @ argument names, whatever that file is called and whether or not it names mypy, so
// a file under the build dir holding a line that is a prefix of --install-types from --ins on
// withholds every pin (installTypesLineRE). A config or arguments file the build fetches or
// the base image holds is not observed, nor is a prefix shorter than --install- that reaches
// mypy from a surface that does not name it: a variable another file sets, or an @ file
// another surface writes.

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

// laneEnvRE matches a PIP_*, UV_* or PDM_* name, in any case, that is not a $, ${ or attribute
// reference, so is being set. pip lowercases what follows PIP_ before it looks the option up,
// so PIP_index_url sets --index-url too, and a Windows runner reads every variable name in any
// case, so uv_index_url there is UV_INDEX_URL.
var laneEnvRE = regexp.MustCompile(`(?:^|[^$A-Za-z0-9_{.])(?i:PIP|UV|PDM)_[A-Za-z0-9_]+`)

// laneEnvKept are the PIP_*, UV_* and PDM_* names whose option changes only output, prompts, caching,
// timing, bytecode, how a file is copied into the environment, or whether the run fails, or
// does only what a flag an allowed form may already carry does: none changes which
// distributions the build installs, the versions, or the environment it installs them into
// beyond what an allowed form can. pip maps PIP_<NAME> to the option --<name> of whatever command it runs, and uv
// maps each UV_* name to one setting, so a name either sets its one option or none.
var laneEnvKept = map[string]bool{
	// pip: global options.
	"PIP_NO_CACHE_DIR": true, "PIP_CACHE_DIR": true, "PIP_DISABLE_PIP_VERSION_CHECK": true,
	"PIP_QUIET": true, "PIP_VERBOSE": true, "PIP_LOG": true, "PIP_LOG_FILE": true,
	"PIP_NO_COLOR": true, "PIP_NO_INPUT": true, "PIP_PROGRESS_BAR": true,
	"PIP_TIMEOUT": true, "PIP_DEFAULT_TIMEOUT": true, "PIP_RETRIES": true, "PIP_RESUME_RETRIES": true,
	"PIP_REQUIRE_VIRTUALENV": true, "PIP_REQUIRE_VENV": true, "PIP_ROOT_USER_ACTION": true,
	// pip: install options. laneFlags already lets every allowed form carry --user.
	"PIP_USER": true, "PIP_COMPILE": true, "PIP_NO_COMPILE": true,
	"PIP_NO_WARN_SCRIPT_LOCATION": true, "PIP_NO_WARN_CONFLICTS": true,
	// uv.
	"UV_NO_CACHE": true, "UV_CACHE_DIR": true, "UV_LINK_MODE": true,
	"UV_COMPILE_BYTECODE": true, "UV_COMPILE_BYTECODE_TIMEOUT": true, "UV_NO_PROGRESS": true,
	"UV_HTTP_TIMEOUT": true, "UV_HTTP_CONNECT_TIMEOUT": true, "UV_REQUEST_TIMEOUT": true,
	"UV_HTTP_RETRIES": true, "UV_CONCURRENT_DOWNLOADS": true, "UV_CONCURRENT_BUILDS": true,
	"UV_CONCURRENT_INSTALLS": true, "UV_LOCK_TIMEOUT": true, "UV_FROZEN": true, "UV_LOCKED": true,
	"UV_NO_INSTALLER_METADATA": true, "UV_PYTHON_DOWNLOADS": true,
	// pdm: PDM_CHECK_UPDATE only turns pdm's own update check off, and PDM_BUILD_SCM_VERSION
	// only sets the version pdm-backend gives the project it builds.
	"PDM_CHECK_UPDATE": true, "PDM_BUILD_SCM_VERSION": true,
}

// laneEnvKeeps reports whether name, which laneEnvRE matched, is one of laneEnvKept in any
// case, as laneEnvRE reads it.
func laneEnvKeeps(name string) bool {
	return laneEnvKept[strings.ToUpper(name)]
}

// laneToken reports whether word is a Python installer: uv, uvx, poetry, pdm, easy_install,
// mamba, micromamba, pixi, rye, hatch, flit, setup.py (install and develop fetch
// install_requires), ensurepip, mypy's --install-types or a prefix of it from --install-,
// any word starting pip or conda, and an interpreter option that runs one as a module with its
// name attached (-mpip, -Impip); or a task runner that runs commands a file not read here
// defines, or installs into the environments it makes (poe and its module poethepoet, invoke
// and its inv, tox). nox is not one: every noxfile imports it, and the noxfile.py it runs is a
// candidate whenever a session installs.
func laneToken(word string) bool {
	switch word {
	case "uv", "uvx", "poetry", "pdm", "easy_install", "mamba", "micromamba", "pixi", "rye",
		"hatch", "flit", "setup.py", "ensurepip", "poe", "poethepoet", "invoke", "inv", "tox":
		return true
	}
	if len(word) >= len(installTypesMin) && strings.HasPrefix(installTypesFlag, word) {
		return true
	}
	if m := attachedModuleRE.FindStringSubmatch(word); m != nil && laneToken(m[1]) {
		return true
	}
	return strings.HasPrefix(word, "pip") || strings.HasPrefix(word, "conda")
}

// installTypesMin is the shortest prefix of installTypesFlag that no other common tool's flag
// shares.
const installTypesFlag, installTypesMin = "--install-types", "--install-"

// installTypesTextRE matches, in a script surface's text, a prefix of --install-types from
// --install- on wherever it sits. No other common tool's flag shares one.
var installTypesTextRE = regexp.MustCompile(`--install-(?:t(?:y(?:p(?:es?)?)?)?)?(?:$|[^\w-])`)

// installTypesAbbrevRE matches, in a script surface's text, a prefix of --install-types from
// --ins on that mypy's parser reads as it, wherever it sits: a word laneToken does not see,
// such as one a variable holds, the default in ${FLAGS:---install}, or an @ file line a printf
// writes after a \n. mypyNamedRE must match the same text.
var installTypesAbbrevRE = regexp.MustCompile(`--ins(?:t(?:a(?:l(?:l(?:-(?:t(?:y(?:p(?:es?)?)?)?)?)?)?)?)?)?(?:$|[^\w-])`)

// installTypesLineRE matches a line that is a prefix of --install-types from --ins on, as
// mypy reads one argument per line from an @ file, split where Python's str.splitlines splits.
var installTypesLineRE = regexp.MustCompile(`(?:^|[\n\r\v\f\x1c-\x1e\x{85}\x{2028}\x{2029}])` +
	`--ins(?:t(?:a(?:l(?:l(?:-(?:t(?:y(?:p(?:es?)?)?)?)?)?)?)?)?)?(?:$|[\n\r\v\f\x1c-\x1e\x{85}\x{2028}\x{2029}])`)

// mypyNamedRE matches mypy anywhere, dmypy and mypy.api included.
var mypyNamedRE = regexp.MustCompile(`(?i)mypy`)

// installTypesKeyRE matches an install_types config key, no_install_types included (mypy
// inverts a no_ key), as a key and not the tail of a --no-install-types flag.
var installTypesKeyRE = regexp.MustCompile(`(?i)(?:^|[^-\w])(?:no[-_])?install[-_]types`)

// mypyConfigInstalls reports whether a file whose content starts with head may be a mypy
// config that sets install_types: it names mypy and an install_types key, whatever the key's
// value or the file's name.
func mypyConfigInstalls(head []byte) bool {
	return mypyNamedRE.Match(head) && installTypesKeyRE.Match(head)
}

// attachedModuleRE matches a cluster of interpreter short options ending in -m with the
// module name attached, which CPython reads as -m <name>: the first m ends the cluster.
var attachedModuleRE = regexp.MustCompile(`^-[A-Za-ln-z]*m(.+)$`)

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

// ensurepipFlags are the flags an allowed ensurepip may carry: none changes what it installs.
// --root is not one: this reads no install location.
var ensurepipFlags = map[string]bool{
	"-U": true, "--upgrade": true, "--default-pip": true, "--altinstall": true, "--user": true,
	"-v": true, "--verbose": true,
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

// seededDistributions are what the interpreter a build runs on, or a venv it creates, may
// already hold: ensurepip and python -m venv seed pip, and before Python 3.12 setuptools;
// virtualenv and uv venv --seed seed wheel too, and an image or distro interpreter may ship any
// of them. Every Python build runs on some interpreter, and where it comes from (a base image,
// a runner, .python-version, a platform runtime) is not read, nor is its site-packages, which
// keeps whatever it ships whatever --without-pip, --no-setuptools or --no-wheel leave out of a
// venv. So each may be installed, at a version nothing read here records, in every build.
var seededDistributions = []string{"pip", "setuptools", "wheel"}

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
	Tool struct {
		Poetry struct {
			Build           any `toml:"build"`
			RequiresPlugins any `toml:"requires-plugins"`
		} `toml:"poetry"`
		Setuptools struct {
			Cmdclass any `toml:"cmdclass"`
		} `toml:"setuptools"`
		PDM struct {
			PackageType  *string `toml:"package-type"`
			Distribution *bool   `toml:"distribution"`
			Build        struct {
				CustomHook    any `toml:"custom-hook"`
				RunSetuptools any `toml:"run-setuptools"`
			} `toml:"build"`
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
// (backendClean). A uv workspace builds its members as well, so a workspace root fails.
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
			if builds && !backendClean(doc, b) {
				return false
			}
		case "uv":
			if doc.Tool.UV.Workspace != nil {
				return false
			}
			builds := doc.BuildSystem != nil
			if p := doc.Tool.UV.Package; p != nil {
				builds = *p
			}
			if builds && !backendClean(doc, b) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// backendClean reports whether the PEP 517 backend a manifest names runs no code from the
// tree when it builds the project: setuptools (also the backend when none is named) with no
// setup.py or setup.cfg beside the manifest, either of which can name command classes in the
// tree, and no tool.setuptools.cmdclass; pdm-backend with no pdm_build.py and no custom-hook
// or run-setuptools; hatchling with no hooks table anywhere in tool.hatch and no
// hatch_build.py or hatch.toml, which hatchling merges into tool.hatch; poetry-core with no
// tool.poetry.build; flit_core; or uv_build. A backend-path, which loads
// the backend itself from the tree, or any other backend fails.
func backendClean(doc rootProject, b scriptsurface.Binder) bool {
	backend := ""
	if bs := doc.BuildSystem; bs != nil {
		if bs.BackendPath != nil {
			return false
		}
		backend = strings.TrimSpace(bs.Backend)
	}
	switch backend {
	case "", "setuptools.build_meta", "setuptools.build_meta:__legacy__":
		return doc.Tool.Setuptools.Cmdclass == nil && b.Clear("pyproject.toml", "setup.py") && b.Clear("pyproject.toml", "setup.cfg")
	case "pdm.backend":
		return doc.Tool.PDM.Build.CustomHook == nil && doc.Tool.PDM.Build.RunSetuptools == nil && b.Clear("pyproject.toml", "pdm_build.py")
	case "hatchling.build":
		return !hasKey(doc.Tool.Hatch, "hooks") && b.Clear("pyproject.toml", "hatch_build.py") && b.Clear("pyproject.toml", "hatch.toml")
	case "poetry.core.masonry.api":
		return doc.Tool.Poetry.Build == nil
	case "flit_core.buildapi", "uv_build":
		return true
	}
	return false
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
	case pythonHeadRE.MatchString(head) && len(words) >= 3 && words[1] == "-m" && words[2] == "ensurepip":
		if tooling == nil || !scriptsurface.FlagsOnly(words[3:], ensurepipFlags) {
			return false
		}
		tooling["pip"], tooling["setuptools"] = true, true
		return true
	case len(words) < 2:
		return false
	case head == "uv" && words[1] == "venv":
		return uvVenv(words[2:])
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

// uvVenv reports whether uv venv's arguments are at most one directory and -p, --python or
// --prompt with a value: an environment with no packages in it.
func uvVenv(args []string) bool {
	dirs := 0
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-p" || a == "--python" || a == "--prompt":
			if i+1 == len(args) || strings.HasPrefix(args[i+1], "-") {
				return false
			}
			i++
		case strings.HasPrefix(a, "--python=") || strings.HasPrefix(a, "--prompt="):
		case strings.HasPrefix(a, "-"):
			return false
		default:
			dirs++
		}
	}
	return dirs <= 1
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
