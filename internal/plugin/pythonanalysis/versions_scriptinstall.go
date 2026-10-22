package pythonanalysis

import (
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
//	pdm sync                       installs the lock as written
//	pipenv install --deploy        refuses a Pipfile.lock the Pipfile has moved past
//	pipenv sync                    installs Pipfile.lock as written
//	poetry|pdm|pipenv run <argv>   run without syncing; <argv> passes the same gate, and pdm
//	                               and pipenv run only where no script table can name <argv>
//
// with only --no-cache-dir, --user and -q added, and with the manifest each binds to (the
// nearest pyproject.toml or Pipfile at or above the command's directory) and the lock it
// installs (the nearest at or above that) read here. Anything
// else that names an installer withholds: a package argument, another flag, pipx, uvx, uv run
// (it syncs), a bare uv sync or pdm install (both re-lock), conda, mamba, easy_install, and
// every other tool laneToken names, run wrappers whose argv names one included. A
// PIP_* or UV_* variable set in any script surface withholds, since every pip or uv the build
// runs reads it. How a surface is read, and what binds a command to a file, is lane-neutral,
// in scriptsurface.

// scriptSpec is the Python lane's part of the rule.
var scriptSpec = scriptsurface.Spec{
	Token:       laneToken,
	Env:         laneEnvRE,
	Allowed:     laneAllowed,
	RunWrapper:  laneRunWrapper,
	RunBinds:    laneRunBinds,
	ReadRegular: readRegular,
	Absent:      absent,
}

// laneEnvRE matches a PIP_* or UV_* name that is not a $, ${ or attribute reference, so is
// being set.
var laneEnvRE = regexp.MustCompile(`(?:^|[^$A-Za-z0-9_{.])(?:PIP|UV)_[A-Z0-9_]+`)

// laneToken reports whether word is a Python installer: uv, uvx, poetry, pdm, easy_install,
// mamba, micromamba, pixi, rye, hatch, flit, setup.py (install and develop fetch
// install_requires), any word starting pip or conda, and an interpreter option that runs one
// as a module with its name attached (-mpip, -Impip); or a task runner that runs commands a
// file not read here defines, or installs into the environments it makes (poe, invoke and its
// inv, tox). nox is not one: every noxfile imports it, and the noxfile.py it runs is a
// candidate whenever a session installs.
func laneToken(word string) bool {
	switch word {
	case "uv", "uvx", "poetry", "pdm", "easy_install", "mamba", "micromamba", "pixi", "rye",
		"hatch", "flit", "setup.py", "poe", "invoke", "inv", "tox":
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
		scripts = func(data []byte) (map[string]any, error) {
			var doc struct {
				Tool struct {
					PDM struct {
						Scripts map[string]any `toml:"scripts"`
					} `toml:"pdm"`
				} `toml:"tool"`
			}
			_, err := toml.Decode(string(data), &doc)
			return doc.Tool.PDM.Scripts, err
		}
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

// laneAllowed reports whether a command holding an installer token, already free of
// expansions and redirects, is one of the allowed forms and binds to files read here.
func laneAllowed(words []string, b scriptsurface.Binder) bool {
	head, ok := scriptsurface.CommandName(words[0])
	if !ok {
		return false
	}
	switch {
	case pipHeadRE.MatchString(head):
		return pipRequirementsInstall(words[1:], b)
	case pythonHeadRE.MatchString(head) && len(words) >= 3 && words[1] == "-m" && pipHeadRE.MatchString(words[2]):
		return pipRequirementsInstall(words[3:], b)
	case len(words) < 2:
		return false
	case head == "uv" && words[1] == "sync":
		return scriptsurface.FlagsOnly(words[2:], laneFlags, "--locked", "--frozen") && b.Nearest("pyproject.toml", "uv.lock") != nil
	case head == "poetry" && words[1] == "install":
		return scriptsurface.FlagsOnly(words[2:], laneFlags) && b.Nearest("pyproject.toml", "poetry.lock") != nil
	case head == "pdm" && words[1] == "sync":
		return scriptsurface.FlagsOnly(words[2:], laneFlags) && b.Nearest("pyproject.toml", "pdm.lock") != nil
	case head == "pipenv" && words[1] == "install":
		return scriptsurface.FlagsOnly(words[2:], laneFlags, "--deploy") && b.Nearest("Pipfile", "Pipfile.lock") != nil
	case head == "pipenv" && words[1] == "sync":
		return scriptsurface.FlagsOnly(words[2:], laneFlags) && b.Nearest("Pipfile", "Pipfile.lock") != nil
	}
	return false
}

// pipRequirementsInstall reports whether pip's arguments are install, the shared flags, and
// one or more -r naming a requirements file read here.
func pipRequirementsInstall(args []string, b scriptsurface.Binder) bool {
	if len(args) == 0 || args[0] != "install" {
		return false
	}
	reqs := 0
	for i := 1; i < len(args); i++ {
		var p string
		switch a := args[i]; {
		case laneFlags[a]:
			continue
		case (a == "-r" || a == "--requirement") && i+1 < len(args):
			p = args[i+1]
			i++
		case strings.HasPrefix(a, "--requirement="):
			p = strings.TrimPrefix(a, "--requirement=")
		default:
			return false
		}
		if name := filepath.Base(p); isManifest(name) && !isRequirementsName(name) || !b.File(p) {
			return false // a lock or build definition is not a requirements file
		}
		reqs++
	}
	return reqs > 0
}
