package jsanalysis

import (
	"regexp"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/scriptsurface"
)

// --- script installs: JavaScript forms ----------------------------------------------
//
// A build can install a package with a command in a Dockerfile, a shell script, a Makefile,
// a CI or platform file or a package.json script, at a version no manifest or lock read here
// records. Version resolution therefore withholds every pin (the whole build, since a named
// install also pulls its own dependencies) when a script surface runs a JavaScript package
// manager in any form other than the few that install exactly what a lock read here says, or
// install nothing:
//
//	npm ci                               refuses a lock package.json has moved past
//	yarn [install] --frozen-lockfile     refuses a yarn.lock package.json has moved past
//	pnpm install --frozen-lockfile       refuses a pnpm-lock.yaml package.json has moved past
//	npm run|run-script <name>            runs a script and installs nothing; the script, like
//	npm test|t|start                     every package.json script value, passes the same gate
//	yarn run <name>, yarn test|start
//
// with only --ignore-scripts and subset flags added (npm: --production and --omit, --include
// or --only with a value from laneSubsetConfigs; yarn and pnpm: --production), and with the package.json
// each binds to (the nearest at or above the command's directory, as npm finds it) and its
// lock read here. Anything else that names a package manager withholds: a package argument,
// another flag, a bare npm install, yarn or pnpm install (each re-locks), yarn install
// --immutable (yarn 1 ignores it), npm exec, npx, pnpx, bunx, yarn dlx, pnpm run (pnpm
// installs before it runs), bun, deno, corepack and the aliases, wrappers and tools laneToken
// names. An npm_config_* or YARN_* variable set in any script surface withholds, since every
// npm or yarn the build runs reads it, unless it is one of laneSubsetConfigs. How a surface is
// read, and what binds a command to a file, is lane-neutral, in scriptsurface.

// scriptSpec is the JavaScript lane's part of the rule. It names no run wrapper: npm and yarn
// run a package.json script, gated where it is written, not a command line.
var scriptSpec = scriptsurface.Spec{
	Token:       laneToken,
	Env:         laneEnvRE,
	EnvKeeps:    laneEnvKeeps,
	Allowed:     laneAllowed,
	ReadRegular: readRegular,
	Absent:      absent,
}

// laneEnvRE matches an npm_config_* (any case), YARN_*, or NPM_FLAGS/PNPM_FLAGS/BUN_FLAGS
// (which Netlify passes to its own install) name that is not a $, ${ or attribute reference,
// so is being set.
var laneEnvRE = regexp.MustCompile(`(?:^|[^$A-Za-z0-9_{.])(?:(?i:npm_config_)[A-Za-z0-9_]+|YARN_[A-Z0-9_]+|(?:P?NPM|BUN)_FLAGS)`)

// laneSubsetConfigs are the npm configs that only choose which of the packages a lock
// records get installed (devDependencies, optionalDependencies, peers), never what a package
// resolves to: exhaustive.go counts every locked package as present whatever its dev or
// optional flag, so setting one installs nothing outside the lock read here. Each maps to the
// values its flag form may take; nil takes none. The variable form (laneEnvKeeps) and the flag
// form (laneNPMFlags) both read this set.
var laneSubsetConfigs = map[string]map[string]bool{
	"production": nil,
	"omit":       {"dev": true, "optional": true, "peer": true},
	"include":    {"dev": true, "optional": true, "peer": true},
	"only":       {"prod": true, "production": true},
}

// laneEnvKeeps reports whether name, which laneEnvRE matched, is npm_config_<config> (any case)
// for one of laneSubsetConfigs.
func laneEnvKeeps(name string) bool {
	if len(name) < len("npm_config_") || !strings.EqualFold(name[:len("npm_config_")], "npm_config_") {
		return false
	}
	_, ok := laneSubsetConfigs[strings.ToLower(name[len("npm_config_"):])]
	return ok
}

// laneToken reports whether word is a JavaScript package manager or package runner, an alias
// or wrapper that runs one (yarnpkg, cnpm, ni and its nci, nlx, nu, na), or a tool
// that installs packages itself or runs commands a file not read here defines (volta, lerna,
// rush, nx, ng, ncu, vlt).
func laneToken(word string) bool {
	switch word {
	case "npm", "npx", "yarn", "pnpm", "pnpx", "bun", "bunx", "deno", "corepack",
		"yarnpkg", "cnpm", "ni", "nci", "nlx", "nu", "na",
		"volta", "lerna", "rush", "nx", "ng", "ncu", "vlt":
		return true
	}
	return false
}

// laneFlags are the flags an allowed yarn or pnpm install may carry.
var laneFlags = map[string]bool{"--production": true, "--ignore-scripts": true}

// laneNPMFlags reports whether args are only flags an allowed npm install may carry:
// --ignore-scripts, and the flag form of each of laneSubsetConfigs, --<config> alone when it
// takes no value, or --<config>=<value> or --<config> <value> with a value it takes.
func laneNPMFlags(args []string) bool {
	for i := 0; i < len(args); i++ {
		if args[i] == "--ignore-scripts" {
			continue
		}
		flag, ok := strings.CutPrefix(args[i], "--")
		if !ok {
			return false
		}
		name, val, inline := strings.Cut(flag, "=")
		vals, ok := laneSubsetConfigs[name]
		switch {
		case !ok:
			return false
		case vals == nil:
			if inline {
				return false
			}
			continue
		case !inline:
			if i+1 >= len(args) {
				return false
			}
			i++
			val = args[i]
		}
		if !vals[val] {
			return false
		}
	}
	return true
}

// laneAllowed reports whether a command holding a package-manager token, already free of
// expansions and redirects, is one of the allowed forms and binds to files read here.
func laneAllowed(words []string, b scriptsurface.Binder) bool {
	head, ok := scriptsurface.CommandName(words[0])
	if !ok || len(words) < 2 {
		return false
	}
	switch head {
	case "npm":
		switch words[1] {
		case "ci":
			return laneNPMFlags(words[2:]) && b.Nearest("package.json", "package-lock.json", "npm-shrinkwrap.json") != nil
		case "run", "run-script":
			return laneRunsScript(words, b)
		case "test", "t", "start":
			return len(words) == 2 && b.Nearest("package.json") != nil
		}
	case "yarn":
		switch words[1] {
		case "run":
			return laneRunsScript(words, b)
		case "test", "start":
			return len(words) == 2 && b.Nearest("package.json") != nil
		}
		args := words[1:]
		if args[0] == "install" {
			args = args[1:]
		}
		return scriptsurface.FlagsOnly(args, laneFlags, "--frozen-lockfile") && b.Nearest("package.json", "yarn.lock") != nil
	case "pnpm":
		return words[1] == "install" && scriptsurface.FlagsOnly(words[2:], laneFlags, "--frozen-lockfile") &&
			b.Nearest("package.json", "pnpm-lock.yaml") != nil
	}
	return false
}

// laneRunsScript reports whether words is "<pm> run <name>" with a literal name and nothing
// after it, bound to a package.json read here.
func laneRunsScript(words []string, b scriptsurface.Binder) bool {
	return len(words) == 3 && words[2] != "" && !strings.HasPrefix(words[2], "-") && b.Nearest("package.json") != nil
}
