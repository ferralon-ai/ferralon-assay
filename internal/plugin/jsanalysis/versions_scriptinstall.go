package jsanalysis

import (
	"encoding/json"
	"os"
	"path/filepath"
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
//	npm install|i                        with no package argument, when the npm lock beside
//	                                     the package.json it installs covers it (lockCovers)
//	yarn [install] --frozen-lockfile     refuses a yarn.lock package.json has moved past
//	pnpm install --frozen-lockfile       refuses a pnpm-lock.yaml package.json has moved past
//	npm run|run-script <name>            runs a script and installs nothing; the script, like
//	npm test|t|start                     every package.json script value, passes the same gate
//	yarn run <name>, yarn test|start
//	concurrently "<cmd>" ...             runs each <cmd>, which passes the same gate
//
// with only --production, --omit=dev and --ignore-scripts added, and with the package.json
// each binds to (the nearest at or above the command's directory, as npm finds it) and its
// lock read here. npm run, run-script, start and install may also carry one --prefix <dir>,
// which binds them to <dir>/package.json alone, read here and a surface the walk checks
// itself. A bare install binds only to the package.json in its package root and the npm locks
// beside it, never one above (laneLockPreserving). Any npm form may follow assignments to
// laneSubsetConfigs variables. concurrently may carry only concurrentlyFlags. Anything else
// that names a package manager withholds: a package argument, another flag, a bare npm
// install its lock does not cover, yarn or pnpm install (each re-locks), yarn install
// --immutable (yarn 1 ignores it), npm exec, npx, pnpx, bunx, yarn dlx, pnpm run (pnpm
// installs before it runs), bun, deno, corepack and the aliases, wrappers and tools laneToken
// names. An npm_config_* or YARN_* variable set in any script surface withholds, since every
// npm or yarn the build runs reads it, unless it is one of laneSubsetConfigs. How a surface is
// read, and what binds a command to a file, is lane-neutral, in scriptsurface.

// scriptSpec is the JavaScript lane's part of the rule for the build at root, whose lockfiles
// (path → what parseLockfile read) are locks. It names no run wrapper: npm and yarn run a
// package.json script, gated where it is written, not a command line.
func scriptSpec(root string, locks map[string]lockInfo) scriptsurface.Spec {
	return scriptsurface.Spec{
		Token:    laneToken,
		Env:      laneEnvRE,
		EnvKeeps: laneEnvKeeps,
		Allowed: func(words []string, b scriptsurface.Binder) bool {
			return laneAllowed(words, b, root, locks)
		},
		Concurrent:  laneConcurrent,
		ReadRegular: readRegular,
		Absent:      absent,
	}
}

// laneEnvRE matches an npm_config_* (any case), YARN_*, or NPM_FLAGS/PNPM_FLAGS/BUN_FLAGS
// (which Netlify passes to its own install) name that is not a $, ${ or attribute reference,
// so is being set.
var laneEnvRE = regexp.MustCompile(`(?:^|[^$A-Za-z0-9_{.])(?:(?i:npm_config_)[A-Za-z0-9_]+|YARN_[A-Z0-9_]+|(?:P?NPM|BUN)_FLAGS)`)

// laneSubsetConfigs are the npm configs that only choose which of the packages a lock
// records get installed (devDependencies, optionalDependencies, peers), never what a package
// resolves to: exhaustive.go counts every locked package as present whatever its dev or
// optional flag, so setting one installs nothing outside the lock read here.
var laneSubsetConfigs = map[string]bool{"production": true, "omit": true, "include": true, "only": true}

// laneEnvKeeps reports whether name, which laneEnvRE matched, is npm_config_<config> (any case)
// for one of laneSubsetConfigs.
func laneEnvKeeps(name string) bool {
	if len(name) < len("npm_config_") || !strings.EqualFold(name[:len("npm_config_")], "npm_config_") {
		return false
	}
	return laneSubsetConfigs[strings.ToLower(name[len("npm_config_"):])]
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

// laneFlags are the flags every allowed install may carry.
var laneFlags = map[string]bool{"--production": true, "--omit=dev": true, "--ignore-scripts": true}

// laneAllowed reports whether a command holding a package-manager token, already free of
// expansions and redirects, is one of the allowed forms and binds to files read here.
func laneAllowed(words []string, b scriptsurface.Binder, root string, locks map[string]lockInfo) bool {
	for len(words) > 0 && laneKeptAssignment(words[0]) {
		words = words[1:]
	}
	if len(words) == 0 {
		return false
	}
	head, ok := scriptsurface.CommandName(words[0])
	if !ok || len(words) < 2 {
		return false
	}
	switch head {
	case "npm":
		switch words[1] {
		case "ci":
			return scriptsurface.FlagsOnly(words[2:], laneFlags) && b.Nearest("package.json", "package-lock.json", "npm-shrinkwrap.json") != nil
		case "install", "i":
			dir, rest, ok := lanePrefix(words[2:])
			return ok && scriptsurface.FlagsOnly(rest, laneFlags) && laneLockPreserving(b, dir, root, locks)
		case "run", "run-script":
			dir, rest, ok := lanePrefix(words[2:])
			return ok && len(rest) == 1 && rest[0] != "" && !strings.HasPrefix(rest[0], "-") && lanePackage(b, dir)
		case "start":
			dir, rest, ok := lanePrefix(words[2:])
			return ok && len(rest) == 0 && lanePackage(b, dir)
		case "test", "t":
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

// laneKeptAssignment reports whether word is a leading NAME=value assignment to a variable
// laneEnvKeeps keeps.
func laneKeptAssignment(word string) bool {
	name, _, ok := strings.Cut(word, "=")
	return ok && laneEnvKeeps(name)
}

// lanePrefix takes one --prefix <dir> or --prefix=<dir> out of args, returning dir ("" when
// there is none) and the args left; ok is false for a second one or one with no dir.
func lanePrefix(args []string) (dir string, rest []string, ok bool) {
	for i := 0; i < len(args); i++ {
		var d string
		switch a := args[i]; {
		case a == "--prefix":
			if i+1 == len(args) {
				return "", nil, false
			}
			i++
			d = args[i]
		case strings.HasPrefix(a, "--prefix="):
			d = strings.TrimPrefix(a, "--prefix=")
		default:
			rest = append(rest, a)
			continue
		}
		if dir != "" || d == "" {
			return "", nil, false
		}
		dir = d
	}
	return dir, rest, true
}

// lanePackage reports whether an npm command binds to a package.json read here: the nearest
// one, or with --prefix dir, dir/package.json and no other.
func lanePackage(b scriptsurface.Binder, dir string) bool {
	if dir == "" {
		return b.Nearest("package.json") != nil
	}
	return b.Prefixed(dir, "package.json") != nil
}

// npmLocks are the lockfiles npm install reads, the first ahead of the second.
var npmLocks = []string{"npm-shrinkwrap.json", "package-lock.json"}

// npmrcLockSafeKeys are the .npmrc settings that leave what a bare npm install puts in
// node_modules to the lock: where packages are fetched from and with which credentials, proxy
// and TLS, and what npm prints. Every setting that changes resolution or the lock itself
// (package-lock, shrinkwrap, legacy-peer-deps, save-*, prefer-offline, …) is left out.
var npmrcLockSafeKeys = map[string]bool{
	"registry": true, "always-auth": true, "strict-ssl": true, "ca": true, "cafile": true,
	"proxy": true, "https-proxy": true, "noproxy": true, "email": true,
	"fund": true, "audit": true, "loglevel": true, "progress": true, "update-notifier": true,
}

// laneLockPreserving reports whether a bare npm install run with package root dir ("." when it
// has no --prefix) installs exactly what its lock records: the package root's package.json is
// read here (Prefixed, with npmLocks) and declares no install rewrite, every npm lock in that
// same directory parsed and covers it (lockCovers, the predicate exhaustiveness uses), there
// is at least one, neither it nor any package.json above it inside root names workspaces,
// which would make npm install against another lock or install other projects too, and every
// .npmrc there or above inside root sets only npmrcLockSafeKeys, so none turns the lock off.
// Anything this cannot read withholds.
func laneLockPreserving(b scriptsurface.Binder, dir, root string, locks map[string]lockInfo) bool {
	if dir == "" {
		dir = "."
	}
	pkgs := b.Prefixed(dir, "package.json", npmLocks...)
	if pkgs == nil {
		return false
	}
	for _, p := range pkgs {
		m, ok := readPackageJSON(p)
		if !ok || m.rewrites {
			return false
		}
		d := filepath.Dir(p)
		covered := 0
		for _, name := range npmLocks {
			l, ok := locks[filepath.Join(d, name)]
			if !ok {
				continue
			}
			if l.kind != lockNPM && l.kind != lockNPMv1 || !lockCovers(l, d, ".", m.declared) {
				return false
			}
			covered++
		}
		if covered == 0 || npmWorkspaceAt(root, d) || !npmrcLockSafe(root, d) {
			return false
		}
	}
	return true
}

// npmrcLockSafe reports whether every .npmrc in dir or a directory above it inside root sets
// only npmrcLockSafeKeys, and can be read.
func npmrcLockSafe(root, dir string) bool {
	for {
		f := filepath.Join(dir, ".npmrc")
		if _, err := os.Lstat(f); err == nil && !npmrcSetsOnly(root, f, npmrcLockSafeKeys) || err != nil && !absent(err) {
			return false
		}
		if dir == root {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// npmWorkspaceAt reports whether the package.json in dir or any directory above it inside root
// has a "workspaces" field, or is there but cannot be read or decoded.
func npmWorkspaceAt(root, dir string) bool {
	for {
		data, err := readRegular(filepath.Join(dir, "package.json"))
		switch {
		case err == nil:
			var m map[string]json.RawMessage
			if json.Unmarshal(data, &m) != nil {
				return true
			}
			if _, ok := m["workspaces"]; ok {
				return true
			}
		case !absent(err):
			return true
		}
		if dir == root {
			return false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return true
		}
		dir = parent
	}
}

// laneConcurrent returns the commands concurrently starts, and whether words runs it. A flag
// outside concurrentlyFlags, a valued one among them, returns none, which withholds.
func laneConcurrent(words []string) ([]string, bool) {
	if head, ok := scriptsurface.CommandName(words[0]); !ok || head != "concurrently" {
		return nil, false
	}
	var cmds []string
	for _, w := range words[1:] {
		switch {
		case concurrentlyFlags[w]:
		case strings.HasPrefix(w, "-"):
			return nil, true
		default:
			cmds = append(cmds, w)
		}
	}
	return cmds, true
}
