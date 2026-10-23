package jsanalysis

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
)

const (
	exPkgJSON = `{"name":"app","dependencies":{"express":"^4.18.0"},"devDependencies":{"left-pad":"^1.3.0"}}`
	// exLockV3 records the root project's specs, as npm writes them.
	exLockV3 = `{"name":"app","lockfileVersion":3,"packages":{
  "": {"name":"app","dependencies":{"express":"^4.18.0"},"devDependencies":{"left-pad":"^1.3.0"}},
  "node_modules/express": {"version":"4.18.2"},
  "node_modules/left-pad": {"version":"1.3.0"}}}`
	exYarnLock = "# yarn lockfile v1\n\nexpress@^4.18.0:\n  version \"4.18.2\"\n\nleft-pad@^1.3.0:\n  version \"1.3.0\"\n"
	exPnpmV5   = "lockfileVersion: 5.4\n\nspecifiers:\n  express: ^4.18.0\n  left-pad: ^1.3.0\n\ndependencies:\n  express: 4.18.2\n\ndevDependencies:\n  left-pad: 1.3.0\n\npackages:\n\n  /express/4.18.2:\n    resolution: {integrity: sha512-x}\n\n  /left-pad/1.3.0:\n    resolution: {integrity: sha512-y}\n"
	exPnpmV6   = "lockfileVersion: '6.0'\n\ndependencies:\n  express:\n    specifier: ^4.18.0\n    version: 4.18.2\n\ndevDependencies:\n  left-pad:\n    specifier: ^1.3.0\n    version: 1.3.0\n\npackages:\n\n  /express@4.18.2:\n    resolution: {integrity: sha512-x}\n\n  /left-pad@1.3.0:\n    resolution: {integrity: sha512-y}\n"
	exPnpmV9   = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      express:\n        specifier: ^4.18.0\n        version: 4.18.2\n    devDependencies:\n      left-pad:\n        specifier: ^1.3.0\n        version: 1.3.0\n\npackages:\n\n  express@4.18.2:\n    resolution: {integrity: sha512-x}\n\n  left-pad@1.3.0:\n    resolution: {integrity: sha512-y}\n\nsnapshots:\n\n  express@4.18.2: {}\n"
)

// Exhaustive is claimed only when complete lockfiles cover every package.json and every name
// and spec it declares, and nothing in the build dir installs the coordinate outside them;
// anything weaker fails open. Each row names the review finding it pins where it has one.
func TestResolveVersions_Exhaustive(t *testing.T) {
	const (
		pkgJSONPeer    = `{"name":"app","dependencies":{"express":"^4.18.0"},"peerDependencies":{"react":">=18"}}`
		pkgJSONMissing = `{"name":"app","dependencies":{"express":"^4.18.0","lodash":"^4.17.0"}}`
		pkgJSONDrift   = `{"name":"app","dependencies":{"express":"^4.19.0"},"devDependencies":{"left-pad":"^1.3.0"}}`
		toolJSON       = `{"name":"tool","dependencies":{"express":"^4.18.0"}}`
		lockV3Tools    = `{"name":"app","lockfileVersion":3,"packages":{
  "": {"name":"app","dependencies":{"express":"^4.18.0"},"devDependencies":{"left-pad":"^1.3.0"}},
  "tools": {"name":"tool","dependencies":{"express":"^4.18.0"}},
  "node_modules/express": {"version":"4.18.2"},
  "node_modules/left-pad": {"version":"1.3.0"},
  "node_modules/tool": {"resolved":"tools","link":true}}}`
		lockV1         = `{"name":"app","lockfileVersion":1,"dependencies":{"express":{"version":"4.18.2"},"left-pad":{"version":"1.3.0"}}}`
		lockV1Git      = `{"name":"app","lockfileVersion":1,"dependencies":{"json5x":{"version":"github:acme/json5#abc123"}}}`
		yarnGit        = exYarnLock + "\njson5x@github:acme/json5#abc123:\n  version \"2.2.1\"\n"
		yarnStale      = "# yarn lockfile v1\n\nexpress@^4.18.0:\n  version \"4.18.2\"\n"
		pnpmCustomReg  = "lockfileVersion: 5.4\n\nspecifiers:\n  express: ^4.18.0\n  left-pad: ^1.3.0\n\npackages:\n\n  /express/4.18.2:\n    resolution: {integrity: sha512-x}\n\n  /left-pad/1.3.0:\n    resolution: {integrity: sha512-y}\n\n  registry.example.com/absent-package/2.2.1:\n    resolution: {tarball: https://registry.example.com/absent-package/-/absent-package-2.2.1.tgz}\n"
		yarnWorkspaces = `{"name":"app","workspaces":["tools"],"dependencies":{"express":"^4.18.0"},"devDependencies":{"left-pad":"^1.3.0"}}`
	)
	// peerLock is a v2/v3 lock that locked the root and the tools workspace, each depending on
	// express, against react peer range rootPeer and toolPeer.
	peerLock := func(version, rootPeer, toolPeer string) string {
		return `{"name":"app","lockfileVersion":` + version + `,"packages":{
  "": {"name":"app","dependencies":{"express":"^4.18.0"},"peerDependencies":{"react":"` + rootPeer + `"}},
  "tools": {"name":"tool","dependencies":{"express":"^4.18.0"},"peerDependencies":{"react":"` + toolPeer + `"}},
  "node_modules/express": {"version":"4.18.2"},
  "node_modules/react": {"version":"17.0.2","peer":true},
  "node_modules/tool": {"resolved":"tools","link":true}}}`
	}
	peerPkg := func(name, peer string) string {
		return `{"name":"` + name + `","dependencies":{"express":"^4.18.0"},"peerDependencies":{"react":"` + peer + `"}}`
	}
	// rewrite is exPkgJSON with one more top-level field.
	rewrite := func(field string) string { return strings.TrimSuffix(exPkgJSON, "}") + "," + field + "}" }
	// catalogLock is exPnpmV9 as pnpm writes it for a left-pad declared as catalog:.
	catalogLock := strings.Replace(exPnpmV9, "left-pad:\n        specifier: ^1.3.0", "left-pad:\n        specifier: 'catalog:'", 1) +
		"\ncatalogs:\n\n  default:\n    left-pad:\n      specifier: ^1.3.0\n      version: 1.3.0\n"
	// yarnNULAt is a yarn v1 lock locking the coordinate, with a comment padded so a NUL lands at
	// byte off.
	yarnNULAt := func(off int) string {
		const marker = "# yarn lockfile v1\n# "
		return marker + strings.Repeat("x", off-len(marker)) + "\x00\n\nabsent-package@^2:\n  version \"2.2.1\"\n"
	}
	const pnpmfileAdds = "module.exports = {hooks: {readPackage(pkg) { pkg.dependencies['absent-package'] = '^2'; return pkg }}}\n"
	tests := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"package-lock covers package.json", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3}, true},
		{"yarn.lock covers package.json", map[string]string{"package.json": exPkgJSON, "yarn.lock": exYarnLock}, true},
		{"pnpm v5 covers package.json", map[string]string{"package.json": exPkgJSON, "pnpm-lock.yaml": exPnpmV5}, true},
		{"pnpm v6 covers package.json", map[string]string{"package.json": exPkgJSON, "pnpm-lock.yaml": exPnpmV6}, true},
		{"pnpm v9 covers package.json", map[string]string{"package.json": exPkgJSON, "pnpm-lock.yaml": exPnpmV9}, true},
		{"unlocked peer fails open", map[string]string{"package.json": pkgJSONPeer, "package-lock.json": exLockV3}, false},
		{"root project is the coordinate", map[string]string{"package.json": `{"name":"Absent-Package","dependencies":{"express":"^4.18.0"}}`, "package-lock.json": exLockV3}, false},
		{"declared name missing from lock", map[string]string{"package.json": pkgJSONMissing, "package-lock.json": exLockV3}, false},
		{"nested package.json declaring an unlocked name", map[string]string{"package.json": exPkgJSON, "package-lock.json": lockV3Tools, "tools/package.json": pkgJSONMissing}, false},
		{"lock only in a subproject", map[string]string{"package.json": exPkgJSON, "web/package-lock.json": exLockV3, "web/package.json": exPkgJSON}, false},
		{"package.json only", map[string]string{"package.json": exPkgJSON}, false},
		{"malformed lock", map[string]string{"package.json": exPkgJSON, "package-lock.json": "{not json"}, false},
		{"malformed package.json", map[string]string{"package.json": "{", "package-lock.json": exLockV3}, false},
		{"workspace package defines the coordinate", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "packages/absent-package/package.json": `{"name":"absent-package"}`}, false},
		{"installed tree without the coordinate", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "node_modules/express/package.json": `{"name":"express"}`}, true},
		{"dependency-free package.json in a build dir", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, ".next/package.json": `{"type":"commonjs"}`}, true},

		// B1: an entry the lock cannot name (git, tarball, path) is opaque.
		{"B1 yarn git entry is opaque", map[string]string{"package.json": exPkgJSON, "yarn.lock": yarnGit}, false},
		{"B1 package-lock v1 git entry is opaque", map[string]string{"package.json": `{"name":"app"}`, "package-lock.json": lockV1Git}, false},

		// B2: no skip list; installed trees and unread lockfiles withhold.
		{"B2 vendored package.json defines the coordinate", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "vendor/absent-package/package.json": `{"name":"absent-package","version":"2.2.1"}`}, false},
		{"B2 dot-dir action declares an unlocked name", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, ".github/actions/x/package.json": `{"name":"x","dependencies":{"absent-package":"^2"}}`}, false},
		{"B2 build-dir tool declares an unlocked name", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "build/tool/package.json": `{"name":"tool","dependencies":{"absent-package":"^2"}}`}, false},
		{"B2 committed node_modules holds the coordinate", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "node_modules/absent-package/package.json": `{"name":"absent-package","version":"2.2.1"}`}, false},
		{"B2 nested node_modules holds the coordinate", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "node_modules/express/node_modules/absent-package/package.json": `{"name":"absent-package"}`}, false},
		{"B2 pnpm store holds the coordinate", map[string]string{"package.json": exPkgJSON, "pnpm-lock.yaml": exPnpmV9, "node_modules/.pnpm/absent-package@2.2.1/node_modules/absent-package/package.json": `{"name":"absent-package"}`}, false},
		{"B2 yarn cache holds the coordinate", map[string]string{"package.json": exPkgJSON, "yarn.lock": exYarnLock, ".yarn/cache/absent-package-npm-2.2.1-abc123.zip": "PK"}, false},
		{"B2 lockfile in a skipped dir is unread", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, ".github/actions/x/package-lock.json": exLockV3}, false},

		// B5: a pnpm key that is not a registry descriptor and carries no name: field is opaque.
		{"B5 pnpm custom-registry key without name", map[string]string{"package.json": exPkgJSON, "pnpm-lock.yaml": pnpmCustomReg}, false},

		// S1: specs, recorded projects, and each lock on its own.
		{"S1 package-lock spec drift", map[string]string{"package.json": pkgJSONDrift, "package-lock.json": exLockV3}, false},
		{"S1 yarn spec drift", map[string]string{"package.json": pkgJSONDrift, "yarn.lock": exYarnLock}, false},
		{"S1 pnpm spec drift", map[string]string{"package.json": pkgJSONDrift, "pnpm-lock.yaml": exPnpmV9}, false},
		{"S1 package-lock v1 records no specs", map[string]string{"package.json": exPkgJSON, "package-lock.json": lockV1}, false},
		{"S1 nested project the lock does not record", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "tools/package.json": toolJSON}, false},
		{"S1 nested project the lock does not record, declaring only a peer it keys", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "tools/package.json": `{"name":"tool","peerDependencies":{"express":"^4.18.0"}}`}, false},
		{"S1 nested workspace the lock records", map[string]string{"package.json": exPkgJSON, "package-lock.json": lockV3Tools, "tools/package.json": toolJSON}, true},
		{"S1 classic yarn workspace named by the root", map[string]string{"package.json": yarnWorkspaces, "yarn.lock": exYarnLock, "tools/package.json": toolJSON}, true},
		{"S1 classic yarn project not a workspace", map[string]string{"package.json": exPkgJSON, "yarn.lock": exYarnLock, "tools/package.json": toolJSON}, false},
		// npm v2/v3 records the project's own peer ranges and re-resolves a drifted one.
		{"S1 package-lock v3 root peer drift", map[string]string{"package.json": peerPkg("app", "^18.0.0"), "package-lock.json": peerLock("3", "^17.0.0", "^17.0.0"), "tools/package.json": peerPkg("tool", "^17.0.0")}, false},
		{"S1 package-lock v3 workspace peer drift", map[string]string{"package.json": peerPkg("app", "^17.0.0"), "package-lock.json": peerLock("3", "^17.0.0", "^17.0.0"), "tools/package.json": peerPkg("tool", "^18.0.0")}, false},
		{"S1 package-lock v3 peer specs match", map[string]string{"package.json": peerPkg("app", "^17.0.0"), "package-lock.json": peerLock("3", "^17.0.0", "^17.0.0"), "tools/package.json": peerPkg("tool", "^17.0.0")}, true},
		{"S1 package-lock v2 root peer drift", map[string]string{"package.json": peerPkg("app", "^18.0.0"), "package-lock.json": peerLock("2", "^17.0.0", "^17.0.0"), "tools/package.json": peerPkg("tool", "^17.0.0")}, false},
		{"S1 package-lock v2 peer specs match", map[string]string{"package.json": peerPkg("app", "^17.0.0"), "package-lock.json": peerLock("2", "^17.0.0", "^17.0.0"), "tools/package.json": peerPkg("tool", "^17.0.0")}, true},
		{"S1 pnpm peer the lock keys", map[string]string{"package.json": strings.TrimSuffix(exPkgJSON, "}") + `,"peerDependencies":{"left-pad":"^1.3.0"}}`, "pnpm-lock.yaml": exPnpmV9}, true},
		{"S1 stale lock beside a covering one", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "yarn.lock": yarnStale}, false},

		// B6: every file that looks like a JS manifest or lockfile, by name or content, is read
		// in full or withholds.
		{"B6 bun.lock", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "bun.lock": "{\n  \"lockfileVersion\": 1,\n  \"workspaces\": {},\n}\n"}, false},
		{"B6 bun.lockb", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "bun.lockb": "#!/usr/bin/env bun\nbun-lockfile-format-v0\n\x00\x01"}, false},
		{"B6 deno.lock", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "deno.lock": `{"version":"4","npm":{"absent-package@2.2.1":{}}}`}, false},
		{"B6 deno.json", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "deno.json": `{"imports":{"x":"npm:absent-package@^2"}}`}, false},
		{"B6 import map naming npm under another name", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "web/imports.json": `{"imports":{"x":"npm:absent-package@^2"}}`}, false},
		{"B6 unknown lockfile name", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "deps.lock": "absent-package 2.2.1\n"}, false},
		{"B6 templated package.json", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "templates/package.json.hbs": `{"name":"{{name}}","dependencies":{"absent-package":"^2"}}`}, false},
		{"B6 manifest by content under another name", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "deploy/app.json": `{"name":"svc","dependencies":{"absent-package":"^2"}}`}, false},
		{"B6 lockfile by content under another name", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "ci/lock.yaml": exPnpmV9}, false},
		{"B6 tsconfig is not a manifest", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "tsconfig.json": `{"compilerOptions":{"strict":true}}`}, true},
		{"B6 NuGet packages.lock.json is not a manifest", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "svc/packages.lock.json": `{"version":1,"dependencies":{"net8.0":{"Serilog":{"type":"Direct","resolved":"3.1.1"}}}}`}, true},
		{"B6 Python lock is not a JS candidate", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "uv.lock": "version = 1\n"}, true},
		{"B6 workspace and registry config without a lock", map[string]string{"package.json": exPkgJSON, "pnpm-workspace.yaml": "packages:\n  - tools\n", ".yarnrc.yml": "nodeLinker: node-modules\n", ".npmrc": "registry=https://registry.example.com/\n", ".pnpmfile.cjs": "module.exports = {hooks: {}}\n"}, false},
		{"B11 npm overrides", map[string]string{"package.json": rewrite(`"overrides":{"left-pad":"npm:absent-package@^2"}`), "package-lock.json": exLockV3}, false},
		{"B11 yarn resolutions", map[string]string{"package.json": rewrite(`"resolutions":{"left-pad":"npm:absent-package@^2"}`), "yarn.lock": exYarnLock}, false},
		{"B11 pnpm.overrides", map[string]string{"package.json": rewrite(`"pnpm":{"overrides":{"left-pad":"npm:absent-package@^2"}}`), "pnpm-lock.yaml": exPnpmV9}, false},
		{"B11 pnpm.packageExtensions", map[string]string{"package.json": rewrite(`"pnpm":{"packageExtensions":{"express":{"dependencies":{"absent-package":"^2"}}}}`), "pnpm-lock.yaml": exPnpmV9}, false},
		{"B11 pnpmfile hook adding a dependency", map[string]string{"package.json": exPkgJSON, "pnpm-lock.yaml": exPnpmV9, ".pnpmfile.cjs": pnpmfileAdds}, false},
		{"B11 yarnrc packageExtensions", map[string]string{"package.json": exPkgJSON, "yarn.lock": exYarnLock, ".yarnrc.yml": "packageExtensions:\n  \"express@*\":\n    dependencies:\n      absent-package: ^2\n"}, false},
		{"B11 pnpm-workspace overrides", map[string]string{"package.json": exPkgJSON, "pnpm-lock.yaml": exPnpmV9, "pnpm-workspace.yaml": "overrides:\n  left-pad: npm:absent-package@^2\n"}, false},
		{"B14 pnpm-workspace catalog", map[string]string{"package.json": exPkgJSON, "pnpm-lock.yaml": exPnpmV9, "pnpm-workspace.yaml": "catalog:\n  left-pad: npm:absent-package@^2\n"}, false},
		{"B14 pnpm-workspace named catalogs", map[string]string{"package.json": exPkgJSON, "pnpm-lock.yaml": exPnpmV9, "pnpm-workspace.yaml": "catalogs:\n  tools:\n    left-pad: npm:absent-package@^2\n"}, false},
		{"B14 catalog: specifier the lock records as catalog:", map[string]string{"package.json": strings.Replace(exPkgJSON, `"left-pad":"^1.3.0"`, `"left-pad":"catalog:"`, 1), "pnpm-lock.yaml": catalogLock}, false},
		{"B15 pnpm config-dependency plugin", map[string]string{"package.json": exPkgJSON, "pnpm-lock.yaml": exPnpmV9, "pnpm-workspace.yaml": "configDependencies:\n  pnpm-plugin-x: 1.0.0+sha512-x\n"}, false},
		{"B16 yarn berry plugin", map[string]string{"package.json": exPkgJSON, "yarn.lock": exYarnLock, ".yarnrc.yml": "plugins:\n  - path: .yarn/plugins/add.cjs\n", ".yarn/plugins/add.cjs": "module.exports = {name: 'add', factory: () => ({hooks: {reduceDependency: d => d}})}\n"}, false},
		{"B11 installer config word past the head", map[string]string{"package.json": exPkgJSON, "yarn.lock": exYarnLock, ".yarnrc.yml": "# " + strings.Repeat("x", buildtree.HeadSize) + "\npackageExtensions:\n  \"express@*\":\n    dependencies:\n      absent-package: ^2\n"}, false},
		{"B11 installer config with a NUL in its head", map[string]string{"package.json": exPkgJSON, "pnpm-lock.yaml": exPnpmV9, "pnpm-workspace.yaml": "# \x00\noverrides:\n  left-pad: npm:absent-package@^2\n"}, false},
		{"B11 pnpm settings that rewrite nothing", map[string]string{"package.json": rewrite(`"pnpm":{"onlyBuiltDependencies":["esbuild"]}`), "pnpm-lock.yaml": exPnpmV9}, true},
		{"B11 installer config that rewrites nothing", map[string]string{"package.json": exPkgJSON, "pnpm-lock.yaml": exPnpmV9, "pnpm-workspace.yaml": "packages:\n  - .\n", ".yarnrc.yml": "nodeLinker: node-modules\n", ".npmrc": "registry=https://registry.example.com/\n"}, true},
		{"B12 pnpm package bundling the coordinate", map[string]string{"package.json": exPkgJSON, "pnpm-lock.yaml": strings.Replace(exPnpmV9, "sha512-x}\n", "sha512-x}\n    bundledDependencies:\n      - absent-package\n", 1)}, false},
		{"B12 pnpm package bundling the coordinate, flow list", map[string]string{"package.json": exPkgJSON, "pnpm-lock.yaml": strings.Replace(exPnpmV9, "sha512-x}\n", "sha512-x}\n    bundledDependencies: [absent-package]\n", 1)}, false},
		{"B13 dependency-free package.json and a pnpmfile without a lock", map[string]string{"package.json": `{"name":"app"}`, ".pnpmfile.cjs": pnpmfileAdds}, false},
		{"B13 dependency-free package.json without a lock", map[string]string{"package.json": `{"name":"app"}`}, false},
		// A NUL makes buildtree.Head report a file binary, but yarn v1 reads past one in a
		// comment, so a lockfile found by content is judged with the NUL removed or made a newline.
		{"lockfile by content, NUL at byte 40", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "ci/deps": yarnNULAt(40)}, false},
		{"lockfile by content, NUL past byte 8000", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "ci/deps": yarnNULAt(8100)}, false},
		{"lockfile by content, NUL splitting the marker", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "ci/deps": "# yarn\x00 lockfile v1\n\nabsent-package@^2:\n  version \"2.2.1\"\n"}, false},
		{"lockfile by content, NUL ending a comment", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "ci/deps": "#\x00__metadata:\n  version: 6\n\n\"absent-package@npm:^2\":\n  version: 2.2.1\n"}, false},
		{"binary file without a lockfile shape", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "assets/logo.png": "\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x01\x00"}, true},
		{"text file without a lockfile shape", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "notes": "absent-package is not used here\n"}, true},
		{"B6 manifest quoted in docs", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "docs/setup.md": `{"dependencies":{"absent-package":"^2"}}`}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveJS(t, writeLockTree(t, tt.files), "absent-package")
			// A copy installed under node_modules is a found match of its own (installedCopies);
			// no lock or manifest in any row holds absent-package.
			installed := false
			for f := range tt.files {
				installed = installed || strings.Contains(f, "node_modules/")
			}
			if r.Found && !installed {
				t.Fatalf("absent-package unexpectedly found")
			}
			if r.Exhaustive != tt.want {
				t.Fatalf("Exhaustive = %v, want %v (partiality %+v)", r.Exhaustive, tt.want, r.Partiality)
			}
		})
	}
}

// A peer-only workspace stays unrecorded: npm --legacy-peer-deps records the workspace's chalk
// peer range without installing a copy that satisfies it, and a plain npm install then adds
// chalk 4, supports-color 7 and has-flag. Lock shape as npm 11.14.1 wrote it.
func TestResolveVersions_ExhaustiveLegacyPeerOnlyWorkspace(t *testing.T) {
	files := map[string]string{
		"package.json":               `{"name":"app","version":"1.0.0","workspaces":["packages/*"],"dependencies":{"babel-code-frame":"6.26.0"}}`,
		"packages/tool/package.json": `{"name":"tool","version":"1.0.0","peerDependencies":{"chalk":"^4.0.0"}}`,
		"package-lock.json": `{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{
  "": {"name":"app","version":"1.0.0","workspaces":["packages/*"],"dependencies":{"babel-code-frame":"6.26.0"}},
  "node_modules/ansi-regex": {"version":"2.1.1"},
  "node_modules/ansi-styles": {"version":"2.2.1"},
  "node_modules/babel-code-frame": {"version":"6.26.0","dependencies":{"chalk":"^1.1.3","esutils":"^2.0.2","js-tokens":"^3.0.2"}},
  "node_modules/chalk": {"version":"1.1.3","dependencies":{"ansi-styles":"^2.2.1","escape-string-regexp":"^1.0.2","has-ansi":"^2.0.0","strip-ansi":"^3.0.0","supports-color":"^2.0.0"}},
  "node_modules/escape-string-regexp": {"version":"1.0.5"},
  "node_modules/esutils": {"version":"2.0.3"},
  "node_modules/has-ansi": {"version":"2.0.0","dependencies":{"ansi-regex":"^2.0.0"}},
  "node_modules/js-tokens": {"version":"3.0.2"},
  "node_modules/strip-ansi": {"version":"3.0.1","dependencies":{"ansi-regex":"^2.0.0"}},
  "node_modules/supports-color": {"version":"2.0.0"},
  "node_modules/tool": {"resolved":"packages/tool","link":true},
  "packages/tool": {"version":"1.0.0","peerDependencies":{"chalk":"^4.0.0"}}}}`,
	}
	r := resolveJS(t, writeLockTree(t, files), "has-flag")
	if r.Found {
		t.Fatalf("has-flag unexpectedly found")
	}
	if r.Exhaustive {
		t.Fatalf("Exhaustive = true, want false")
	}
}

// B3: a script surface the version veto withholds on may install a package no lock or
// manifest read here names, so it withholds Exhaustive too; a kept form installs only what a
// read lock holds and does not.
func TestResolveVersions_ExhaustiveScriptInstall(t *testing.T) {
	const docker = "FROM node:20\nWORKDIR /app\nCOPY package.json package-lock.json ./\nRUN "
	npm := func(extra map[string]string) map[string]string {
		files := map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3}
		for k, v := range extra {
			files[k] = v
		}
		return files
	}
	withScripts := strings.TrimSuffix(exPkgJSON, "}")
	tests := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"Dockerfile installs the coordinate after npm ci", npm(map[string]string{"Dockerfile": docker + "npm ci && npm install absent-package\n"}), false},
		{"postinstall installs the coordinate", npm(map[string]string{"package.json": withScripts + `,"scripts":{"postinstall":"npm install absent-package"}}`}), false},
		{"Dockerfile npm install, which may rewrite the lock", npm(map[string]string{"Dockerfile": docker + "npm install\n"}), false},
		{"PowerShell installs the coordinate", npm(map[string]string{"deploy.ps1": "npm install absent-package\n"}), false},

		// Kept forms install only what a read lock holds.
		{"Dockerfile npm ci", npm(map[string]string{"Dockerfile": docker + "npm ci\n"}), true},
		{"Dockerfile npm ci --omit=dev", npm(map[string]string{"Dockerfile": docker + "npm ci --omit=dev\n"}), true},
		{"Dockerfile yarn --frozen-lockfile", map[string]string{"package.json": exPkgJSON, "yarn.lock": exYarnLock, "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY package.json yarn.lock ./\nRUN yarn --frozen-lockfile\n"}, true},
		{"Dockerfile pnpm install --frozen-lockfile", map[string]string{"package.json": exPkgJSON, "pnpm-lock.yaml": exPnpmV9, "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY package.json pnpm-lock.yaml ./\nRUN pnpm install --frozen-lockfile\n"}, true},
		{"Dockerfile npm ci, then a script that builds", npm(map[string]string{"package.json": withScripts + `,"scripts":{"build":"tsc"}}`, "Dockerfile": docker + "npm ci && npm run build\n"}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveJS(t, writeLockTree(t, tt.files), "absent-package")
			if r.Found {
				t.Fatalf("absent-package unexpectedly found")
			}
			if r.Exhaustive != tt.want {
				t.Fatalf("Exhaustive = %v, want %v (partiality %+v)", r.Exhaustive, tt.want, r.Partiality)
			}
		})
	}
}

// B2, B6: the walk never follows a symlink. A symlinked manifest, a directory linked from
// outside the build dir or into node_modules, or an installed package linked from outside the
// build dir, is not fully read; an in-tree workspace link, and a directory linked to one the walk
// reads itself, are.
func TestResolveVersions_ExhaustiveSymlinks(t *testing.T) {
	const lockV3Tools = `{"name":"app","lockfileVersion":3,"packages":{
  "": {"name":"app","dependencies":{"express":"^4.18.0"},"devDependencies":{"left-pad":"^1.3.0"}},
  "tools": {"name":"tool","dependencies":{"express":"^4.18.0"}},
  "node_modules/express": {"version":"4.18.2"},
  "node_modules/left-pad": {"version":"1.3.0"},
  "node_modules/tool": {"resolved":"tools","link":true}}}`
	files := func() map[string]string {
		return map[string]string{
			"package.json":                      exPkgJSON,
			"package-lock.json":                 lockV3Tools,
			"tools/package.json":                `{"name":"tool","dependencies":{"express":"^4.18.0"}}`,
			"node_modules/express/package.json": `{"name":"express"}`,
		}
	}
	tests := []struct {
		name string
		link func(t *testing.T, dir string) (target, link string)
		want bool
	}{
		{"in-tree workspace link", func(t *testing.T, dir string) (string, string) {
			return filepath.Join("..", "tools"), filepath.Join(dir, "node_modules", "tool")
		}, true},
		{"directory linked from outside", func(t *testing.T, dir string) (string, string) {
			return t.TempDir(), filepath.Join(dir, "linked")
		}, false},
		{"directory linked to an in-tree directory", func(t *testing.T, dir string) (string, string) {
			return "tools", filepath.Join(dir, "web")
		}, true},
		{"directory linked into node_modules", func(t *testing.T, dir string) (string, string) {
			return filepath.Join("node_modules", "express"), filepath.Join(dir, "vendor")
		}, false},
		{"symlinked package.json", func(t *testing.T, dir string) (string, string) {
			return filepath.Join("..", "tools", "package.json"), filepath.Join(dir, "web", "package.json")
		}, false},
		{"installed package linked from outside", func(t *testing.T, dir string) (string, string) {
			out := t.TempDir()
			if err := os.WriteFile(filepath.Join(out, "package.json"), []byte(`{"name":"other"}`), 0o644); err != nil {
				t.Fatal(err)
			}
			return out, filepath.Join(dir, "node_modules", "other")
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeLockTree(t, files())
			if r := resolveJS(t, dir, "absent-package"); !r.Exhaustive {
				t.Fatalf("baseline Exhaustive = false, want true (partiality %+v)", r.Partiality)
			}
			target, link := tt.link(t, dir)
			if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Skipf("symlink: %v", err)
			}
			if r := resolveJS(t, dir, "absent-package"); r.Exhaustive != tt.want {
				t.Fatalf("Exhaustive = %v, want %v", r.Exhaustive, tt.want)
			}
		})
	}
}

// TestManifestCandidates pins the JS classifier's contract: every file whose name or content
// looks like a JS manifest or lockfile is a candidate, and FullyRead is true only for a
// package.json that decodes or a lockfile the resolver discovers and reads without opaque entries.
func TestManifestCandidates(t *testing.T) {
	root := writeLockTree(t, map[string]string{
		"package.json":                      exPkgJSON,
		"package-lock.json":                 exLockV3,
		"bun.lock":                          "{\"lockfileVersion\": 1}\n",
		"deno.json":                         `{"imports":{}}`,
		"build/package-lock.json":           exLockV3,
		"broken/package.json":               `{"dependencies":{"x":1}}`,
		"deploy/app.json":                   `{"dependencies":{"absent-package":"^2"}}`,
		"templates/package.json.hbs":        `{"name":"{{name}}"}`,
		"tsconfig.json":                     `{"compilerOptions":{}}`,
		"uv.lock":                           "version = 1\n",
		"node_modules/express/package.json": `{"name":"express","dependencies":{"x":"1"}}`,
	})
	type row struct {
		Path      string
		FullyRead bool
	}
	var got []row
	for _, c := range ManifestCandidates(root) {
		rel, _ := filepath.Rel(root, c.Path)
		got = append(got, row{filepath.ToSlash(rel), c.FullyRead})
	}
	want := []row{
		{"broken/package.json", false},     // a dependency map that is not all strings
		{"build/package-lock.json", false}, // outside the directories lockFiles walks
		{"bun.lock", false},                // a format the resolver never parses
		{"deno.json", false},               // likewise
		{"deploy/app.json", false},         // a manifest by content, never parsed
		{"package-lock.json", true},
		{"package.json", true},
		{"templates/package.json.hbs", false}, // a template of a manifest
	}
	if !slices.Equal(got, want) {
		t.Errorf("candidates:\n%v\nwant:\n%v", got, want)
	}
}

// B1, B5, S2: the installed package is found under its real name whatever key or spelling the
// lock or advisory uses, so it is never read as absent.
func TestResolveVersions_RealPackageIdentity(t *testing.T) {
	const (
		aliasJSON = `{"name":"app","dependencies":{"foo":"npm:absent-package@^2.2.1"}}`
		berryLock = "__metadata:\n  version: 6\n\n\"foo@npm:absent-package@^2.2.1\":\n  version: 2.2.1\n  resolution: \"absent-package@npm:2.2.1\"\n"
		pnpmGit   = "lockfileVersion: '6.0'\n\npackages:\n\n  github.com/acme/absent-package/abc123:\n    resolution: {tarball: https://codeload.github.com/acme/absent-package/tar.gz/abc123}\n    name: absent-package\n    version: 2.2.1\n"
	)
	tests := []struct {
		name, coord string
		files       map[string]string
		version     string
	}{
		{"B1 package-lock v1 alias", "absent-package", map[string]string{"package.json": aliasJSON, "package-lock.json": `{"lockfileVersion":1,"dependencies":{"foo":{"version":"npm:absent-package@2.2.1"}}}`}, "2.2.1"},
		{"B1 package-lock v1 transitive alias", "absent-package", map[string]string{"package.json": `{"name":"app"}`, "package-lock.json": `{"lockfileVersion":1,"dependencies":{"express":{"version":"4.18.2","dependencies":{"bar":{"version":"npm:absent-package@2.2.1"}}}}}`}, "2.2.1"},
		{"B1 classic yarn alias", "absent-package", map[string]string{"package.json": aliasJSON, "yarn.lock": "# yarn lockfile v1\n\nfoo@npm:absent-package@^2.2.1:\n  version \"2.2.1\"\n"}, "2.2.1"},
		{"B1 classic yarn alias in a later descriptor", "absent-package", map[string]string{"package.json": aliasJSON, "yarn.lock": "# yarn lockfile v1\n\n\"bar@^1.0.0\", \"foo@npm:absent-package@^2.2.1\":\n  version \"2.2.1\"\n"}, "2.2.1"},
		{"B1 berry alias", "absent-package", map[string]string{"package.json": aliasJSON, "yarn.lock": berryLock}, "2.2.1"},
		{"B5 pnpm git entry named by its name field", "absent-package", map[string]string{"package.json": `{"name":"app"}`, "pnpm-lock.yaml": pnpmGit}, "2.2.1"},
		{"S2 percent-encoded scope", "%40acme/absent-package", map[string]string{"package.json": `{"name":"app"}`, "package-lock.json": `{"lockfileVersion":3,"packages":{"":{},"node_modules/@acme/absent-package":{"version":"2.2.1"}}}`}, "2.2.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveJS(t, writeLockTree(t, tt.files), tt.coord)
			if !r.Found || r.Match.Version != tt.version {
				t.Fatalf("found=%v match=%+v, want %s present at %s", r.Found, r.Match, tt.coord, tt.version)
			}
		})
	}
}

// Lockfile dev/optional flags are never evidence of absence: a dev-only locked package is present.
func TestResolveVersions_DevLockedPackagePresent(t *testing.T) {
	const devLock = `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/jest": { "version": "29.7.0", "dev": true },
    "node_modules/fsevents": { "version": "2.3.3", "optional": true }
  }
}`
	tests := []struct{ name, coord, version string }{
		{"dev flag", "jest", "29.7.0"},
		{"optional flag", "fsevents", "2.3.3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveJS(t, writeLockTree(t, map[string]string{"package.json": `{"name":"app"}`, "package-lock.json": devLock}), tt.coord)
			if !r.Found || r.Match.Version != tt.version {
				t.Fatalf("%s not reported present: found=%v match=%+v", tt.coord, r.Found, r.Match)
			}
		})
	}
}

// Lockfile maps are walked in sorted key order, so All and Match are identical across runs. Go
// randomizes map iteration, so an unsorted walk fails this within a few of the 64 runs.
func TestResolveVersions_LockWalkOrderDeterministic(t *testing.T) {
	tests := []struct {
		name, lock string
		want       []string
	}{
		{
			"package-lock v3 packages",
			`{"lockfileVersion":3,"packages":{"":{},"node_modules/zeta":{"version":"1.0.0"},"node_modules/qs":{"version":"6.5.0"},"node_modules/alpha":{"version":"1.0.0"},"node_modules/alpha/node_modules/qs":{"version":"6.11.0"},"node_modules/mid":{"version":"2.0.0"}}}`,
			[]string{"alpha@1.0.0", "qs@6.11.0", "mid@2.0.0", "qs@6.5.0", "zeta@1.0.0"},
		},
		{
			"package-lock v1 dependencies and children",
			`{"lockfileVersion":1,"dependencies":{"zeta":{"version":"1.0.0"},"qs":{"version":"6.5.0"},"alpha":{"version":"1.0.0","dependencies":{"qs":{"version":"6.11.0"},"beta":{"version":"3.0.0"},"gamma":{"version":"4.0.0"}}}}}`,
			[]string{"alpha@1.0.0", "beta@3.0.0", "gamma@4.0.0", "qs@6.11.0", "qs@6.5.0", "zeta@1.0.0"},
		},
		{
			"declared seed without a lockfile",
			"",
			[]string{"alpha@", "beta@", "mid@", "qs@", "zeta@"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"package.json": `{"name":"app"}`, "package-lock.json": tt.lock}
			if tt.lock == "" {
				files = map[string]string{"package.json": `{"name":"app","dependencies":{"zeta":"^1","qs":"^6","alpha":"^1","mid":"^2","beta":"^3"}}`}
			}
			dir := writeLockTree(t, files)
			first := resolveJS(t, dir, "qs").Match
			for i := 0; i < 64; i++ {
				r := resolveJS(t, dir, "qs")
				got := make([]string, 0, len(r.All))
				for _, d := range r.All {
					got = append(got, d.Coordinate+"@"+d.Version)
				}
				if !slices.Equal(got, tt.want) {
					t.Fatalf("run %d: All = %v, want %v", i, got, tt.want)
				}
				if !reflect.DeepEqual(r.Match, first) {
					t.Fatalf("run %d: Match = %+v, first run %+v", i, r.Match, first)
				}
			}
		})
	}
}
