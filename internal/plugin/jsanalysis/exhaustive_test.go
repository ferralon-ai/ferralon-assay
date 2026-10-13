package jsanalysis

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
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
		{"S1 nested workspace the lock records", map[string]string{"package.json": exPkgJSON, "package-lock.json": lockV3Tools, "tools/package.json": toolJSON}, true},
		{"S1 classic yarn workspace named by the root", map[string]string{"package.json": yarnWorkspaces, "yarn.lock": exYarnLock, "tools/package.json": toolJSON}, true},
		{"S1 classic yarn project not a workspace", map[string]string{"package.json": exPkgJSON, "yarn.lock": exYarnLock, "tools/package.json": toolJSON}, false},
		{"S1 stale lock beside a covering one", map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "yarn.lock": yarnStale}, false},
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

// B2: WalkDir does not follow a symlinked directory, so whatever it holds is unread.
func TestResolveVersions_ExhaustiveSymlinkedDir(t *testing.T) {
	dir := writeLockTree(t, map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3})
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "linked")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if r := resolveJS(t, dir, "absent-package"); r.Exhaustive {
		t.Fatalf("Exhaustive = true with a symlinked directory in the build dir")
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
