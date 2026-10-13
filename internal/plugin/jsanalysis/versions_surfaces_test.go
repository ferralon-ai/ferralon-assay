package jsanalysis

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	rootLockJSON5  = `{"lockfileVersion": 3, "packages": {"": {"name": "app"}, "node_modules/json5": {"version": "1.0.2"}}}`
	otherLockJSON5 = `{"lockfileVersion": 3, "packages": {"node_modules/json5": {"version": "2.2.3"}}}`
	copyJSON5      = `{"name": "json5", "version": "2.2.3"}`
)

// mustVetoedJS asserts the coordinate is found UNRESOLVED and the result is partial.
func mustVetoedJS(t *testing.T, dir, coord string) {
	t.Helper()
	res := resolveJS(t, dir, coord)
	mustUnresolved(t, res)
	if res.Partiality.Complete {
		t.Fatalf("result must be partial; got %+v", res.Partiality)
	}
}

// Every JavaScript install surface the resolver does not read vetoes the root lock's pin,
// wherever the shared walk finds it and whatever case its name is in, and so does a file only
// its content marks as one.
func TestResolveVersions_UnreadInstallSurfaceVetoes(t *testing.T) {
	for name, tc := range map[string]struct{ file, body string }{
		"build dir lock":        {"build/package-lock.json", otherLockJSON5},
		"vendor dir lock":       {"vendor/x/package-lock.json", otherLockJSON5},
		"action lock":           {".github/actions/a/package-lock.json", otherLockJSON5},
		"dist dir yarn lock":    {"dist/yarn.lock", "# yarn lockfile v1\n\njson5@^2:\n  version \"2.2.3\"\n"},
		"yarn lock under .yarn": {".yarn/sub/yarn.lock", "# yarn lockfile v1\n\njson5@^2:\n  version \"2.2.3\"\n"},
		"bun lock":              {"svc/bun.lock", `{"lockfileVersion": 1, "packages": {"json5": ["json5@2.2.3"]}}`},
		"bun binary lock":       {"svc/bun.lockb", "\x00bun"},
		"deno lock":             {"svc/deno.lock", `{"version": "4", "npm": {"json5@2.2.3": {}}}`},
		"deno manifest":         {"svc/deno.json", `{"imports": {"json5": "npm:json5@2.2.3"}}`},
		"pnpm yml lock":         {"svc/pnpm-lock.yml", "lockfileVersion: '9.0'\n"},
		"other lock":            {"svc/deps.lock", "json5 2.2.3\n"},
		"Package-Lock case":     {"svc/Package-Lock.json", otherLockJSON5},
		"YARN.lock case":        {"svc/YARN.lock", "# yarn lockfile v1\n"},
		"templated lock":        {"svc/package-lock.json.tmpl", otherLockJSON5},
		"pnpmfile":              {".pnpmfile.cjs", "module.exports = { hooks: {} }\n"},
		"rewrite config":        {"pnpm-workspace.yaml", "packageExtensions:\n  a:\n    dependencies:\n      json5: 2.2.3\n"},
		"lock content":          {"svc/frozen.json", otherLockJSON5},
		"manifest content":      {"svc/deps.json5", `{"dependencies": {"json5": "2.2.3"}}`},
		"pnpm lock content":     {"svc/lock", "lockfileVersion: '9.0'\nimporters:\n  .: {}\n"},
		"store copy":            {".pnpm-store/v3/files/ab/cdef0123", copyJSON5},
		"store package.json":    {".pnpm-store/v3/tmp/json5/package.json", copyJSON5},
		"yarn cache copy":       {".yarn/cache/json5/package.json", copyJSON5},
		"git dir lock":          {".git/package-lock.json", otherLockJSON5},
		"undecodable manifest":  {"svc/package.json", "{not json"},
		"unreadable copy":       {"node_modules/json5/package.json", "{not json"},
		"BUN.LOCKB case":        {"svc/BUN.LOCKB", "\x00bun"},
		"Deno.JSON case":        {"svc/Deno.JSON", `{"imports": {}}`},
		"templated name only":   {"svc/yarn.lock.tmpl", "{{ .Lock }}\n"},
		"yarn v1 content":       {"svc/frozen-yarn", "# yarn lockfile v1\n\njson5@^2:\n  version \"2.2.3\"\n"},
		"yarn berry content":    {"svc/frozen-berry", "__metadata:\n  version: 8\n"},
	} {
		t.Run(name, func(t *testing.T) {
			mustVetoedJS(t, writeLockTree(t, map[string]string{
				"package-lock.json": rootLockJSON5,
				tc.file:             tc.body,
			}), "json5")
		})
	}
}

// Each install surface name vetoes by its name alone, holding nothing its content would be
// recognised by, in a directory the resolver's own walk does not enter.
func TestResolveVersions_SurfaceNameAloneVetoes(t *testing.T) {
	for _, name := range []string{
		"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
		"pnpm-lock.yml", "bun.lock", "bun.lockb", "deno.lock", "deno.json", "deno.jsonc",
		"bower.json", "import_map.json",
	} {
		t.Run(name, func(t *testing.T) {
			mustVetoedJS(t, writeLockTree(t, map[string]string{
				"package-lock.json": rootLockJSON5,
				"build/" + name:     "{}\n",
			}), "json5")
		})
	}
}

// A package installed in a node_modules directory is another copy of it, in every layout npm,
// yarn and pnpm install: a copy at another version than the lock's leaves the pin
// unresolved.
func TestResolveVersions_InstalledCopiesRead(t *testing.T) {
	for name, file := range map[string]string{
		"hoisted":        "node_modules/json5/package.json",
		"nested":         "node_modules/a/node_modules/json5/package.json",
		"pnpm":           "node_modules/.pnpm/json5@2.2.3/node_modules/json5/package.json",
		"yarn unplugged": ".yarn/unplugged/json5-npm-2.2.3-abc/node_modules/json5/package.json",
		"workspace":      "packages/web/node_modules/json5/package.json",
	} {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{"package-lock.json": rootLockJSON5, file: copyJSON5}
			if name == "nested" {
				files["node_modules/a/package.json"] = `{"name": "a", "version": "1.0.0"}`
			}
			mustUnresolved(t, resolveJS(t, writeLockTree(t, files), "json5"))
		})
	}
	scoped := writeLockTree(t, map[string]string{
		"package-lock.json":                     `{"lockfileVersion": 3, "packages": {"node_modules/@s/p": {"version": "1.0.0"}}}`,
		"node_modules/@s/p/package.json":        `{"name": "@s/p", "version": "2.0.0"}`,
		"node_modules/@s/other/package.json":    `{"version": "1.0.0"}`,
		"node_modules/.bin/placeholder":         "",
		"node_modules/.package-lock.json":       rootLockJSON5,
		"node_modules/no-manifest/index.js":     "",
		"node_modules/unversioned/package.json": `{"name": "unversioned"}`,
	})
	mustUnresolved(t, resolveJS(t, scoped, "@s/p"))
	mustUnresolved(t, resolveJS(t, scoped, "unversioned"))
	if res := resolveJS(t, scoped, "@s/other"); !res.Found || res.Match.Version != "1.0.0" {
		t.Fatalf("a copy with no name is named by its directory; got %+v", res.Match)
	}
}

// Surfaces the resolver reads in full do not veto: the lock's pin resolves, complete, beside
// the project's package.json, an installed copy at the same version, a pnpm symlink, registry
// configuration, CI and documentation files, and VCS metadata.
func TestResolveVersions_FullyReadSurfacesResolve(t *testing.T) {
	dir := writeLockTree(t, map[string]string{
		"package-lock.json":               rootLockJSON5,
		"package.json":                    `{"name": "app", "version": "1.0.0", "dependencies": {"json5": "^1.0.0"}}`,
		"packages/web/package.json":       `{"name": "web", "dependencies": {"json5": "^1.0.0"}}`,
		"node_modules/json5/package.json": `{"name": "json5", "version": "1.0.2"}`,
		".npmrc":                          "registry=https://registry.npmjs.org/\n",
		".github/workflows/ci.yml":        "on: push\njobs: {}\n",
		"docs/install.md":                 "Pin `\"json5\": \"2.2.3\"` in package.json.\n",
		"tsconfig.json":                   `{"compilerOptions": {"strict": true}}`,
		".git/HEAD":                       "ref: refs/heads/main\n",
		".yarn/releases/yarn-4.0.0.cjs":   "module.exports = {}\n",
	})
	if err := os.Symlink(filepath.Join(dir, "node_modules", "json5"), filepath.Join(dir, "node_modules", "linked")); err != nil {
		t.Fatal(err)
	}
	res := resolveJS(t, dir, "json5")
	mustMatch(t, res, "1.0.2")
	if !res.Partiality.Complete {
		t.Fatalf("result must be complete; got %+v", res.Partiality)
	}
}

// A node_modules that is a symlink leaving the build dir is an unread surface.
func TestResolveVersions_NodeModulesLinkOutsideVetoes(t *testing.T) {
	outside := writeLockTree(t, map[string]string{"json5/package.json": copyJSON5})
	dir := writeLockTree(t, map[string]string{"package-lock.json": rootLockJSON5})
	if err := os.Symlink(outside, filepath.Join(dir, "node_modules")); err != nil {
		t.Fatal(err)
	}
	mustVetoedJS(t, dir, "json5")
}

// A package link in node_modules that leaves the build dir (an npm link), scoped or not, is an
// unread copy.
func TestResolveVersions_PackageLinkOutsideVetoes(t *testing.T) {
	outside := writeLockTree(t, map[string]string{"json5/package.json": copyJSON5})
	for name, link := range map[string]string{
		"unscoped": "node_modules/json5",
		"scoped":   "node_modules/@s/json5",
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeLockTree(t, map[string]string{"package-lock.json": rootLockJSON5, "node_modules/@s/.keep": ""})
			if err := os.Symlink(filepath.Join(outside, "json5"), filepath.Join(dir, filepath.FromSlash(link))); err != nil {
				t.Fatal(err)
			}
			mustVetoedJS(t, dir, "json5")
		})
	}
}
