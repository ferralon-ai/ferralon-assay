package jsanalysis

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// The rows below use a first-party program that loads nothing: a first-party load of any package
// already withholds run-wide, which would hide whether the layout itself withholds.

func vetoDep(version string) *depPkg {
	return &depPkg{
		path: "node_modules/q", name: "q", version: version,
		files: map[string]string{
			"package.json": `{"name":"q","version":"` + version + `","main":"index.js"}`,
			"index.js":     "exports.run = function run() {};\n",
		},
	}
}

func ciWorkflow(steps string) string {
	return "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n" + steps
}

// vetoFixture is a single-region npm build pinning q@2.0.0 plus extra, with q's tarball in the
// store.
func vetoFixture(t *testing.T, extra map[string]string) (string, artifactcache.Store) {
	t.Helper()
	files := map[string]string{"index.js": guardIdle}
	maps.Copy(files, extra)
	f := newDepFixture(t, files, vetoDep("2.0.0"))
	return f.dir, f.memStore()
}

// nestedVetoFixture is a build with two npm lock roots, the build root and web/, each pinning its
// own copy of q, plus extra.
func nestedVetoFixture(t *testing.T, extra map[string]string) (string, artifactcache.Store) {
	t.Helper()
	outer := vetoDep("2.0.0")
	inner := vetoDep("2.1.0")
	inner.tgz = buildTgz(t, inner.files)
	lock, err := json.Marshal(map[string]any{"name": "web", "lockfileVersion": 3, "requires": true, "packages": map[string]any{
		"":               map[string]any{"name": "web", "version": "1.0.0"},
		"node_modules/q": map[string]any{"version": inner.version, "resolved": "https://registry.npmjs.org/q/-/q-2.1.0.tgz", "integrity": sri(inner.tgz)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"index.js":              guardIdle,
		"web/index.js":          guardIdle,
		"web/package.json":      `{"name":"web","version":"1.0.0"}`,
		"web/package-lock.json": string(lock),
	}
	maps.Copy(files, extra)
	f := newDepFixture(t, files, outer)
	store := artifactcache.NewMemStore(map[artifactcache.Ref][]byte{
		f.ref(outer): outer.tgz,
		f.ref(inner): inner.tgz,
	})
	return f.dir, store
}

func runWideWithheld(cg plugin.CallGraphResult) bool {
	return hasReason(cg.Partiality, plugin.PartialReasonUninspectablePackage)
}

// TestLayoutVeto: an install surface the lane does not read, or a script that may install a
// package no lock read here records, leaves the dependency layout incomplete, so the call graph
// withholds run-wide. Each targeting row resolves on a layout that ignores the veto.
func TestLayoutVeto(t *testing.T) {
	const (
		pkgJSON = `{"name":"app","version":"1.0.0"}`
		hook    = "#!/bin/sh\nnpm install left-pad\n"
	)
	for _, tc := range []struct {
		name     string
		nested   bool
		files    map[string]string
		withheld bool
	}{
		{"single_region_ci_install", false, map[string]string{".github/workflows/ci.yml": ciWorkflow("      - run: npm ci && npm install q@1.0.0\n")}, true},
		{"nested_ci_install", true, map[string]string{".github/workflows/ci.yml": ciWorkflow("      - run: npm install q@1.0.0\n        working-directory: web\n")}, true},
		{"control_ci_installs_nothing_extra", false, map[string]string{".github/workflows/ci.yml": ciWorkflow("      - run: npm ci\n")}, false},
		{"control_nested_ci_installs_nothing_extra", true, map[string]string{".github/workflows/ci.yml": ciWorkflow("      - run: npm ci\n      - run: npm ci\n        working-directory: web\n")}, false},
		{"control_no_surface", false, nil, false},
		{"control_nested_no_surface", true, nil, false},

		// One row per veto form.
		{"lifecycle_postinstall", false, map[string]string{"package.json": `{"name":"app","version":"1.0.0","scripts":{"postinstall":"npm install --no-save q@1.0.0"}}`}, true},
		{"dockerfile_install", false, map[string]string{"Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY package.json package-lock.json ./\nRUN npm ci && npm install q@1.0.0\n"}, true},
		{"rebound_lock", false, map[string]string{".github/workflows/ci.yml": ciWorkflow("      - run: sed -i s/2.0.0/1.0.0/ package-lock.json && npm ci\n")}, true},
		{"live_sample_hook", false, map[string]string{".git/hooks/pre-commit.sample": hook, "package.json": `{"name":"app","version":"1.0.0","scripts":{"x":"sh .git/hooks/pre-commit.sample"}}`}, true},
		{"unread_foreign_lock", false, map[string]string{"bun.lockb": "\x00bun lockfile\x00"}, true},
		{"unread_install_hook", false, map[string]string{".pnpmfile.cjs": "module.exports = {};\n"}, true},
		{"unread_rewrite_config", false, map[string]string{".npmrc": "# overrides applied by a wrapper\nregistry=https://registry.npmjs.org/\n"}, true},
		{"unread_escaped_hook_key", false, map[string]string{".npmrc": "\"pnpm\\u0066ile\"=./hook.cjs\n"}, true},
		{"unread_unparsable_npmrc_key", false, map[string]string{".npmrc": "\"bad\\q\"=1\n"}, true},
		{"control_npmrc_registry_only", false, map[string]string{".npmrc": "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n"}, false},
		{"unread_member_manifest", false, map[string]string{"package.json": `{"name":"app","version":"1.0.0","private":true,"workspaces":["packages/*"]}`, "packages/a/package.json": "{"}, true},
		{"unread_lock_in_skipped_dir", false, map[string]string{"vendor/tool/package.json": pkgJSON, "vendor/tool/package-lock.json": `{"name":"tool","lockfileVersion":3,"packages":{"":{"name":"tool"}}}`}, true},
		{"unread_templated_manifest", false, map[string]string{"package.json.tmpl": `{"name":"app","version":"1.0.0","dependencies":{"q":"{{ .Q }}"}}`}, true},
		{"unread_cached_copy", false, map[string]string{".pnpm-store/v3/q/package.json": `{"name":"q","version":"1.0.0"}`}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var (
				dir   string
				store artifactcache.Store
			)
			if tc.nested {
				dir, store = nestedVetoFixture(t, tc.files)
			} else {
				dir, store = vetoFixture(t, tc.files)
			}
			cg := withDeps(t, dir, store)
			if got := runWideWithheld(cg); got != tc.withheld {
				t.Errorf("withheld run-wide = %v, want %v; got %+v", got, tc.withheld, cg.Partiality)
			}
			if !tc.withheld && !cg.Partiality.Complete {
				t.Errorf("control must stay complete; got %+v", cg.Partiality)
			}
		})
	}
}

// TestLayoutVeto_RunCache: the scan the versions op and the call graph share through the run
// cache gives each build its own answer, in either order.
func TestLayoutVeto_RunCache(t *testing.T) {
	vetoed := newDepFixture(t, map[string]string{"index.js": guardIdle, ".github/workflows/ci.yml": ciWorkflow("      - run: npm ci && npm install q@1.0.0\n")}, vetoDep("2.0.0"))
	clean := newDepFixture(t, map[string]string{"index.js": guardIdle}, vetoDep("2.0.0"))
	vCache, cCache := vetoed.diskCache(t), clean.diskCache(t)

	graph := func(ctx context.Context, f *depFixture, cache string) plugin.CallGraphResult {
		t.Helper()
		cg, err := callGraphFor(ctx, f.dir, cache)
		if err != nil {
			t.Fatal(err)
		}
		return cg
	}
	versions := func(ctx context.Context, f *depFixture) plugin.DependencyVersionResult {
		t.Helper()
		res, err := ResolveDependencyVersions(ctx, plugin.ResolveVersionsRequest{BuildDir: f.dir, Coordinate: "q"})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	newCtx := func() (context.Context, string) {
		dir := t.TempDir()
		return WithRunCacheDir(context.Background(), dir), dir
	}

	t.Run("versions_then_graph", func(t *testing.T) {
		ctx, _ := newCtx()
		if res := versions(ctx, vetoed); res.Exhaustive || res.Partiality.Complete {
			t.Errorf("versions op must withhold on the vetoed build; got %+v", res)
		}
		if cg := graph(ctx, vetoed, vCache); !runWideWithheld(cg) {
			t.Errorf("call graph must withhold after the versions op cached the scan; got %+v", cg.Partiality)
		}
	})
	t.Run("graph_then_versions", func(t *testing.T) {
		ctx, _ := newCtx()
		if cg := graph(ctx, vetoed, vCache); !runWideWithheld(cg) {
			t.Errorf("call graph must withhold; got %+v", cg.Partiality)
		}
		if res := versions(ctx, vetoed); res.Exhaustive || res.Partiality.Complete {
			t.Errorf("versions op must withhold after the call graph cached the scan; got %+v", res)
		}
	})
	t.Run("keys_do_not_cross_vetoed_first", func(t *testing.T) {
		ctx, _ := newCtx()
		_ = versions(ctx, vetoed)
		if cg := graph(ctx, clean, cCache); runWideWithheld(cg) || !cg.Partiality.Complete {
			t.Errorf("a clean build must not read a vetoed build's scan; got %+v", cg.Partiality)
		}
	})
	t.Run("keys_do_not_cross_clean_first", func(t *testing.T) {
		ctx, _ := newCtx()
		_ = versions(ctx, clean)
		if cg := graph(ctx, vetoed, vCache); !runWideWithheld(cg) {
			t.Errorf("a vetoed build must not read a clean build's scan; got %+v", cg.Partiality)
		}
	})
	t.Run("graph_caches_scan", func(t *testing.T) {
		ctx, dir := newCtx()
		_ = graph(ctx, clean, cCache)
		if ents, err := filepath.Glob(filepath.Join(dir, "installsurfaces-*")); err != nil || len(ents) != 1 {
			t.Fatalf("the call graph must cache the scan: one installsurfaces entry expected, got %v (%v)", ents, err)
		}
	})
	// A corrupt entry is not an answer: both callers recompute and the vetoed build still withholds.
	for _, bad := range []struct{ name, content string }{
		{"corrupt_entry_garbage", "not json"},
		{"corrupt_entry_empty", ""},
		{"corrupt_entry_truncated", `{"Unread":tr`},
	} {
		t.Run(bad.name, func(t *testing.T) {
			ctx, dir := newCtx()
			_ = versions(ctx, vetoed)
			ents, err := filepath.Glob(filepath.Join(dir, "installsurfaces-*"))
			if err != nil || len(ents) != 1 {
				t.Fatalf("one installsurfaces entry expected, got %v (%v)", ents, err)
			}
			if err := os.WriteFile(ents[0], []byte(bad.content), 0o644); err != nil {
				t.Fatal(err)
			}
			if cg := graph(ctx, vetoed, vCache); !runWideWithheld(cg) {
				t.Errorf("call graph must recompute past a corrupt entry and withhold; got %+v", cg.Partiality)
			}
			if res := versions(ctx, vetoed); res.Exhaustive || res.Partiality.Complete {
				t.Errorf("versions op must recompute past a corrupt entry and withhold; got %+v", res)
			}
		})
	}
	t.Run("scan_is_cached", func(t *testing.T) {
		ctx, dir := newCtx()
		_ = versions(ctx, clean)
		ents, err := filepath.Glob(filepath.Join(dir, "installsurfaces-*"))
		if err != nil || len(ents) != 1 {
			t.Fatalf("one installsurfaces entry expected, got %v (%v)", ents, err)
		}
		if _, err := os.Stat(ents[0]); err != nil {
			t.Fatal(err)
		}
	})
}

// TestLayoutVeto_NoLock: a build with no lock at all still honours the veto.
func TestLayoutVeto_NoLock(t *testing.T) {
	for _, tc := range []struct {
		name     string
		files    map[string]string
		withheld bool
	}{
		{"ci_install_without_lock", map[string]string{".github/workflows/ci.yml": ciWorkflow("      - run: npm install q@1.0.0\n")}, true},
		{"control_no_surface_without_lock", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"index.js": guardIdle, "package.json": `{"name":"app","version":"1.0.0"}`}
			maps.Copy(files, tc.files)
			cg := withDeps(t, writeProgram(t, files), artifactcache.NewMemStore(nil))
			if got := runWideWithheld(cg); got != tc.withheld {
				t.Errorf("withheld run-wide = %v, want %v; got %+v", got, tc.withheld, cg.Partiality)
			}
			if !tc.withheld && !cg.Partiality.Complete {
				t.Errorf("control must stay complete; got %+v", cg.Partiality)
			}
		})
	}
}

// TestLayoutVeto_Yarn: on a yarn classic build, a frozen yarn install withholds through the layout,
// since yarn 1 does not hold a workspace to its lock under --frozen-lockfile.
func TestLayoutVeto_Yarn(t *testing.T) {
	const yarnLock = "# yarn lockfile v1\n"
	for _, tc := range []struct {
		name     string
		files    map[string]string
		withheld bool
	}{
		{"yarn_frozen_install", map[string]string{".github/workflows/ci.yml": ciWorkflow("      - run: yarn install --frozen-lockfile\n")}, true},
		{"yarn_frozen_bare", map[string]string{".github/workflows/ci.yml": ciWorkflow("      - run: yarn --frozen-lockfile\n")}, true},
		{"control_yarn_no_surface", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"index.js": guardIdle, "package.json": `{"name":"app","version":"1.0.0"}`, "yarn.lock": yarnLock}
			maps.Copy(files, tc.files)
			cg := withDeps(t, writeProgram(t, files), artifactcache.NewMemStore(nil))
			if got := runWideWithheld(cg); got != tc.withheld {
				t.Errorf("withheld run-wide = %v, want %v; got %+v", got, tc.withheld, cg.Partiality)
			}
			if !tc.withheld && !cg.Partiality.Complete {
				t.Errorf("control must stay complete; got %+v", cg.Partiality)
			}
		})
	}
}
