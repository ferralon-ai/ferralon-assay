package jsanalysis

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestReachability_Strict: a clear practical mode makes on an assumption the lane infers is withheld
// in strict mode, with the lane's usual no-ingress limit in its place; a clear on no assumption, or on
// the caller's own entry-point declaration, stands in both. Practical output is the same whether or
// not a strict run shares its caches.
func TestReachability_Strict(t *testing.T) {
	const (
		sink = "npm:idle@1.0.0#bad"
		purl = "pkg:npm/idle@1.0.0"
		app  = "const used = require('used');\nused.make().go();\n"
	)
	idle := closurePkg("idle", map[string]string{"index.js": "exports.bad = function bad() {};\n"})
	usedWith := func(src string) *depPkg { return closurePkg("used", map[string]string{"index.js": src}) }
	const usedPlain = "exports.make = function make() { return { go() {} }; };\n"
	for _, tc := range []struct {
		name     string
		first    map[string]string
		pkgs     []*depPkg
		unread   []string
		override string
		// assumed is a fragment of the assumption practical names on its clear, "" for none.
		assumed string
		// strictClears is whether strict still clears.
		strictClears bool
	}{
		{name: "nothing loads it", first: map[string]string{"index.js": app}, pkgs: []*depPkg{usedWith(usedPlain), idle}, strictClears: true},
		{name: "computed load in a loaded package", first: map[string]string{"index.js": app},
			pkgs:    []*depPkg{usedWith("exports.make = function make(n) { require(n); return { go() {} }; };\n"), idle},
			assumed: "computed module loads in used are assumed"},
		{name: "computed load in first-party code", first: map[string]string{"index.js": app + "module.exports = n => require(n);\n"},
			pkgs: []*depPkg{usedWith(usedPlain), idle}, assumed: "computed module loads in first-party code are assumed"},
		{name: "unread loaded package", first: map[string]string{"index.js": app}, pkgs: []*depPkg{usedWith(usedPlain), idle}, unread: []string{"used"},
			assumed: "the code of used, which is not read, is assumed"},
		{name: "declared entry-point override", first: map[string]string{"index.js": app, "package.json": `{"name":"app","version":"1.0.0","scripts":{"start":"tool --serve"}}`},
			pkgs:     []*depPkg{usedWith(usedPlain), idle, closurePkg("tool", map[string]string{"package.json": `{"name":"tool","version":"1.0.0","bin":{"tool":"bin/tool.js"}}`, "bin/tool.js": "require('idle');\n"})},
			override: "!js:bin=bin:tool", assumed: "!js:bin=bin:tool", strictClears: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDepFixture(t, tc.first, tc.pkgs...)
			kept := *f
			kept.pkgs = slices.DeleteFunc(slices.Clone(f.pkgs), func(p *depPkg) bool { return slices.Contains(tc.unread, p.name) })
			cache := kept.diskCache(t)
			run := func(strict bool) plugin.ReachabilityResult {
				t.Helper()
				req := plugin.ReachabilityRequest{BuildDir: f.dir, Symbols: []string{sink}, Package: purl, DependencyCache: cache, Strict: strict}
				if tc.override != "" {
					req.EntryOverride = jsOverride(t, tc.override)
				}
				res, err := Reachability(context.Background(), req)
				if err != nil {
					t.Fatal(err)
				}
				return res
			}

			practical := run(false)
			if practical.Refutation == nil {
				t.Fatalf("practical does not clear; partiality %+v", practical.Partiality)
			}
			named := slices.ContainsFunc(practical.Refutation.Assumptions, func(a string) bool { return tc.assumed != "" && strings.Contains(a, tc.assumed) })
			if tc.assumed != "" && !named {
				t.Errorf("practical assumptions %q do not name %q", practical.Refutation.Assumptions, tc.assumed)
			}
			if tc.assumed == "" && len(practical.Refutation.Assumptions) != 0 {
				t.Errorf("practical assumptions = %q, want none", practical.Refutation.Assumptions)
			}

			strict := run(true)
			if got := strict.Refutation != nil; got != tc.strictClears {
				t.Fatalf("strict clears = %v, want %v; refutation %+v partiality %+v", got, tc.strictClears, strict.Refutation, strict.Partiality)
			}
			if tc.strictClears {
				if !reflect.DeepEqual(strict.Refutation, practical.Refutation) {
					t.Errorf("strict refutation %+v, want practical's %+v", strict.Refutation, practical.Refutation)
				}
			} else {
				if !slices.Contains(strict.Partiality.Reasons, plugin.PartialReasonNoIngress) {
					t.Errorf("a withheld clear keeps the no-ingress limit; got %+v", strict.Partiality)
				}
				for _, s := range strict.Partiality.Scoped {
					if len(s.Targets) != 0 {
						t.Errorf("strict scopes %s to %q; with no bounded closure every limit counts against every advisory", s.Reason, s.Targets)
					}
				}
			}

			if again := run(false); !reflect.DeepEqual(again, practical) {
				t.Errorf("practical after a strict run = %+v, want %+v", again, practical)
			}
		})
	}
}

// TestCallGraph_StrictUnscoped: on a build whose hidden loaded code practical mode scopes to the
// closure, strict mode leaves every dependency limit unscoped.
func TestCallGraph_StrictUnscoped(t *testing.T) {
	f := newDepFixture(t, map[string]string{"index.js": "const used = require('used');\nused.run();\n"},
		closurePkg("used", nil), closurePkg("idle", nil))
	kept := *f
	kept.pkgs = slices.DeleteFunc(slices.Clone(f.pkgs), func(p *depPkg) bool { return p.name == "used" })
	cache := kept.diskCache(t)
	run := func(strict bool) plugin.CallGraphResult {
		t.Helper()
		res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: f.dir, DependencyCache: cache, Strict: strict})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	scoped := func(res plugin.CallGraphResult) bool {
		return slices.ContainsFunc(res.Partiality.Scoped, func(s plugin.ScopedReason) bool { return len(s.Targets) != 0 })
	}
	if practical := run(false); !scoped(practical) {
		t.Fatalf("practical scopes no limit to the closure; the fixture tests nothing (%+v)", practical.Partiality)
	}
	if strict := run(true); scoped(strict) {
		t.Errorf("strict scopes a limit to the closure: %+v", strict.Partiality)
	}
}

// TestResolveVersions_Strict: an answer practical mode gives on an install it takes to honour the
// lockfile, or to be inactive, is withheld in strict mode as an unreadable install is.
func TestResolveVersions_Strict(t *testing.T) {
	const (
		lock = `{"name":"app","lockfileVersion":3,"packages":{` +
			`"":{"name":"app","version":"1.0.0","dependencies":{"express":"^4.19.0"}},` +
			`"node_modules/express":{"version":"4.19.2"}}}`
		pkg = `{"name":"app","version":"1.0.0","dependencies":{"express":"^4.19.0"}}`
	)
	for _, tc := range []struct {
		name       string
		files      map[string]string
		annotation string
	}{
		{name: "install over the whole tree", files: map[string]string{"Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY . /app\nRUN npm install\n"}, annotation: AnnotationInstallHonoursLock},
		{name: "inactive install surface", files: map[string]string{"scripts/setup.js": "const { execSync } = require('child_process')\nexecSync('npm install express@4.19.2', { stdio: 'inherit' })\n"}, annotation: plugin.AnnotationInstallSurfaceInactive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"package-lock.json": lock, "package.json": pkg}
			for k, v := range tc.files {
				files[k] = v
			}
			dir := writeLockTree(t, files)
			practical := resolveJS(t, dir, "express")
			if !practical.Match.Resolved || !slices.ContainsFunc(practical.Annotations, func(a plugin.Annotation) bool { return a.Reason == tc.annotation }) {
				t.Fatalf("practical = %+v, want resolved with a %s annotation", practical, tc.annotation)
			}
			strict, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: dir, Coordinate: "express", Strict: true})
			if err != nil {
				t.Fatal(err)
			}
			if strict.Match.Resolved || strict.Exhaustive || len(strict.Annotations) != 0 {
				t.Errorf("strict = %+v, want unresolved, not exhaustive, with no annotation", strict)
			}
			if !slices.Contains(strict.Partiality.Reasons, plugin.PartialReasonToolFailure) {
				t.Errorf("strict partiality = %+v, want tool_failure", strict.Partiality)
			}
		})
	}
}
