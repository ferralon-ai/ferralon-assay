package jsanalysis

import (
	"context"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// qsLock is an npm v3 lockfile: qs depends on side-channel, whose nested object-inspect
// (not the hoisted one) depends on nested-only. Nothing declares json5, but it is hoisted,
// so any package's require('json5') resolves to it.
const qsLock = `{"lockfileVersion":3,"packages":{
"":{"name":"app","dependencies":{"qs":"^6"}},
"node_modules/qs":{"dependencies":{"side-channel":"^1"}},
"node_modules/side-channel":{"dependencies":{"object-inspect":"^1"}},
"node_modules/side-channel/node_modules/object-inspect":{"dependencies":{"nested-only":"1"}},
"node_modules/object-inspect":{},
"node_modules/nested-only":{},
"node_modules/json5":{}
}}`

// jsonOnlyLock installs json5 and nothing else, so json5's resolution reach is itself.
const jsonOnlyLock = `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/json5":{}}}`

// scopedFor returns the scoped limit for (reason, npm package pkg), or nil.
func scopedFor(p plugin.Partiality, reason, pkg string) *plugin.ScopedReason {
	for i := range p.Scoped {
		if p.Scoped[i].Reason == reason && p.Scoped[i].Package == npmPURL(pkg) {
			return &p.Scoped[i]
		}
	}
	return nil
}

func hasScopedReason(p plugin.Partiality, reason string) bool {
	for _, sr := range p.Scoped {
		if sr.Reason == reason {
			return true
		}
	}
	return false
}

type scopedWant struct {
	reason, pkg, path string
	targets           []string // nil = unbounded
}

type edgeWant struct {
	caller, callee string
}

// TestCallGraph_LoadShapes pins how each load shape is accounted for: a scoped limit
// against one package, a run-wide limit, real edges, or nothing.
func TestCallGraph_LoadShapes(t *testing.T) {
	const (
		uninspectable = plugin.PartialReasonUninspectablePackage
		computedReq   = plugin.PartialReasonComputedRequireSpecifier
	)
	cases := []struct {
		name     string
		files    map[string]string
		scoped   []scopedWant
		runWide  []string
		absent   []string // reasons that must appear neither run-wide nor scoped
		edges    []edgeWant
		noDidNot bool // no did_not_run reason at all
	}{
		{
			name: "package Targets are its resolution reach, undeclared hoisted packages included",
			files: map[string]string{
				"package-lock.json": qsLock,
				"app.js":            "const qs = require('qs');\nfunction f(s) { return qs.parse(s); }\nf(process.argv);\n",
			},
			scoped: []scopedWant{{uninspectable, "qs", "app.js", []string{
				"pkg:npm/json5", "pkg:npm/nested-only", "pkg:npm/object-inspect", "pkg:npm/qs", "pkg:npm/side-channel",
			}}},
		},
		{
			name: "scoped package without a lockfile is unbounded",
			files: map[string]string{
				"src/app.js": "const core = require('@babel/core');\nfunction f(s) { return core.transform(s); }\nf(process.argv);\n",
			},
			scoped: []scopedWant{{uninspectable, "@babel/core", "src/app.js", nil}},
		},
		{
			name: "first importing module in file order locates the limit",
			files: map[string]string{
				"package-lock.json": qsLock,
				"b.js":              "const qs = require('qs');\nfunction g(s) { return qs.parse(s); }\ng(process.argv);\n",
				"a.js":              "import qs from 'qs';\nfunction f(s) { return qs.parse(s); }\nf(process.argv);\n",
			},
			scoped: []scopedWant{{uninspectable, "qs", "a.js", []string{
				"pkg:npm/json5", "pkg:npm/nested-only", "pkg:npm/object-inspect", "pkg:npm/qs", "pkg:npm/side-channel",
			}}},
		},
		{
			name:     "inert builtin",
			files:    map[string]string{"app.js": "const fs = require('fs');\nconst p = require('node:path');\nfunction f(s) { return fs.readFileSync(p.join(s)); }\nf(process.argv);\n"},
			noDidNot: true,
		},
		{
			name:    "code-loading builtin stays run-wide",
			files:   map[string]string{"app.js": "const vm = require('vm');\nfunction f(s) { return vm.runInNewContext(s); }\nf(process.argv);\n"},
			runWide: []string{uninspectable},
		},
		{
			name:    "unknown node: builtin stays run-wide",
			files:   map[string]string{"app.js": "const x = require('node:future');\nfunction f(s) { return x.go(s); }\nf(process.argv);\n"},
			runWide: []string{uninspectable},
		},
		{
			name: "installed polyfill shadows the builtin",
			files: map[string]string{
				"node_modules/events/package.json": `{"name":"events"}`,
				"app.js":                           "const EventEmitter = require('events');\nfunction f() { return new EventEmitter(); }\nf();\n",
			},
			scoped: []scopedWant{{uninspectable, "events", "app.js", nil}},
		},
		{
			name: "package self-reference resolves first-party",
			files: map[string]string{
				"package.json": `{"name":"app","exports":{"./util":"./lib/util.js"}}`,
				"lib/util.js":  "function trim(s) { return s.trim(); }\nmodule.exports = { trim };\n",
				"app.js":       "const { trim } = require('app/util');\nfunction f(s) { return trim(s); }\nf(process.argv);\n",
			},
			edges:    []edgeWant{{funcSCIP("app", nil, "f", 1), funcSCIP("lib/util", nil, "trim", 1)}},
			noDidNot: true,
		},
		{
			name: "unexported self subpath stays run-wide",
			files: map[string]string{
				"package.json": `{"name":"app","exports":{"./util":"./lib/util.js"}}`,
				"lib/util.js":  "function trim(s) { return s.trim(); }\nmodule.exports = { trim };\n",
				"app.js":       "const s = require('app/secret');\nfunction f(x) { return s.go(x); }\nf(process.argv);\n",
			},
			runWide: []string{uninspectable},
			absent:  []string{},
		},
		{
			name: "self-reference with an out-of-tree condition branch stays run-wide",
			files: map[string]string{
				"package.json": `{"name":"app","exports":{"./util":{"import":"./lib/util.js","require":"./dist/util.cjs"}}}`,
				"lib/util.js":  "function trim(s) { return s.trim(); }\nmodule.exports = { trim };\n",
				"app.js":       "const { trim } = require('app/util');\nfunction f(s) { return trim(s); }\nf(process.argv);\n",
			},
			runWide: []string{uninspectable},
		},
		{
			name: "literal dynamic import is a package load, not a computed specifier",
			files: map[string]string{
				"package-lock.json": jsonOnlyLock,
				"app.js":            "async function f(s) { const J = await import('json5'); return J.parse(s); }\nf(process.argv);\n",
			},
			scoped: []scopedWant{{uninspectable, "json5", "app.js", []string{"pkg:npm/json5"}}},
			absent: []string{plugin.PartialReasonDynamicImportSpecifier},
		},
		{
			name: "unexported createRequire result called with a literal is a package load",
			files: map[string]string{
				"package-lock.json": jsonOnlyLock,
				"app.js":            "const req = module.constructor.createRequire(__filename);\nfunction load(s) { return req('json5').parse(s); }\nload(process.argv);\n",
			},
			scoped: []scopedWant{{uninspectable, "json5", "app.js", []string{"pkg:npm/json5"}}},
			absent: []string{computedReq},
		},
		{
			name: "fully computed require stays run-wide (fixture C)",
			files: map[string]string{"index.js": `function add(a, b) {
  return a + b;
}
module.exports = { add };
function load(n) {
  return require(n);
}
`},
			runWide: []string{computedReq},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeProgram(t, tc.files)})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			p := res.Partiality
			for _, w := range tc.scoped {
				sr := scopedFor(p, w.reason, w.pkg)
				if sr == nil {
					t.Errorf("want scoped %s for %s; got scoped %+v reasons %v", w.reason, w.pkg, p.Scoped, p.Reasons)
					continue
				}
				if sr.Path != w.path {
					t.Errorf("%s/%s Path = %q, want %q", w.reason, w.pkg, sr.Path, w.path)
				}
				if !reflect.DeepEqual(sr.Targets, w.targets) {
					t.Errorf("%s/%s Targets = %#v, want %#v", w.reason, w.pkg, sr.Targets, w.targets)
				}
			}
			for _, r := range tc.runWide {
				if !hasReason(p, r) {
					t.Errorf("want run-wide %s; got reasons %v", r, p.Reasons)
				}
				if hasScopedReason(p, r) {
					t.Errorf("run-wide %s must not also be scoped; got %+v", r, p.Scoped)
				}
			}
			for _, r := range tc.absent {
				if hasReason(p, r) || hasScopedReason(p, r) {
					t.Errorf("%s must be absent; got reasons %v scoped %+v", r, p.Reasons, p.Scoped)
				}
			}
			for _, e := range tc.edges {
				if !hasEdge(res.Edges, e.caller, e.callee) {
					t.Errorf("missing edge %s -> %s; got %+v", e.caller, e.callee, res.Edges)
				}
			}
			if tc.noDidNot && didNotRunCounts(p, "") {
				t.Errorf("want no did_not_run reason; got reasons %v scoped %+v", p.Reasons, p.Scoped)
			}
			if !p.Complete && len(p.Reasons) == 0 && len(p.Scoped) == 0 {
				t.Errorf("Partial with no reasons: %+v", p)
			}
		})
	}
}

// TestReachability_ScopedLimitsPropagate: the call graph's scoped limits reach the
// reachability and taint results unchanged.
func TestReachability_ScopedLimitsPropagate(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"package-lock.json": qsLock,
		"app.js": `const express = require('express');
const qs = require('qs');
const app = express();
function sink(u) { return qs.parse(u); }
function route(req, res) { res.send(sink(req.query.u)); }
app.get('/go', route);
`,
	})
	sink := resolveSink(t, dir, "sink")
	ctx := context.Background()
	reach, err := Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	taint, err := ComputeTaint(ctx, plugin.ComputeTaintRequest{BuildDir: dir, Sinks: []string{sink}})
	if err != nil {
		t.Fatalf("ComputeTaint: %v", err)
	}
	for name, p := range map[string]plugin.Partiality{"reachability": reach.Partiality, "taint": taint.Partiality} {
		if scopedFor(p, plugin.PartialReasonUninspectablePackage, "qs") == nil {
			t.Errorf("%s: want the qs scoped limit; got %+v", name, p.Scoped)
		}
		if p.Complete {
			t.Errorf("%s: a scoped limit must leave the result Partial", name)
		}
	}
}
