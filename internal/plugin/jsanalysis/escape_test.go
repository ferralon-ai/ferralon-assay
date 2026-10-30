package jsanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestCallGraph_EscapeRoots pins which first-party functions become roots because a
// package (or computed access) could call them through an edge this lane does not see, and
// that each such root is on the wire in Escaped, while a function that is not one is not.
func TestCallGraph_EscapeRoots(t *testing.T) {
	cases := []struct {
		name     string
		files    map[string]string
		roots    []string
		notRoots []string
	}{
		{
			name: "address-taken function passed to a package",
			files: map[string]string{"app.js": `const lib = require('lib');
function onData(x) { return x; }
lib.on('data', onData);
`},
			roots: []string{funcSCIP("app", nil, "onData", 1)},
		},
		{
			name: "class method on an instance passed to a package",
			files: map[string]string{"app.js": `const lib = require('lib');
class Jar {
  setCookie(c) { return c; }
}
lib.use(new Jar());
`},
			roots: []string{funcSCIP("app", []string{"Jar"}, "setCookie", 1)},
		},
		{
			name: "direct-call-only function is not a root",
			files: map[string]string{"app.js": `function helper(x) { return x; }
function main() { return helper(1); }
module.exports = { main };
`},
			roots:    []string{funcSCIP("app", nil, "main", 0)},
			notRoots: []string{funcSCIP("app", nil, "helper", 1)},
		},
		{
			name:  "exported function",
			files: map[string]string{"app.mjs": "export function api(x) { return x; }\nexport default function main() { return 1; }\n"},
			roots: []string{funcSCIP("app", nil, "api", 1), funcSCIP("app", nil, "main", 0)},
		},
		{
			name: "exported arrow const",
			files: map[string]string{"app.mjs": `export const api = (x) => { return x; };
const inner = (x) => { return x; };
export function main() { return inner(1); }
`},
			roots:    []string{funcSCIP("app", nil, "api", 1)},
			notRoots: []string{funcSCIP("app", nil, "inner", 1)},
		},
		{
			name: "returned and stored function",
			files: map[string]string{"app.js": `function a(x) { return x; }
function b(x) { return x; }
function make() { return a; }
const table = { b };
module.exports = { make, table };
`},
			roots: []string{funcSCIP("app", nil, "a", 1), funcSCIP("app", nil, "b", 1)},
		},
		{
			name: "call/apply/bind wrap",
			files: map[string]string{"app.js": `function f(x) { return x; }
function main() { return f.call(null, 1); }
module.exports = { main };
`},
			roots: []string{funcSCIP("app", nil, "f", 1)},
		},
		{
			name: "name used in a template substitution",
			files: map[string]string{"app.js": "function fmt(x) { return x; }\n" +
				"function main() { return `v=${fmt(1)}`; }\nmodule.exports = { main };\n"},
			roots: []string{funcSCIP("app", nil, "fmt", 1)},
		},
		{
			name: "JSX tag",
			files: map[string]string{"app.jsx": `import React from 'react';
function Widget(props) { return null; }
export function Page() { return <Widget a={1} />; }
`},
			roots: []string{funcSCIP("app", nil, "Widget", 1)},
		},
		{
			name: "same-named property access is not an escape",
			files: map[string]string{"app.js": `function parse(s) { return s; }
function main(obj) { return obj.parse; }
module.exports = { main };
`},
			notRoots: []string{funcSCIP("app", nil, "parse", 1)},
		},
		{
			name: "eval makes every function a root",
			files: map[string]string{"app.js": `function hidden(x) { return x; }
function main(s) { return eval(s); }
module.exports = { main };
`},
			roots: []string{funcSCIP("app", nil, "hidden", 1)},
		},
		{
			name:  "script-mode top-level functions are globals",
			files: map[string]string{"app.js": "function a() { return 1; }\nfunction b() { return a(); }\n"},
			roots: []string{funcSCIP("app", nil, "a", 0), funcSCIP("app", nil, "b", 0)},
		},
		{
			name: "member of an exported object literal",
			files: map[string]string{"app.js": `function handler(req) { return req; }
module.exports = { routes: { '/x': handler } };
`},
			roots: []string{funcSCIP("app", nil, "handler", 1)},
		},
		{
			name: "constructor invoked with new",
			files: map[string]string{"app.js": `function Jar(x) { this.x = x; }
function main() { return new Jar(1); }
module.exports = { main };
`},
			roots: []string{funcSCIP("app", nil, "Jar", 1)},
		},
		{
			name: "spread of a function binding",
			files: map[string]string{"app.js": `function h(x) { return x; }
function main(arr) { return [...h, ...arr]; }
module.exports = { main };
`},
			roots: []string{funcSCIP("app", nil, "h", 1)},
		},
		{
			name: "named function expression passed as an argument",
			files: map[string]string{"app.js": `const lib = require('lib');
lib.use(function handler(req) { return req; });
`},
			roots: []string{funcSCIP("app", nil, "handler", 1)},
		},
		{
			name: "Function() without new makes every function a root",
			files: map[string]string{"app.js": `function hidden(x) { return x; }
function main(s) { return Function(s)(); }
module.exports = { main };
`},
			roots: []string{funcSCIP("app", nil, "hidden", 1)},
		},
		{
			name: "Vue SFC script functions are roots: the template calls them by name",
			files: map[string]string{"app.vue": `<template><p>{{ fmt(1) }}</p></template>
<script>
function fmt(x) { return x; }
export default {};
</script>
`},
			roots: []string{funcSCIP("app", nil, "fmt", 1)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeProgram(t, tc.files)})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			got := map[string]bool{}
			for _, r := range res.Roots {
				got[r.SCIP] = true
			}
			escaped := map[string]bool{}
			for _, e := range res.Escaped {
				escaped[e.SCIP] = true
			}
			for _, r := range tc.roots {
				if !got[r] {
					t.Errorf("want root %s; got %v", r, res.Roots)
				}
				if !escaped[r] {
					t.Errorf("want %s escaped; got %v", r, res.Escaped)
				}
			}
			for _, r := range tc.notRoots {
				if got[r] {
					t.Errorf("%s must not be a root", r)
				}
				if escaped[r] {
					t.Errorf("%s must not be escaped", r)
				}
			}
		})
	}
}

// TestCallGraph_EscapeRootsAreNotIngresses: a root is searched from, but it is not an
// attacker-reachable entry point.
func TestCallGraph_EscapeRootsAreNotIngresses(t *testing.T) {
	dir := writeProgram(t, map[string]string{"app.js": `const lib = require('lib');
function onData(x) { return x; }
lib.on('data', onData);
`})
	ing, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}
	for _, i := range ing.Ingresses {
		if i.Symbol.SCIP == funcSCIP("app", nil, "onData", 1) {
			t.Fatalf("escape root became an ingress: %+v", i)
		}
	}
}

// TestReachability_IngressPreferredOverRoot: a sink that is both an escape root and
// reached from an ingress reports the ingress path.
func TestReachability_IngressPreferredOverRoot(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"app.js": `const express = require('express');
const qs = require('qs');
const app = express();
function sink(u) { return qs.parse(u); }
function route(req, res) { res.send(sink(req.query.u)); }
app.get('/go', route);
module.exports = { sink };
`,
	})
	sink := resolveSink(t, dir, "sink")
	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("want one path; got %+v", res.Paths)
	}
	if got := res.Paths[0].Ingress.SCIP; got != funcSCIP("app", nil, "route", 2) {
		t.Errorf("path ingress = %q, want the route handler", got)
	}
}
