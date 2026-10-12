package jsanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestCallGraph_OutOfTreePackageNeverOnlyInherent pins the invariant the refutation gate
// relies on: a graph with edges whose only partiality reasons are inherent can refute, so
// a module that loads an out-of-tree package, in any form, must declare a did_not_run
// reason. The package's code runs and this lane never opens it.
func TestCallGraph_OutOfTreePackageNeverOnlyInherent(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
	}{
		{"direct member head", map[string]string{"app.js": `
const JSON5 = require('json5');
function load(s) { return JSON5.parse(s); }
load(process.argv);
`}},
		{"alias of the binding", map[string]string{"app.js": `
const lib = require('json5'); const p = lib;
function load(s) { return p.parse(s); }
load(process.argv);
`}},
		{"inline require in a function", map[string]string{"app.js": `
function load(s) { return require('json5').parse(s); }
load(process.argv);
`}},
		{"inline require at top level", map[string]string{"app.js": `
function run() { return 1; }
require('json5').parse(process.argv);
run();
`}},
		{"destructured require", map[string]string{"app.js": `
const { parse } = require('json5');
function load(s) { return parse(s); }
load(process.argv);
`}},
		{"binding passed as a value", map[string]string{"app.js": `
const JSON5 = require('json5');
function apply(f, s) { return f(s); }
function load(s) { return apply(JSON5.parse, s); }
load(process.argv);
`}},
		{"ESM default", map[string]string{"app.js": `
import JSON5 from 'json5';
function load(s) { return JSON5.parse(s); }
load(process.argv);
`}},
		{"ESM named", map[string]string{"app.js": `
import { parse } from 'json5';
function load(s) { return parse(s); }
load(process.argv);
`}},
		{"ESM namespace", map[string]string{"app.js": `
import * as J from 'json5';
function load(s) { return J.parse(s); }
load(process.argv);
`}},
		{"ESM side-effect import", map[string]string{"app.js": `
import 'json5';
function load(s) { return s; }
load(process.argv);
`}},
		{"dynamic import with a literal", map[string]string{"app.js": `
async function load(s) { const J = await import('json5'); return J.parse(s); }
load(process.argv);
`}},
		{"TS import-equals", map[string]string{"app.ts": `
import JSON5 = require('json5');
function load(s: string) { return JSON5.parse(s); }
load(process.argv[2]);
`}},
		{"named re-export", map[string]string{
			"lib.js": "export { parse } from 'json5';\n",
			"app.js": `
import { parse } from './lib';
function load(s) { return parse(s); }
load(process.argv);
`}},
		{"star re-export", map[string]string{
			"lib.js": "export * from 'json5';\n",
			"app.js": `
import { parse } from './lib';
function load(s) { return parse(s); }
load(process.argv);
`}},
		{"subpath import mapped to a package", map[string]string{
			"package.json": `{"name":"app","imports":{"#json":"json5"}}`,
			"app.js": `
import { parse } from '#json';
function load(s) { return parse(s); }
load(process.argv);
`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeProgram(t, tc.files)})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			if len(res.Edges) == 0 {
				t.Fatalf("fixture must have edges, so the gate's zero-edge arm cannot be what holds it undetermined")
			}
			if !hasDidNotRun(res.Partiality) {
				t.Errorf("out-of-tree package use declared only %v; want a did_not_run reason", res.Partiality.Reasons)
			}
		})
	}
}

// TestCallGraph_InTreeOnlyDeclaresNoDidNotRun is the control: in-tree loads and an
// unresolved local call leave the graph with inherent reasons only, so the invariant above
// is not met by declaring did_not_run on every module.
func TestCallGraph_InTreeOnlyDeclaresNoDidNotRun(t *testing.T) {
	dir := writeProgram(t, map[string]string{
		"util.js": "function trim(s) { return s.trim(); }\nmodule.exports = { trim };\n",
		"app.js": `
const { trim } = require('./util');
import './util';
function load(s) { return trim(s); }
load(process.argv);
`,
	})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if len(res.Edges) == 0 {
		t.Fatalf("control must have edges; got none")
	}
	if hasDidNotRun(res.Partiality) {
		t.Errorf("in-tree only program declared %v; want inherent reasons only", res.Partiality.Reasons)
	}
}

func hasDidNotRun(p plugin.Partiality) bool {
	for _, r := range p.Reasons {
		if report.ClassifyPartialityReason(r) == report.PartialityDidNotRun {
			return true
		}
	}
	return false
}
