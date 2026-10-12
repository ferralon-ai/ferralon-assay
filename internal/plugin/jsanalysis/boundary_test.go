package jsanalysis

import (
	"context"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const expressManifest = `{"name":"app","version":"1.0.0","dependencies":{"express":"4.18.2","json5":"2.2.1","tough-cookie":"4.1.2","multer":"1.4.5","qs":"6.14.1"}}`

const expressLock = `{
  "name": "app",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/express": { "version": "4.18.2" },
    "node_modules/json5": { "version": "2.2.1" },
    "node_modules/tough-cookie": { "version": "4.1.2" },
    "node_modules/multer": { "version": "1.4.5" },
    "node_modules/qs": { "version": "6.14.1" }
  }
}`

// fixtureB is the measurement fixture: a top-level Express app redirecting to a
// request-controlled URL (CVE-2024-29041).
const fixtureB = `const express = require('express');
const app = express();
app.get('/', (req, res) => res.redirect(req.query.u));
app.listen(3000);
`

var expressAdvisory = []string{"express.response.location", "express.response.redirect"}

func resolveFor(t *testing.T, dir, purl string, symbols []string) plugin.SymbolResolutionResult {
	t.Helper()
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{BuildDir: dir, PURL: purl, AdvisorySymbols: symbols})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	return res
}

func resolvedSCIPs(res plugin.SymbolResolutionResult) []string {
	var out []string
	for _, s := range res.Resolved {
		out = append(out, s.SCIP)
	}
	return out
}

// TestBoundary_ExpressRedirectPath: the route handler's res.redirect is an edge into
// express's response object, the advisory symbol resolves to that node with the lockfile's
// package as its Origin, and reachability reports the handler → boundary path without
// counting the boundary node as searched.
func TestBoundary_ExpressRedirectPath(t *testing.T) {
	ctx := context.Background()
	dir := writeProgram(t, map[string]string{"index.js": fixtureB, "package.json": expressManifest, "package-lock.json": expressLock})
	const sink = "npm:express#response.redirect"
	mi := funcSCIP("index", nil, moduleInitFunc, 0)
	handler := funcSCIP("index", nil, handlerAt(t, fixtureB, "(req, res) =>"), 2)

	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	for _, e := range [][2]string{
		{mi, handler},
		{handler, sink},
		{mi, "npm:express#<call>"},
		{mi, "npm:express#<call>.listen"},
	} {
		if !hasEdge(cg.Edges, e[0], e[1]) {
			t.Errorf("missing edge %s -> %s; edges %+v", e[0], e[1], cg.Edges)
		}
	}
	if !hasReason(cg.Partiality, plugin.PartialReasonUninspectablePackage) {
		t.Errorf("an edge into a package must keep uninspectable_package declared; got %+v", cg.Partiality)
	}

	res := resolveFor(t, dir, "pkg:npm/express@4.18.2", expressAdvisory)
	if got := resolvedSCIPs(res); !slices.Equal(got, []string{sink}) {
		t.Fatalf("resolved = %v, want [%s]", got, sink)
	}
	if res.Origins[sink] != "pkg:npm/express" {
		t.Errorf("origin = %q, want pkg:npm/express", res.Origins[sink])
	}
	if got := res.Matched["express.response.redirect"]; !slices.Equal(got, []string{sink}) {
		t.Errorf("matched[express.response.redirect] = %v", got)
	}
	if _, ok := res.Matched["express.response.location"]; ok {
		t.Errorf("location has no edge in the graph and must not match: %+v", res.Matched)
	}

	reach, err := Reachability(ctx, plugin.ReachabilityRequest{BuildDir: dir, Symbols: []string{sink}})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if len(reach.Paths) != 1 {
		t.Fatalf("want one path to %s, got %+v", sink, reach.Paths)
	}
	trace := reach.Paths[0].Trace
	if trace[len(trace)-1].SCIP != sink || trace[0].SCIP != handler {
		t.Errorf("trace = %+v, want %s ... %s", trace, handler, sink)
	}
	if len(reach.Searched) != 0 {
		t.Errorf("a boundary node is never searched; got Searched=%v", reach.Searched)
	}
}

// TestBoundary_FirstPartyNeverMasquerades: when the advisory names a package the build
// depends on, a first-party function of the same name, or a first-party module named
// after the package, never resolves as the advisory symbol.
func TestBoundary_FirstPartyNeverMasquerades(t *testing.T) {
	files := map[string]string{
		"package.json":      expressManifest,
		"package-lock.json": expressLock,
		"index.js": `const express = require('express');
const { response } = require('./lib/express');
const { parse } = require('./src/json5');
const app = express();
function redirect(u) { return u; }
app.get('/', (req, res) => { redirect(req.query.u); response.redirect(req.query.u); parse(req.body); });
`,
		"lib/express.js": `class response { redirect(u) { return u; } }
module.exports = { response };
`,
		"src/json5.js": `function parse(s) { return s; }
module.exports = { parse };
`,
	}
	dir := writeProgram(t, files)
	cases := []struct {
		purl    string
		symbols []string
	}{
		{"pkg:npm/express@4.18.2", []string{"redirect", "express.response.redirect", "response.redirect"}},
		{"pkg:npm/json5@2.2.1", []string{"json5.parse", "parse"}},
	}
	for _, c := range cases {
		res := resolveFor(t, dir, c.purl, c.symbols)
		for _, s := range res.Resolved {
			if !isBoundaryID(s.SCIP) {
				t.Errorf("%s: first-party %s resolved as an advisory symbol", c.purl, s.SCIP)
			}
		}
	}
}

// TestBoundary_NoLockfileNoOrigin: a boundary node whose package no lockfile resolves still
// resolves (a candidate), but carries no Origin, so it can never ground a refutation.
func TestBoundary_NoLockfileNoOrigin(t *testing.T) {
	dir := writeProgram(t, map[string]string{"index.js": fixtureB, "package.json": expressManifest})
	res := resolveFor(t, dir, "pkg:npm/express@4.18.2", expressAdvisory)
	if got := resolvedSCIPs(res); !slices.Equal(got, []string{"npm:express#response.redirect"}) {
		t.Fatalf("resolved = %v", got)
	}
	if len(res.Origins) != 0 {
		t.Errorf("no lockfile package → no Origin; got %v", res.Origins)
	}
}

// TestBoundary_Edges covers the boundary id each call form produces, and the forms that
// must produce none.
func TestBoundary_Edges(t *testing.T) {
	mi := funcSCIP("app", nil, moduleInitFunc, 0)
	cases := []struct {
		name   string
		src    string
		caller string // "" = module init; "@marker" = the inline handler at marker (arity 2 unless noted)
		arity  int
		want   string // boundary callee that must exist
		absent string // boundary callee that must not exist
	}{
		{name: "namespace member", src: "const JSON5 = require('json5');\nJSON5.parse(process.argv[2]);\n", want: "npm:json5#parse"},
		{name: "esm default import", src: "import JSON5 from 'json5';\nJSON5.parse(x);\n", want: "npm:json5#parse"},
		{name: "named import", src: "import { parse } from 'json5';\nparse(x);\n", want: "npm:json5#parse"},
		{name: "imported class instance", src: "const { CookieJar } = require('tough-cookie');\nconst jar = new CookieJar();\njar.setCookie(c, u);\n", want: "npm:tough-cookie#CookieJar.setCookie"},
		{name: "derived value method", src: "const multer = require('multer');\nconst upload = multer({ dest: 'u/' });\nconst express = require('express');\nconst router = express.Router();\nrouter.post('/', upload.single('image'), (req, res) => res.send('ok'));\n", want: "npm:multer#<call>.single"},
		{name: "router handler", src: "const express = require('express');\nconst router = express.Router();\nrouter.get('/', (req, res) => { res.json(req.query); });\n", caller: "@(req, res) =>", arity: 2, want: "npm:express#response.json"},
		{name: "request member", src: "const express = require('express');\nconst app = express();\napp.get('/', (req, res) => { req.get('host'); });\n", caller: "@(req, res) =>", arity: 2, want: "npm:express#request.get"},
		{name: "middleware arity 3", src: "const express = require('express');\nconst app = express();\napp.use((req, res, next) => { res.redirect('/'); });\n", caller: "@(req, res, next) =>", arity: 3, want: "npm:express#response.redirect"},
		{name: "error handler arity 4", src: "const express = require('express');\nconst app = express();\napp.use((err, req, res, next) => { res.redirect('/'); });\n", caller: "@(err, req, res, next) =>", arity: 4, want: "npm:express#response.redirect", absent: "npm:express#request.redirect"},
		{name: "named handler", src: "const express = require('express');\nconst app = express();\nfunction h(req, res) { res.location(req.query.u); }\napp.get('/', h);\n", caller: "h", arity: 2, want: "npm:express#response.location"},
		{name: "node builtin", src: "const fs = require('fs');\nfs.readFileSync('x');\n", absent: "npm:fs#readFileSync"},
		{name: "untyped helper param", src: "const express = require('express');\nconst app = express();\nfunction helper(res) { res.redirect('/'); }\napp.get('/', (req, res) => helper(res));\n", absent: "npm:express#response.redirect"},
		{name: "handler on a non-router value", src: "const axios = require('axios');\naxios.get('/x', (req, res) => res.redirect('/'));\n", absent: "npm:express#response.redirect"},
		{name: "relative import", src: "const u = require('./util');\nu.parse(x);\n", absent: "npm:./util#parse"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := writeProgram(t, map[string]string{"app.js": c.src, "package.json": expressManifest})
			cg, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			if c.want != "" {
				caller := mi
				switch {
				case len(c.caller) > 0 && c.caller[0] == '@':
					caller = funcSCIP("app", nil, handlerAt(t, c.src, c.caller[1:]), c.arity)
				case c.caller != "":
					caller = funcSCIP("app", nil, c.caller, c.arity)
				}
				if !hasEdge(cg.Edges, caller, c.want) {
					t.Errorf("missing edge %s -> %s; edges %+v", caller, c.want, cg.Edges)
				}
			}
			if c.absent != "" {
				for _, e := range cg.Edges {
					if e.Callee.SCIP == c.absent {
						t.Errorf("unexpected edge %s -> %s", e.Caller.SCIP, e.Callee.SCIP)
					}
				}
			}
		})
	}
}

// TestBoundary_AdvisorySpellings: tough-cookie's advisory symbols carry no package
// qualifier, express's response object resolves under its res alias, and an internal
// helper resolves to the public member internalEntries says runs it.
func TestBoundary_AdvisorySpellings(t *testing.T) {
	files := map[string]string{
		"package.json":      expressManifest,
		"package-lock.json": expressLock,
		"app.js": `const express = require('express');
const { CookieJar } = require('tough-cookie');
const jar = new CookieJar();
const multer = require('multer');
const qs = require('qs');
const upload = multer({ dest: 'uploads/' });
const app = express();
app.get('/', (req, res) => { jar.setCookie(req.query.c, 'http://x'); res.redirect('/'); });
app.post('/up', upload.single('image'), (req, res) => res.json(qs.parse(req.body.q)));
`,
	}
	dir := writeProgram(t, files)
	cases := []struct {
		purl    string
		symbols []string
		want    string
		matched string
	}{
		{"pkg:npm/tough-cookie@4.1.2", []string{"MemoryCookieStore.putCookie", "CookieJar.setCookie"}, "npm:tough-cookie#CookieJar.setCookie", "CookieJar.setCookie"},
		{"pkg:npm/express@4.18.2", []string{"express.res.redirect"}, "npm:express#response.redirect", "express.res.redirect"},
		{"pkg:npm/multer@1.4.5", []string{"multer.MulterError", "multer.makeMiddleware"}, "npm:multer#<call>.single", "multer.makeMiddleware"},
		{"pkg:npm/qs@6.14.1", []string{"qs.interpretNumericEntities", "qs.parseArrayValue", "qs.parseValues"}, "npm:qs#parse", "qs.parseValues"},
	}
	for _, c := range cases {
		res := resolveFor(t, dir, c.purl, c.symbols)
		if got := resolvedSCIPs(res); !slices.Equal(got, []string{c.want}) {
			t.Errorf("%s: resolved = %v, want [%s]", c.purl, got, c.want)
		}
		if got := res.Matched[c.matched]; !slices.Equal(got, []string{c.want}) {
			t.Errorf("%s: matched[%s] = %v", c.purl, c.matched, got)
		}
		if res.Origins[c.want] == "" {
			t.Errorf("%s: no origin for %s", c.purl, c.want)
		}
	}
}
