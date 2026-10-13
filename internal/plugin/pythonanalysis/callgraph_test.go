package pythonanalysis

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func hasEdge(edges []plugin.CallEdge, caller, callee string) bool {
	for _, e := range edges {
		if e.Caller.SCIP == caller && e.Callee.SCIP == callee {
			return true
		}
	}
	return false
}

func hasReason(p plugin.Partiality, reason string) bool {
	for _, r := range p.Reasons {
		if r == reason {
			return true
		}
	}
	return false
}

// flaskApp is the canonical chain: a Flask route handler (registered by the @app.route
// decorator) calls a utility that calls the sink — handle_fetch → handle → fetch_url →
// open_conn. Every callee is unique by (name, arity) so the source-lexical resolver
// connects each edge soundly.
const flaskApp = `
from flask import Flask
app = Flask(__name__)

@app.route('/fetch')
def handle_fetch():
    return handle(1)

def handle(target):
    return fetch_url(target)

def fetch_url(target):
    return open_conn(target)

def open_conn(url):
    return url
`

func TestCallGraph_RouteChainEdgesResolve(t *testing.T) {
	dir := writeTree(t, map[string]string{"app.py": flaskApp})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	handleFetch := funcSCIP("app", nil, "handle_fetch", 0)
	handle := funcSCIP("app", nil, "handle", 1)
	fetchURL := funcSCIP("app", nil, "fetch_url", 1)
	openConn := funcSCIP("app", nil, "open_conn", 1)

	for _, want := range [][2]string{{handleFetch, handle}, {handle, fetchURL}, {fetchURL, openConn}} {
		if !hasEdge(res.Edges, want[0], want[1]) {
			t.Errorf("missing edge %s -> %s\nedges: %+v", want[0], want[1], res.Edges)
		}
	}
	// A lexical Python call graph is ALWAYS declared Partial (dynamic dispatch).
	if res.Partiality.Complete {
		t.Error("Python call graph must never be Complete (structurally weak; dynamic dispatch)")
	}
	if !hasReason(res.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Errorf("call graph must carry standing dynamic_dispatch reason; got %+v", res.Partiality)
	}
}

func TestCallGraph_RouteHandlerIsRoot(t *testing.T) {
	dir := writeTree(t, map[string]string{"app.py": flaskApp})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	handleFetch := funcSCIP("app", nil, "handle_fetch", 0)
	found := false
	for _, r := range res.Roots {
		if r.SCIP == handleFetch {
			found = true
		}
	}
	if !found {
		t.Errorf("Flask route handler handle_fetch not registered as a call-graph root; roots=%v", res.Roots)
	}
}

func TestCallGraph_ControlFlowKeywordsAreNotEdges(t *testing.T) {
	// if/while/for/return look like "word(" but must NOT become call edges; the real
	// calls cond()/loop()/pick() must.
	src := `
def run():
    if cond():
        while loop():
            return
    for i in pick():
        pass

def cond():
    return True

def loop():
    return False

def pick():
    return []
`
	dir := writeTree(t, map[string]string{"c.py": src})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	run := funcSCIP("c", nil, "run", 0)
	cond := funcSCIP("c", nil, "cond", 0)
	loop := funcSCIP("c", nil, "loop", 0)
	pick := funcSCIP("c", nil, "pick", 0)
	if !hasEdge(res.Edges, run, cond) || !hasEdge(res.Edges, run, loop) || !hasEdge(res.Edges, run, pick) {
		t.Errorf("expected run->cond, run->loop, run->pick edges; edges=%+v", res.Edges)
	}
	for _, e := range res.Edges {
		if e.Caller.SCIP == "" || e.Callee.SCIP == "" {
			t.Errorf("empty endpoint in edge %+v", e)
		}
	}
}

// TestCallGraph_MethodChainResolves proves the scanner handles a class with a method that
// calls the sink (a different declaration shape than the module-function chain).
func TestCallGraph_MethodChainResolves(t *testing.T) {
	src := `
class Fetcher:
    def fetch(self, target):
        return self.open(target)

    def open(self, url):
        return url
`
	dir := writeTree(t, map[string]string{"svc.py": src})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	fetch := funcSCIP("svc", []string{"Fetcher"}, "fetch", 2)
	open := funcSCIP("svc", []string{"Fetcher"}, "open", 2)
	if !hasEdge(res.Edges, fetch, open) {
		t.Errorf("expected Fetcher.fetch -> Fetcher.open edge; edges=%+v", res.Edges)
	}
}

// TestCallGraph_AmbiguousCalleeDoesNotFabricateEdge is the inv.5 honesty test: when a
// callee's (name, arity) matches MORE THAN ONE declared function (two modules each declare
// process(1)), the resolver cannot soundly pick one, so it fabricates NO edge. The sink
// must NOT be reachable from entry.
func TestCallGraph_AmbiguousCalleeDoesNotFabricateEdge(t *testing.T) {
	a := `
def entry(x):
    process(x)
`
	b := `
def process(x):
    sink()

def sink():
    pass
`
	c := `
def process(x):
    pass
`
	dir := writeTree(t, map[string]string{"a.py": a, "b.py": b, "c.py": c})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if !hasReason(res.Partiality, plugin.PartialReasonDynamicDispatch) {
		t.Errorf("ambiguous callee must carry dynamic_dispatch reason, got %+v", res.Partiality)
	}
	entry := funcSCIP("a", nil, "entry", 1)
	for _, e := range res.Edges {
		if e.Caller.SCIP == entry {
			t.Errorf("ambiguous call fabricated an edge from entry: %+v", e)
		}
	}
}

func TestCallGraph_UnknownCalleeIsPartialNoEdge(t *testing.T) {
	src := `
def run():
    external_library_call(1, 2)
`
	dir := writeTree(t, map[string]string{"c.py": src})
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if res.Partiality.Complete {
		t.Error("unknown callee must declare partiality")
	}
	if len(res.Edges) != 0 {
		t.Errorf("unknown callee must not fabricate any edge; got %+v", res.Edges)
	}
}

func TestCallGraph_MissingBuildDirIsHardError(t *testing.T) {
	_, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: "testdata/does-not-exist"})
	if err == nil {
		t.Fatal("expected a hard error for a nonexistent build dir")
	}
}

// TestCallGraph_ImportBindingBoundaryEdges: a call through an import binding reaches a
// dependency attribute and emits an edge to its boundary node, named by the import path
// the code used; unmapped imports, first-party modules, and names bound in another def
// emit none.
func TestCallGraph_ImportBindingBoundaryEdges(t *testing.T) {
	cases := []struct {
		name     string
		files    map[string]string
		caller   string
		boundary string // "" = no boundary edge from caller
	}{
		{
			name:     "jinja2 call-result receiver",
			files:    map[string]string{"app.py": "from jinja2 import Environment\n\ndef render(x):\n    return Environment().from_string(x)\n"},
			caller:   funcSCIP("app", nil, "render", 1),
			boundary: "pypi:jinja2#jinja2.Environment.from_string",
		},
		{
			name:     "jinja2 instance binding",
			files:    map[string]string{"app.py": "from jinja2 import Environment\n\ndef render(x):\n    env = Environment(autoescape=False)\n    return env.from_string(x)\n"},
			caller:   funcSCIP("app", nil, "render", 1),
			boundary: "pypi:jinja2#jinja2.Environment.from_string",
		},
		{
			name:     "curated non-identity pyjwt",
			files:    map[string]string{"app.py": "import jwt\n\ndef check(t):\n    return jwt.decode(t)\n"},
			caller:   funcSCIP("app", nil, "check", 1),
			boundary: "pypi:pyjwt#jwt.decode",
		},
		{
			name:     "from-import alias",
			files:    map[string]string{"app.py": "from jwt import decode as jd\n\ndef check(t):\n    return jd(t)\n"},
			caller:   funcSCIP("app", nil, "check", 1),
			boundary: "pypi:pyjwt#jwt.decode",
		},
		{
			name: "PEP 503 fallback against declared manifest",
			files: map[string]string{
				"requirements.txt": "requests==2.31.0\n",
				"app.py":           "import requests\n\ndef fetch(u):\n    return requests.get(u)\n",
			},
			caller:   funcSCIP("app", nil, "fetch", 1),
			boundary: "pypi:requests#requests.get",
		},
		{
			name: "import as alias of submodule",
			files: map[string]string{
				"requirements.txt": "acme-tools==1.0\n",
				"app.py":           "import acme_tools.net as n\n\ndef go(u):\n    return n.fetch(u)\n",
			},
			caller:   funcSCIP("app", nil, "go", 1),
			boundary: "pypi:acme-tools#acme_tools.net.fetch",
		},
		{
			name:     "function-local import",
			files:    map[string]string{"app.py": "def check(t):\n    import jwt\n    return jwt.decode(t)\n"},
			caller:   funcSCIP("app", nil, "check", 1),
			boundary: "pypi:pyjwt#jwt.decode",
		},
		{
			name:   "function-local import does not leak to another def",
			files:  map[string]string{"app.py": "def a(t):\n    import jwt\n    return t\n\ndef b(t):\n    return jwt.decode(t)\n"},
			caller: funcSCIP("app", nil, "b", 1),
		},
		{
			name:   "undeclared, uncurated import maps to nothing",
			files:  map[string]string{"app.py": "import requests\n\ndef fetch(u):\n    return requests.get(u)\n"},
			caller: funcSCIP("app", nil, "fetch", 1),
		},
		{
			name:     "import binding beats a later instance binding of the same name",
			files:    map[string]string{"app.py": "from jinja2 import Environment\nimport jwt\njwt = Environment()\n\ndef check(t):\n    return jwt.decode(t)\n"},
			caller:   funcSCIP("app", nil, "check", 1),
			boundary: "pypi:pyjwt#jwt.decode",
		},
		{
			name:     "curated non-identity python-dotenv",
			files:    map[string]string{"app.py": "from dotenv import load_dotenv\n\ndef boot(p):\n    return load_dotenv(p)\n"},
			caller:   funcSCIP("app", nil, "boot", 1),
			boundary: "pypi:python-dotenv#dotenv.load_dotenv",
		},
		{
			name:     "curated non-identity teams-ai",
			files:    map[string]string{"app.py": "import teams\n\ndef boot(o):\n    return teams.Application(o)\n"},
			caller:   funcSCIP("app", nil, "boot", 1),
			boundary: "pypi:teams-ai#teams.Application",
		},
		{
			name: "azure namespace root names no single distribution",
			files: map[string]string{
				"requirements.txt": "azure-identity==1.26.0\n",
				"app.py":           "from azure.identity import DefaultAzureCredential\n\ndef cred(o):\n    return DefaultAzureCredential(o)\n",
			},
			caller: funcSCIP("app", nil, "cred", 1),
		},
		{
			name: "botframework namespace root names no single distribution",
			files: map[string]string{
				"requirements.txt": "botframework-connector==4.17.1\n",
				"app.py":           "from botframework.connector import ConnectorClient\n\ndef client(o):\n    return ConnectorClient(o)\n",
			},
			caller: funcSCIP("app", nil, "client", 1),
		},
		{
			name: "first-party module shadows the distribution",
			files: map[string]string{
				"jwt.py": "def decode(t):\n    return t\n",
				"app.py": "import jwt\n\ndef check(t):\n    return jwt.decode(t)\n",
			},
			caller: funcSCIP("app", nil, "check", 1),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeTree(t, c.files)})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			var got []string
			for _, e := range res.Edges {
				if e.Caller.SCIP == c.caller && strings.HasPrefix(e.Callee.SCIP, boundaryPrefix) {
					got = append(got, e.Callee.SCIP)
				}
			}
			if c.boundary == "" {
				if len(got) != 0 {
					t.Fatalf("want no boundary edge from %s, got %v", c.caller, got)
				}
				return
			}
			if !slices.Contains(got, c.boundary) {
				t.Fatalf("boundary edges from %s = %v, want %s among them\nedges: %+v", c.caller, got, c.boundary, res.Edges)
			}
		})
	}
}

// TestCallGraph_ModuleLevelCallsGetModuleInitCaller: calls at module (and class-body)
// level run at import time; they are attributed to a synthetic module-init caller that
// is a root, so top-level `app = create_app()` and `jwt.decode(...)` produce edges.
func TestCallGraph_ModuleLevelCallsGetModuleInitCaller(t *testing.T) {
	src := "import jwt\n\ndef create_app():\n    return 1\n\napp = create_app()\nclaims = jwt.decode(TOKEN)\n"
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeTree(t, map[string]string{"main.py": src})})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	init := moduleInitSCIP("main")
	for _, callee := range []string{funcSCIP("main", nil, "create_app", 0), "pypi:pyjwt#jwt.decode"} {
		if !hasEdge(res.Edges, init, callee) {
			t.Errorf("missing module-init edge %s -> %s\nedges: %+v", init, callee, res.Edges)
		}
	}
	var isRoot bool
	for _, r := range res.Roots {
		isRoot = isRoot || r.SCIP == init
	}
	if !isRoot {
		t.Errorf("module-init caller %s must be a root; roots=%v", init, res.Roots)
	}
}

// TestCallGraph_DynamicImports: a literal dynamic import is recorded as a load root on the
// program; a dynamic import the scanner cannot name adds the run-wide dynamic_import
// reason.
func TestCallGraph_DynamicImports(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		roots     []string
		dynReason bool
	}{
		{"importlib literal", "import importlib\nmod = importlib.import_module(\"yaml\")\n", []string{"yaml"}, false},
		{"from-imported literal with package", "from importlib import import_module\n\ndef f():\n    return import_module('.sub', package=__package__)\n", []string{".sub"}, false},
		{"__import__ literal", "m = __import__(r'os.path')\n", []string{"os.path"}, false},
		{"pkgutil resolve_name literal", "import pkgutil\nf = pkgutil.resolve_name('acme.plugins:load')\n", []string{"acme.plugins"}, false},
		{"non-literal name", "from importlib import import_module\n\ndef load(name):\n    return import_module(name)\n", nil, true},
		{"f-string", "import importlib\n\ndef load(n):\n    return importlib.import_module(f\"plugins.{n}\")\n", nil, true},
		{"concatenation", "import importlib\n\ndef load(n):\n    return importlib.import_module(\"plugins.\" + n)\n", nil, true},
		{"entry points", "from importlib.metadata import entry_points\n\nfor ep in entry_points(group='acme.plugins'):\n    ep.load()\n", nil, true},
		{"comment and string only", "# importlib.import_module(name)\ns = 'import_module(name)'\n", nil, false},
		{"def named import_module", "def import_module(name):\n    return name\n", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"m.py": c.src})
			prog, err := loadProgram(dir)
			if err != nil {
				t.Fatalf("loadProgram: %v", err)
			}
			if got := prog.files[0].loadRoots; !reflect.DeepEqual(got, c.roots) {
				t.Errorf("loadRoots = %v, want %v", got, c.roots)
			}
			res := callGraphOf(prog)
			if got := hasReason(res.Partiality, plugin.PartialReasonDynamicImportSpecifier); got != c.dynReason {
				t.Errorf("dynamic_import reason = %v, want %v (reasons %v)", got, c.dynReason, res.Partiality.Reasons)
			}
		})
	}
}

// TestLoadProgram_BuildScripts: a packaging build script's imports are build-time, so the
// script is left out of the program (no module, no boundary edge from its module-init),
// while it stays first-party. Every way runtime code could still load the script keeps it.
func TestLoadProgram_BuildScripts(t *testing.T) {
	const setupPy = "from setuptools import setup\nsetup(name='app')\n"
	const runtime = "def check(t):\n    return t\n"
	// nsSetupPy sits in the namespace package pkg (no __init__.py), so pkg.setup is importable.
	const nsSetupPy = "from setuptools import setup\nimport yaml\ncfg = yaml.load(open('c.yml'))\nsetup(name='app')\n"
	const yamlLoad = "pypi:pyyaml#yaml.load"
	cases := []struct {
		name     string
		files    map[string]string
		script   string // module of the build-script candidate
		excluded bool
		edge     string // boundary edge the kept script's module-init must still have
	}{
		{
			name:     "setup.py importing setuptools is excluded",
			files:    map[string]string{"setup.py": setupPy, "app.py": runtime},
			script:   "setup",
			excluded: true,
		},
		{
			name:     "setup.py importing distutils is excluded",
			files:    map[string]string{"setup.py": "from distutils.core import setup\nsetup(name='app')\n", "app.py": runtime},
			script:   "setup",
			excluded: true,
		},
		{
			name: "hatch_build.py importing hatchling is excluded",
			files: map[string]string{
				"hatch_build.py": "from hatchling.builders.hooks.plugin.interface import BuildHookInterface\n\nclass Hook(BuildHookInterface):\n    def initialize(self, version, data):\n        return data\n",
				"app.py":         runtime,
			},
			script:   "hatch_build",
			excluded: true,
		},
		{
			name:   "setup.py importing no build backend stays",
			files:  map[string]string{"setup.py": "import click\n\ndef setup(cfg):\n    return click.echo(cfg)\n", "app.py": runtime},
			script: "setup",
		},
		{
			name:   "setup.py inside a regular package stays",
			files:  map[string]string{"pkg/__init__.py": "", "pkg/setup.py": setupPy, "app.py": runtime},
			script: "pkg/setup",
		},
		{
			name:   "runtime import of the script's module keeps it",
			files:  map[string]string{"setup.py": setupPy, "app.py": "import setup\n\ndef check(t):\n    return t\n"},
			script: "setup",
		},
		{
			name:   "runtime star import of the script's module keeps it",
			files:  map[string]string{"setup.py": setupPy, "app.py": "from setup import *\n\ndef check(t):\n    return t\n"},
			script: "setup",
		},
		{
			name:   "runtime literal dynamic import of the script's module keeps it",
			files:  map[string]string{"setup.py": setupPy, "app.py": "import importlib\nmod = importlib.import_module('setup')\n"},
			script: "setup",
		},
		{
			name:     "setup.py in a namespace package nothing loads is excluded",
			files:    map[string]string{"pkg/setup.py": nsSetupPy, "pkg/run.py": runtime},
			script:   "pkg/setup",
			excluded: true,
		},
		{
			name:   "dotted import of a namespace-package setup.py keeps it",
			files:  map[string]string{"pkg/setup.py": nsSetupPy, "app.py": "import pkg.setup\n\ndef check(t):\n    return t\n"},
			script: "pkg/setup",
			edge:   yamlLoad,
		},
		{
			name:   "from-import of a namespace-package setup.py keeps it",
			files:  map[string]string{"pkg/setup.py": nsSetupPy, "app.py": "from pkg import setup\n\ndef check(t):\n    return t\n"},
			script: "pkg/setup",
			edge:   yamlLoad,
		},
		{
			name:   "relative import of a sibling setup.py keeps it",
			files:  map[string]string{"pkg/setup.py": nsSetupPy, "pkg/run.py": "from . import setup\n\ndef check(t):\n    return t\n"},
			script: "pkg/setup",
			edge:   yamlLoad,
		},
		{
			name:   "relative import of a root setup.py keeps it",
			files:  map[string]string{"setup.py": nsSetupPy, "app.py": "from . import setup\n\ndef check(t):\n    return t\n"},
			script: "setup",
			edge:   yamlLoad,
		},
		{
			name:   "literal dynamic import of a namespace-package setup.py keeps it",
			files:  map[string]string{"pkg/setup.py": nsSetupPy, "app.py": "import importlib\nmod = importlib.import_module('pkg.setup')\n"},
			script: "pkg/setup",
			edge:   yamlLoad,
		},
		{
			name:   "any other dynamic import keeps it",
			files:  map[string]string{"setup.py": nsSetupPy, "app.py": "import importlib\nmod = importlib.import_module('json')\n"},
			script: "setup",
			edge:   yamlLoad,
		},
		{
			name:   "relative import climbing above the build root keeps it",
			files:  map[string]string{"setup.py": nsSetupPy, "app.py": "from .. import helpers\n\ndef check(t):\n    return t\n"},
			script: "setup",
			edge:   yamlLoad,
		},
		{
			name:   "an entry point naming the script keeps it",
			files:  map[string]string{"setup.py": nsSetupPy, "app.py": runtime, "pyproject.toml": "[project]\nname = \"app\"\n\n[project.scripts]\ntool = \"setup:main\"\n"},
			script: "setup",
			edge:   yamlLoad,
		},
		{
			name:     "an entry point naming another module leaves it out",
			files:    map[string]string{"setup.py": nsSetupPy, "app.py": runtime, "pyproject.toml": "[project]\nname = \"app\"\n\n[project.scripts]\ntool = \"app:check\"\n"},
			script:   "setup",
			excluded: true,
		},
		{
			name:   "runtime dynamic import the scanner cannot name keeps it",
			files:  map[string]string{"setup.py": setupPy, "app.py": "import importlib\n\ndef load(n):\n    return importlib.import_module(n)\n"},
			script: "setup",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.files["requirements.txt"] = "setuptools\nhatchling\nclick\n"
			prog, err := loadProgram(writeTree(t, c.files))
			if err != nil {
				t.Fatalf("loadProgram: %v", err)
			}
			var present bool
			for _, f := range prog.files {
				present = present || f.module == c.script
			}
			if present == c.excluded {
				t.Fatalf("build script %s in program = %v, want %v", c.script, present, !c.excluded)
			}
			top, _, _ := strings.Cut(c.script, "/")
			if !prog.dists.firstParty[top] {
				t.Errorf("first-party tops %v lost %s", prog.dists.firstParty, top)
			}
			init := moduleInitSCIP(c.script)
			var fromScript []string
			for _, e := range callGraphOf(prog).Edges {
				if e.Caller.SCIP == init && strings.HasPrefix(e.Callee.SCIP, boundaryPrefix) {
					fromScript = append(fromScript, e.Callee.SCIP)
				}
			}
			if c.excluded && len(fromScript) != 0 {
				t.Errorf("excluded build script still contributes boundary edges %v", fromScript)
			}
			if c.edge != "" && !slices.Contains(fromScript, c.edge) {
				t.Errorf("kept build script's boundary edges %v lack %s", fromScript, c.edge)
			}
		})
	}
}

// TestLoadProgram_UnreadableConfigKeepsBuildScripts: an entry-point config that cannot be
// read might name the build script, so the script stays in.
func TestLoadProgram_UnreadableConfigKeepsBuildScripts(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"setup.py": "from setuptools import setup\nsetup(name='app')\n",
		"app.py":   "def check(t):\n    return t\n",
	})
	if err := os.Symlink(filepath.Join(dir, "missing.cfg"), filepath.Join(dir, "setup.cfg")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	prog, err := loadProgram(dir)
	if err != nil {
		t.Fatalf("loadProgram: %v", err)
	}
	if !slices.ContainsFunc(prog.files, func(f fileParse) bool { return f.module == "setup" }) {
		t.Fatal("setup.py left out although setup.cfg could not be read")
	}
}

// TestLoadProgram_RuntimeSetuptoolsStillCounts is the control for build-script exclusion:
// a runtime module importing setuptools keeps its import and boundary edge while the
// project's setup.py beside it is left out.
func TestLoadProgram_RuntimeSetuptoolsStillCounts(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"requirements.txt": "setuptools\n",
		"setup.py":         "from setuptools import setup\nsetup(name='app')\n",
		"app.py":           "import setuptools\n\ndef pkgs(d):\n    return setuptools.find_packages(d)\n",
	})
	prog, err := loadProgram(dir)
	if err != nil {
		t.Fatalf("loadProgram: %v", err)
	}
	for _, f := range prog.files {
		if f.module == "setup" {
			t.Fatal("setup.py should be left out of the program")
		}
	}
	res := callGraphOf(prog)
	if !hasEdge(res.Edges, funcSCIP("app", nil, "pkgs", 1), "pypi:setuptools#setuptools.find_packages") {
		t.Fatalf("runtime setuptools edge missing; edges: %+v", res.Edges)
	}
}
