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
		boundary string   // must be among the boundary edges from caller
		exact    []string // the boundary edges from caller, exactly
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
			name:   "azure.identity.X reaches azure-identity under the shared azure namespace",
			files:  map[string]string{"app.py": "from azure.identity import DefaultAzureCredential\n\ndef cred(o):\n    return DefaultAzureCredential(o)\n"},
			caller: funcSCIP("app", nil, "cred", 1),
			exact:  []string{"pypi:azure-identity#azure.identity.DefaultAzureCredential"},
		},
		{
			name:   "dotted import chain reaches azure-identity",
			files:  map[string]string{"app.py": "import azure.identity\n\ndef cred(o):\n    return azure.identity.DefaultAzureCredential(o)\n"},
			caller: funcSCIP("app", nil, "cred", 1),
			exact:  []string{"pypi:azure-identity#azure.identity.DefaultAzureCredential"},
		},
		{
			name:   "botframework.connector.X reaches botframework-connector",
			files:  map[string]string{"app.py": "from botframework.connector import ConnectorClient\n\ndef client(o):\n    return ConnectorClient(o)\n"},
			caller: funcSCIP("app", nil, "client", 1),
			exact:  []string{"pypi:botframework-connector#botframework.connector.ConnectorClient"},
		},
		{
			name:   "longest curated package wins: azure.identity.broker is not azure-identity",
			files:  map[string]string{"app.py": "from azure.identity.broker import InteractiveBrowserBrokerCredential\n\ndef cred(o):\n    return InteractiveBrowserBrokerCredential(o)\n"},
			caller: funcSCIP("app", nil, "cred", 1),
			exact:  []string{"pypi:azure-identity-broker#azure.identity.broker.InteractiveBrowserBrokerCredential"},
		},
		{
			name: "declared sibling does not take another package's import",
			files: map[string]string{
				"requirements.txt": "azure-core==1.41.0\n",
				"app.py":           "from azure.identity import DefaultAzureCredential\n\ndef cred(o):\n    return DefaultAzureCredential(o)\n",
			},
			caller: funcSCIP("app", nil, "cred", 1),
			exact:  []string{"pypi:azure-identity#azure.identity.DefaultAzureCredential"},
		},
		{
			name:   "bare azure namespace root names no distribution",
			files:  map[string]string{"requirements.txt": "azure-core==1.41.0\n", "app.py": "import azure\n\ndef cred(o):\n    return azure.load(o)\n"},
			caller: funcSCIP("app", nil, "cred", 1),
		},
		{
			name: "uncurated package under the azure namespace names no distribution",
			files: map[string]string{
				"requirements.txt": "azure-core==1.41.0\n",
				"app.py":           "from azure.keyvault.secrets import SecretClient\n\ndef cred(o):\n    return SecretClient(o)\n",
			},
			caller: funcSCIP("app", nil, "cred", 1),
		},
		{
			name:   "curated package matches whole segments only",
			files:  map[string]string{"app.py": "from azure.identityx import Credential\n\ndef cred(o):\n    return Credential(o)\n"},
			caller: funcSCIP("app", nil, "cred", 1),
		},
		{
			name:   "teams reaches every distribution shipping it",
			files:  map[string]string{"requirements.txt": "teams-ai==1.8.2\n", "app.py": "import teams\n\ndef boot(o):\n    return teams.Application(o)\n"},
			caller: funcSCIP("app", nil, "boot", 1),
			exact:  []string{"pypi:teams#teams.Application", "pypi:teams-ai#teams.Application", "pypi:teams-ai-azml-model#teams.Application"},
		},
		{
			name:   "dotenv reaches every distribution shipping it",
			files:  map[string]string{"app.py": "from dotenv import load_dotenv\n\ndef boot(p):\n    return load_dotenv(p)\n"},
			caller: funcSCIP("app", nil, "boot", 1),
			exact:  []string{"pypi:django-dotenv#dotenv.load_dotenv", "pypi:python-dotenv#dotenv.load_dotenv", "pypi:python-dotenv-yaml#dotenv.load_dotenv"},
		},
		{
			name:   "jwt reaches every distribution shipping it",
			files:  map[string]string{"app.py": "import jwt\n\ndef check(t):\n    return jwt.decode(t)\n"},
			caller: funcSCIP("app", nil, "check", 1),
			exact:  []string{"pypi:jwt#jwt.decode", "pypi:pyjwt#jwt.decode"},
		},
		{
			name:   "PIL reaches every distribution shipping it",
			files:  map[string]string{"app.py": "from PIL import Image\n\ndef load(p):\n    return Image.open(p)\n"},
			caller: funcSCIP("app", nil, "load", 1),
			exact:  []string{"pypi:pillow#PIL.Image.open", "pypi:pillow-simd#PIL.Image.open"},
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
			if c.exact != nil {
				slices.Sort(got)
				if !slices.Equal(got, c.exact) {
					t.Fatalf("boundary edges from %s = %v, want exactly %v", c.caller, got, c.exact)
				}
				return
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

// buildScriptCase is one tree for the build-script exclusion tests. script is the module of
// the build-script candidate; edge is a boundary edge a kept script's module init must
// still have.
type buildScriptCase struct {
	name     string
	files    map[string]string
	script   string
	excluded bool
	edge     string
}

const (
	setupPy = "from setuptools import setup\nsetup(name='app')\n"
	// yamlSetupPy loads YAML when it runs, so a kept copy's module init has yamlLoad.
	yamlSetupPy = "from setuptools import setup\nimport yaml\ncfg = yaml.load(open('c.yml'))\nsetup(name='app')\n"
	yamlLoad    = "pypi:pyyaml#yaml.load"
	runtimePy   = "def check(t):\n    return t\n"
)

// checkBuildScript loads dir and checks whether c.script is in the program, that it stays
// first-party either way, and its module init's boundary edges.
func checkBuildScript(t *testing.T, dir string, c buildScriptCase) {
	t.Helper()
	prog, err := loadProgram(dir)
	if err != nil {
		t.Fatalf("loadProgram: %v", err)
	}
	present := slices.ContainsFunc(prog.files, func(f fileParse) bool { return f.module == c.script })
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
}

// benignPython runs only what its literal names and arguments say: plain imports, metadata
// and constant reads, and process launches with literal arguments.
const benignPython = `import subprocess
import os.path
import importlib
from importlib.metadata import version
from importlib import invalidate_caches, reload
from pkgutil import get_data, extend_path
from builtins import str
from os import path, sep

out = subprocess.run(["git", "describe"], check=True, stdout=subprocess.PIPE)
subprocess.call(["make"], stderr=subprocess.STDOUT)
subprocess.check_call(("make", "docs"), stdin=subprocess.DEVNULL)
subprocess.check_output(["git", "rev-parse", "HEAD"], timeout=5, env={"A": "1"})
subprocess.Popen([r"make", b"x"], cwd=None)
subprocess.getoutput("date")
subprocess.getstatusoutput('date')
errors = (subprocess.CalledProcessError, subprocess.TimeoutExpired, subprocess.SubprocessError)
done, info, quote = subprocess.CompletedProcess, subprocess.STARTUPINFO, subprocess.list2cmdline
v = version("app")
missing = importlib.metadata.PackageNotFoundError
here = os.path.dirname(__file__)
os.system("make docs")
os.execv("/usr/bin/make", ["make", "-j", 4])
importlib.invalidate_caches()
`

// keptBy is a row where files beside a root setup.py keep it in the program.
func keptBy(name string, files map[string]string) buildScriptCase {
	all := map[string]string{"setup.py": yamlSetupPy, "app.py": runtimePy}
	for p, s := range files {
		all[p] = s
	}
	return buildScriptCase{name: name, files: all, script: "setup", edge: yamlLoad}
}

// TestLoadProgram_BuildScripts: a packaging build script's imports are build-time, so a
// setup.py or hatch_build.py at the build root is left out of the program (no module, no
// boundary edge from its module init) while it stays first-party. It stays in when any
// other file under the build root mentions its name as a whole word, ignoring case, when any
// file that can carry Python names a loader, reaches a loader module other than plainly, or
// launches a process with arguments that are not all literals, when a relative import climbs
// above the root, or when a string in its own text names it.
func TestLoadProgram_BuildScripts(t *testing.T) {
	cases := []buildScriptCase{
		{
			name:     "setup.py importing setuptools is excluded",
			files:    map[string]string{"setup.py": setupPy, "app.py": runtimePy},
			script:   "setup",
			excluded: true,
		},
		{
			name:     "setup.py importing distutils is excluded",
			files:    map[string]string{"setup.py": "from distutils.core import setup\nsetup(name='app')\n", "app.py": runtimePy},
			script:   "setup",
			excluded: true,
		},
		{
			name: "hatch_build.py importing hatchling is excluded",
			files: map[string]string{
				"hatch_build.py": "from hatchling.builders.hooks.plugin.interface import BuildHookInterface\n\nclass Hook(BuildHookInterface):\n    def initialize(self, version, data):\n        return data\n",
				"app.py":         runtimePy,
			},
			script:   "hatch_build",
			excluded: true,
		},
		{
			name:     "a loader in the script's own text leaves it out",
			files:    map[string]string{"setup.py": "from setuptools import setup\nns = {}\nexec(open('src/app/version.py').read(), ns)\nsetup(name='app', version=ns['v'])\n", "app.py": runtimePy},
			script:   "setup",
			excluded: true,
		},
		{
			name:   "setup.py importing no build backend stays",
			files:  map[string]string{"setup.py": "import click\n\ndef setup(cfg):\n    return click.echo(cfg)\n", "app.py": runtimePy},
			script: "setup",
		},
		{
			name:   "setup.py beside a root __init__.py stays",
			files:  map[string]string{"__init__.py": "", "setup.py": yamlSetupPy},
			script: "setup",
			edge:   yamlLoad,
		},
		{
			name:   "setup.py below the build root stays",
			files:  map[string]string{"pkg/setup.py": yamlSetupPy, "pkg/run.py": runtimePy},
			script: "pkg/setup",
			edge:   yamlLoad,
		},

		// Another file mentions the script.
		keptBy("runtime import of the script's module keeps it", map[string]string{"app.py": "import setup\n\ndef check(t):\n    return t\n"}),
		keptBy("runtime star import of the script's module keeps it", map[string]string{"app.py": "from setup import *\n"}),
		keptBy("relative import of the script keeps it", map[string]string{"app.py": "from . import setup\n"}),
		keptBy("a comment naming the script keeps it", map[string]string{"app.py": "# python setup.py serve starts the dev server\n"}),
		keptBy("a Procfile launching the script keeps it", map[string]string{"Procfile": "web: python setup.py serve\n"}),
		keptBy("a Procfile naming it in another case keeps it", map[string]string{"Procfile": "web: python SETUP.PY serve\n"}),
		keptBy("a Dockerfile variant running the module keeps it", map[string]string{"Dockerfile.prod": "FROM python:3.12\nCMD [\"python\", \"-m\", \"setup\"]\n"}),
		keptBy("a Containerfile launching the script keeps it", map[string]string{"Containerfile": "FROM python:3.12\nENTRYPOINT python setup.py\n"}),
		keptBy("a named .dockerfile launching the script keeps it", map[string]string{"deploy/api.dockerfile": "FROM python:3.12\nCMD python setup.py\n"}),
		keptBy("a compose command launching the script keeps it", map[string]string{"docker-compose.yml": "services:\n  web:\n    command: python setup.py\n"}),
		keptBy("a shell script launching the script keeps it", map[string]string{"boot.sh": "#!/bin/sh\nexec python setup.py\n"}),
		keptBy("a systemd unit launching the script keeps it", map[string]string{"deploy/app.service": "[Service]\nExecStart=/usr/bin/python3 /srv/app/setup.py serve\n"}),
		keptBy("a supervisord program launching the script keeps it", map[string]string{"supervisord.conf": "[program:app]\ncommand=python setup.py serve\n"}),
		keptBy("a Makefile target running the script keeps it", map[string]string{"Makefile": "serve:\n\tpython setup.py serve\n"}),
		keptBy("a CI workflow running the module keeps it", map[string]string{".github/workflows/ci.yml": "jobs:\n  run:\n    steps:\n      - run: python -m setup\n"}),
		keptBy("a git hook running the script keeps it", map[string]string{".git/hooks/post-merge": "#!/bin/sh\npython setup.py develop\n"}),
		keptBy("a file under build/ naming the script keeps it", map[string]string{"build/run.cfg": "entry = setup\n"}),
		keptBy("a file under env/ naming the script keeps it", map[string]string{"env/bin/start": "#!/bin/sh\nexec python /srv/setup.py\n"}),
		keptBy("a pyproject entry point naming the script keeps it", map[string]string{"pyproject.toml": "[project]\nname = \"app\"\n\n[project.scripts]\nfoo = \"setup:main\"\n"}),
		keptBy("a setup.cfg console script naming the script keeps it", map[string]string{"setup.cfg": "[options.entry_points]\nconsole_scripts =\n    foo = setup:main\n"}),
		keptBy("an entry point through a package path keeps it", map[string]string{"pyproject.toml": "[project.scripts]\nfoo = \"pkg.setup:main\"\n"}),

		// The script's own strings name it.
		{
			name:   "an entry point the script declares about itself keeps it",
			files:  map[string]string{"setup.py": "from setuptools import setup\nimport yaml\ncfg = yaml.load(open('c.yml'))\nsetup(name='app', entry_points={'console_scripts': ['foo = setup:main']})\n", "app.py": runtimePy},
			script: "setup",
			edge:   yamlLoad,
		},
		{
			name:   "a module-only entry point the script declares keeps it",
			files:  map[string]string{"setup.py": "from setuptools import setup\nimport yaml\ncfg = yaml.load(open('c.yml'))\nsetup(name='app', entry_points={'app.plugins': ['foo = setup']})\n", "app.py": runtimePy},
			script: "setup",
			edge:   yamlLoad,
		},
		{
			name:   "py_modules listing the script keeps it",
			files:  map[string]string{"setup.py": "from setuptools import setup\nimport yaml\ncfg = yaml.load(open('c.yml'))\nsetup(name='app', py_modules=['setup', 'app'])\n", "app.py": runtimePy},
			script: "setup",
			edge:   yamlLoad,
		},

		// Nothing that could load the script.
		{
			name: "files that never mention the script leave it out",
			files: map[string]string{
				"setup.py":           yamlSetupPy,
				"app.py":             runtimePy,
				"Procfile":           "web: gunicorn app:check\n",
				"Dockerfile":         "FROM python:3.12\nRUN pip install .\nCMD [\"python\", \"app.py\"]\n",
				"Makefile":           "test:\n\tpytest\n",
				"setuptools.sh":      "pip install -U setuptools\n",
				"scripts/setup_env":  "export SETUP_ENV=1\n",
				"pyproject.toml":     "[project]\nname = \"app\"\n\n[project.scripts]\nfoo = \"app:check\"\n",
				"docs/loaders.md":    "Never call runpy.run_path(sys.argv[1]) on untrusted input.\n",
				"tools/version.py":   benignPython,
				"Dockerfile.tools":   "FROM python:3.12\nRUN python -c \"from importlib.metadata import version; print(version('pip'))\"\n",
				"start.sh":           "#!/bin/sh\nexec gunicorn app:check\n",
				".gitignore":         "build/\n",
				"src/app/version.py": "v = '1.0'\n",
			},
			script:   "setup",
			excluded: true,
		},
		{
			name:     "a mention under node_modules leaves it out",
			files:    map[string]string{"setup.py": yamlSetupPy, "app.py": runtimePy, "node_modules/tool/run.sh": "python setup.py\n"},
			script:   "setup",
			excluded: true,
		},
		{
			name:     "a mention or loader under site-packages leaves it out",
			files:    map[string]string{"setup.py": yamlSetupPy, "app.py": runtimePy, ".venv/lib/python3.12/site-packages/x/y.py": "import setup\nimport runpy\nrunpy.run_path(p)\n"},
			script:   "setup",
			excluded: true,
		},

		// A Python file loads code by path or computed name.
		keptBy("runpy.run_path with a computed path keeps it", map[string]string{"app.py": "import runpy, sys\nrunpy.run_path(sys.argv[1])\n"}),
		keptBy("exec of a file read from the environment keeps it", map[string]string{"app.py": "import os\nexec(open(os.environ['S']).read())\n"}),
		keptBy("spec_from_file_location over a plugin dir keeps it", map[string]string{"app.py": "import importlib.util, os\nfor f in os.listdir('plugins'):\n    s = importlib.util.spec_from_file_location(f, os.path.join('plugins', f))\n    importlib.util.module_from_spec(s)\n"}),
		keptBy("SourceFileLoader on a computed path keeps it", map[string]string{"app.py": "import sys\nfrom importlib.machinery import SourceFileLoader\nSourceFileLoader('x', sys.argv[1]).load_module()\n"}),
		keptBy("an aliased loader import keeps it", map[string]string{"app.py": "from runpy import run_path as rp\n\ndef go(p):\n    return rp(p)\n"}),
		keptBy("a literal dynamic import keeps it", map[string]string{"app.py": "import importlib\nmod = importlib.import_module('json')\n"}),
		keptBy("a dynamic import the scanner cannot name keeps it", map[string]string{"app.py": "import importlib\n\ndef load(n):\n    return importlib.import_module(n)\n"}),
		keptBy("a loader in a script the program doesn't parse keeps it", map[string]string{".github/scripts/release.py": "import runpy, sys\nrunpy.run_path(sys.argv[1])\n"}),
		keptBy("a loader in a .pth file keeps it", map[string]string{"boot.pth": "import os; exec(open(os.environ['BOOT']).read())\n"}),
		keptBy("a loader in a python-shebang script keeps it", map[string]string{"bin/run": "#!/usr/bin/env python3\nimport runpy, sys\nrunpy.run_path(sys.argv[1])\n"}),
		keptBy("relative import climbing above the build root keeps it", map[string]string{"app.py": "from .. import helpers\n"}),

		// A loader reached by name, or named in text the interpreter may run.
		keptBy("a loader named only in a comment or string keeps it", map[string]string{"tools/comment.py": "# exec and run_path appear only in this comment\nmsg = 'spec_from_file_location'\n"}),
		keptBy("a string-keyed getattr on importlib keeps it", map[string]string{"app.py": "import importlib\nload = getattr(importlib, name)\n"}),
		keptBy("a concatenated loader name keeps it", map[string]string{"app.py": "import importlib\nload = getattr(importlib, 'imp' + 'ort_module')\n"}),
		keptBy("a loader module's __dict__ keeps it", map[string]string{"app.py": "import importlib\nload = importlib.__dict__['imp' + 'ort_module']\n"}),
		keptBy("attrgetter on a loader module keeps it", map[string]string{"app.py": "import importlib, operator\nload = operator.attrgetter('imp' + 'ort_module')(importlib)\n"}),
		keptBy("an aliased loader module keeps it", map[string]string{"app.py": "import importlib as il\nload = getattr(il, name)\n"}),
		keptBy("an aliased loader submodule keeps it", map[string]string{"app.py": "import importlib.util as u\nload = getattr(u, name)\n"}),
		keptBy("a loader submodule from-imported keeps it", map[string]string{"app.py": "from importlib import util\nload = getattr(util, name)\n"}),
		keptBy("a loader submodule handed on as a value keeps it", map[string]string{"app.py": "import importlib\nu = importlib.util\n"}),
		keptBy("a dunder deeper in a loader module chain keeps it", map[string]string{"app.py": "import importlib\nf = importlib.util.__dict__[n]\n"}),
		keptBy("a private subprocess attribute keeps it", map[string]string{"app.py": "import subprocess\nsubprocess._posixsubprocess.fork_exec(args)\n"}),
		keptBy("subprocess named in a string keeps it", map[string]string{"app.py": "import sys\nsys.modules['subprocess'].run(cmd)\n"}),
		keptBy("os named in a string keeps it", map[string]string{"app.py": "import sys\nsys.modules['os'].system(cmd)\n"}),
		keptBy("a from-import aliased from a loader module keeps it", map[string]string{"app.py": "from importlib import reload as r\n"}),
		keptBy("builtins reached by name keeps it", map[string]string{"app.py": "import builtins\nf = vars(builtins)[name]\n"}),
		keptBy("__builtins__ indexed keeps it", map[string]string{"app.py": "f = __builtins__['ev' + 'al']\n"}),
		keptBy("a Dockerfile RUN python -c naming a loader keeps it", map[string]string{"Dockerfile": "FROM python:3.12\nRUN python3 -c \"import importlib; getattr(importlib, 'imp' + 'ort_module')\"\n"}),
		keptBy("flags before -c keep it", map[string]string{"Dockerfile": "FROM python:3.12\nRUN python3 -I -u -c \"import importlib; getattr(importlib, n)\"\n"}),
		keptBy("a flag cluster ending in c keeps it", map[string]string{"Dockerfile": "FROM python:3.12\nRUN python -Ic \"import importlib; getattr(importlib, n)\"\n"}),
		keptBy("a shell heredoc into python keeps it", map[string]string{"boot.sh": "#!/bin/sh\npython3 <<'EOF'\nimport importlib, sys\ngetattr(importlib, sys.argv[1])\nEOF\n"}),
		keptBy("python reading a script from stdin keeps it", map[string]string{"boot.sh": "#!/bin/sh\npython3 - \"$@\" <<'EOF'\nimport importlib, sys\ngetattr(importlib, sys.argv[1])\nEOF\n"}),
		keptBy("a script piped into python keeps it", map[string]string{"boot.sh": "#!/bin/sh\necho \"import importlib; getattr(importlib, n)\" | python3\n"}),
		keptBy("a uv run --script shebang keeps it", map[string]string{"bin/tool": "#!/usr/bin/env -S uv run --script\nimport importlib, sys\ngetattr(importlib, sys.argv[1])\n"}),
		keptBy("a pipx run shebang keeps it", map[string]string{"bin/tool": "#!/usr/bin/env -S pipx run\nimport importlib, sys\ngetattr(importlib, sys.argv[1])\n"}),
		keptBy("a pypy shebang keeps it", map[string]string{"bin/tool": "#!/usr/bin/pypy3\nimport importlib, sys\ngetattr(importlib, sys.argv[1])\n"}),
		keptBy("a Cython .pyx naming a loader keeps it", map[string]string{"ext/fast.pyx": "import importlib\ndef go(n):\n    return getattr(importlib, n)\n"}),
		keptBy("a Cython .pxd naming a loader keeps it", map[string]string{"ext/fast.pxd": "# run_path\n"}),
		keptBy("a Cython .pxi naming a loader keeps it", map[string]string{"ext/fast.pxi": "# run_path\n"}),
		keptBy("a .pyw naming a loader keeps it", map[string]string{"gui.pyw": "# run_path\n"}),
		keptBy("a CI step running python -c keeps it", map[string]string{".github/workflows/ci.yml": "jobs:\n  r:\n    steps:\n      - run: python -c \"import importlib, os; getattr(importlib, os.environ['L'])\"\n"}),
		keptBy("a notebook naming a loader keeps it", map[string]string{"nb/explore.ipynb": "{\"cells\": [{\"cell_type\": \"code\", \"source\": [\"import importlib\\n\", \"getattr(importlib, n)\"]}]}\n"}),

		// A process launch that could run any script.
		keptBy("subprocess with a computed argument keeps it", map[string]string{"app.py": "import subprocess, sys\nsubprocess.run([sys.executable, sys.argv[1]])\n"}),
		keptBy("subprocess with an f-string keeps it", map[string]string{"app.py": "import subprocess\nsubprocess.run(f\"python {p}\", shell=True)\n"}),
		keptBy("a subprocess launch referenced, not called, keeps it", map[string]string{"app.py": "import subprocess\nrunner = subprocess.check_output\n"}),
		keptBy("a subprocess launch from-imported keeps it", map[string]string{"app.py": "from subprocess import run\n"}),
		keptBy("subprocess aliased keeps it", map[string]string{"app.py": "import subprocess as sp\nsp.run(cmd)\n"}),
		keptBy("getattr on subprocess keeps it", map[string]string{"app.py": "import subprocess\ngetattr(subprocess, 'run')(cmd)\n"}),
		keptBy("subprocess Popen with a computed argument keeps it", map[string]string{"app.py": "import subprocess\nsubprocess.Popen(cmd)\n"}),
		keptBy("os.system with a computed argument keeps it", map[string]string{"app.py": "import os\nos.system(cmd)\n"}),
		keptBy("os.popen with a computed argument keeps it", map[string]string{"app.py": "import os\nos.popen(cmd)\n"}),
		keptBy("os.execv with a computed argument keeps it", map[string]string{"app.py": "import os, sys\nos.execv(sys.executable, [sys.executable, sys.argv[1]])\n"}),
		keptBy("os.spawnv with a computed argument keeps it", map[string]string{"app.py": "import os\nos.spawnv(os.P_WAIT, p, [p])\n"}),
		keptBy("os.posix_spawn with a computed argument keeps it", map[string]string{"app.py": "import os\nos.posix_spawn(p, [p], {})\n"}),
		keptBy("os.startfile with a computed argument keeps it", map[string]string{"app.py": "import os\nos.startfile(p)\n"}),
		keptBy("an os launch from-imported keeps it", map[string]string{"app.py": "from os import execv\n"}),
		keptBy("a star import from os keeps it", map[string]string{"app.py": "from os import *\n"}),
		keptBy("os aliased keeps it", map[string]string{"app.py": "import os as o\no.system(cmd)\n"}),
		keptBy("os handed on as a value keeps it", map[string]string{"app.py": "import os\nm = os\n"}),
		keptBy("getattr on os keeps it", map[string]string{"app.py": "import os\ngetattr(os, 'system')(cmd)\n"}),
		keptBy("os.__dict__ keeps it", map[string]string{"app.py": "import os\nos.__dict__['system'](cmd)\n"}),
		keptBy("posix.system with a computed argument keeps it", map[string]string{"app.py": "import posix\nposix.system(cmd)\n"}),
		keptBy("pty.spawn with a computed argument keeps it", map[string]string{"app.py": "import pty\npty.spawn(argv)\n"}),
		keptBy("asyncio create_subprocess_exec with a computed argument keeps it", map[string]string{"app.py": "import asyncio\n\nasync def go(p):\n    await asyncio.create_subprocess_exec('python', p)\n"}),
		keptBy("asyncio create_subprocess_shell with a computed argument keeps it", map[string]string{"app.py": "import asyncio\n\nasync def go(c):\n    await asyncio.create_subprocess_shell(c)\n"}),
		keptBy("loop.subprocess_exec with a computed argument keeps it", map[string]string{"app.py": "async def go(loop, proto, p):\n    await loop.subprocess_exec(proto, p)\n"}),
		keptBy("loop.subprocess_shell with a computed argument keeps it", map[string]string{"app.py": "async def go(loop, proto, c):\n    await loop.subprocess_shell(proto, c)\n"}),
		keptBy("a launch in a Dockerfile python -c keeps it", map[string]string{"Dockerfile": "FROM python:3.12\nRUN python -c \"import os, sys; os.system(sys.argv[1])\" x\n"}),
	}
	// The leaves are listed here, not read from the loader tables, so dropping one from a
	// table turns its row red instead of removing it.
	leafs := []string{
		"run_path", "run_module", "exec", "execfile", "eval", "spec_from_file_location",
		"spec_from_loader", "module_from_spec", "exec_module", "load_module", "SourceFileLoader",
		"SourcelessFileLoader", "load_source", "load_compiled", "load_package", "iter_modules",
		"zipimporter", "import_module", "__import__", "resolve_name", "entry_points",
		"iter_entry_points", "load_entry_point", "walk_packages",
	}
	for _, m := range []map[string]bool{fileLoaderLeafs, dynamicImportLiteralLeafs, dynamicImportOpaqueLeafs} {
		for l := range m {
			if !slices.Contains(leafs, l) {
				t.Errorf("loader %s has no row", l)
			}
		}
	}
	for _, l := range leafs {
		cases = append(cases, keptBy("loader "+l+" keeps it", map[string]string{"app.py": "import mod\n\ndef go(p):\n    return mod." + l + "(p)\n"}))
	}
	// Likewise every module reached by getattr, and every asyncio launch with a computed
	// argument.
	modules := []string{"importlib", "runpy", "imp", "pkgutil", "zipimport", "builtins", "__builtins__", "os", "posix", "nt", "pty"}
	for m := range loaderModules {
		if !slices.Contains(modules, m) {
			t.Errorf("loader module %s has no row", m)
		}
	}
	for m := range processModules {
		if !slices.Contains(modules, m) {
			t.Errorf("process module %s has no row", m)
		}
	}
	for _, m := range modules {
		cases = append(cases, keptBy("getattr on "+m+" keeps it", map[string]string{"app.py": "import " + m + "\nf = getattr(" + m + ", n)\n"}))
	}
	launches := []string{"create_subprocess_exec", "create_subprocess_shell", "subprocess_exec", "subprocess_shell"}
	for l := range processLaunchLeafs {
		if !slices.Contains(launches, l) {
			t.Errorf("process launch %s has no row", l)
		}
	}
	for _, l := range launches {
		cases = append(cases, keptBy("launch "+l+" with a computed argument keeps it", map[string]string{"app.py": "async def go(x, p):\n    await x." + l + "('python', p)\n"}))
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.files["requirements.txt"] = "setuptools\nhatchling\nclick\n"
			checkBuildScript(t, writeTree(t, c.files), c)
		})
	}
}

// TestLoadProgram_BuildScriptScanFailsClosed: a file or directory the build-tree scan
// can't read in full might mention the script, so every build script stays in. A symlinked
// directory is read only through its target, when the walk itself reads that target.
func TestLoadProgram_BuildScriptScanFailsClosed(t *testing.T) {
	unreadable := func(t *testing.T, p string) {
		if os.Geteuid() == 0 {
			t.Skip("root reads files whatever their mode")
		}
		if err := os.Chmod(p, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o755) })
	}
	symlink := func(t *testing.T, target, link string) {
		if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name     string
		files    map[string]string
		prepare  func(t *testing.T, dir string)
		excluded bool
	}{
		{
			name:    "an unreadable file keeps it",
			files:   map[string]string{"deploy/app.service": "[Service]\n"},
			prepare: func(t *testing.T, dir string) { unreadable(t, filepath.Join(dir, "deploy/app.service")) },
		},
		{
			// build/ is outside the program's source walk, so the scan is what has to stop.
			name:    "an unreadable directory keeps it",
			files:   map[string]string{"build/deploy/app.service": "[Service]\n"},
			prepare: func(t *testing.T, dir string) { unreadable(t, filepath.Join(dir, "build/deploy")) },
		},
		{
			name:  "a binary file keeps it",
			files: map[string]string{"assets/blob.bin": "PK\x00\x01\x02"},
		},
		{
			name:  "a file larger than the scan limit keeps it",
			files: map[string]string{"data/big.txt": strings.Repeat("x", 4096)},
			prepare: func(t *testing.T, _ string) {
				old := maxScannedFile
				maxScannedFile = 1024
				t.Cleanup(func() { maxScannedFile = old })
			},
		},
		{
			name: "a dangling setup.cfg symlink keeps it",
			prepare: func(t *testing.T, dir string) {
				symlink(t, filepath.Join(dir, "missing.cfg"), filepath.Join(dir, "setup.cfg"))
			},
		},
		{
			name: "a dangling Procfile symlink keeps it",
			prepare: func(t *testing.T, dir string) {
				symlink(t, filepath.Join(dir, "missing"), filepath.Join(dir, "Procfile"))
			},
		},
		{
			name: "a symlink to a file outside the build dir keeps it",
			prepare: func(t *testing.T, dir string) {
				out := filepath.Join(t.TempDir(), "run.sh")
				if err := os.WriteFile(out, []byte("echo hi\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				symlink(t, out, filepath.Join(dir, "run.sh"))
			},
		},
		{
			name:    "a symlinked directory outside the build dir keeps it",
			prepare: func(t *testing.T, dir string) { symlink(t, t.TempDir(), filepath.Join(dir, "deploy")) },
		},
		{
			name:  "a symlinked directory into node_modules keeps it",
			files: map[string]string{"node_modules/tool/run.sh": "echo hi\n"},
			prepare: func(t *testing.T, dir string) {
				symlink(t, filepath.Join(dir, "node_modules/tool"), filepath.Join(dir, "tool"))
			},
		},
		{
			name:     "a symlinked directory to one the walk reads leaves it out",
			files:    map[string]string{"deploy/app.service": "[Service]\nExecStart=/usr/bin/gunicorn app:check\n"},
			prepare:  func(t *testing.T, dir string) { symlink(t, filepath.Join(dir, "deploy"), filepath.Join(dir, "ops")) },
			excluded: true,
		},
		{
			name:  "a symlink to a file inside the build dir leaves it out",
			files: map[string]string{"deploy/app.service": "[Service]\nExecStart=/usr/bin/gunicorn app:check\n"},
			prepare: func(t *testing.T, dir string) {
				symlink(t, filepath.Join(dir, "deploy/app.service"), filepath.Join(dir, "app.service"))
			},
			excluded: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			files := map[string]string{"setup.py": setupPy, "app.py": runtimePy}
			for p, s := range c.files {
				files[p] = s
			}
			dir := writeTree(t, files)
			if c.prepare != nil {
				c.prepare(t, dir)
			}
			checkBuildScript(t, dir, buildScriptCase{script: "setup", excluded: c.excluded})
		})
	}
}

// TestLoadProgram_RuntimeSetuptoolsStillCounts is the control for build-script exclusion:
// a runtime module importing setuptools keeps its import and boundary edge while the
// project's setup.py beside it is left out. Nothing mentions app.py, so only its file name
// keeps it from being a candidate.
func TestLoadProgram_RuntimeSetuptoolsStillCounts(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"requirements.txt": "setuptools\n",
		"setup.py":         "from setuptools import setup\nsetup(name='proj')\n",
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

// TestReadScanned: the build-tree scan reads a file whole or reports why it couldn't. The
// walk opens each file before the scan sees it, so this is the only place an open that
// fails here, after the walk's own succeeded, shows up.
func TestReadScanned(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	old := maxScannedFile
	maxScannedFile = 16
	t.Cleanup(func() { maxScannedFile = old })
	cases := []struct {
		name, path, why string
	}{
		{"text", write("ok.txt", "python setup.py\n"), ""},
		{"missing", filepath.Join(dir, "gone.txt"), "unreadable"},
		{"too large", write("big.txt", strings.Repeat("x", 17)), "too large to scan"},
		{"binary", write("bin.dat", "PK\x00\x01"), "binary"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, why := readScanned(c.path)
			if why != c.why {
				t.Fatalf("why = %q, want %q", why, c.why)
			}
			if why == "" && string(data) != "python setup.py\n" {
				t.Errorf("data = %q", data)
			}
		})
	}
}
