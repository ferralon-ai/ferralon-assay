package pythonanalysis

import (
	"context"
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
			name:   "declaring one shipper keeps the edge to every shipper",
			files:  map[string]string{"requirements.txt": "pyjwt==2.8.0\n", "app.py": "import jwt\n\ndef check(t):\n    return jwt.decode(t)\n"},
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
			name: "declared distribution of the import's own name beside the curated shippers",
			files: map[string]string{
				"requirements.txt": "dotenv==0.0.5\n",
				"app.py":           "import dotenv\n\ndef key(p):\n    return dotenv.get_key(p, \"k\")\n",
			},
			caller: funcSCIP("app", nil, "key", 1),
			exact:  []string{"pypi:django-dotenv#dotenv.get_key", "pypi:dotenv#dotenv.get_key", "pypi:python-dotenv#dotenv.get_key", "pypi:python-dotenv-yaml#dotenv.get_key"},
		},
		{
			name: "declared legacy azure monolith under the shared namespace",
			files: map[string]string{
				"requirements.txt": "azure==0.11.1\n",
				"app.py":           "from azure.storage import BlobService\nimport azure.servicebus\n\ndef wire(a):\n    BlobService(a)\n    return azure.servicebus.ServiceBusService(a)\n",
			},
			caller: funcSCIP("app", nil, "wire", 1),
			exact:  []string{"pypi:azure#azure.servicebus.ServiceBusService", "pypi:azure#azure.storage.BlobService"},
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

// TestCallGraph_ManifestReadInPartIsToolFailure: the PEP 503 fallback maps an import to a
// distribution only when a manifest declares it. When a manifest fails to parse, or a file
// declares dependencies the lane does not read, AND some import resolves to no distribution,
// the name that would attribute it may be in the part not read, so the call graph carries
// tool_failure. With every import attributed (declared, curated, standard library or
// first-party) the unread part changes no boundary node and adds no reason. A pyproject TOML
// rejects still lends its lexical [project] names to the fallback.
func TestCallGraph_ManifestReadInPartIsToolFailure(t *testing.T) {
	const app = "import acmelib\n\ndef fetch(u):\n    return acmelib.get(u)\n"
	const edge = "pypi:acmelib#acmelib.get"
	const setupCfg = "[options]\ninstall_requires =\n    acmelib\n"
	// interp builds a tree whose Pipfile goes unread, whose only read manifest declares
	// acmelib, and whose interpreter is declared by the given files.
	interp := func(imports string, files map[string]string) map[string]string {
		tree := map[string]string{
			"requirements.txt": "acmelib==1.0\n",
			"Pipfile":          "[packages]\npyasyncore = \"*\"\ngraphlib-backport = \"*\"\n",
			"app.py":           app + "\n" + imports,
		}
		for k, v := range files {
			tree[k] = v
		}
		return tree
	}
	requires := func(spec string) map[string]string {
		return map[string]string{"pyproject.toml": "[project]\nname = \"app\"\nrequires-python = \"" + spec + "\"\n"}
	}
	cases := []struct {
		name        string
		files       map[string]string
		toolFailure bool
		boundary    bool
	}{
		{
			name:     "clean requirements",
			files:    map[string]string{"requirements.txt": "acmelib==1.0\n", "app.py": app},
			boundary: true,
		},
		{
			name: "unread Pipfile, import declared nowhere read",
			files: map[string]string{
				"Pipfile": "[packages]\nacmelib = \"*\"\n",
				"app.py":  app,
			},
			toolFailure: true,
		},
		{
			name: "setup.cfg read, import declared there",
			files: map[string]string{
				"setup.cfg": setupCfg,
				"app.py":    app,
			},
			boundary: true,
		},
		{
			name: "unparseable requirements, import declared nowhere read",
			files: map[string]string{
				"requirements.txt": "acmelib==1.0\nhttps://example.com/pkg.whl\n",
				"app.py":           app + "\nimport othermod\n",
			},
			toolFailure: true,
			boundary:    true,
		},
		{
			name: "complete manifests, import declared nowhere",
			files: map[string]string{
				"requirements.txt": "flask==3.0.0\n",
				"app.py":           app,
			},
		},
		{
			name: "unparseable requirements, import declared in the part read",
			files: map[string]string{
				"requirements.txt": "acmelib==1.0\nhttps://example.com/pkg.whl\n",
				"app.py":           app,
			},
			boundary: true,
		},
		{
			name: "pyproject TOML rejects, import declared lexically",
			files: map[string]string{
				"pyproject.toml": "[project]\nname = \"app\"\ndependencies = [\"acmelib>=1\"]\n\n[tool.broken\n",
				"app.py":         app,
			},
			boundary: true,
		},
		{
			name: "unread setup.cfg, standard library import",
			files: map[string]string{
				"requirements.txt": "acmelib==1.0\n",
				"setup.cfg":        setupCfg,
				"app.py":           app + "\nimport os.path\nfrom collections import OrderedDict\n",
			},
			boundary: true,
		},
		{
			name: "unread setup.cfg, first-party import",
			files: map[string]string{
				"requirements.txt": "acmelib==1.0\n",
				"setup.cfg":        setupCfg,
				"helpers.py":       "def h():\n    return 1\n",
				"app.py":           app + "\nimport helpers\n",
			},
			boundary: true,
		},
		{
			name: "unread setup.cfg, curated import",
			files: map[string]string{
				"requirements.txt": "acmelib==1.0\n",
				"setup.cfg":        setupCfg,
				"app.py":           app + "\nimport jwt\n",
			},
			boundary: true,
		},
		{
			name:        "unread Pipfile, asyncore on 3.12 or later",
			files:       interp("import asyncore\n", requires(">=3.12")),
			toolFailure: true,
			boundary:    true,
		},
		{
			name:        "unread Pipfile, graphlib on 3.8",
			files:       interp("import graphlib\n", requires("==3.8.*")),
			toolFailure: true,
			boundary:    true,
		},
		{
			name:        "unread Pipfile, undeclared third-party import",
			files:       interp("import othermod\n", requires(">=3.12")),
			toolFailure: true,
			boundary:    true,
		},
		{
			name:     "unread Pipfile, asyncore on 3.8 through 3.11",
			files:    interp("import asyncore\n", requires(">=3.8,<3.12")),
			boundary: true,
		},
		{
			name:     "unread Pipfile, graphlib on 3.9 or later",
			files:    interp("import graphlib\n", requires(">=3.9")),
			boundary: true,
		},
		{
			name:        "unread Pipfile, asyncore only on releases newer than the tables",
			files:       interp("import asyncore\n", requires(">=3.15")),
			toolFailure: true,
			boundary:    true,
		},
		{
			name:        "unread Pipfile, dataclasses on 3.6 or later",
			files:       interp("import dataclasses\n", requires(">=3.6")),
			toolFailure: true,
			boundary:    true,
		},
		{
			name:        "unread Pipfile, enum on 2.7 or later",
			files:       interp("import enum\n", requires(">=2.7")),
			toolFailure: true,
			boundary:    true,
		},
		{
			name:     "unread Pipfile, no interpreter declared, module 3.8 and later ship",
			files:    interp("import dataclasses\nimport asyncio\n", nil),
			boundary: true,
		},
		{
			name:        "unread Pipfile, no interpreter declared, module 3.8 lacks",
			files:       interp("import tomllib\n", nil),
			toolFailure: true,
			boundary:    true,
		},
		{
			name:        "unread Pipfile, no interpreter declared, module 3.12 dropped",
			files:       interp("import distutils\n", nil),
			toolFailure: true,
			boundary:    true,
		},
		{
			name:        "unread Pipfile, unreadable requires-python",
			files:       interp("import dataclasses\n", requires("3.8 or newer")),
			toolFailure: true,
			boundary:    true,
		},
		{
			name:     "unread Pipfile, one of two curated shippers declared",
			files:    interp("import jwt\n", map[string]string{"requirements.txt": "acmelib==1.0\npyjwt==2.8.0\n"}),
			boundary: true,
		},
		{
			name:        "unread Pipfile, neither curated shipper declared",
			files:       interp("import jwt\n", nil),
			toolFailure: true,
			boundary:    true,
		},
		{
			name:     "unread Pipfile, sole curated shipper undeclared",
			files:    interp("import yaml\n", nil),
			boundary: true,
		},
		{
			name:     "unread Pipfile, distribution of the import's own name declared beside curated shippers",
			files:    interp("import dotenv\n", map[string]string{"requirements.txt": "acmelib==1.0\ndotenv==0.0.5\n"}),
			boundary: true,
		},
		{
			name:     "unread Pipfile, instance binding of a curated import",
			files:    interp("from jinja2 import Environment\n\ndef render(x):\n    env = Environment()\n    return env.from_string(x)\n", nil),
			boundary: true,
		},
		{
			name:     "unread Pipfile, .python-version pin",
			files:    interp("import tomllib\n", map[string]string{".python-version": "3.11\n"}),
			boundary: true,
		},
		{
			name:     "unread Pipfile, uv.lock requires-python",
			files:    interp("import asyncore\n", map[string]string{"uv.lock": "version = 1\nrequires-python = \">=3.8, <3.12\"\n"}),
			boundary: true,
		},
		{
			name: "B2-1 othermod declared only in requirements.lock",
			files: map[string]string{
				"requirements.txt":  "acmelib==1.0\n",
				"requirements.lock": "othermod==1.0\n",
				"app.py":            app + "\nimport othermod\n",
			},
			toolFailure: true,
			boundary:    true,
		},
		{
			name: "B2-2 othermod declared only in pylock.toml",
			files: map[string]string{
				"requirements.txt": "acmelib==1.0\n",
				"pylock.toml":      "lock-version = \"1.0\"\n\n[[packages]]\nname = \"othermod\"\nversion = \"1.0\"\n",
				"app.py":           app + "\nimport othermod\n",
			},
			toolFailure: true,
			boundary:    true,
		},
		{
			name: "B2-3 othermod declared only in tox deps",
			files: map[string]string{
				"requirements.txt": "acmelib==1.0\n",
				"tox.ini":          "[testenv]\ndeps =\n    othermod\n",
				"app.py":           app + "\nimport othermod\n",
			},
			toolFailure: true,
			boundary:    true,
		},
		{
			name: "B2-4 othermod declared only in a conda environment's pip section",
			files: map[string]string{
				"requirements.txt": "acmelib==1.0\n",
				"conda-env.yml":    "channels:\n  - conda-forge\ndependencies:\n  - pip:\n    - othermod\n",
				"app.py":           app + "\nimport othermod\n",
			},
			toolFailure: true,
			boundary:    true,
		},
		{
			name: "B2-5 othermod declared only under build/",
			files: map[string]string{
				"requirements.txt":       "acmelib==1.0\n",
				"build/requirements.txt": "othermod==1.0\n",
				"app.py":                 app + "\nimport othermod\n",
			},
			toolFailure: true,
			boundary:    true,
		},
		{
			name: "B2-6 othermod declared only in a Pipfile (holds before and after the merge)",
			files: map[string]string{
				"requirements.txt": "acmelib==1.0\n",
				"Pipfile":          "[packages]\nothermod = \"*\"\n",
				"app.py":           app + "\nimport othermod\n",
			},
			toolFailure: true,
			boundary:    true,
		},
		{
			name: "B2-7 unread requirements.lock, othermod also declared in the part read",
			files: map[string]string{
				"requirements.txt":  "acmelib==1.0\nothermod==1.0\n",
				"requirements.lock": "othermod==1.0\n",
				"app.py":            app + "\nimport othermod\n",
			},
			boundary: true,
		},
		{
			name: "B2-8 build hook the install-surface classifier never reads in full",
			files: map[string]string{
				"requirements.txt": "acmelib==1.0\n",
				"hatch_build.py":   "from hatchling.builders.hooks.plugin.interface import BuildHookInterface\nclass H(BuildHookInterface):\n    pass\n",
				"app.py":           app + "\nimport othermod\n",
			},
			toolFailure: true,
			boundary:    true,
		},
		{
			name: "B2-9 dynamic optional-dependencies with no source read",
			files: map[string]string{
				"requirements.txt": "acmelib==1.0\n",
				"pyproject.toml":   "[project]\nname = \"app\"\ndynamic = [\"dependencies\", \"optional-dependencies\"]\n\n[tool.setuptools.dynamic]\ndependencies = {file = [\"requirements.txt\"]}\n",
				"app.py":           app + "\nimport othermod\n",
			},
			toolFailure: true,
			boundary:    true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeTree(t, c.files)})
			if err != nil {
				t.Fatalf("CallGraph: %v", err)
			}
			if got := hasReason(res.Partiality, plugin.PartialReasonToolFailure); got != c.toolFailure {
				t.Errorf("tool_failure = %v, want %v (reasons %v)", got, c.toolFailure, res.Partiality.Reasons)
			}
			caller := funcSCIP("app", nil, "fetch", 1)
			if got := hasEdge(res.Edges, caller, edge); got != c.boundary {
				t.Errorf("boundary edge %s -> %s present = %v, want %v\nedges: %+v", caller, edge, got, c.boundary, res.Edges)
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

// TestCallGraph_TestModuleHazards: an opaque dynamic import or evaluated code in a test
// module withholds only when production code imports that module or has an edge into it.
func TestCallGraph_TestModuleHazards(t *testing.T) {
	const (
		opaque = "import importlib\n\ndef load(n):\n    return importlib.import_module(n)\n"
		evals  = "def run_eval(s):\n    return eval(s)\n"
		fcall  = "def show(x):\n    return f\"{g(x)}\"\n"
		app    = "def main():\n    return 1\n"
	)
	cases := []struct {
		name           string
		files          map[string]string
		dynamic, sites bool
	}{
		{"opaque import under tests", map[string]string{"app.py": app, "tests/test_a.py": opaque}, false, false},
		{"eval under tests", map[string]string{"app.py": app, "tests/test_a.py": evals}, false, false},
		{"f-string call under test", map[string]string{"app.py": app, "test/helpers.py": fcall}, false, false},
		{"test_ file at the root", map[string]string{"app.py": app, "test_app.py": opaque}, false, false},
		{"_test file", map[string]string{"app.py": app, "pkg/app_test.py": evals}, false, false},
		{"conftest", map[string]string{"app.py": app, "conftest.py": opaque + evals}, false, false},
		{"test module imported only by tests", map[string]string{"app.py": app, "tests/helpers.py": opaque + evals, "tests/test_a.py": "from tests.helpers import load\n"}, false, false},
		{"test module called only by tests", map[string]string{"app.py": app, "tests/helpers.py": evals, "tests/test_a.py": "def test_x():\n    run_eval('1')\n"}, false, false},
		{"production hazard", map[string]string{"app.py": opaque + evals, "tests/test_a.py": app}, true, true},
		{"from-imported by production", map[string]string{"app.py": "from tests.helpers import load\n", "tests/helpers.py": opaque + evals}, true, true},
		{"imported by production", map[string]string{"app.py": "import tests.helpers\n", "tests/helpers.py": opaque}, true, false},
		{"star-imported by production", map[string]string{"app.py": "from tests.helpers import *\n", "tests/helpers.py": evals}, false, true},
		{"package init of a production import", map[string]string{"app.py": "import tests.helpers\n", "tests/__init__.py": opaque, "tests/helpers.py": app}, true, false},
		{"relative import by production", map[string]string{"pkg/__init__.py": "", "pkg/app.py": "from .tests import helpers\n", "pkg/tests/helpers.py": opaque}, true, false},
		{"relative package import by production", map[string]string{"pkg/__init__.py": "", "pkg/app.py": "from . import tests\n", "pkg/tests/__init__.py": opaque}, true, false},
		{"literal dynamic import by production", map[string]string{"app.py": "import importlib\nh = importlib.import_module('tests.helpers')\n", "tests/helpers.py": evals}, false, true},
		{"bare name a test module answers to", map[string]string{"app.py": "import helpers\n", "tests/helpers.py": opaque}, true, false},
		{"through another test module", map[string]string{"app.py": "from tests import util\n", "tests/util.py": "from tests.deep import load\n", "tests/deep.py": opaque}, true, false},
		{"edge from production", map[string]string{"app.py": "def main():\n    return run_eval('1')\n", "tests/helpers.py": evals}, false, true},
		{"backslash before import", map[string]string{"app.py": "from tests.helpers \\\n    import load\n", "tests/helpers.py": opaque}, true, false},
		{"backslash after import", map[string]string{"app.py": "from tests import \\\n    helpers\n", "tests/helpers.py": opaque}, true, false},
		{"backslash in a plain import", map[string]string{"app.py": "import \\\n    tests.helpers\n", "tests/helpers.py": opaque}, true, false},
		{"parenthesis after import", map[string]string{"app.py": "from tests import(helpers)\n", "tests/helpers.py": opaque}, true, false},
		{"tabs", map[string]string{"app.py": "from\ttests\timport\thelpers\n", "tests/helpers.py": opaque}, true, false},
		{"__import__ keyword fromlist", map[string]string{"app.py": "h = __import__('tests', fromlist=['helpers'])\n", "tests/helpers.py": opaque}, true, false},
		{"__import__ positional fromlist", map[string]string{"app.py": "h = __import__('tests', None, None, ['helpers'])\n", "tests/helpers.py": opaque}, true, false},
		{"__import__ without fromlist", map[string]string{"app.py": "h = __import__('tests')\n", "tests/helpers.py": opaque}, false, false},
		{"star import of a package", map[string]string{"app.py": "from tests import *\n", "tests/__init__.py": "__all__ = ['helpers']\n", "tests/helpers.py": opaque}, true, false},
		{"unread import", map[string]string{"app.py": "from tests import helpers as h, 1bad\n", "tests/other.py": opaque}, true, false},
		{"space before a dot", map[string]string{"app.py": "import tests .helpers\n", "tests/other.py": opaque}, true, false},
		{"after a byte order mark", map[string]string{"app.py": "\ufefffrom tests import helpers\n", "tests/helpers.py": opaque}, true, false},
		{"after a form feed", map[string]string{"app.py": "\f\nx = 1\n\ffrom tests import helpers\n", "tests/helpers.py": opaque}, true, false},
		{"star import of a package below the root", map[string]string{"src/app.py": "from tests import *\n", "src/tests/__init__.py": "__all__ = ['helpers']\n", "src/tests/helpers.py": opaque}, true, false},
		{"relative star import of a package", map[string]string{"pkg/__init__.py": "", "pkg/app.py": "from .tests import *\n", "pkg/tests/__init__.py": "__all__ = ['helpers']\n", "pkg/tests/helpers.py": opaque}, true, false},
		{"unread from text", map[string]string{"app.py": "from tests import\n", "tests/other.py": opaque}, true, false},
		{"unread plain import item", map[string]string{"app.py": "import tests, 1bad\n", "tests/other.py": opaque}, true, false},
		{"continued from-import of production", map[string]string{"app.py": "from lib \\\n    import(x,\n    y,)\n", "lib.py": app, "tests/other.py": opaque}, false, false},
		{"continued plain import of production", map[string]string{"app.py": "import \\\n\tlib as l\n", "lib.py": app, "tests/other.py": opaque}, false, false},
		{"continued raise from", map[string]string{"app.py": "def f(e):\n    raise ValueError() \\\n        from e\n", "tests/other.py": opaque}, false, false},
		{"after a continued block opener", map[string]string{"app.py": "if True: \\\n    import tests.helpers\n", "tests/helpers.py": opaque}, true, false},
		{"after a continued semicolon", map[string]string{"app.py": "import os; \\\r\n    import tests.helpers\n", "tests/helpers.py": opaque}, true, false},
		{"after a leading continuation", map[string]string{"app.py": "\\\nimport tests.helpers\n", "tests/helpers.py": opaque}, true, false},
		{"spaces around a dot", map[string]string{"app.py": "import tests . helpers\n", "tests/other.py": opaque}, true, false},
		{"edge through another test module", map[string]string{"app.py": "def main():\n    return relay('1')\n", "tests/relay.py": "def relay(s):\n    return run_eval(s)\n", "tests/helpers.py": evals}, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := mustCallGraph(t, c.files)
			if got := hasReason(res.Partiality, plugin.PartialReasonDynamicImportSpecifier); got != c.dynamic {
				t.Errorf("dynamic_import = %v, want %v (reasons %v)", got, c.dynamic, res.Partiality.Reasons)
			}
			if got := hasReason(res.Partiality, plugin.PartialReasonUnlistedSites); got != c.sites {
				t.Errorf("unlisted_sites = %v, want %v (reasons %v)", got, c.sites, res.Partiality.Reasons)
			}
		})
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
		{"file-path loader through an alias", "from importlib.util import spec_from_file_location as sffl\n\ndef load(p):\n    return sffl('plugin', p)\n", nil, true},
		{"runpy as a value", "import runpy\n\nRUN = runpy.run_path\n", nil, true},
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

// TestCallGraph_TestModuleIngresses: a framework route in test code production never runs is
// neither a call-graph root nor an ingress; one in a test module production imports or calls
// stays both.
func TestCallGraph_TestModuleIngresses(t *testing.T) {
	const (
		route   = "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/x')\ndef handle():\n    return 1\n\ndef helper():\n    return 2\n"
		fastapi = "from fastapi import APIRouter\nrouter = APIRouter()\n\n@router.get('/x')\nasync def handle():\n    return 1\n"
		method  = "class Views:\n    @app.route('/x')\n    def handle(self):\n        return 1\n"
		mainApp = "def main():\n    return 1\n"
	)
	cases := []struct {
		name      string
		module    string
		enclosing []string
		arity     int
		files     map[string]string
		want      bool
	}{
		{"under tests", "tests/conftest", nil, 0, map[string]string{"app.py": mainApp, "tests/conftest.py": route}, false},
		{"test_ file at the root", "test_app", nil, 0, map[string]string{"app.py": mainApp, "test_app.py": route}, false},
		{"root conftest", "conftest", nil, 0, map[string]string{"conftest.py": route}, false},
		{"imported only by tests", "tests/routes", nil, 0, map[string]string{"tests/routes.py": route, "tests/test_a.py": "from tests.routes import app\n"}, false},
		{"fastapi under tests", "tests/routes", nil, 0, map[string]string{"app.py": mainApp, "tests/routes.py": fastapi}, false},
		{"method handler under tests", "tests/views", []string{"Views"}, 1, map[string]string{"app.py": mainApp, "tests/views.py": method}, false},
		{"production module", "app", nil, 0, map[string]string{"app.py": route, "tests/test_a.py": "from app import app\n"}, true},
		{"imported by production", "tests/routes", nil, 0, map[string]string{"app.py": "from tests.routes import app\n", "tests/routes.py": route}, true},
		{"edge from production", "tests/routes", nil, 0, map[string]string{"app.py": "def main():\n    return helper()\n", "tests/routes.py": route}, true},
		{"through another test module", "tests/routes", nil, 0, map[string]string{"app.py": "import tests.util\n", "tests/util.py": "from tests.routes import app\n", "tests/routes.py": route}, true},
		{"relative import by production", "pkg/tests/routes", nil, 0, map[string]string{"pkg/__init__.py": "", "pkg/app.py": "from .tests import routes\n", "pkg/tests/routes.py": route}, true},
		{"fastapi imported by production", "tests/routes", nil, 0, map[string]string{"app.py": "from tests.routes import router\n", "tests/routes.py": fastapi}, true},
		{"method handler imported by production", "tests/views", []string{"Views"}, 1, map[string]string{"app.py": "from tests.views import Views\n", "tests/views.py": method}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			handle := funcSCIP(c.module, c.enclosing, "handle", c.arity)
			res := mustCallGraph(t, c.files)
			isRoot := false
			for _, r := range res.Roots {
				isRoot = isRoot || r.SCIP == handle
			}
			if isRoot != c.want {
				t.Errorf("handle is a root = %v, want %v (roots %v)", isRoot, c.want, res.Roots)
			}
			ings, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: writeTree(t, c.files)})
			if err != nil {
				t.Fatalf("FindIngresses: %v", err)
			}
			if _, ok := ingressFor(ings.Ingresses, handle); ok != c.want {
				t.Errorf("handle is an ingress = %v, want %v (ingresses %v)", ok, c.want, ings.Ingresses)
			}
		})
	}
}

// TestFindIngresses_HiddenRouteDynamicImport: ingress discovery is partial (dynamic_import)
// when it leaves out an unreached test-module route and a reached file holds a dynamic
// import the scanner cannot name, or evaluates code, either of which may load that route.
func TestFindIngresses_HiddenRouteDynamicImport(t *testing.T) {
	const (
		route  = "from flask import Flask\napp = Flask(__name__)\n\n@app.route('/x')\ndef handle():\n    return 1\n"
		opaque = "import importlib\n\ndef load(n):\n    return importlib.import_module(n)\n"
	)
	cases := []struct {
		name    string
		files   map[string]string
		dynamic bool
	}{
		{"hidden route and production dynamic import", map[string]string{"app.py": opaque, "tests/routes.py": route}, true},
		{"hidden route only", map[string]string{"app.py": "def main():\n    return 1\n", "tests/routes.py": route}, false},
		{"production dynamic import only", map[string]string{"app.py": opaque + route}, false},
		{"dynamic import in unreached test code", map[string]string{"app.py": "def main():\n    return 1\n", "tests/load.py": opaque, "tests/routes.py": route}, false},
		{"hidden route and production exec", map[string]string{"app.py": "def run(src):\n    exec(src)\n", "tests/routes.py": route}, true},
		{"hidden route and production eval", map[string]string{"app.py": "def run(src):\n    return eval(src)\n", "tests/routes.py": route}, true},
		{"exec in unreached test code", map[string]string{"app.py": "def main():\n    return 1\n", "tests/load.py": "def run(src):\n    exec(src)\n", "tests/routes.py": route}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: writeTree(t, c.files)})
			if err != nil {
				t.Fatalf("FindIngresses: %v", err)
			}
			if got := hasReason(res.Partiality, plugin.PartialReasonDynamicImportSpecifier); got != c.dynamic {
				t.Errorf("dynamic_import = %v, want %v (partiality %+v)", got, c.dynamic, res.Partiality)
			}
			if !c.dynamic && !res.Partiality.Complete {
				t.Errorf("want Complete, got %+v", res.Partiality)
			}
		})
	}
}
