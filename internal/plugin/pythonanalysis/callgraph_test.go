package pythonanalysis

import (
	"context"
	"reflect"
	"slices"
	"strconv"
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

// TestCallGraph_ModuleQualifiedResolution: a name the deciding scope binds by first-party
// import resolves to the function its import path names, whatever else shares the name; a
// bare name its scope binds by def resolves to that def; a name bound only by dependency
// import names no first-party function. A same-named function the edge does not name still
// escapes.
func TestCallGraph_ModuleQualifiedResolution(t *testing.T) {
	impl, other := funcSCIP("pkg/impl", nil, "f", 1), funcSCIP("other", nil, "f", 1)
	lib := map[string]string{
		"pkg/__init__.py": "from .impl import f\n",
		"pkg/impl.py":     "def f(x):\n    return x\n",
		"other.py":        "def f(x):\n    return x\n",
	}
	with := func(extra map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range lib {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	cases := []struct {
		name   string
		files  map[string]string
		caller string
		want   string   // the one first-party edge from caller, "" for none
		absent []string // first-party callees that must get no edge from caller
		escape []string // must escape
		listed bool     // the site is in Unresolved
	}{
		{
			name:   "package re-export",
			files:  with(map[string]string{"app.py": "import pkg\n\ndef index():\n    return pkg.f(1)\n"}),
			caller: funcSCIP("app", nil, "index", 0),
			want:   impl, absent: []string{other}, escape: []string{other},
		},
		{
			name:   "module through package chain",
			files:  with(map[string]string{"app.py": "import pkg\n\ndef index():\n    return pkg.impl.f(1)\n"}),
			caller: funcSCIP("app", nil, "index", 0),
			want:   impl, absent: []string{other}, escape: []string{other},
		},
		{
			name:   "from-imported module",
			files:  with(map[string]string{"app.py": "from pkg import impl\n\ndef index():\n    return impl.f(1)\n"}),
			caller: funcSCIP("app", nil, "index", 0),
			want:   impl, absent: []string{other},
		},
		{
			name:   "from-imported function",
			files:  with(map[string]string{"app.py": "from pkg.impl import f\n\ndef index():\n    return f(1)\n"}),
			caller: funcSCIP("app", nil, "index", 0),
			want:   impl, absent: []string{other},
		},
		{
			name: "renamed re-export",
			files: with(map[string]string{
				"pkg/__init__.py": "from .impl import g as f\n",
				"pkg/impl.py":     "def g(x):\n    return x\n",
				"app.py":          "import pkg\n\ndef index():\n    return pkg.f(1)\n",
			}),
			caller: funcSCIP("app", nil, "index", 0),
			want:   funcSCIP("pkg/impl", nil, "g", 1), absent: []string{other},
		},
		{
			name: "star re-export",
			files: with(map[string]string{
				"pkg/__init__.py": "from .impl import *\n",
				"app.py":          "import pkg\n\ndef index():\n    return pkg.f(1)\n",
			}),
			caller: funcSCIP("app", nil, "index", 0),
			want:   impl, absent: []string{other},
		},
		{
			name:   "same-module def",
			files:  with(map[string]string{"app.py": "def f(x):\n    return x\n\ndef index():\n    return f(1)\n"}),
			caller: funcSCIP("app", nil, "index", 0),
			want:   funcSCIP("app", nil, "f", 1), absent: []string{impl, other}, escape: []string{impl, other},
		},
		{
			name:   "def beside an import of the name",
			files:  with(map[string]string{"app.py": "from pkg.impl import f\n\nif X:\n    def f(x):\n        return x\n\ndef index():\n    return f(1)\n"}),
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{impl, other, funcSCIP("app", nil, "f", 1)},
			escape: []string{impl, other, funcSCIP("app", nil, "f", 1)},
			listed: true,
		},
		{
			name:   "dependency module receiver",
			files:  map[string]string{"util.py": "def loads(s):\n    return s\n", "app.py": "import json\n\ndef run(x):\n    return json.loads(x)\n"},
			caller: funcSCIP("app", nil, "run", 1),
			absent: []string{funcSCIP("util", nil, "loads", 1)},
			escape: []string{funcSCIP("util", nil, "loads", 1)},
			listed: true,
		},
		{
			name:   "dependency from-import",
			files:  map[string]string{"util.py": "def loads(s):\n    return s\n", "app.py": "from json import loads\n\ndef run(x):\n    return loads(x)\n"},
			caller: funcSCIP("app", nil, "run", 1),
			absent: []string{funcSCIP("util", nil, "loads", 1)},
			escape: []string{funcSCIP("util", nil, "loads", 1)},
			listed: true,
		},
		{
			name: "dependency import with a first-party fallback",
			files: map[string]string{
				"pkg/compat.py": "def loads(s):\n    return s\n",
				"pkg/app.py":    "try:\n    import ujson as json\nexcept ImportError:\n    from . import compat as json\n\ndef run(x):\n    return json.loads(x)\n",
			},
			caller: funcSCIP("pkg/app", nil, "run", 1),
			want:   funcSCIP("pkg/compat", nil, "loads", 1),
			listed: true,
		},
		{
			name: "re-export through an import cycle",
			files: map[string]string{
				"a.py":   "from b import f\n",
				"b.py":   "import a\nfrom c import f\n",
				"c.py":   "def f(x):\n    return x\n",
				"d.py":   "def f(x):\n    return x\n",
				"app.py": "import a\n\ndef index():\n    return a.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			want:   funcSCIP("c", nil, "f", 1), absent: []string{funcSCIP("d", nil, "f", 1)},
		},
		{
			name: "import cycle that binds no def names nothing",
			files: map[string]string{
				"a.py":   "from b import f\n",
				"b.py":   "from a import f\n",
				"c.py":   "def f(x):\n    return x\n",
				"app.py": "import a\n\ndef index():\n    return a.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("c", nil, "f", 1)}, escape: []string{funcSCIP("c", nil, "f", 1)},
			listed: true,
		},
		{
			name: "module path whose module does not bind the name",
			files: map[string]string{
				"pkg/__init__.py": "", "pkg/impl.py": "X = 1\n",
				"other.py": "def f(x):\n    return x\n",
				"app.py":   "from pkg import impl\n\ndef index():\n    return impl.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("other", nil, "f", 1)}, escape: []string{funcSCIP("other", nil, "f", 1)},
			listed: true,
		},
		{
			name: "module path through a module-level value",
			files: map[string]string{
				"app/__init__.py": "db = make_db()\n", "app/auth.py": "def session(x):\n    return x\n",
				"main.py": "from app import db\n\ndef run():\n    return db.session(1)\n",
			},
			caller: funcSCIP("main", nil, "run", 0),
			absent: []string{funcSCIP("app/auth", nil, "session", 1)}, escape: []string{funcSCIP("app/auth", nil, "session", 1)},
			listed: true,
		},
		{
			name: "module path through a dependency star import",
			files: map[string]string{
				"pkg/__init__.py": "", "pkg/impl.py": "from json import *\n",
				"util.py": "def loads(s):\n    return s\n",
				"app.py":  "from pkg import impl\n\ndef run(x):\n    return impl.loads(x)\n",
			},
			caller: funcSCIP("app", nil, "run", 1),
			absent: []string{funcSCIP("util", nil, "loads", 1)}, escape: []string{funcSCIP("util", nil, "loads", 1)},
			listed: true,
		},
		{
			name: "module path through a module's first-party attribute",
			files: map[string]string{
				"pkg/__init__.py": "from .sub import tools\n", "pkg/sub/__init__.py": "", "pkg/sub/tools.py": "def f(x):\n    return x\n",
				"other.py": "def f(x):\n    return x\n",
				"app.py":   "import pkg\n\ndef index():\n    return pkg.tools.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			want:   funcSCIP("pkg/sub/tools", nil, "f", 1), absent: []string{funcSCIP("other", nil, "f", 1)},
		},
		{
			name: "module path to a class member keeps the name fallback",
			files: map[string]string{
				"pkg/__init__.py": "", "pkg/impl.py": "class K:\n    @staticmethod\n    def m(x):\n        return x\n",
				"app.py": "from pkg import impl\n\ndef index():\n    return impl.K.m(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			want:   funcSCIP("pkg/impl", []string{"K"}, "m", 1),
		},
		{
			name: "module path to an attribute both imported and a class",
			files: map[string]string{
				"pkg/__init__.py":     "from .sub import tools\n\nclass tools:\n    @staticmethod\n    def f(x):\n        return x\n",
				"pkg/sub/__init__.py": "", "pkg/sub/tools.py": "def f(x):\n    return x\n",
				"app.py": "import pkg\n\ndef index():\n    return pkg.tools.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("pkg/sub/tools", nil, "f", 1), funcSCIP("pkg", []string{"tools"}, "f", 1)},
			listed: true,
		},
		{
			name: "module path to an attribute imported then reassigned",
			files: map[string]string{
				"pkg/__init__.py":     "from .sub import tools\n\ntools = wrap(tools)\n",
				"pkg/sub/__init__.py": "", "pkg/sub/tools.py": "def f(x):\n    return x\n",
				"app.py": "import pkg\n\ndef index():\n    return pkg.tools.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("pkg/sub/tools", nil, "f", 1)},
			listed: true,
		},
		{
			name: "module path to a submodule its package rebinds",
			files: map[string]string{
				"pkg/__init__.py": "from . import sub\n\nsub = make()\n", "pkg/sub.py": "def f(x):\n    return x\n",
				"app.py": "import pkg\n\ndef index():\n    return pkg.sub.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("pkg/sub", nil, "f", 1)},
			listed: true,
		},
		{
			name: "src layout package importing its own submodule relatively",
			files: map[string]string{
				"pyproject.toml":      "[project]\nname = \"pkg\"\n",
				"src/pkg/__init__.py": "from . import sub\n", "src/pkg/sub.py": "def f(x):\n    return x\n",
				"src/app.py": "import pkg\n\ndef index():\n    return pkg.sub.f(1)\n",
			},
			caller: funcSCIP("src/app", nil, "index", 0),
			want:   funcSCIP("src/pkg/sub", nil, "f", 1),
		},
		{
			name: "src layout attribute path through a relatively imported submodule",
			files: map[string]string{
				"pyproject.toml":      "[project]\nname = \"pkg\"\n",
				"src/pkg/__init__.py": "from . import sub\n", "src/pkg/sub/__init__.py": "from .impl import tools\n",
				"src/pkg/sub/impl/__init__.py": "", "src/pkg/sub/impl/tools.py": "def f(x):\n    return x\n",
				"src/app.py": "import pkg\n\ndef index():\n    return pkg.sub.tools.f(1)\n",
			},
			caller: funcSCIP("src/app", nil, "index", 0),
			want:   funcSCIP("src/pkg/sub/impl/tools", nil, "f", 1),
		},
		{
			name: "namespace package beside a same-named package importing its own submodule",
			files: map[string]string{
				"pkg/sub.py": "def f(x):\n    return x\n", "tests/pkg/__init__.py": "from . import sub\n", "tests/pkg/sub.py": "def h(x):\n    return x\n",
				"app.py": "import pkg.sub\n\ndef index():\n    return pkg.sub.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			want:   funcSCIP("pkg/sub", nil, "f", 1),
		},
		{
			name: "src layout submodule its package rebinds to another module",
			files: map[string]string{
				"pyproject.toml":      "[project]\nname = \"pkg\"\n",
				"src/pkg/__init__.py": "from .other import sub\n", "src/pkg/other/__init__.py": "", "src/pkg/other/sub.py": "def f(x):\n    return x\n", "src/pkg/sub.py": "def f(x):\n    return x\n",
				"src/app.py": "import pkg\n\ndef index():\n    return pkg.sub.f(1)\n",
			},
			caller: funcSCIP("src/app", nil, "index", 0),
			absent: []string{funcSCIP("src/pkg/sub", nil, "f", 1)},
			listed: true,
		},
		{
			name: "module path to a submodule its package rebinds through two star imports",
			files: map[string]string{
				"pkg/__init__.py": "from . import sub\nfrom .a import *\n", "pkg/a.py": "from .b import *\n", "pkg/b.py": "sub = make()\n", "pkg/sub.py": "def f(x):\n    return x\n",
				"app.py": "import pkg\n\ndef index():\n    return pkg.sub.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("pkg/sub", nil, "f", 1)},
			listed: true,
		},
		{
			name: "src layout package importing its own submodule absolutely",
			files: map[string]string{
				"pyproject.toml":      "[project]\nname = \"pkg\"\n",
				"src/pkg/__init__.py": "from pkg import sub\n", "src/pkg/sub.py": "def f(x):\n    return x\n",
				"src/app.py": "import pkg\n\ndef index():\n    return pkg.sub.f(1)\n",
			},
			caller: funcSCIP("src/app", nil, "index", 0),
			want:   funcSCIP("src/pkg/sub", nil, "f", 1),
		},
		{
			name: "module path to a submodule its package rebinds by star-importing a subpackage's own",
			files: map[string]string{
				"pkg/__init__.py": "from .x import *\n", "pkg/x/__init__.py": "from . import sub\n", "pkg/x/sub.py": "def f(x):\n    return x\n", "pkg/sub.py": "def f(x):\n    return x\n",
				"app.py": "import pkg\n\ndef index():\n    return pkg.sub.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("pkg/sub", nil, "f", 1)},
			listed: true,
		},
		{
			name: "module path through a package whose star imports form a cycle",
			files: map[string]string{
				"pkg/__init__.py": "from .a import *\n", "pkg/a.py": "from .b import *\n", "pkg/b.py": "from .a import *\n", "pkg/sub.py": "def f(x):\n    return x\n",
				"app.py": "import pkg\n\ndef index():\n    return pkg.sub.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			want:   funcSCIP("pkg/sub", nil, "f", 1),
		},
		{
			name: "module path to a submodule its grandparent package rebinds",
			files: map[string]string{
				"a/__init__.py": "from . import b\n\nb = make()\n", "a/b/__init__.py": "", "a/b/c.py": "def f(x):\n    return x\n",
				"app.py": "import a.b.c\n\ndef index():\n    return a.b.c.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("a/b/c", nil, "f", 1)},
			listed: true,
		},
		{
			name: "module path to a submodule its package rebinds by a star import",
			files: map[string]string{
				"pkg/__init__.py": "from . import sub\nfrom .helpers import *\n", "pkg/helpers.py": "sub = make()\n", "pkg/sub.py": "def f(x):\n    return x\n",
				"app.py": "import pkg\n\ndef index():\n    return pkg.sub.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("pkg/sub", nil, "f", 1)},
			listed: true,
		},
		{
			name: "module path to a submodule a star import binds to another module",
			files: map[string]string{
				"pkg/__init__.py": "from .helpers import *\n", "pkg/helpers.py": "from other import sub\n",
				"other/__init__.py": "", "other/sub.py": "def f(x):\n    return x\n", "pkg/sub.py": "def f(x):\n    return x\n",
				"app.py": "import pkg\n\ndef index():\n    return pkg.sub.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("pkg/sub", nil, "f", 1)},
			listed: true,
		},
		{
			name: "module path through the attribute of a submodule its package rebinds",
			files: map[string]string{
				"pkg/__init__.py": "from . import sub\n\nsub = make()\n", "pkg/sub/__init__.py": "from other import tools\n",
				"other/__init__.py": "", "other/tools.py": "def f(x):\n    return x\n",
				"app.py": "import pkg\n\ndef index():\n    return pkg.sub.tools.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("other/tools", nil, "f", 1)},
			listed: true,
		},
		{
			name: "module path through a class or an import to a renamed def",
			files: map[string]string{
				"pkg/__init__.py":     "try:\n    from .sub import tools\nexcept ImportError:\n    class tools:\n        @staticmethod\n        def f(x):\n            return x\n",
				"pkg/sub/__init__.py": "", "pkg/sub/tools.py": "from .impl import g as f\n", "pkg/sub/impl.py": "def g(x):\n    return x\n",
				"app.py": "import pkg\n\ndef index():\n    return pkg.tools.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("pkg", []string{"tools"}, "f", 1), funcSCIP("pkg/sub/impl", nil, "g", 1)},
			listed: true,
		},
		{
			name: "module path to a submodule beside an unrelated rebound name",
			files: map[string]string{
				"pkg/__init__.py": "from . import sub\n\nother = make()\n", "pkg/sub.py": "def f(x):\n    return x\n", "elsewhere.py": "def f(x):\n    return x\n",
				"app.py": "import pkg\n\ndef index():\n    return pkg.sub.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			want:   funcSCIP("pkg/sub", nil, "f", 1),
			absent: []string{funcSCIP("elsewhere", nil, "f", 1)},
		},
		{
			name: "module path through a star re-exported attribute",
			files: map[string]string{
				"pkg/__init__.py": "from .sub import *\n", "pkg/sub/__init__.py": "from . import tools\n", "pkg/sub/tools.py": "def f(x):\n    return x\n",
				"other.py": "def f(x):\n    return x\n",
				"app.py":   "import pkg\n\ndef index():\n    return pkg.tools.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			want:   funcSCIP("pkg/sub/tools", nil, "f", 1), absent: []string{funcSCIP("other", nil, "f", 1)},
		},
		{
			name: "module path through two attributes to a class member",
			files: map[string]string{
				"pkg/__init__.py": "from .sub import tools\n", "pkg/sub/__init__.py": "", "pkg/sub/tools.py": "class K:\n    @staticmethod\n    def m(x):\n        return x\n",
				"app.py": "import pkg\n\ndef index():\n    return pkg.tools.K.m(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			want:   funcSCIP("pkg/sub/tools", []string{"K"}, "m", 1),
		},
		{
			name: "module path below a namespace package keeps the name fallback",
			files: map[string]string{
				"ns/other.py": "def f(x):\n    return x\n",
				"app.py":      "import ns.ext\n\ndef index():\n    return ns.ext.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			want:   funcSCIP("ns/other", nil, "f", 1),
		},
		{
			name: "first-party package below a directory the distribution scan reads as the top",
			files: map[string]string{
				"backend/app/util.py":  "def loads(s):\n    return s\n",
				"backend/app/views.py": "from app import util\n\ndef run(x):\n    return util.loads(x)\n",
			},
			caller: funcSCIP("backend/app/views", nil, "run", 1),
			want:   funcSCIP("backend/app/util", nil, "loads", 1),
		},
		{
			name:   "def beside a dependency import of the name",
			files:  map[string]string{"app.py": "from json import loads\n\ndef loads(s):\n    return s\n\ndef run(x):\n    return loads(x)\n"},
			caller: funcSCIP("app", nil, "run", 1),
			want:   funcSCIP("app", nil, "loads", 1),
			listed: true,
		},
		{
			name: "dependency import beside a module star import",
			files: map[string]string{
				"pkg/impl.py": "def loads(s):\n    return s\n",
				"pkg/app.py":  "from json import loads\nfrom .impl import *\n\ndef run(x):\n    return loads(x)\n",
			},
			caller: funcSCIP("pkg/app", nil, "run", 1),
			want:   funcSCIP("pkg/impl", nil, "loads", 1),
			listed: true,
		},
		{
			name:   "dependency import the module rebinds",
			files:  map[string]string{"util.py": "def loads(s):\n    return s\n", "app.py": "import json\njson = make()\n\ndef run(x):\n    return json.loads(x)\n"},
			caller: funcSCIP("app", nil, "run", 1),
			want:   funcSCIP("util", nil, "loads", 1),
			listed: true,
		},
		{
			name: "nested def beside a module-level class of the name",
			files: map[string]string{
				"app.py":   "def make():\n    def Loader(x):\n        return x\n    return Loader\n\nclass Loader:\n    def __init__(self, x):\n        self.x = x\n\ndef index():\n    return Loader(1)\n",
				"other.py": "def Loader(x):\n    return x\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("app", nil, "Loader", 1), funcSCIP("other", nil, "Loader", 1)},
			listed: true,
		},
		{
			name: "module path to a class beside a nested def of the name",
			files: with(map[string]string{
				"pkg/impl.py": "class f:\n    def __init__(self, x):\n        self.x = x\n\ndef helper():\n    def f(x):\n        return x\n    return f\n",
				"app.py":      "from pkg import impl\n\ndef index():\n    return impl.f(1)\n",
			}),
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{impl, other},
			listed: true,
		},
		{
			name:   "def the module rebinds to another module's function",
			files:  with(map[string]string{"app.py": "import other\n\ndef f(x):\n    return x\n\nf = other.f\n\ndef index():\n    return f(1)\n"}),
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("app", nil, "f", 1)},
			escape: []string{other},
			listed: true,
		},
		{
			name:   "nested def beside a module-level class, the only def of the name",
			files:  map[string]string{"app.py": "def make():\n    def Loader(x):\n        return x\n    return Loader\n\nclass Loader:\n    def __init__(self, x):\n        self.x = x\n\ndef index():\n    return Loader(1)\n"},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("app", nil, "Loader", 1)},
			listed: true,
		},
		{
			name:   "def a later class of the name replaces",
			files:  map[string]string{"app.py": "def f(x):\n    return x\n\nclass f:\n    def __init__(self, x):\n        self.x = x\n\ndef index():\n    return f(1)\n"},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("app", nil, "f", 1)},
			listed: true,
		},
		{
			name:   "def the module rebinds through a wrapper, the only def of the name",
			files:  map[string]string{"app.py": "def wrap(g):\n    return g\n\ndef f(x):\n    return x\n\nf = wrap(f)\n\ndef index():\n    return f(1)\n"},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("app", nil, "f", 1)},
			listed: true,
		},
		{
			name:   "module-level def whose arity misses beside a nested def that fits",
			files:  map[string]string{"app.py": "def f(x, y, z):\n    return x\n\ndef make():\n    def f(x):\n        return x\n    return f\n\ndef index():\n    return f(1)\n"},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("app", nil, "f", 1)},
			listed: true,
		},
		{
			name: "module path to a name the module rebinds over a star import",
			files: map[string]string{
				"pkg/__init__.py": "",
				"pkg/x.py":        "def f(x):\n    return x\n",
				"pkg/impl.py":     "from .x import *\n\ndef wrap(g):\n    return g\n\ndef f(x):\n    return x\n\nf = wrap(f)\n",
				"app.py":          "from pkg import impl\n\ndef index():\n    return impl.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("pkg/x", nil, "f", 1), funcSCIP("pkg/impl", nil, "f", 1)},
			listed: true,
		},
		{
			name: "module path to a class beside a def of its name elsewhere",
			files: map[string]string{
				"pkg/__init__.py": "",
				"other.py":        "def f(x):\n    return x\n",
				"pkg/impl.py":     "class f:\n    def __init__(self, x):\n        pass\n",
				"app.py":          "from pkg import impl\n\ndef index():\n    return impl.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("other", nil, "f", 1)},
			listed: true,
		},
		{
			name: "module path to a def the module rebinds through a global",
			files: map[string]string{
				"pkg/__init__.py": "",
				"other.py":        "def g(x):\n    return x\n",
				"pkg/impl.py":     "import other\n\ndef f(x):\n    return x\n\ndef init():\n    global f\n    f = other.g\n",
				"app.py":          "from pkg import impl\n\ndef index():\n    return impl.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("pkg/impl", nil, "f", 1), funcSCIP("other", nil, "g", 1)},
			listed: true,
		},
		{
			name: "module path to a def the module rebinds through a global in a class body",
			files: map[string]string{
				"pkg/__init__.py": "",
				"other.py":        "def g(x):\n    return x\n",
				"pkg/impl.py":     "import other\n\ndef f(x):\n    return x\n\nclass K:\n    global f\n    f = other.g\n",
				"app.py":          "from pkg import impl\n\ndef index():\n    return impl.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("pkg/impl", nil, "f", 1), funcSCIP("other", nil, "g", 1)},
			listed: true,
		},
		{
			name: "call to a def a global import in a class body rebinds",
			files: map[string]string{
				"pkg/__init__.py": "",
				"pkg/y.py":        "def g(x):\n    return x\n",
				"pkg/impl.py":     "def f(x):\n    return x\n\nclass K:\n    global f\n    from .y import g as f\n\ndef run():\n    return f(1)\n",
			},
			caller: funcSCIP("pkg/impl", nil, "run", 0),
			want:   funcSCIP("pkg/y", nil, "g", 1),
			absent: []string{funcSCIP("pkg/impl", nil, "f", 1)},
			listed: true,
		},
		{
			name: "standard-library module beside a first-party module of its name",
			files: map[string]string{
				"util.py": "def loads(s):\n    return s\n", "app/__init__.py": "", "app/json.py": "X = 1\n",
				"run.py": "import json\n\ndef run(x):\n    return json.loads(x)\n",
			},
			caller: funcSCIP("run", nil, "run", 1),
			absent: []string{funcSCIP("util", nil, "loads", 1)},
			escape: []string{funcSCIP("util", nil, "loads", 1)},
			listed: true,
		},
		{
			name: "declared dependency beside a first-party module of its name",
			files: map[string]string{
				"pyproject.toml": "[project]\nname = \"svc\"\ndependencies = [\"redis\"]\n",
				"util.py":        "def get(k):\n    return k\n", "app/__init__.py": "", "app/redis.py": "X = 1\n",
				"run.py": "import redis\n\ndef run(k):\n    return redis.get(k)\n",
			},
			caller: funcSCIP("run", nil, "run", 1),
			absent: []string{funcSCIP("util", nil, "get", 1)},
			escape: []string{funcSCIP("util", nil, "get", 1)},
			listed: true,
		},
		{
			name: "curated dependency beside a first-party module of its name",
			files: map[string]string{
				"util.py": "def safe_load(s):\n    return s\n", "app/__init__.py": "", "app/yaml.py": "X = 1\n",
				"run.py": "import yaml\n\ndef run(s):\n    return yaml.safe_load(s)\n",
			},
			caller: funcSCIP("run", nil, "run", 1),
			absent: []string{funcSCIP("util", nil, "safe_load", 1)},
			escape: []string{funcSCIP("util", nil, "safe_load", 1)},
			listed: true,
		},
		{
			name: "module path to a def the module imports over its own",
			files: map[string]string{
				"pkg/__init__.py": "",
				"pkg/x.py":        "def f(x):\n    return x\n",
				"pkg/impl.py":     "from .x import f\n\ndef f(x, y, z):\n    return x\n",
				"app.py":          "from pkg import impl\n\ndef index():\n    return impl.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("pkg/x", nil, "f", 1)},
			listed: true,
		},
		{
			name: "module path to a name the module assigns",
			files: map[string]string{
				"pkg/__init__.py": "",
				"lib.py":          "def f(x):\n    return x\n",
				"pkg/impl.py":     "import lib\n\nf = lib.f\n",
				"app.py":          "from pkg import impl\n\ndef index():\n    return impl.f(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("lib", nil, "f", 1)},
			listed: true,
		},
		{
			name: "module path to a name the module imports from a dependency",
			files: map[string]string{
				"pkg/__init__.py": "",
				"lib.py":          "def dumps(x):\n    return x\n",
				"pkg/impl.py":     "from json import dumps\n",
				"app.py":          "from pkg import impl\n\ndef index():\n    return impl.dumps(1)\n",
			},
			caller: funcSCIP("app", nil, "index", 0),
			absent: []string{funcSCIP("lib", nil, "dumps", 1)},
			listed: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := mustCallGraph(t, tc.files)
			var got []string
			for _, e := range res.Edges {
				if e.Caller.SCIP == tc.caller && !strings.HasPrefix(e.Callee.SCIP, "pypi:") {
					got = append(got, e.Callee.SCIP)
				}
			}
			if tc.want != "" && !slices.Equal(got, []string{tc.want}) {
				t.Errorf("edges from caller = %v, want exactly %s", got, tc.want)
			}
			for _, a := range tc.absent {
				if slices.Contains(got, a) {
					t.Errorf("unexpected edge to %s; edges %v", a, got)
				}
			}
			esc := symbolSet(res.Escaped)
			for _, e := range tc.escape {
				if !esc[e] {
					t.Errorf("%s must escape; escaped %v", e, res.Escaped)
				}
			}
			listed := slices.ContainsFunc(res.Unresolved, func(u plugin.UnresolvedCall) bool { return u.Caller.SCIP == tc.caller })
			if listed != tc.listed {
				t.Errorf("site listed = %v, want %v; unresolved %+v", listed, tc.listed, res.Unresolved)
			}
		})
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
		{"qualified builtins.exec in production", map[string]string{"app.py": "import builtins\n\ndef run(s):\n    builtins.exec(s)\n"}, false, true},
		{"qualified builtins.eval in production", map[string]string{"app.py": "import builtins\n\ndef run(s):\n    return builtins.eval(s)\n"}, false, true},
		{"dynamic import in an f-string", map[string]string{"app.py": "import importlib\n\ndef run(n):\n    return f\"{importlib.import_module(n)}\"\n"}, true, false},
		{"__import__ in an f-string", map[string]string{"app.py": "def run(n):\n    return f\"{__import__(n)}\"\n"}, true, false},
		{"plain call in an f-string", map[string]string{"app.py": "def run(s):\n    return f\"{len(s)}\"\n"}, false, false},
		{"loader in an f-string", map[string]string{"app.py": "import runpy\n\ndef run(p):\n    return f\"{runpy.run_path(p)}\"\n"}, true, false},
		{"dynamic import in an unclosed f-string substitution", map[string]string{"app.py": "import importlib\n\ndef run(n):\n    return f\"{importlib.import_module(n)\"\n"}, true, true},
		{"string loader in an unclosed f-string substitution", map[string]string{"app.py": "from werkzeug.utils import import_string\n\ndef run(n):\n    return f\"{import_string(n)\"\n"}, true, true},
		{"__import__ in an unclosed f-string substitution", map[string]string{"app.py": "def run(n):\n    return f\"{__import__(n)\"\n"}, true, true},
		{"loader in an unclosed f-string substitution", map[string]string{"app.py": "import runpy\n\ndef run(p):\n    return f\"{runpy.run_path(p)\"\n"}, true, true},
		{"plain call in an unclosed f-string substitution", map[string]string{"app.py": "def run(s):\n    return f\"{len(s)\"\n"}, false, true},
		{"method named eval", map[string]string{"app.py": "def run(m):\n    m.eval()\n"}, false, false},
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
		{"resolve_name renamed and called with a name", "from pkgutil import resolve_name as R\n\ndef go(spec):\n    return R(spec)\n", nil, true},
		{"resolve_name renamed and called with a literal", "from pkgutil import resolve_name as R\nh = R('acme.plugins:load')\n", []string{"acme.plugins"}, false},
		{"resolve_name renamed with a dotted literal", "from pkgutil import resolve_name as R\nh = R('acme.plugins.load')\n", []string{"acme.plugins", "acme.plugins.load"}, false},
		{"resolve_name renamed with a keyword name", "from pkgutil import resolve_name as R\n\ndef go(spec):\n    return R(name=spec)\n", nil, true},
		{"resolve_name bound to another name", "import pkgutil\nR = pkgutil.resolve_name\n\ndef go(spec):\n    return R(spec)\n", nil, true},
		{"resolve_name passed as a value", "import pkgutil\n\ndef load(specs):\n    return list(map(pkgutil.resolve_name, specs))\n", nil, true},
		{"backport resolve_name renamed and called with a name", "from pkgutil_resolve_name import resolve_name as R\n\ndef go(spec):\n    return R(spec)\n", nil, true},
		{"backport resolve_name renamed with a literal", "from pkgutil_resolve_name import resolve_name as R\nh = R(name='acme.plugins:load')\n", []string{"acme.plugins"}, false},
		{"name keyword is not another loader's", "from werkzeug.utils import import_string\n\ndef view(path):\n    return import_string(path, name='x')\n", nil, true},
		{"resolve_name from another module", "from acme.util import resolve_name as R\n\ndef go(spec):\n    return R(spec)\n", nil, false},
		{"non-literal name", "from importlib import import_module\n\ndef load(name):\n    return import_module(name)\n", nil, true},
		{"f-string", "import importlib\n\ndef load(n):\n    return importlib.import_module(f\"plugins.{n}\")\n", nil, true},
		{"after an f-string reusing its quote", "import importlib\nx = f\"{d[\"it's\"]}\"; importlib.import_module(name)\n", nil, true},
		{"literal after an f-string reusing its quote", "import importlib\nx = f\"{d[\"it's\"]}\"; importlib.import_module('yaml')\n", []string{"yaml"}, false},
		{"after a format spec cut by its literal's quote", "import importlib\nx = f\"{x:>\"; importlib.import_module(name); y = \"}\"\n", nil, true},
		{"after a single-quoted format spec cut by a newline", "import importlib\nx = f\"{x:>\nimportlib.import_module(name)  # }\"\n", nil, true},
		{"after a triple-quoted format spec cut by its quotes", "import importlib\nx = f\"\"\"{x:>\"\"\"; importlib.import_module(name); y = \"\"\"}\"\"\"\n", nil, true},
		{"inside an f-string reusing its quote", "import importlib\nx = f\"{importlib.import_module(d[\"k\"])}\"\n", nil, true},
		{"literal inside a triple-quoted substitution with a quote in its spec", "import importlib\nx = f\"\"\"{d[\"\"\"importlib.import_module(n)\"\"\"]:\"}\"\"\"\n", nil, false},
		{"after a nested format spec cut by its literal's quote", "import importlib\nx = f\"{a:{b:\"} + importlib.import_module(name) + \"}\"\n", nil, true},
		{"after an f-string substitution left open by a nested literal", "import importlib\nx = f\"{a\"\nimportlib.import_module(name)\ny = b}\"\n", nil, true},
		{"after many f-string substitutions left open by a comment", "import importlib\n" + strings.Repeat("x = f\"{a # \"\n", 64) + "importlib.import_module(name)\n", nil, true},
		{"concatenation", "import importlib\n\ndef load(n):\n    return importlib.import_module(\"plugins.\" + n)\n", nil, true},
		{"entry points", "from importlib.metadata import entry_points\n\nfor ep in entry_points(group='acme.plugins'):\n    ep.load()\n", nil, true},
		{"file-path loader through an alias", "from importlib.util import spec_from_file_location as sffl\n\ndef load(p):\n    return sffl('plugin', p)\n", nil, true},
		{"runpy as a value", "import runpy\n\nRUN = runpy.run_path\n", nil, true},
		{"importlib literal continued", "import importlib\nmod = importlib \\\n    .import_module(\"yaml\")\n", []string{"yaml"}, false},
		{"pkgutil resolve_name literal continued", "import pkgutil\nf = pkgutil.resolve_name \\\n    ('acme.plugins:load')\n", []string{"acme.plugins"}, false},
		{"pkgutil resolve_name literal continued with CRLF", "import pkgutil\r\nf = pkgutil.resolve_name \\\r\n    ('acme.plugins:load')\r\n", []string{"acme.plugins"}, false},
		{"pkgutil resolve_name non-literal continued", "import pkgutil\n\ndef f(spec):\n    return pkgutil.resolve_name \\\n        (spec)\n", nil, true},
		{"entry points continued", "from importlib.metadata import entry_points\n\neps = entry_points \\\n    (group='acme.plugins')\n", nil, true},
		// The string-loader scan reads past the newline here and loads acme.plugins, which
		// Python never calls. An extra root over-approximates, so it is kept.
		{"resolve_name before a parenthesised line", "import pkgutil\npkgutil.resolve_name\n('acme.plugins:load')\n", []string{"acme.plugins"}, false},
		{"comment and string only", "# importlib.import_module(name)\ns = 'import_module(name)'\n", nil, false},
		{"def named import_module", "def import_module(name):\n    return name\n", nil, false},
		{"run_path fetched by getattr", "import runpy\n\ndef f(p):\n    return getattr(runpy, 'run_path')(p)\n", nil, true},
		{"module_from_spec fetched from a dotted module", "import importlib.util\n\ndef f(spec):\n    return getattr(importlib.util, 'module_from_spec')(spec)\n", nil, true},
		{"run_module fetched through vars", "import runpy\nRUN = vars(runpy)['run_module']\n", nil, true},
		{"entry_points fetched through __dict__", "import importlib.metadata as md\nEP = md.__dict__['entry_points']\n", nil, true},
		{"entry_points fetched through __dict__.get", "import importlib.metadata as md\nEP = md.__dict__.get('entry_points')\n", nil, true},
		{"resolve_name fetched from any object with a literal", "def f(mod):\n    return getattr(mod, 'resolve_name')('acme.plugins:load')\n", []string{"acme.plugins"}, false},
		{"resolve_name fetched from any object with a name", "def f(mod, s):\n    return getattr(mod, 'resolve_name')(s)\n", nil, true},
		{"exec_module fetched as a value", "def f(mod):\n    return getattr(mod, 'exec_module')\n", nil, true},
		{"unrelated attribute fetched by getattr", "def f(mod):\n    return getattr(mod, 'run'), vars(mod)['x'], mod.__dict__.get('y')\n", nil, false},
		{"import_module fetched from a module value", "import sys\n\ndef f(s):\n    return getattr(sys.modules['importlib'], 'import_module')(s)\n", nil, true},
		{"__import__ fetched from any object", "def f(b, s):\n    return getattr(b, '__import__')(s)\n", nil, true},
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

// testURLs is a Django urlconf only test settings load; it names testView, a view in
// tests/views.py.
const (
	testURLs = "from django.urls import path\nfrom tests import views\n\nurlpatterns = [path('v/', views.v)]\n"
	testView = "\ndef v(request):\n    return 1\n"
)

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
		{"launched by a manifest entry point", "tests/server", nil, 0, map[string]string{"pyproject.toml": "[project.scripts]\nsrv = \"tests.server:main\"\n", "tests/server.py": mainApp + "\n" + route}, true},
		{"test-only Django urlconf", "tests/views", nil, 0, map[string]string{"app.py": mainApp, "tests/urls.py": testURLs, "tests/views.py": route + testView}, false},
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
		{"hidden route and production builtins.exec", map[string]string{"app.py": "import builtins\n\ndef run(src):\n    builtins.exec(src)\n", "tests/routes.py": route}, true},
		{"hidden route and production f-string dynamic import", map[string]string{"app.py": "import importlib\n\ndef run(n):\n    return f\"{importlib.import_module(n)}\"\n", "tests/routes.py": route}, true},
		{"hidden route and production getattr", map[string]string{"app.py": "def run(o, n):\n    return getattr(o, n)\n", "tests/routes.py": route}, false},
		{"hidden route and production f-string call", map[string]string{"app.py": "def run(s):\n    return f\"{len(s)}\"\n", "tests/routes.py": route}, false},
		{"test-only Django urlconf view with a dynamic import", map[string]string{"app.py": "def main():\n    return 1\n", "tests/urls.py": testURLs, "tests/views.py": opaque + testView, "tests/routes.py": route}, false},
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

// TestCallGraph_StringLoaders: a loader that imports the module a string names records a
// literal name as a load root, and a name the scanner cannot read adds the dynamic_import
// reason; a loader is matched by the dotted name the file's imports resolve it to.
func TestCallGraph_StringLoaders(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		roots     []string
		dynReason bool
	}{
		{"werkzeug import_string literal", "from werkzeug.utils import import_string\nview = import_string('acme.views.Index')\n", []string{"acme.views", "acme.views.Index"}, false},
		{"werkzeug import_string colon form", "import werkzeug\nview = werkzeug.import_string('acme.views:Index')\n", []string{"acme.views"}, false},
		{"django import_string through an alias", "from django.utils.module_loading import import_string as load\nBackend = load(dotted_path='acme.backends.Mail')\n", []string{"acme.backends", "acme.backends.Mail"}, false},
		{"import_string computed", "from werkzeug.utils import import_string\n\ndef view(name):\n    return import_string(name)\n", nil, true},
		{"import_string unpacked", "from werkzeug.utils import import_string\n\ndef view(kw):\n    return import_string(**kw)\n", nil, true},
		{"uvicorn.run literal", "import uvicorn\n\nif __name__ == '__main__':\n    uvicorn.run('acme.asgi:app', port=8000)\n", []string{"acme.asgi"}, false},
		{"uvicorn Config keyword", "from uvicorn import Config\ncfg = Config(app='acme.asgi:app')\n", []string{"acme.asgi"}, false},
		{"uvicorn.run f-string", "import uvicorn\n\ndef serve(m):\n    uvicorn.run(f'{m}:app')\n", nil, true},
		{"uvicorn.run from the environment", "import os\nimport uvicorn\nuvicorn.run(os.environ['APP'])\n", nil, true},
		{"uvicorn.run from getenv", "import os\nimport uvicorn\nuvicorn.run(os.getenv('APP', 'acme.asgi:app'))\n", nil, true},
		{"uvicorn.run literal or app object", "import uvicorn\n\ndef serve(app, reload):\n    uvicorn.run('acme.asgi:app' if reload else app)\n", []string{"acme.asgi"}, false},
		{"import_string literal or computed", "from werkzeug.utils import import_string\n\ndef view(name, default):\n    return import_string('acme.views' if default else name)\n", []string{"acme", "acme.views"}, true},
		{"literal in the else branch", "import uvicorn\n\ndef serve(app, reload):\n    uvicorn.run(app if not reload else 'acme.asgi:app')\n", []string{"acme.asgi"}, false},
		{"two literal branches", "import uvicorn\n\ndef serve(prod):\n    uvicorn.run('acme.asgi:app' if prod else 'acme.dev:app')\n", []string{"acme.asgi", "acme.dev"}, false},
		{"literal or environment branch", "import os\nimport uvicorn\n\ndef serve(dev):\n    uvicorn.run('acme.asgi:app' if dev else os.environ['APP'])\n", []string{"acme.asgi"}, true},
		{"parenthesised conditional", "import uvicorn\n\ndef serve(app, reload):\n    uvicorn.run(('acme.asgi:app' if reload else app), port=8000)\n", []string{"acme.asgi"}, false},
		{"name-only conditional of literals", "from werkzeug.utils import import_string\n\ndef view(a):\n    return import_string('acme.a' if a else 'acme.b')\n", []string{"acme", "acme.a", "acme.b"}, false},
		{"app keyword after another", "import uvicorn\nuvicorn.run(\n    host='0.0.0.0',\n    app='acme.asgi:app',\n)\n", []string{"acme.asgi"}, false},
		{"app keyword from the environment", "import os\nimport uvicorn\nuvicorn.run(host='0.0.0.0', app=os.environ['APP'])\n", nil, true},
		{"import_string keyword after another", "from werkzeug.utils import import_string\nimport_string(silent=True, import_name='acme.views')\n", []string{"acme", "acme.views"}, false},
		{"empty module name", "import uvicorn\nuvicorn.run(':app')\n", nil, false},
		{"star import", "from uvicorn import *\nrun('acme.asgi:app')\n", []string{"acme.asgi"}, false},
		{"import_string as a value", "from werkzeug.utils import import_string\nfrom django.conf import settings\nBACKENDS = list(map(import_string, settings.BACKENDS))\n", nil, true},
		{"import_string bound to another name", "from django.utils.module_loading import import_string\nload = import_string\n", nil, true},
		{"import_string in a parenthesised import", "from werkzeug.utils import (\n    cached_property,\n    import_string,\n)\nview = import_string('acme.views')\n", []string{"acme", "acme.views"}, false},
		{"uvicorn.run app object", "import uvicorn\nfrom acme.asgi import app\nuvicorn.run(app, host='0.0.0.0')\n", nil, false},
		{"flask from_object literal", "from flask import Flask\napp = Flask(__name__)\napp.config.from_object('acme.settings.Prod')\n", []string{"acme.settings", "acme.settings.Prod"}, false},
		{"flask from_object on a call", "def make():\n    create_app().config.from_object('acme.settings')\n", []string{"acme", "acme.settings"}, false},
		{"flask from_object class", "from flask import Flask\nfrom acme.settings import Prod\napp = Flask(__name__)\napp.config.from_object(Prod)\n", nil, false},
		{"flask from_object from the environment", "import os\n\ndef make(app):\n    app.config.from_object(os.environ.get('SETTINGS'))\n", nil, true},
		{"celery config_from_object literal", "from celery import Celery\napp = Celery('acme')\napp.config_from_object('django.conf:settings', namespace='CELERY')\n", []string{"django.conf"}, false},
		{"celery config_from_object variable", "def make(app, settings):\n    app.config_from_object(settings)\n", nil, false},
		{"subprocess.run is not a loader", "import subprocess\n\ndef go(cmd):\n    subprocess.run(cmd)\n    subprocess.run('acme.tool')\n", nil, false},
		{"unbound import_string", "def import_string(name):\n    return name\n\nimport_string('acme.views')\n", nil, false},
		{"run on an unrelated module", "import server\nserver.run('acme.asgi:app')\n", nil, false},
		{"attribute named like a loader", "import werkzeug\nobj.werkzeug.import_string('acme.views')\n", nil, false},
		{"loader name on a call receiver", "import uvicorn\nimport werkzeug\nmake().werkzeug.import_string(name)\nservers[0].uvicorn.run('acme.asgi:app')\n", nil, false},
		{"bare config.from_object name", "from acme import config\nconfig.from_object('acme.settings')\n", nil, false},
		{"uvicorn Config as a type", "from typing import Optional\nimport uvicorn\nfrom uvicorn import Config\n\ndef build(cfg: uvicorn.Config, alt: Optional[Config]) -> Config:\n    assert isinstance(cfg, uvicorn.config.Config)\n    return cfg\n", nil, false},
		{"uvicorn Config subclassed", "import uvicorn\n\nclass Settings(uvicorn.Config):\n    pass\n", nil, true},
		{"uvicorn Config subclassed across lines", "import uvicorn\n\nclass Settings(\n    Base,\n    uvicorn.Config,\n):\n    pass\n", nil, true},
		{"uvicorn Config subclassed after a statement", "import uvicorn\nx = 1; class S(uvicorn.Config): pass\n", nil, true},
		{"uvicorn Config bound and called", "import uvicorn\ncfg_cls = uvicorn.Config\ncfg = cfg_cls('acme.asgi:app')\n", nil, true},
		{"uvicorn Config in a partial", "import functools\nimport uvicorn\nmk = functools.partial(uvicorn.Config, port=80)\n", nil, true},
		{"uvicorn Config returned", "import uvicorn\n\ndef factory():\n    return uvicorn.Config\n", nil, true},
		{"uvicorn Config in a dict", "import uvicorn\nFACTORIES = {'u': uvicorn.Config}\n", nil, true},
		{"uvicorn Config in a lambda", "import uvicorn\nmk = lambda: uvicorn.Config\n", nil, true},
		{"uvicorn Config in a list", "import uvicorn\nKINDS = [uvicorn.Config]\n", nil, true},
		{"uvicorn Config in a returned list", "import uvicorn\n\ndef kinds():\n    return [uvicorn.Config]\n", nil, true},
		{"uvicorn Config in a loop list", "import uvicorn\nfor k in [uvicorn.Config]:\n    k('acme.asgi:app')\n", nil, true},
		{"uvicorn Config in a lambda default", "import uvicorn\n\ndef f(mk=lambda: uvicorn.Config):\n    return mk()\n", nil, true},
		{"aliased Config as a type", "from uvicorn import Config as UC\n\ndef f(c: UC) -> None:\n    pass\n", nil, false},
		{"Config annotations in a class body and a tuple isinstance", "import typing\nimport uvicorn\n\nclass S(Base):\n    cfg: uvicorn.Config\n    kind: typing.Type[uvicorn.Config]\n\ndef check(c):\n    return isinstance(c, (int, uvicorn.Config))\n", nil, false},
		{"Config annotation on a multi-line def", "import uvicorn\n\nasync def serve(\n    host,\n    cfg: uvicorn.Config,\n):\n    pass\n", nil, false},
		{"uvicorn.run passed as a value", "import uvicorn\nserve = uvicorn.run\n", nil, true},
		{"environment or literal", "import os\nimport uvicorn\n\ndef serve(path):\n    uvicorn.run(path or 'acme.asgi:app')\n", []string{"acme.asgi"}, false},
		{"literal and computed", "from werkzeug.utils import import_string\n\ndef view(name, on):\n    return import_string(on and 'acme.views' or name)\n", []string{"acme", "acme.views"}, true},
		{"else against a literal", "from werkzeug.utils import import_string\n\ndef view(a):\n    return import_string('acme.a' if a else'acme.b')\n", []string{"acme", "acme.a", "acme.b"}, false},
		{"star import with a method named run", "from uvicorn import *\n\nclass Svc:\n    def run(self):\n        pass\n\nrun('acme.asgi:app')\n", []string{"acme.asgi"}, false},
		{"star import with an inner class named Config", "from uvicorn import *\n\nclass M(BaseModel):\n    class Config:\n        frozen = True\n\nConfig('acme.asgi:app')\n", []string{"acme.asgi"}, false},
		{"star import shadowed by a def", "from uvicorn import *\n\ndef run(target):\n    return target\n\nhandlers = [run]\n", nil, false},
		{"resolve_name by a literal getattr", "import pkgutil\nR = getattr(pkgutil, 'resolve_name', None)\n\ndef go(spec):\n    return R(spec)\n", nil, true},
		{"import_string by a literal getattr on a submodule", "import werkzeug.utils\nload = getattr(werkzeug.utils, 'import_string')\n", nil, true},
		{"import_string by a literal getattr on an imported submodule", "from werkzeug import utils\nload = getattr(utils, \"import_string\")\n", nil, true},
		{"resolve_name by a literal getattr on an alias", "import pkgutil as pu\nR = getattr(pu, 'resolve_name')\n", nil, true},
		{"resolve_name by a vars subscript", "import pkgutil\nR = vars(pkgutil)['resolve_name']\n", nil, true},
		{"resolve_name by a __dict__ get", "import pkgutil\nR = pkgutil.__dict__.get('resolve_name')\n", nil, true},
		{"run by a __dict__ subscript", "import uvicorn\nserve = uvicorn.__dict__['run']\n", nil, true},
		{"literal getattr called with a computed name", "import pkgutil\n\ndef go(spec):\n    return getattr(pkgutil, 'resolve_name')(spec)\n", nil, true},
		{"literal getattr called with a literal", "import pkgutil\nf = getattr(pkgutil, 'resolve_name')('acme.plugins:load')\n", []string{"acme.plugins"}, false},
		{"vars subscript called with a literal", "import werkzeug\nv = vars(werkzeug)['import_string']('acme.views:Index')\n", []string{"acme.views"}, false},
		{"computed getattr on a loader module", "import pkgutil\n\ndef f(n):\n    return getattr(pkgutil, n)\n", nil, true},
		{"computed vars subscript on a loader module", "import uvicorn\n\ndef f(n):\n    return vars(uvicorn)[n]\n", nil, true},
		{"loader module __dict__ iterated", "import pkgutil\nNAMES = list(pkgutil.__dict__.items())\n", nil, true},
		{"loader module __dict__ by a literal getattr", "import pkgutil\nD = getattr(pkgutil, '__dict__')\n", nil, true},
		{"loader module passed as a value", "import pkgutil\n\nfetch(pkgutil)\n", nil, true},
		{"unrelated literal getattr on a loader module", "import pkgutil\n__path__ = getattr(pkgutil, 'extend_path')(__path__, __name__)\n", nil, false},
		{"unrelated vars and __dict__ subscripts on a loader module", "import pkgutil\nE = vars(pkgutil)['extend_path']\nV = pkgutil.__dict__.get('iter_importers')\nW = pkgutil.__dict__['get_data']\n", nil, false},
		{"loader module __dict__ get as a value", "import pkgutil\nlookup = pkgutil.__dict__.get\n", nil, true},
		{"computed __dict__ get on a loader module", "import pkgutil\n\ndef f(n):\n    return pkgutil.__dict__.get(n)\n", nil, true},
		{"loader module bound to a name", "import pkgutil\nM = pkgutil\n", nil, true},
		{"loader module patched and restored", "import uvicorn\n\ndef test_run(monkeypatch):\n    monkeypatch.setattr(uvicorn, 'run', lambda app, **kw: None)\n    delattr(uvicorn, 'run')\n", nil, false},
		{"opaque leaf fetched from a loader module by literal getattr", "import pkgutil\n\ndef f(p):\n    return list(getattr(pkgutil, 'walk_packages')(p))\n", nil, true},
		{"opaque leaf fetched from a loader module's vars", "import pkgutil\n\ndef f(p):\n    return list(vars(pkgutil)['iter_modules'](p))\n", nil, true},
		{"loader module patched by patch.object", "import uvicorn\nfrom unittest import mock\n\n@mock.patch.object(uvicorn, 'run')\ndef test_a(run):\n    pass\n\ndef test_b(mocker):\n    with mock.patch.object(uvicorn, \"run\"):\n        pass\n    return mocker.patch.object(uvicorn, \"run\")\n", nil, false},
		{"optional loader module tested for presence", "try:\n    import uvicorn\nexcept ImportError:\n    uvicorn = None\ntry:\n    import werkzeug\nexcept ImportError:\n    werkzeug = None\n\nHAS = werkzeug is not None\nX = 1 if uvicorn else 0\n\ndef serve():\n    if uvicorn is None:\n        raise RuntimeError\n    if not werkzeug:\n        return\n    while uvicorn:\n        break\n    if uvicorn:\n        pass\n    elif werkzeug != None:\n        pass\n", nil, false},
		{"optional loader module compared with ==", "try:\n    import uvicorn\nexcept ImportError:\n    uvicorn = None\n\nMISSING = uvicorn == None\n", nil, false},
		{"not before a spaced loader attribute", "import werkzeug.utils\n\ndef f(s):\n    return not werkzeug.utils . import_string(s)\n", nil, true},
		{"not before a continued loader attribute", "import werkzeug.utils\n\ndef f(s):\n    return not werkzeug.utils \\\n        .import_string(s)\n", nil, true},
		{"loader module as an arithmetic operand of a comparison", "import uvicorn\n\ndef f(reg):\n    return reg + uvicorn == 0\n", nil, true},
		{"loader module in a chained comparison", "import uvicorn\n\ndef f(x, y):\n    return x == uvicorn == y\n", nil, true},
		{"not before a loader module membership test", "import uvicorn\n\ndef f(reg):\n    return not uvicorn in reg\n", nil, true},
		{"not before a loader attribute on the next line in brackets", "import werkzeug.utils\n\ndef f(s):\n    return (not werkzeug.utils\n            .import_string(s))\n", nil, true},
		{"loader module as an arithmetic operand across a bracketed line", "import uvicorn\n\ndef f(reg):\n    return (reg +\n            uvicorn == 0)\n", nil, true},
		{"loader module compared with another object", "import uvicorn\n\ndef f(reg):\n    return uvicorn == reg\n", nil, true},
		{"loader module bound before a statement opening with a bracket", "import uvicorn\nX = uvicorn\n(a, b) = 1, 2\n", nil, true},
		{"loader module compared with an expression starting with None", "import uvicorn\n\ndef f(reg):\n    return uvicorn == None + reg\n", nil, true},
		{"loader module as an arithmetic operand of an is None test", "import uvicorn\n\ndef f(reg):\n    return reg + uvicorn is None\n", nil, true},
		{"loader module as an arithmetic operand of a None comparison", "import uvicorn\n\ndef f(reg):\n    return reg + uvicorn == None\n", nil, true},
		{"loader module in a chained comparison ending in None", "import uvicorn\n\ndef f(x):\n    return x == uvicorn == None\n", nil, true},
		{"loader module inside a conditional expression's condition", "import uvicorn\n\ndef f(reg):\n    return 1 if uvicorn + reg else 0\n", nil, true},
		{"loader module passed to an object method that is not patch.object", "import uvicorn\n\ndef f(registry):\n    return registry.object(uvicorn, 'run')\n", nil, true},
		{"loader module as an or operand", "try:\n    import uvicorn\nexcept ImportError:\n    uvicorn = None\n\nserver = None or uvicorn\n", nil, true},
		{"loader module name bound to a function and called", "from uvicorn import main\n\nif __name__ == '__main__':\n    main()\n", nil, false},
		{"loader module name as another object's attribute", "import pkgutil\n\ndef f(cfg, n):\n    return getattr(cfg.pkgutil, n)\n", nil, false},
		{"loader module name as an attribute of a call result", "import pkgutil\n\ndef f(cfg, n):\n    return getattr(cfg().pkgutil, n)\n", nil, false},
		{"loader module rebound when absent", "try:\n    import pkgutil_resolve_name\nexcept ImportError:\n    pkgutil_resolve_name = None\n", nil, false},
		{"hasattr on a loader module", "import pkgutil\nOK = hasattr(pkgutil, 'resolve_name')\n", nil, false},
		{"plain attribute of a loader module", "import werkzeug\nV = werkzeug.__version__\n", nil, false},
		{"computed getattr on a module that hosts no loader", "import os\n\ndef f(n):\n    return getattr(os, n)\n", nil, false},
		{"loader on a sys.modules entry", "import sys\n\ndef f(s):\n    return sys.modules['werkzeug.utils'].import_string(s)\n", nil, true},
		{"loader on a sys.modules entry with a literal", "import sys\nV = sys.modules['werkzeug.utils'].import_string('acme.views')\n", []string{"acme", "acme.views"}, false},
		{"loader on a sys.modules.get entry", "import sys\n\ndef f(s):\n    return sys.modules.get('werkzeug.utils').import_string(s)\n", nil, true},
		{"loader on a from-imported modules entry", "from sys import modules\n\ndef f(s):\n    return modules['pkgutil'].resolve_name(s)\n", nil, true},
		{"loader on an import_module result", "import importlib\n\ndef f(s):\n    return importlib.import_module('werkzeug.utils').import_string(s)\n", []string{"werkzeug.utils"}, true},
		{"loader on an __import__ fromlist result", "def f(s):\n    return __import__('django.utils.module_loading', fromlist=['import_string']).import_string(s)\n", []string{"django.utils.module_loading"}, true},
		{"loader under an __import__ top package", "def f(s):\n    return __import__('django.utils.module_loading').utils.module_loading.import_string(s)\n", []string{"django.utils.module_loading"}, true},
		{"__import__ top package bound to an attribute", "class F:\n    def __init__(self):\n        self.m = __import__('django.core.cache')\n", []string{"django.core.cache"}, true},
		{"__import__ with a computed fromlist", "def f(names):\n    return __import__('django.core.cache', fromlist=names)\n", []string{"django.core.cache"}, true},
		{"__import__ fromlist of a module that hosts no loader", "class F:\n    def __init__(self):\n        self.m = __import__('django.core.cache', fromlist=['cache'])\n", []string{"django.core.cache"}, false},
		{"__import__ positional fromlist of a module that hosts no loader", "def f():\n    return __import__('django.core.cache', None, None, ['cache'])\n", []string{"django.core.cache"}, false},
		{"loader on a sys.modules entry as a statement", "import sys\n\ndef f(s):\n    sys.modules['werkzeug.utils'].import_string(s)\n", nil, true},
		{"loader on a from-imported modules entry by name", "from sys import modules\n\ndef f(s):\n    return modules['werkzeug.utils'].import_string(s)\n", nil, true},
		{"loader host passed as a keyword argument", "import sys\nregister(mod=sys.modules['werkzeug.utils'])\n", nil, true},
		{"loader on a bound import_module result", "import importlib\nm = importlib.import_module('werkzeug.utils')\n\ndef f(s):\n    return m.import_string(s)\n", []string{"werkzeug.utils"}, true},
		{"loader on an __import__ result with a computed fromlist", "def f(names, s):\n    return __import__('django.utils.module_loading', fromlist=names).import_string(s)\n", []string{"django.utils.module_loading"}, true},
		{"loader under the top package of an __import__ with a computed fromlist item", "def f(n, s):\n    return __import__('django.utils.module_loading', fromlist=[n]).utils.module_loading.import_string(s)\n", []string{"django.utils.module_loading"}, true},
		{"loader name on an __import__ top package", "def f(s):\n    return __import__('django.utils.module_loading').import_string(s)\n", []string{"django.utils.module_loading"}, false},
		{"loader module bound by an annotated assignment", "import importlib\nm: object = importlib.import_module('werkzeug.utils')\n\ndef f(s):\n    return m.import_string(s)\n", []string{"werkzeug.utils"}, true},
		{"loader module returned by a lambda", "import importlib\nget = lambda: importlib.import_module('werkzeug.utils')\n\ndef f(s):\n    return get().import_string(s)\n", []string{"werkzeug.utils"}, true},
		{"loader module in a multi-line list", "import importlib\nMODS = [\n    importlib.import_module('werkzeug.utils')\n]\n", []string{"werkzeug.utils"}, true},
		{"loader module as a multi-line dict value", "import importlib\nMODS = {\n    'u': importlib.import_module('werkzeug.utils')\n}\n", []string{"werkzeug.utils"}, true},
		{"loader module as the last element of a multi-line tuple", "import importlib\nMODS = (\n    1,\n    importlib.import_module('werkzeug.utils')\n)\n", []string{"werkzeug.utils"}, true},
		{"loader module as a multi-line call argument", "import importlib\nregister(\n    importlib.import_module('werkzeug.utils')\n)\n", []string{"werkzeug.utils"}, true},
		{"loader module as a multi-line keyword argument", "import importlib\nregister(\n    mod=importlib.import_module('werkzeug.utils')\n)\n", []string{"werkzeug.utils"}, true},
		{"loader module bound through parentheses", "import importlib\nm = (\n    importlib.import_module('werkzeug.utils')\n)\n", []string{"werkzeug.utils"}, true},
		{"loader module bound across a backslash", "import importlib\nm = \\\n    importlib.import_module('werkzeug.utils')\n", []string{"werkzeug.utils"}, true},
		{"loader module bound across a backslash with CRLF", "import importlib\r\nm = \\\r\n    importlib.import_module('werkzeug.utils')  # u\r\n", []string{"werkzeug.utils"}, true},
		{"loader fetched from a bound import_module result", "import importlib\nm = importlib.import_module('pkgutil')\n\ndef f(s):\n    return getattr(m, 'resolve_name')(s)\n", []string{"pkgutil"}, true},
		{"loader on a bound import_module result with a literal", "import importlib\nm = importlib.import_module('pkgutil')\nh = m.resolve_name('acme.plugins:load')\n", []string{"acme.plugins", "pkgutil"}, false},
		{"loader module returned by import_module passed as a value", "import importlib\nregister(importlib.import_module('werkzeug.utils'))\n", []string{"werkzeug.utils"}, true},
		{"loader submodule fetched from an __import__ result", "def f():\n    return getattr(__import__('werkzeug'), 'utils')\n", []string{"werkzeug"}, true},
		{"loader submodule fetched by getattr", "import werkzeug\nU = getattr(werkzeug, 'utils')\n", nil, true},
		{"loader host package fetched from its parent", "import django\nU = getattr(django, 'utils')\n", nil, true},
		{"parent of a loader host passed as a value", "import django\nregister(django)\n", nil, true},
		{"parent of a loader host used plainly", "import django\nfrom django.conf import settings\ndjango.setup()\nX = django.conf.settings.DEBUG\nV = django.VERSION\n", nil, false},
		{"import_module of a loader host discarded", "import importlib\nimportlib.import_module('werkzeug.utils')\n", []string{"werkzeug.utils"}, false},
		{"sys.modules store of a loader host", "import sys\nsys.modules['werkzeug.utils'] = stub\n", nil, false},
		{"sys.modules delete of a loader host", "import sys\ndel sys.modules['pkgutil']\n", nil, false},
		{"loader host presence in sys.modules", "import sys\nOK = 'werkzeug' in sys.modules\n", nil, false},
		{"other attribute of a bound import_module result", "import importlib\nm = importlib.import_module('pkgutil')\nP = m.extend_path(__path__, __name__)\n", []string{"pkgutil"}, false},
		{"computed getattr on an import_module result that hosts no loader", "import importlib\n\ndef f(n):\n    return getattr(importlib.import_module('json'), n)\n", []string{"json"}, false},
		{"plain attribute of a sys.modules loader host", "import sys\nV = getattr(sys.modules['uvicorn'], '__version__')\n", nil, false},
		{"bound import_module result tested for presence", "import importlib\nm = importlib.import_module('uvicorn')\nif m is None:\n    pass\n", []string{"uvicorn"}, false},
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

// A source file's line endings change neither its call graph nor its symbol index: "\r\n" and a
// lone "\r" end a line as "\n" does, as they do for Python's tokenizer.
func TestCallGraphAndIndex_LineEndings(t *testing.T) {
	src := flaskApp + `
import importlib
greeting = 'hello \
world'; plugin = importlib.import_module('yaml')
doc = """first
second"""
total = 1 + \
    2

def load(name):
    return importlib.import_module(name)
`
	handleFetch := funcSCIP("app", nil, "handle_fetch", 0)
	handle := funcSCIP("app", nil, "handle", 1)
	run := func(t *testing.T, src string) (plugin.CallGraphResult, []string, plugin.SymbolIndexResult) {
		t.Helper()
		dir := writeTree(t, map[string]string{"app.py": src})
		prog, err := loadProgram(dir)
		if err != nil {
			t.Fatalf("loadProgram: %v", err)
		}
		res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
		if err != nil {
			t.Fatalf("CallGraph: %v", err)
		}
		return res, prog.files[0].loadRoots, indexOf(t, dir)
	}
	lf, lfRoots, lfIndex := run(t, src)
	if !hasEdge(lf.Edges, handleFetch, handle) {
		t.Fatalf("LF: missing edge %s -> %s", handleFetch, handle)
	}
	if !reflect.DeepEqual(lfRoots, []string{"yaml"}) || !hasReason(lf.Partiality, plugin.PartialReasonDynamicImportSpecifier) {
		t.Fatalf("LF: loadRoots = %v, reasons %v", lfRoots, lf.Partiality.Reasons)
	}
	if !hasDisplay(lfIndex, "load()") && !hasDisplay(lfIndex, "load(1)") {
		t.Fatalf("LF: load not indexed")
	}
	for _, eol := range []string{"\r\n", "\r"} {
		t.Run(strconv.Quote(eol), func(t *testing.T) {
			res, roots, index := run(t, strings.ReplaceAll(src, "\n", eol))
			if !reflect.DeepEqual(res, lf) {
				t.Errorf("call graph differs from LF:\n got %+v\nwant %+v", res, lf)
			}
			if !reflect.DeepEqual(roots, lfRoots) {
				t.Errorf("loadRoots = %v, want %v", roots, lfRoots)
			}
			if !reflect.DeepEqual(index, lfIndex) {
				t.Errorf("index differs from LF:\n got %+v\nwant %+v", index, lfIndex)
			}
		})
	}
}
