package pythonanalysis

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// route is a Flask app module header; each fixture's app.py appends its own body to it.
const route = "from flask import Flask\nimport threading\napp = Flask(__name__)\n\ndef danger(x):\n    return x\n\n"

func symbolSet(syms []plugin.Symbol) map[string]bool {
	out := map[string]bool{}
	for _, s := range syms {
		out[s.SCIP] = true
	}
	return out
}

func mustCallGraph(t *testing.T, files map[string]string) plugin.CallGraphResult {
	t.Helper()
	res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: writeTree(t, files)})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	return res
}

// TestReachability_HiddenEdgesReachTheSink: a sink behind an edge the lexical scanner cannot
// draw (a function handed over as a value, an import alias, a dunder the interpreter calls,
// a decorator application) is reached, through an escape root or a drawn edge.
func TestReachability_HiddenEdgesReachTheSink(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		sink  string
	}{
		{
			name:  "cb_param",
			files: map[string]string{"app.py": route + "def handler_cb(v):\n    return danger(v)\n\ndef run(cb):\n    return cb(1)\n\n@app.route('/')\ndef index():\n    return run(handler_cb)\n"},
		},
		{
			name:  "cb_map",
			files: map[string]string{"app.py": route + "def handler_cb(v):\n    return danger(v)\n\n@app.route('/')\ndef index():\n    return list(map(handler_cb, [1]))\n"},
		},
		{
			name:  "cb_registry",
			files: map[string]string{"app.py": route + "def handler_cb(v):\n    return danger(v)\n\nHANDLERS = {\"a\": handler_cb}\n\n@app.route('/')\ndef index():\n    return HANDLERS[\"a\"](1)\n"},
		},
		{
			name:  "cb_thread",
			files: map[string]string{"app.py": route + "def handler_cb():\n    return danger(1)\n\n@app.route('/')\ndef index():\n    threading.Thread(target=handler_cb).start()\n"},
		},
		{
			name:  "cb_addurl",
			files: map[string]string{"app.py": route + "def handler_cb():\n    return danger(1)\n\napp.add_url_rule(\"/\", view_func=handler_cb)\n"},
		},
		{
			name:  "cb_baredeco",
			files: map[string]string{"app.py": route + "REG = {}\n\ndef register(fn):\n    REG[fn.__name__] = fn\n    return fn\n\n@register\ndef handler_cb(v):\n    return danger(v)\n\n@app.route('/')\ndef index():\n    return REG[\"handler_cb\"](1)\n"},
		},
		{
			name:  "cb_lambda",
			files: map[string]string{"app.py": route + "def handler_cb(v):\n    return danger(v)\n\ndef run(cb):\n    return cb(1)\n\n@app.route('/')\ndef index():\n    return run(lambda v: handler_cb(v))\n"},
		},
		{
			name: "re_plain",
			files: map[string]string{
				"pkg/__init__.py": "from .impl import f\n",
				"pkg/impl.py":     "from app import danger\n\ndef f(x):\n    return danger(x)\n",
				"app.py":          route + "import pkg\n\n@app.route('/')\ndef index():\n    return pkg.f(1)\n",
			},
		},
		{
			name: "re_star",
			files: map[string]string{
				"pkg/__init__.py": "from .impl import *\n",
				"pkg/impl.py":     "from app import danger\n\ndef f(x):\n    return danger(x)\n",
				"app.py":          route + "import pkg\n\n@app.route('/')\ndef index():\n    return pkg.f(1)\n",
			},
		},
		{
			name: "re_all",
			files: map[string]string{
				"pkg/__init__.py": "from .impl import *\n__all__ = [\"f\"]\n",
				"pkg/impl.py":     "from app import danger\n\ndef f(x):\n    return danger(x)\n",
				"app.py":          route + "import pkg\n\n@app.route('/')\ndef index():\n    return pkg.f(1)\n",
			},
		},
		{
			name: "re_importas",
			files: map[string]string{
				"pkg/__init__.py": "",
				"pkg/impl.py":     "from app import danger\n\ndef f(x):\n    return danger(x)\n",
				"app.py":          route + "import pkg.impl as x\n\n@app.route('/')\ndef index():\n    return x.f(1)\n",
			},
		},
		{
			name: "re_chain",
			files: map[string]string{
				"pkg/__init__.py":     "from .sub import f\n",
				"pkg/sub/__init__.py": "from .impl import f\n",
				"pkg/sub/impl.py":     "from app import danger\n\ndef f(x):\n    return danger(x)\n",
				"app.py":              route + "import pkg\n\n@app.route('/')\ndef index():\n    return pkg.f(1)\n",
			},
		},
		{
			name: "re_alias",
			files: map[string]string{
				"pkg/__init__.py": "from .impl import f as g\n",
				"pkg/impl.py":     "from app import danger\n\ndef f(x):\n    return danger(x)\n",
				"app.py":          route + "import pkg\n\n@app.route('/')\ndef index():\n    return pkg.g(1)\n",
			},
		},
		{
			name: "re_fromimport_alias",
			files: map[string]string{
				"pkg/__init__.py": "from .impl import f as g\n",
				"pkg/impl.py":     "from app import danger\n\ndef f(x):\n    return danger(x)\n",
				"app.py":          route + "from pkg import g\n\n@app.route('/')\ndef index():\n    return g(1)\n",
			},
		},
		{
			name: "alias_direct",
			files: map[string]string{
				"helpers.py": "from app import danger\n\ndef f(x):\n    return danger(x)\n",
				"app.py":     route + "from helpers import f as h\n\n@app.route('/')\ndef index():\n    return h(1)\n",
			},
		},
		{
			name: "re_collide",
			files: map[string]string{
				"pkg/__init__.py": "from .impl import f\n",
				"pkg/impl.py":     "from app import danger\n\ndef f(x):\n    return danger(x)\n",
				"other.py":        "def f(x):\n    return x\n",
				"app.py":          route + "import pkg\n\n@app.route('/')\ndef index():\n    return pkg.f(1)\n",
			},
		},
		{
			name:  "adj_dunder_constructor",
			files: map[string]string{"app.py": route + "class C:\n    def __init__(self, v):\n        danger(v)\n\n@app.route('/')\ndef index():\n    return C(1)\n"},
		},
		{
			name:  "adj_dunder_with",
			files: map[string]string{"app.py": route + "class C:\n    def __init__(self, v):\n        self.v = v\n    def __enter__(self):\n        return danger(self.v)\n    def __exit__(self, *a):\n        return False\n\n@app.route('/')\ndef index():\n    with C(2):\n        pass\n"},
		},
		{
			name:  "adj_decorator",
			files: map[string]string{"app.py": route + "def deco(fn):\n    danger(1)\n    return fn\n\n@deco\ndef wrapped():\n    return 1\n"},
		},
		{
			name:  "decorator_factory",
			files: map[string]string{"app.py": route + "def deco(tag):\n    danger(tag)\n    return lambda fn: fn\n\n@deco(\"t\")\ndef wrapped():\n    return 1\n"},
		},
		{
			name:  "defaulted_parameter",
			files: map[string]string{"app.py": route + "def helper(x, y=1, z=2):\n    return danger(x)\n\n@app.route('/')\ndef index():\n    return helper(1)\n"},
		},
		{
			name:  "fstring_substitution",
			files: map[string]string{"app.py": route + "def helper(x):\n    return danger(x)\n\n@app.route('/')\ndef index():\n    return f\"{helper(1)}\"\n"},
		},
		{
			name:  "one_line_body",
			files: map[string]string{"app.py": route + "def helper(x): return danger(x)\n\n@app.route('/')\ndef index(): return helper(1)\n"},
		},
		{
			name:  "default_argument_value",
			files: map[string]string{"app.py": route + "def handler_cb(v):\n    return danger(v)\n\ndef run(cb=handler_cb):\n    return cb(1)\n\n@app.route('/')\ndef index():\n    return run()\n"},
		},
		{
			name: "module_as_value",
			files: map[string]string{
				"pkg/__init__.py": "",
				"pkg/handlers.py": "from app import danger\n\ndef on_a(x):\n    return danger(x)\n",
				"pkg/wire.py":     "from . import handlers\n\ndef dispatch(name):\n    return lookup(handlers, name)(1)\n",
				"app.py":          route,
			},
		},
		{
			name:  "computed_getattr",
			files: map[string]string{"app.py": route + "def handle_a(v):\n    return danger(v)\n\n@app.route('/')\ndef index():\n    import sys\n    return getattr(sys.modules[__name__], \"handle_\" + \"a\")(1)\n"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := funcSCIP("app", nil, "danger", 1)
			res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: writeTree(t, tc.files), Symbols: []string{sink}})
			if err != nil {
				t.Fatalf("Reachability: %v", err)
			}
			if len(res.Paths) == 0 {
				t.Fatalf("%s: sink not reached; partiality %v", tc.name, res.Partiality.Reasons)
			}
			if len(res.Searched) != 0 || res.Refutation != nil {
				t.Fatalf("Python must emit no Searched/Refutation; got %v / %v", res.Searched, res.Refutation)
			}
		})
	}
}

// TestCallGraph_AmbiguousSiteIsUnresolvedNotAnEdge: a callee name two first-party
// declarations share gets no edge, is listed in Unresolved with dynamic_dispatch and no
// Targets, and both declarations escape so a reader of the listed site can reach them.
func TestCallGraph_AmbiguousSiteIsUnresolvedNotAnEdge(t *testing.T) {
	res := mustCallGraph(t, map[string]string{
		"pkg/__init__.py": "from .impl import f\n",
		"pkg/impl.py":     "def f(x):\n    return x\n",
		"other.py":        "def f(x):\n    return x\n",
		"app.py":          "import pkg\n\ndef index():\n    return pkg.f(1)\n",
	})
	caller := funcSCIP("app", nil, "index", 0)
	impl, other := funcSCIP("pkg/impl", nil, "f", 1), funcSCIP("other", nil, "f", 1)
	if hasEdge(res.Edges, caller, impl) || hasEdge(res.Edges, caller, other) {
		t.Fatalf("an ambiguous callee must get no edge; edges %v", res.Edges)
	}
	want := plugin.UnresolvedCall{Caller: sym(caller), Callee: "pkg.f", Arity: 1, Reason: plugin.PartialReasonDynamicDispatch}
	if !slices.ContainsFunc(res.Unresolved, func(u plugin.UnresolvedCall) bool {
		return u.Caller == want.Caller && u.Callee == want.Callee && u.Arity == want.Arity && u.Reason == want.Reason && u.Targets == nil
	}) {
		t.Fatalf("missing Unresolved %+v; got %+v", want, res.Unresolved)
	}
	esc := symbolSet(res.Escaped)
	if !esc[impl] || !esc[other] {
		t.Fatalf("both candidates must escape; escaped %v", res.Escaped)
	}
	if hasReason(res.Partiality, plugin.PartialReasonUnlistedSites) {
		t.Fatalf("every declined site is listed, so unlisted_sites must be absent; got %v", res.Partiality.Reasons)
	}
}

// TestCallGraph_UnresolvedListsEveryDeclinedSite: each call site with no first-party edge
// is listed once with the callee as written; a site with an edge is not.
func TestCallGraph_UnresolvedListsEveryDeclinedSite(t *testing.T) {
	src := "import json\n\nHANDLERS = {}\n\ndef helper(x):\n    return x\n\n@register\ndef run(k, v):\n    helper(v)\n    json.loads(v)\n    HANDLERS[k](v)\n    make()(v)\n    print(v)\n    print(v)\n"
	res := mustCallGraph(t, map[string]string{"app.py": src})
	run := sym(funcSCIP("app", nil, "run", 2))
	init := sym(moduleInitSCIP("app"))
	want := []plugin.UnresolvedCall{
		{Caller: init, Callee: "register", Arity: 1},
		{Caller: run, Callee: "HANDLERS[k]", Arity: 1},
		{Caller: run, Callee: "json.loads", Arity: 1},
		{Caller: run, Callee: "make", Arity: 0},
		{Caller: run, Callee: "make()", Arity: 1},
		{Caller: run, Callee: "print", Arity: 1},
	}
	var got []plugin.UnresolvedCall
	for _, u := range res.Unresolved {
		if u.Reason != plugin.PartialReasonDynamicDispatch {
			t.Errorf("Unresolved %+v: reason must be dynamic_dispatch", u)
		}
		u.Reason = ""
		got = append(got, u)
	}
	if !slices.EqualFunc(got, want, func(a, b plugin.UnresolvedCall) bool {
		return a.Caller == b.Caller && a.Callee == b.Callee && a.Arity == b.Arity && a.Targets == nil
	}) {
		t.Fatalf("Unresolved =\n%+v\nwant\n%+v", got, want)
	}
}

// TestCallGraph_EscapeTriggers: which declared functions escape. Each case names the
// functions that must and must not land in Escaped (and so in Roots).
func TestCallGraph_EscapeTriggers(t *testing.T) {
	plain := "def target(x):\n    return x\n\ndef caller():\n    return target(1)\n"
	cases := []struct {
		name    string
		files   map[string]string
		escaped []string
		kept    []string
	}{
		{
			name:  "direct call only does not escape",
			files: map[string]string{"m.py": plain},
			kept:  []string{funcSCIP("m", nil, "target", 1), funcSCIP("m", nil, "caller", 0)},
		},
		{
			name:    "name passed as value",
			files:   map[string]string{"m.py": plain + "def other():\n    return run(target)\n"},
			escaped: []string{funcSCIP("m", nil, "target", 1)},
			kept:    []string{funcSCIP("m", nil, "other", 0)},
		},
		{
			name:    "name used as value in another module",
			files:   map[string]string{"m.py": plain, "n.py": "from m import target\nCB = target\n"},
			escaped: []string{funcSCIP("m", nil, "target", 1)},
		},
		{
			name:    "attribute leaf used as value",
			files:   map[string]string{"m.py": plain, "n.py": "import m\nCB = [m.target]\n"},
			escaped: []string{funcSCIP("m", nil, "target", 1)},
		},
		{
			name:  "import statement and keyword argument name do not escape",
			files: map[string]string{"m.py": plain, "n.py": "from m import target\n\ndef g():\n    return target(target=1)\n"},
			kept:  []string{funcSCIP("m", nil, "target", 1)},
		},
		{
			name:    "alias used as value escapes the original",
			files:   map[string]string{"pkg/__init__.py": "from .impl import target as t2\n", "pkg/impl.py": "def target(x):\n    return x\n", "n.py": "from pkg import t2\nCB = t2\n"},
			escaped: []string{funcSCIP("pkg/impl", nil, "target", 1)},
		},
		{
			name:    "class member",
			files:   map[string]string{"m.py": "class C:\n    def method(self):\n        return 1\n"},
			escaped: []string{funcSCIP("m", []string{"C"}, "method", 1)},
		},
		{
			name:    "module-level dunder",
			files:   map[string]string{"m.py": "def __getattr__(name):\n    return name\n"},
			escaped: []string{funcSCIP("m", nil, "__getattr__", 1)},
		},
		{
			name:    "unrecognised decorator",
			files:   map[string]string{"m.py": "import functools\n\n@functools.lru_cache\ndef cached(x):\n    return x\n"},
			escaped: []string{funcSCIP("m", nil, "cached", 1)},
		},
		{
			name:  "route decorator is an ingress, not an escape",
			files: map[string]string{"m.py": "@app.route('/')\ndef index():\n    return 1\n"},
			kept:  []string{funcSCIP("m", nil, "index", 0)},
		},
		{
			name:    "call with no arity match escapes the candidate",
			files:   map[string]string{"m.py": "def target(x, y=1, z=2):\n    return x\n\ndef caller():\n    return target(1)\n"},
			escaped: []string{funcSCIP("m", nil, "target", 3)},
		},
		{
			name:    "edged callee stays, the other arity escapes",
			files:   map[string]string{"m.py": "def target(x):\n    return x\n", "n.py": "def target(x, y, z=1):\n    return x\n\ndef caller():\n    return target(1, 2)\n"},
			escaped: []string{funcSCIP("m", nil, "target", 1)},
			kept:    []string{funcSCIP("n", nil, "target", 3)},
		},
		{
			name:    "module used as value",
			files:   map[string]string{"pkg/__init__.py": "", "pkg/handlers.py": "def on_a(x):\n    return x\n", "pkg/wire.py": "from . import handlers\nREG = [handlers]\n"},
			escaped: []string{funcSCIP("pkg/handlers", nil, "on_a", 1)},
		},
		{
			name:  "module attribute read does not escape the module",
			files: map[string]string{"pkg/__init__.py": "", "pkg/conf.py": "LEVEL = 1\n\ndef helper(x):\n    return x\n", "pkg/wire.py": "from pkg import conf\nX = conf.LEVEL\n"},
			kept:  []string{funcSCIP("pkg/conf", nil, "helper", 1)},
		},
		{
			name:    "f-string substitution",
			files:   map[string]string{"m.py": plain + "def other():\n    return f\"{target}\"\n"},
			escaped: []string{funcSCIP("m", nil, "target", 1)},
		},
		{
			name:  "test module neither escapes nor makes escape",
			files: map[string]string{"m.py": plain, "tests/test_m.py": "from m import target\n\nclass TestM:\n    def test_x(self):\n        run(target)\n"},
			kept:  []string{funcSCIP("m", nil, "target", 1), funcSCIP("tests/test_m", []string{"TestM"}, "test_x", 1), moduleInitSCIP("tests/test_m")},
		},
		{
			name:    "module top-level frame",
			files:   map[string]string{"m.py": plain},
			escaped: []string{moduleInitSCIP("m")},
		},
	}
	for _, trigger := range []string{
		"getattr(obj, name)", "globals()[name]", "vars(obj)", "locals()", "obj.__dict__",
		"eval(src)", "exec(src)", "__import__(name)", "operator.attrgetter(name)",
		"operator.methodcaller(name)", "inspect.getmembers(obj)", "sys.modules[name]",
		"importlib.import_module(name)",
	} {
		cases = append(cases, struct {
			name    string
			files   map[string]string
			escaped []string
			kept    []string
		}{
			name:    "computed name " + trigger,
			files:   map[string]string{"m.py": plain + "def dyn(obj, name, src):\n    return " + trigger + "\n", "n.py": plain},
			escaped: []string{funcSCIP("m", nil, "target", 1), funcSCIP("m", nil, "caller", 0), funcSCIP("m", nil, "dyn", 3)},
			kept:    []string{funcSCIP("n", nil, "caller", 0)},
		})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := mustCallGraph(t, tc.files)
			esc, roots := symbolSet(res.Escaped), symbolSet(res.Roots)
			for _, s := range tc.escaped {
				if !esc[s] || !roots[s] {
					t.Errorf("%s must be escaped and a root; escaped %v", s, res.Escaped)
				}
			}
			for _, s := range tc.kept {
				if esc[s] {
					t.Errorf("%s must not escape; escaped %v", s, res.Escaped)
				}
			}
		})
	}
}

// TestCallGraph_AliasUnion: a call through a name an import binds to a first-party function
// under another name resolves through the alias, with the same arity rule.
func TestCallGraph_AliasUnion(t *testing.T) {
	cases := []struct {
		name   string
		files  map[string]string
		caller string
		callee string
	}{
		{
			name:   "relative alias",
			files:  map[string]string{"pkg/__init__.py": "", "pkg/impl.py": "def f(x):\n    return x\n", "pkg/use.py": "from .impl import f as g\n\ndef c():\n    return g(1)\n"},
			caller: funcSCIP("pkg/use", nil, "c", 0),
			callee: funcSCIP("pkg/impl", nil, "f", 1),
		},
		{
			name:   "absolute first-party alias",
			files:  map[string]string{"helpers.py": "def f(x):\n    return x\n", "app.py": "from helpers import f as h\n\ndef c():\n    return h(1)\n"},
			caller: funcSCIP("app", nil, "c", 0),
			callee: funcSCIP("helpers", nil, "f", 1),
		},
		{
			name:   "parent-relative alias",
			files:  map[string]string{"pkg/__init__.py": "", "pkg/impl.py": "def f(x):\n    return x\n", "pkg/sub/__init__.py": "", "pkg/sub/use.py": "from ..impl import f as g\n\ndef c():\n    return g(1)\n"},
			caller: funcSCIP("pkg/sub/use", nil, "c", 0),
			callee: funcSCIP("pkg/impl", nil, "f", 1),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := mustCallGraph(t, tc.files)
			if !hasEdge(res.Edges, tc.caller, tc.callee) {
				t.Fatalf("missing edge %s -> %s; edges %v", tc.caller, tc.callee, res.Edges)
			}
		})
	}
}

// TestCallGraph_RelativeBindingNamesNoDistribution: a relative import whose name matches a
// declared dependency stays first-party: it yields no boundary binding and no pypi node.
func TestCallGraph_RelativeBindingNamesNoDistribution(t *testing.T) {
	if b := parseImportStatement("from .yaml import load as yl"); b != nil {
		t.Fatalf("a relative import must yield no boundary binding; got %+v", b)
	}
	if got, want := parseRelativeImport("from .yaml import load as yl, dump"), []importBinding{{"yl", ".yaml.load"}, {"dump", ".yaml.dump"}}; !slices.Equal(got, want) {
		t.Fatalf("parseRelativeImport = %+v, want %+v", got, want)
	}
	if got, want := parseRelativeImport("from . import yaml"), []importBinding{{"yaml", ".yaml"}}; !slices.Equal(got, want) {
		t.Fatalf("parseRelativeImport = %+v, want %+v", got, want)
	}
	res := mustCallGraph(t, map[string]string{
		"requirements.txt": "pyyaml==6.0\n",
		"pkg/__init__.py":  "",
		"pkg/yaml.py":      "def load(x):\n    return x\n",
		"pkg/use.py":       "from .yaml import load as yl\nfrom . import yaml\n\ndef c(s):\n    yaml.load(s)\n    return yl(s)\n",
	})
	for _, e := range res.Edges {
		if strings.HasPrefix(e.Callee.SCIP, "pypi:") {
			t.Fatalf("a relative binding must never name a distribution; edge %v", e)
		}
	}
}

// TestCallGraph_UnlistedSites: unlisted_sites is set exactly when a declined call site is
// missing from Unresolved.
func TestCallGraph_UnlistedSites(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"every site listed", "def f(x):\n    return g(x)\n", false},
		{"f-string without a call", "def f(x):\n    return f\"{x}\"\n", false},
		{"f-string with a call", "def f(x):\n    return f\"{g(x)}\"\n", true},
		{"evaluated code", "def f(src):\n    return eval(src)\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := mustCallGraph(t, map[string]string{"m.py": tc.src})
			if got := hasReason(res.Partiality, plugin.PartialReasonUnlistedSites); got != tc.want {
				t.Fatalf("unlisted_sites = %v, want %v; reasons %v", got, tc.want, res.Partiality.Reasons)
			}
		})
	}
}
