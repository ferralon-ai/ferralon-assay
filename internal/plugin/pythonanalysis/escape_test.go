package pythonanalysis

import (
	"context"
	"os"
	"path/filepath"
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
			name: "computed_getattr",
			files: map[string]string{
				"wire.py": "import sys\nfrom app import danger\n\ndef handle_a(v):\n    return danger(v)\n\ndef dispatch(name):\n    return getattr(sys.modules[__name__], \"handle_\" + name)(1)\n",
				"app.py":  route,
			},
		},
		{
			name: "alias_of_alias_import",
			files: map[string]string{
				"pkg/__init__.py":  "from .impl import f as g\n",
				"pkg/impl.py":      "from app import danger\n\ndef f(x):\n    return danger(x)\n",
				"pkg2/__init__.py": "from pkg import g as h\n",
				"app.py":           route + "from pkg2 import h\n\n@app.route('/')\ndef index():\n    return h(1)\n",
			},
		},
		{
			name: "alias_of_alias_attr",
			files: map[string]string{
				"pkg/__init__.py":  "from .impl import f as g\n",
				"pkg/impl.py":      "from app import danger\n\ndef f(x):\n    return danger(x)\n",
				"pkg2/__init__.py": "from pkg import g as h\n",
				"app.py":           route + "import pkg2\n\n@app.route('/')\ndef index():\n    return pkg2.h(1)\n",
			},
		},
		{
			name: "alias_of_alias_value",
			files: map[string]string{
				"pkg/__init__.py":  "from .impl import f as g\n",
				"pkg/impl.py":      "from app import danger\n\ndef f(x):\n    return danger(x)\n",
				"pkg2/__init__.py": "from pkg import g as h\n",
				"app.py":           route + "from pkg2 import h\n\ndef run(cb):\n    return cb(1)\n\n@app.route('/')\ndef index():\n    return run(h)\n",
			},
		},
		{
			name: "importlib_literal_getattr",
			files: map[string]string{
				"plugins/__init__.py": "",
				"plugins/x.py":        "from app import danger\n\ndef run(v):\n    return danger(v)\n",
				"wire.py":             "import importlib\n\ndef load():\n    m = importlib.import_module('plugins.x')\n    return getattr(m, 'run')(1)\n",
				"app.py":              route,
			},
		},
		{
			name: "sys_modules_literal",
			files: map[string]string{
				"plugins/__init__.py": "",
				"plugins/x.py":        "from app import danger\n\ndef run(v):\n    return danger(v)\n",
				"wire.py":             "import sys\nimport plugins.x\n\ndef load(name):\n    return getattr(sys.modules['plugins.x'], name)(1)\n",
				"app.py":              route,
			},
		},
		{
			name: "module_dunder_dict",
			files: map[string]string{
				"pkg/__init__.py": "",
				"pkg/handlers.py": "from app import danger\n\ndef on_a(x):\n    return danger(x)\n",
				"pkg/wire.py":     "from . import handlers\n\ndef dispatch(name):\n    return handlers.__dict__[name](1)\n",
				"app.py":          route,
			},
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
			name: "defaulted callee edged from one site escapes from another",
			files: map[string]string{
				"a.py": "def g(x, y=1, z=2):\n    return x\n",
				"c.py": "from a import g\n\ndef one():\n    return g(1, 2)\n",
				"d.py": "from a import g\n\ndef two():\n    return g(1)\n",
			},
			escaped: []string{funcSCIP("a", nil, "g", 3)},
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
			name:    "unknown module attribute escapes the module",
			files:   map[string]string{"pkg/__init__.py": "", "pkg/conf.py": "LEVEL = 1\n\ndef helper(x):\n    return x\n", "pkg/wire.py": "from pkg import conf\nX = conf.missing\n"},
			escaped: []string{funcSCIP("pkg/conf", nil, "helper", 1)},
		},
		{
			name:    "re-exported alias read through the module",
			files:   map[string]string{"pkg/__init__.py": "from .impl import target as t2\n", "pkg/impl.py": "def target(x):\n    return x\n\ndef other(x):\n    return x\n", "n.py": "import pkg\nX = pkg.t2\n"},
			escaped: []string{funcSCIP("pkg/impl", nil, "target", 1)},
			kept:    []string{funcSCIP("pkg/impl", nil, "other", 1)},
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
		{
			name:   "alias of an alias",
			files:  map[string]string{"pkg/__init__.py": "from .impl import f as g\n", "pkg/impl.py": "def f(x):\n    return x\n", "pkg2/__init__.py": "from pkg import g as h\n", "app.py": "from pkg2 import h\n\ndef c():\n    return h(1)\n"},
			caller: funcSCIP("app", nil, "c", 0),
			callee: funcSCIP("pkg/impl", nil, "f", 1),
		},
		{
			name:   "alias of an alias through the module",
			files:  map[string]string{"pkg/__init__.py": "from .impl import f as g\n", "pkg/impl.py": "def f(x):\n    return x\n", "pkg2/__init__.py": "from pkg import g as h\n", "app.py": "import pkg2\n\ndef c():\n    return pkg2.h(1)\n"},
			caller: funcSCIP("app", nil, "c", 0),
			callee: funcSCIP("pkg/impl", nil, "f", 1),
		},
		{
			name:   "re-export under the same name",
			files:  map[string]string{"pkg/__init__.py": "from .impl import f as g\n", "pkg/impl.py": "def f(x):\n    return x\n", "pkg2/__init__.py": "from pkg import g\n", "app.py": "from pkg2 import g\n\ndef c():\n    return g(1)\n"},
			caller: funcSCIP("app", nil, "c", 0),
			callee: funcSCIP("pkg/impl", nil, "f", 1),
		},
		{
			name:   "if/else alternative to None",
			files:  map[string]string{"pkg/__init__.py": "", "pkg/impl.py": "def f(x):\n    return x\n", "pkg/a.py": "import os\n\nif os.environ.get('FAST'):\n    from .impl import f as g\nelse:\n    g = None\n\ndef go():\n    return g(1)\n"},
			caller: funcSCIP("pkg/a", nil, "go", 0),
			callee: funcSCIP("pkg/impl", nil, "f", 1),
		},
		{
			name:   "fallback inside a def",
			files:  map[string]string{"pkg/__init__.py": "", "pkg/impl.py": "def f(x):\n    return x\n", "pkg/a.py": "def go():\n    try:\n        from .impl import f as g\n    except ImportError:\n        g = None\n    return g(1)\n"},
			caller: funcSCIP("pkg/a", nil, "go", 0),
			callee: funcSCIP("pkg/impl", nil, "f", 1),
		},
		{
			name:   "import fallback to None",
			files:  map[string]string{"pkg/__init__.py": "", "pkg/impl.py": "def f(x):\n    return x\n", "pkg/a.py": "try:\n    from .impl import f as g\nexcept ImportError:\n    g = None\n\ndef go():\n    return g(1)\n"},
			caller: funcSCIP("pkg/a", nil, "go", 0),
			callee: funcSCIP("pkg/impl", nil, "f", 1),
		},
		{
			name:   "import fallback from a dependency",
			files:  map[string]string{"requirements.txt": "ujson==5.0\n", "pkg/__init__.py": "", "pkg/impl.py": "def f(x):\n    return x\n", "pkg/a.py": "try:\n    from ujson import loads as g\nexcept ImportError:\n    from .impl import f as g\n\ndef go():\n    return g(1)\n"},
			caller: funcSCIP("pkg/a", nil, "go", 0),
			callee: funcSCIP("pkg/impl", nil, "f", 1),
		},
		{
			name:   "class attribute of the same name",
			files:  map[string]string{"pkg/__init__.py": "", "pkg/impl.py": "def f(x):\n    return x\n", "pkg/a.py": "from .impl import f as run\n\nclass Job:\n    run = None\n\ndef go():\n    return run(1)\n"},
			caller: funcSCIP("pkg/a", nil, "go", 0),
			callee: funcSCIP("pkg/impl", nil, "f", 1),
		},
		{
			name:   "module-level lambda parameter of the same name",
			files:  map[string]string{"pkg/__init__.py": "", "pkg/impl.py": "def f(x):\n    return x\n", "pkg/a.py": "from .impl import f as g\n\nH = lambda g: g\n\ndef go():\n    return g(1)\n"},
			caller: funcSCIP("pkg/a", nil, "go", 0),
			callee: funcSCIP("pkg/impl", nil, "f", 1),
		},
		{
			name:   "module-level comprehension variable of the same name",
			files:  map[string]string{"pkg/__init__.py": "", "pkg/impl.py": "def f(x):\n    return x\n", "pkg/a.py": "from .impl import f as g\n\nM = {g: 1 for g in range(3)}\n\ndef go():\n    return g(1)\n"},
			caller: funcSCIP("pkg/a", nil, "go", 0),
			callee: funcSCIP("pkg/impl", nil, "f", 1),
		},
		{
			name:   "class attribute of the same name in a def",
			files:  map[string]string{"pkg/__init__.py": "", "pkg/impl.py": "def f(x):\n    return x\n", "pkg/a.py": "from .impl import f as run\n\ndef go():\n    class Job:\n        run = None\n    return run(1)\n"},
			caller: funcSCIP("pkg/a", nil, "go", 0),
			callee: funcSCIP("pkg/impl", nil, "f", 1),
		},
		{
			name:   "local of the same name in another def",
			files:  map[string]string{"pkg/__init__.py": "", "pkg/impl.py": "def f(x):\n    return x\n", "pkg/a.py": "from .impl import f as g\n\ndef other(xs):\n    for g in xs:\n        pass\n\ndef go():\n    return g(1)\n"},
			caller: funcSCIP("pkg/a", nil, "go", 0),
			callee: funcSCIP("pkg/impl", nil, "f", 1),
		},
		{
			name:   "import cycle ends",
			files:  map[string]string{"a/__init__.py": "from b import y as x\n", "b/__init__.py": "from a import x as y\n", "impl.py": "def x(v):\n    return v\n", "app.py": "from a import x\n\ndef c():\n    return x(1)\n"},
			caller: funcSCIP("app", nil, "c", 0),
			callee: funcSCIP("impl", nil, "x", 1),
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

// TestCallGraph_AliasNeedsTheCallersBinding: an import alias resolves a call only where
// the calling code holds the binding. A same-named call through a dependency, a parameter,
// local or dependency import that alone binds the name in the deciding scope, a parameter
// or a straight-line rebinding beside the import in that scope, a lambda
// parameter or comprehension variable in the same statement, and a file that never imports
// the alias all keep the edges the name alone gives; the alias they pass up still escapes.
func TestCallGraph_AliasNeedsTheCallersBinding(t *testing.T) {
	impl := funcSCIP("pkg/impl", nil, "f", 1)
	cases := []struct {
		name   string
		files  map[string]string
		caller string
		edged  string
		// escapes: the alias the site does not take is still a frame it may land on.
		escapes bool
	}{
		{
			name: "dependency receiver",
			files: map[string]string{
				"requirements.txt": "pyyaml==6.0\n",
				"pkg/a.py":         "from .impl import f as load\n\ndef use():\n    return load(1)\n",
				"b.py":             "import yaml\n\ndef parse(s):\n    return yaml.load(s)\n",
			},
			caller: funcSCIP("b", nil, "parse", 1),
		},
		{
			name:   "parameter in a file without the binding",
			files:  map[string]string{"pkg/a.py": "from .impl import f as run\n", "c.py": "def go(run):\n    return run(1)\n"},
			caller: funcSCIP("c", nil, "go", 1),
		},
		{
			name:    "parameter shadows the binding",
			files:   map[string]string{"pkg/a.py": "from .impl import f as run\n\ndef go(run):\n    return run(1)\n"},
			caller:  funcSCIP("pkg/a", nil, "go", 1),
			escapes: true,
		},
		{
			name:    "local shadows the binding",
			files:   map[string]string{"pkg/a.py": "from .impl import f as run\n\ndef go(make):\n    run = make()\n    return run(1)\n"},
			caller:  funcSCIP("pkg/a", nil, "go", 1),
			escapes: true,
		},
		{
			name:    "parameter shadows the module binding",
			files:   map[string]string{"pkg/a.py": "from .impl import f as g\n", "pkg/__init__.py": "from .impl import f as g\n", "e.py": "import pkg\n\ndef go(pkg):\n    return pkg.g(1)\n"},
			caller:  funcSCIP("e", nil, "go", 1),
			escapes: true,
		},
		{
			name:    "dependency import in the def shadows the module binding",
			files:   map[string]string{"requirements.txt": "pyyaml==6.0\n", "pkg/a.py": "from .impl import f as g\n\ndef go():\n    from yaml import load as g\n    return g(1)\n"},
			caller:  funcSCIP("pkg/a", nil, "go", 0),
			escapes: true,
		},
		{
			name:    "dependency module in the def shadows the module binding",
			files:   map[string]string{"requirements.txt": "pyyaml==6.0\n", "pkg/__init__.py": "from .impl import f as g\n", "e.py": "import pkg\n\ndef go():\n    import yaml as pkg\n    return pkg.g(1)\n"},
			caller:  funcSCIP("e", nil, "go", 0),
			escapes: true,
		},
		{
			name:    "straight-line instance rebinds the module binding",
			files:   map[string]string{"pkg/h.py": "class Handler:\n    def __call__(self, x):\n        return x\n", "pkg/a.py": "from .impl import f as handler\nfrom .h import Handler\nhandler = Handler()\n\ndef go():\n    return handler(1)\n"},
			caller:  funcSCIP("pkg/a", nil, "go", 0),
			escapes: true,
		},
		{
			name:    "straight-line dependency import rebinds the module binding",
			files:   map[string]string{"requirements.txt": "pyyaml==6.0\n", "pkg/a.py": "from .impl import f as g\nfrom yaml import load as g\n\ndef go():\n    return g(1)\n"},
			caller:  funcSCIP("pkg/a", nil, "go", 0),
			escapes: true,
		},
		{
			name:    "straight-line assignment in a def after a guarded import",
			files:   map[string]string{"pkg/a.py": "def go(make):\n    try:\n        from .impl import f as g\n    except ImportError:\n        pass\n    g = make()\n    return g(1)\n"},
			caller:  funcSCIP("pkg/a", nil, "go", 1),
			escapes: true,
		},
		{
			name:    "parameter beside an import in the same def",
			files:   map[string]string{"pkg/a.py": "def go(g):\n    if g is None:\n        from .impl import f as g\n    return g(1)\n"},
			caller:  funcSCIP("pkg/a", nil, "go", 1),
			escapes: true,
		},
		{
			name:    "module for target rebinds the module binding",
			files:   map[string]string{"pkg/a.py": "from .impl import f as g\nfor g in []:\n    pass\n\ndef go():\n    return g(1)\n"},
			caller:  funcSCIP("pkg/a", nil, "go", 0),
			escapes: true,
		},
		{
			name:    "lambda parameter in the same statement",
			files:   map[string]string{"pkg/a.py": "from .impl import f as g\n\nH = lambda g: g(1)\n"},
			caller:  moduleInitSCIP("pkg/a"),
			escapes: true,
		},
		{
			name:    "comprehension variable in the same statement",
			files:   map[string]string{"pkg/a.py": "from .impl import f as g\n\nR = [g(1) for g in FS]\n"},
			caller:  moduleInitSCIP("pkg/a"),
			escapes: true,
		},
		{
			name:    "comprehension variable as the chain head",
			files:   map[string]string{"pkg/__init__.py": "from .impl import f as g\n", "c.py": "import pkg as m\n\nR = [m.g(1) for m in MODS]\n"},
			caller:  moduleInitSCIP("c"),
			escapes: true,
		},
		{
			name:   "unique declaration elsewhere keeps its edge",
			files:  map[string]string{"pkg/a.py": "from .impl import f as g\n", "d.py": "def g(x):\n    return x\n\ndef go():\n    return g(1)\n"},
			caller: funcSCIP("d", nil, "go", 0),
			edged:  funcSCIP("d", nil, "g", 1),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"pkg/__init__.py": "", "pkg/impl.py": "def f(x):\n    return x\n"}
			for k, v := range tc.files {
				files[k] = v
			}
			res := mustCallGraph(t, files)
			if hasEdge(res.Edges, tc.caller, impl) {
				t.Fatalf("no binding in scope, so no edge %s -> %s; edges %v", tc.caller, impl, res.Edges)
			}
			if tc.edged != "" && !hasEdge(res.Edges, tc.caller, tc.edged) {
				t.Fatalf("missing edge %s -> %s; edges %v", tc.caller, tc.edged, res.Edges)
			}
			if tc.escapes && !symbolSet(res.Escaped)[impl] {
				t.Fatalf("%s must escape; escaped %v", impl, res.Escaped)
			}
		})
	}
}

// TestCallGraph_ModuleLookups: a module a literal dynamic import or sys.modules lookup names
// is a value, so all of its functions escape (an __import__ call hands over each package on
// the way down). Only literal forms are read, through whatever name the file binds sys,
// sys.modules, importlib or import_module to; any other reference to them declares
// dynamic_import. A lookup of the file's own module, a membership test, a store and a
// delete hand no module over.
func TestCallGraph_ModuleLookups(t *testing.T) {
	run := funcSCIP("plugins/x", nil, "run", 1)
	boot := funcSCIP("plugins", nil, "boot", 1)
	cases := []struct {
		name    string
		src     string
		escaped bool
		pkg     bool
		dynamic bool
	}{
		{"import_module literal", "import importlib\n\ndef load():\n    return importlib.import_module('plugins.x')\n", true, false, false},
		{"__import__ literal", "def load():\n    return __import__('plugins.x')\n", true, true, false},
		{"relative import_module literal", "import importlib\n\ndef load():\n    return importlib.import_module('.x', 'plugins')\n", true, false, false},
		{"relative import_module own package", "import importlib\n\ndef load():\n    return importlib.import_module('.x', package=__package__)\n", true, false, false},
		{"sys.modules literal", "import sys\n\ndef load():\n    return sys.modules['plugins.x']\n", true, false, false},
		{"sys.modules.get literal", "import sys\n\ndef load():\n    return sys.modules.get('plugins.x')\n", true, false, false},
		{"sys.modules own module", "import sys\n\ndef load():\n    return sys.modules[__name__]\n", false, false, false},
		{"from sys import modules literal", "from sys import modules\n\ndef load():\n    return modules['plugins.x']\n", true, false, false},
		{"import_module renamed literal", "from importlib import import_module as load\n\ndef go():\n    return load('plugins.x')\n", true, false, false},
		{"membership, store and delete", "import sys\n\ndef reg(name, mod):\n    if name in sys.modules:\n        del sys.modules[name]\n    sys.modules[name] = mod\n", false, false, false},
		{"import statements alone", "import sys\nimport importlib\nfrom importlib import import_module\nfrom sys import modules\n", false, false, false},
		{"sys.modules computed", "import sys\n\ndef load(name):\n    return sys.modules[name]\n", false, false, true},
		{"sys.modules values", "import sys\n\ndef go(n, x):\n    for m in list(sys.modules.values()):\n        fn = getattr(m, n, None)\n        if fn:\n            return fn(x)\n", false, false, true},
		{"from sys import modules computed", "from sys import modules\n\ndef go(mod, n, x):\n    return getattr(modules[mod], n)(x)\n", false, false, true},
		{"star import of sys", "from sys import *\n\ndef go(mod):\n    return modules[mod]\n", false, false, true},
		{"sys aliased", "import sys as s\n\ndef go(mod, n, x):\n    return getattr(s.modules[mod], n)(x)\n", false, false, true},
		{"importlib aliased", "import importlib as il\n\ndef go(mod, n, x):\n    return getattr(il.import_module(mod), n)(x)\n", false, false, true},
		{"import_module renamed", "from importlib import import_module as load\n\ndef go(mod, n, x):\n    return getattr(load(mod), n)(x)\n", false, false, true},
		{"import_module as a value", "import importlib\n\nLOAD = importlib.import_module\n", false, false, true},
		{"sys as a value", "import sys\n\nS = sys\n", false, false, true},
		{"sys dunder attribute", "import sys\n\nD = sys.__dict__\n", false, false, true},
		{"concatenated key", "import sys\n\ndef go(m):\n    return sys.modules['plugins.' + m]\n", false, false, true},
		{"f-string key", "import sys\n\ndef go(m):\n    return sys.modules[f'plugins.{m}']\n", false, false, true},
		{"relative import_module computed package", "import importlib\n\ndef go(p):\n    return importlib.import_module('.x', p)\n", false, false, true},
		{"__import__ with a level", "def go():\n    return __import__('x', globals(), None, [], 1)\n", false, false, true},
		{"__import__ with a level keyword", "def go():\n    return __import__('x', level=1)\n", false, false, true},
		{"relative __import__", "def go():\n    return __import__('.x')\n", false, false, true},
		{"relative import_module without a package", "import importlib\n\ndef go():\n    return importlib.import_module('.x')\n", false, false, true},
		{"sys.modules as a value", "import sys\n\nM = dict(sys.modules)\n", false, false, true},
		{"concatenated get key", "import sys\n\ndef go(m):\n    return sys.modules.get('plugins.' + m)\n", false, false, true},
		{"importlib alias as a value", "import importlib as il\n\nI = il\n", false, false, true},
		{"attribute named like an alias", "from importlib import import_module as load\n\nclass C:\n    def go(self, m):\n        return self.load(m)\n", false, false, false},
		{"keyword argument named sys", "import sys\n\ndef go(f):\n    return f(sys=1)\n", false, false, false},
		{"plain dunder attribute", "import sys\n\nOUT = sys.__stdout__\n", false, false, false},
		{"sys imported from another module", "from os import sys as s2\n\ndef go(mod, n, x):\n    return getattr(s2.modules[mod], n)(x)\n", false, false, true},
		{"modules imported from a re-exported sys", "from os.sys import modules as m\n\ndef go(mod):\n    return m[mod]\n", false, false, true},
		{"importlib imported from another module", "from pkg import importlib as il\n\ndef go(mod):\n    return il.import_module(mod)\n", false, false, true},
		{"sys through a module attribute", "import os\n\ndef go(mod, n, x):\n    return getattr(os.sys.modules[mod], n)(x)\n", false, false, true},
		{"iterating sys.modules keys", "import sys\nimport importlib\n\ndef go(n, x):\n    for k in sys.modules:\n        if k.startswith('plugins'):\n            return getattr(importlib.import_module(k), n)(x)\n", false, false, true},
		{"sys.modules get by a class module", "import sys\n\ndef owner(cls):\n    return sys.modules.get(cls.__module__)\n", false, false, true},
		{"iterating a copy of sys.modules", "import sys\n\ndef which(obj, name):\n    for module_name, module in sys.modules.copy().items():\n        if getattr(module, name, None) is obj:\n            return module_name\n", false, false, true},
		{"find_spec then exec_module", "import importlib.util\n\ndef go(p, n, x):\n    spec = importlib.util.find_spec(p)\n    m = importlib.util.module_from_spec(spec)\n    spec.loader.exec_module(m)\n    return getattr(m, n)(x)\n", false, false, true},
		{"__import__ package with a computed fromlist", "def go(n, x):\n    m = __import__('plugins', fromlist=[n])\n    return getattr(getattr(m, n), n)(x)\n", true, true, false},
		{"__import__ package with a positional fromlist", "def go(n, x):\n    m = __import__('plugins', globals(), locals(), [n])\n    return getattr(getattr(m, n), n)(x)\n", true, true, false},
		{"getattr of a lookup attribute", "import sys\n\ndef go(m):\n    return getattr(sys, 'modules')[m]\n", false, false, true},
		{"getattr of a plain attribute", "import sys\n\nP = getattr(sys, 'platform')\n", false, false, false},
		{"spec from a file location", "import importlib.util\n\ndef load(path):\n    spec = importlib.util.spec_from_file_location('plugin', path)\n    mod = importlib.util.module_from_spec(spec)\n    spec.loader.exec_module(mod)\n    return mod\n", false, false, true},
		{"module from spec renamed", "from importlib.util import module_from_spec as mfs\n\ndef load(spec):\n    return mfs(spec)\n", false, false, true},
		{"exec_module alone", "def load(spec, mod):\n    spec.loader.exec_module(mod)\n", false, false, true},
		{"source file loader", "from importlib.machinery import SourceFileLoader\n\ndef load(path):\n    return SourceFileLoader('plugin', path).load_module()\n", false, false, true},
		{"source file loader without load_module", "from importlib.machinery import SourceFileLoader\n\ndef loader(path):\n    return SourceFileLoader('plugin', path)\n", false, false, true},
		{"sourceless file loader renamed", "from importlib.machinery import SourcelessFileLoader as SL\n\ndef load(path):\n    return SL('plugin', path)\n", false, false, true},
		{"runpy run_path", "import runpy\n\ndef go(path):\n    return runpy.run_path(path)\n", false, false, true},
		{"runpy run_module renamed", "from runpy import run_module as rm\n\ndef go(name):\n    return rm(name)\n", false, false, true},
		{"imp load_source", "import imp\n\ndef go(path):\n    return imp.load_source('plugin', path)\n", false, false, true},
		{"imp load_module renamed", "from imp import load_module as lm\n\ndef go(*a):\n    return lm(*a)\n", false, false, true},
		{"pkgutil iter_modules", "import pkgutil\n\ndef go(path):\n    return [m.name for m in pkgutil.iter_modules(path)]\n", false, false, true},
		{"pkgutil walk_packages renamed", "from pkgutil import walk_packages as wp\n\ndef go(path):\n    return list(wp(path))\n", false, false, true},
		{"zipimport", "import zipimport\n\ndef go(path):\n    return zipimport.zipimporter(path).load_module('plugin')\n", false, false, true},
		{"zipimporter renamed", "from zipimport import zipimporter as Z\n\ndef go(path):\n    return Z(path)\n", false, false, true},
		{"module loader", "def go():\n    return __loader__.get_data('x')\n", false, false, true},
		{"loader passed as a value", "from runpy import run_path\n\nRUN = run_path\n", false, false, true},
		{"spec from a loader", "import importlib.util\n\ndef load(name, loader):\n    return importlib.util.spec_from_loader(name, loader)\n", false, false, true},
		{"imp load_compiled", "import imp\n\ndef go(path):\n    return imp.load_compiled('plugin', path)\n", false, false, true},
		{"extension file loader", "from importlib.machinery import ExtensionFileLoader\n\ndef load(path):\n    return ExtensionFileLoader('plugin', path)\n", false, false, true},
		{"zipimport module as a value", "import zipimport\n\nZI = zipimport\n", false, false, true},
		{"loader imports alone", "import runpy\nimport zipimport\nfrom importlib.util import spec_from_file_location\nfrom importlib.machinery import SourceFileLoader as SFL\n", false, false, false},
		{"def named like a loader", "def run_path(p):\n    return p\n", false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := mustCallGraph(t, map[string]string{
				"plugins/__init__.py": "def boot(v):\n    return v\n",
				"plugins/x.py":        "def run(v):\n    return v\n",
				"plugins/wire.py":     tc.src,
			})
			if got := symbolSet(res.Escaped)[run]; got != tc.escaped {
				t.Fatalf("%s escaped = %v, want %v", run, got, tc.escaped)
			}
			if got := symbolSet(res.Escaped)[boot]; got != tc.pkg {
				t.Fatalf("%s escaped = %v, want %v", boot, got, tc.pkg)
			}
			if got := hasReason(res.Partiality, plugin.PartialReasonDynamicImportSpecifier); got != tc.dynamic {
				t.Fatalf("dynamic_import = %v, want %v; reasons %v", got, tc.dynamic, res.Partiality.Reasons)
			}
		})
	}
}

// TestCallGraph_HeaderAndClassBodySitesListed: calls in a parameter default, a class base and
// a one-line class body run in the enclosing frame and are listed there.
func TestCallGraph_HeaderAndClassBodySitesListed(t *testing.T) {
	init := sym(moduleInitSCIP("m"))
	cases := []struct {
		name   string
		src    string
		callee string
		arity  int
	}{
		{"parameter default", "def f(x=g(1)):\n    return x\n", "g", 1},
		{"class base", "class C(make_base()):\n    pass\n", "make_base", 0},
		{"one-line class body", "class C: x = g(1)\n", "g", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := mustCallGraph(t, map[string]string{"m.py": tc.src})
			if !slices.ContainsFunc(res.Unresolved, func(u plugin.UnresolvedCall) bool {
				return u.Caller == init && u.Callee == tc.callee && u.Arity == tc.arity
			}) {
				t.Fatalf("missing Unresolved %s/%d on the module frame; got %+v", tc.callee, tc.arity, res.Unresolved)
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
		{"t-string without a call", "def f(x):\n    return t\"{x}\"\n", false},
		{"t-string with a call", "def f(x):\n    return t\"{g(x)}\"\n", true},
		{"raw t-string with a call", "def f(x):\n    return rt\"{g(x)}\"\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := mustCallGraph(t, map[string]string{"m.py": tc.src})
			if got := hasReason(res.Partiality, plugin.PartialReasonUnlistedSites); got != tc.want {
				t.Fatalf("unlisted_sites = %v, want %v; reasons %v", got, tc.want, res.Partiality.Reasons)
			}
		})
	}
	t.Run("unread source", func(t *testing.T) {
		dir := writeTree(t, map[string]string{"m.py": "def f(x):\n    return x\n"})
		if err := os.Symlink("missing.py", filepath.Join(dir, "gone.py")); err != nil {
			t.Fatal(err)
		}
		res, err := CallGraph(context.Background(), plugin.CallGraphRequest{BuildDir: dir})
		if err != nil {
			t.Fatalf("CallGraph: %v", err)
		}
		if !hasReason(res.Partiality, plugin.PartialReasonUnlistedSites) {
			t.Fatalf("an unread source's sites are not listed, so unlisted_sites must be set; reasons %v", res.Partiality.Reasons)
		}
	})
}
