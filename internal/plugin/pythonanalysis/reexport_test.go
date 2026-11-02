package pythonanalysis

import (
	"maps"
	"testing"
)

// TestCallGraph_ReexportRebinding: a site that imports a name through a module re-exporting
// it keeps its alias edge, and is listed when that module may bind the name another way: an
// assignment, a star import that may bind it, a store through a module object, or a package
// attribute stored with another module. Where the module on the path itself binds the name
// another way, the site has no edge; it is listed, and both the re-exported function and the
// binding that may replace it escape. A plain re-export, a None fallback, a star import that
// cannot bind the name, or a store of another name leaves the site complete.
func TestCallGraph_ReexportRebinding(t *testing.T) {
	impl := funcSCIP("pkg/impl", nil, "f", 1)
	goC := funcSCIP("c", nil, "go", 0)
	vuln := funcSCIP("pkg/v", nil, "vuln", 1)
	const reexport = "from .impl import f as g\n"
	const bare = "from pkg.a import g\n\ndef go():\n    return g(1)\n"
	const fromPkg = "from pkg import a\n\ndef go():\n    return a.g(1)\n"
	sub := map[string]string{
		"pkg/sub/__init__.py": "from . import a\nfrom . import x as a\n",
		"pkg/sub/a.py":        "from ..impl import f as g\n",
		"pkg/sub/x.py":        "from ..v import vuln as g\n",
	}
	cases := []struct {
		name string
		// a is pkg/a.py, c is c.py (the site); extra adds files.
		a, c   string
		extra  map[string]string
		callee string
		// noInit makes pkg a namespace package.
		noInit bool
		// defined moves the edge's target from pkg/impl.f to a def of g in pkg/x.py.
		defined bool
		listed  bool
		// edgeless: a module on the path binds the name by something the walk cannot name,
		// so the site gets no edge. It must still be listed with no Targets and the target
		// must escape, which keeps it reachable from the site.
		edgeless bool
		// vulnWins: the binding that holds the name at runtime is pkg/v.vuln, which must
		// escape too, or the function the site really calls is unreachable.
		vulnWins bool
	}{
		{name: "assigned after the re-export", a: reexport + "from .v import vuln\ng = vuln\n", c: bare, callee: "g", listed: true, edgeless: true, vulnWins: true},
		{name: "star import that binds the name", a: reexport + "from .x import *\n", c: bare, callee: "g", listed: true, edgeless: true, vulnWins: true,
			extra: map[string]string{"pkg/x.py": "from .v import vuln as g\n"}},
		{name: "star import of a dependency", a: reexport + "from os.path import *\n", c: bare, callee: "g", listed: true},
		{name: "stored through the module object", a: reexport, c: bare, callee: "g", listed: true,
			extra: map[string]string{"b.py": "import pkg.a\nfrom pkg.v import vuln\npkg.a.g = vuln\n"}},
		{name: "re-exported twice, assigned at the end", a: "from .b import g\n", c: bare, callee: "g", listed: true, edgeless: true, vulnWins: true,
			extra: map[string]string{"pkg/b.py": reexport + "from .v import vuln\ng = vuln\n"}},
		{name: "qualified through a from-imported module that assigns", a: reexport + "from .v import vuln\ng = vuln\n", c: fromPkg, callee: "a.g", listed: true, edgeless: true, vulnWins: true},
		{name: "from-imported package attribute stored with another module", a: reexport, c: fromPkg, callee: "a.g", listed: true,
			extra: map[string]string{"b.py": "import pkg\nimport pkg.x\npkg.a = pkg.x\n", "pkg/x.py": "from .v import vuln as g\n"}},
		{name: "aliased import of a package attribute stored with another module", a: reexport, c: "import pkg.a as m\n\ndef go():\n    return m.g(1)\n", callee: "m.g", listed: true,
			extra: map[string]string{"b.py": "import pkg\nimport pkg.x\npkg.a = pkg.x\n", "pkg/x.py": "from .v import vuln as g\n"}},

		{name: "star import of a module that defines and assigns the name", a: "from .x import *\n", c: bare, callee: "g", listed: true, edgeless: true, vulnWins: true, defined: true,
			extra: map[string]string{"pkg/x.py": "def g(x):\n    return x\n\nfrom .v import vuln\ng = vuln\n"}},
		{name: "qualified through a package that binds the module twice", c: "import pkg.sub.a\n\ndef go():\n    return pkg.sub.a.g(1)\n", callee: "pkg.sub.a.g", listed: true, edgeless: true, vulnWins: true, extra: sub},
		{name: "qualified through a from-imported package that binds the module twice", c: "from pkg import sub\nimport pkg.sub.a\n\ndef go():\n    return sub.a.g(1)\n", callee: "sub.a.g", listed: true, edgeless: true, vulnWins: true, extra: sub},
		{name: "qualified through a package whose star import binds the module again", c: "import pkg.sub.a\n\ndef go():\n    return pkg.sub.a.g(1)\n", callee: "pkg.sub.a.g", listed: true, edgeless: true, vulnWins: true,
			extra: map[string]string{"pkg/sub/__init__.py": "from . import a\nfrom .y import *\n", "pkg/sub/a.py": "from ..impl import f as g\n", "pkg/sub/y.py": "from . import x as a\n", "pkg/sub/x.py": "from ..v import vuln as g\n"}},
		{name: "qualified through a package that binds the module to another module's attribute", c: "import pkg.sub.a\n\ndef go():\n    return pkg.sub.a.g(1)\n", callee: "pkg.sub.a.g", listed: true, edgeless: true, vulnWins: true,
			extra: map[string]string{"pkg/sub/__init__.py": "from . import a\nfrom .x import mod as a\n", "pkg/sub/a.py": "from ..impl import f as g\n", "pkg/sub/x.py": "from .. import w as mod\n", "pkg/w.py": "from .v import vuln as g\n"}},
		{name: "qualified through a package that import-as binds the module through a rebound ancestor", c: "import pkg.sub.a\n\ndef go():\n    return pkg.sub.a.g(1)\n", callee: "pkg.sub.a.g", listed: true, edgeless: true, vulnWins: true,
			extra: map[string]string{"pkg/__init__.py": "from . import q\nfrom . import alt as q\n", "pkg/sub/__init__.py": "from . import a\nimport pkg.q.x as a\n", "pkg/sub/a.py": "from ..impl import f as g\n",
				"pkg/q/__init__.py": "", "pkg/q/x.py": "from ..impl import f as g\n", "pkg/alt/__init__.py": "from . import x\n", "pkg/alt/x.py": "from ..v import vuln as g\n"}},
		{name: "names computed in the module", a: reexport + "from .v import vuln\nglobals().update(g=vuln)\n", c: bare, callee: "g", listed: true},
		{name: "class defined after the re-export", a: reexport + "class g:\n    pass\n", c: bare, callee: "g", listed: true, edgeless: true},
		{name: "namespace stored through from another module", a: reexport, c: bare, callee: "g", listed: true,
			extra: map[string]string{"b.py": "import pkg.a\nfrom pkg.v import vuln\npkg.a.__dict__['g'] = vuln\n"}},
		{name: "dependency import of the name", a: reexport + "try:\n    from fastlib import g\nexcept ImportError:\n    pass\n", c: bare, callee: "g", listed: true, edgeless: true},
		{name: "nested star import that binds the name", a: reexport + "from .x import *\n", c: bare, callee: "g", listed: true, edgeless: true, vulnWins: true,
			extra: map[string]string{"pkg/x.py": "from .y import *\n", "pkg/y.py": "from .v import vuln as g\n"}},
		{name: "star import of an unparsed first-party module", a: reexport + "from .native import *\n", c: bare, callee: "g", listed: true},
		{name: "star import of a module that computes names", a: reexport + "from .x import *\n", c: bare, callee: "g", listed: true,
			extra: map[string]string{"pkg/x.py": "from .v import vuln\nglobals().update(g=vuln)\n"}},
		{name: "star import of a module stored into whole", a: reexport + "from .x import *\n", c: bare, callee: "g", listed: true,
			extra: map[string]string{"pkg/x.py": "def h(x):\n    return x\n", "b.py": "import pkg.x\nfrom pkg.v import vuln\npkg.x.__dict__.update(g=vuln)\n"}},
		{name: "star import of a module the name is stored into", a: reexport + "from .x import *\n", c: bare, callee: "g", listed: true,
			extra: map[string]string{"pkg/x.py": "def h(x):\n    return x\n", "b.py": "import pkg.x\nfrom pkg.v import vuln\npkg.x.g = vuln\n"}},
		{name: "namespace package attribute stored with another module", a: reexport, c: fromPkg, callee: "a.g", listed: true, noInit: true,
			extra: map[string]string{"b.py": "import pkg\nimport pkg.x\npkg.a = pkg.x\n", "pkg/x.py": "from .v import vuln as g\n"}},

		{name: "plain re-export", a: reexport, c: bare, callee: "g"},
		{name: "re-export with a None fallback", a: "try:\n    from .impl import f as g\nexcept ImportError:\n    g = None\n", c: bare, callee: "g"},
		{name: "star import that cannot bind the name", a: reexport + "from .x import *\n", c: bare, callee: "g",
			extra: map[string]string{"pkg/x.py": "def h(x):\n    return x\n"}},
		{name: "another name stored through the module object", a: reexport, c: bare, callee: "g",
			extra: map[string]string{"b.py": "import pkg.a\nfrom pkg.v import vuln\npkg.a.h = vuln\n"}},
		{name: "qualified through a from-imported module", a: reexport, c: fromPkg, callee: "a.g"},
		{name: "star import of a module that defines the name", a: "from .x import *\n", c: bare, callee: "g", defined: true,
			extra: map[string]string{"pkg/x.py": "def g(x):\n    return x\n"}},
		{name: "qualified through a package that binds the module once", c: "import pkg.sub.a\n\ndef go():\n    return pkg.sub.a.g(1)\n", callee: "pkg.sub.a.g", extra: map[string]string{"pkg/sub/__init__.py": "from . import a\n", "pkg/sub/a.py": "from ..impl import f as g\n"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{
				"pkg/__init__.py": "",
				"pkg/impl.py":     "def f(x):\n    return x\n",
				"pkg/v.py":        "def vuln(x):\n    return x\n",
				"pkg/a.py":        tc.a,
				"c.py":            tc.c,
			}
			maps.Copy(files, tc.extra)
			if tc.noInit {
				delete(files, "pkg/__init__.py")
			}
			target := impl
			if tc.defined {
				target = funcSCIP("pkg/x", nil, "g", 1)
			}
			res := mustCallGraph(t, files)
			if tc.edgeless {
				if !symbolSet(res.Escaped)[target] {
					t.Fatalf("%s must escape; escaped %v", target, res.Escaped)
				}
				if tc.vulnWins && !symbolSet(res.Escaped)[vuln] {
					t.Fatalf("%s must escape; escaped %v", vuln, res.Escaped)
				}
			} else if !hasEdge(res.Edges, goC, target) {
				t.Fatalf("missing alias edge %s -> %s; edges %v", goC, target, res.Edges)
			}
			listed := false
			for _, u := range res.Unresolved {
				if u.Caller.SCIP == goC && u.Callee == tc.callee && len(u.Targets) == 0 {
					listed = true
				}
			}
			if listed != tc.listed {
				t.Fatalf("%s(1) listed = %v, want %v; unresolved %v", tc.callee, listed, tc.listed, res.Unresolved)
			}
		})
	}
}

// TestCallGraph_ReexportRebindingSrcLayout: in a src/ layout, a package attribute stored
// through the absolute spelling of a namespace package lists a site that reads it through
// the relative spelling.
func TestCallGraph_ReexportRebindingSrcLayout(t *testing.T) {
	res := mustCallGraph(t, map[string]string{
		"src/pkg/impl.py": "def f(x):\n    return x\n",
		"src/pkg/v.py":    "def vuln(x):\n    return x\n",
		"src/pkg/x.py":    "from .v import vuln as g\n",
		"src/pkg/a.py":    "from .impl import f as g\n",
		"src/b.py":        "import pkg\nimport pkg.x\npkg.a = pkg.x\n",
		"src/pkg/c.py":    "from . import a\n\ndef go():\n    return a.g(1)\n",
	})
	goC, impl := funcSCIP("src/pkg/c", nil, "go", 0), funcSCIP("src/pkg/impl", nil, "f", 1)
	if !hasEdge(res.Edges, goC, impl) {
		t.Fatalf("missing alias edge %s -> %s; edges %v", goC, impl, res.Edges)
	}
	for _, u := range res.Unresolved {
		if u.Caller.SCIP == goC && u.Callee == "a.g" && len(u.Targets) == 0 {
			return
		}
	}
	t.Fatalf("a.g(1) not listed; unresolved %v", res.Unresolved)
}

// TestCallGraph_SubmoduleBoundToItsOwnAttribute: a package that binds its submodule's name to
// that submodule's attribute of the same name (from .config import config) is a common shape;
// a site through the submodule completes, and still reaches the submodule's function.
func TestCallGraph_SubmoduleBoundToItsOwnAttribute(t *testing.T) {
	for _, c := range []string{
		"from pkg.config import load\n\ndef go():\n    return load(1)\n",
		"import pkg.config\n\ndef go():\n    return pkg.config.load(1)\n",
	} {
		res := mustCallGraph(t, map[string]string{
			"pkg/__init__.py": "from .config import config\n",
			"pkg/config.py":   "config = {}\n\ndef load(x):\n    return x\n",
			"c.py":            c,
		})
		goC, load := funcSCIP("c", nil, "go", 0), funcSCIP("pkg/config", nil, "load", 1)
		if !hasEdge(res.Edges, goC, load) && !symbolSet(res.Escaped)[load] {
			t.Fatalf("%q: %s unreachable; edges %v, escaped %v", c, load, res.Edges, res.Escaped)
		}
	}
}

// TestCallGraph_ImportAsBindingThroughItself: a package that binds a submodule's name by a
// dotted import-as through that same name (import pkg.c.c as c) rewrites a path through it
// once, as the statement runs once; a site through the submodule completes and still reaches
// the function.
func TestCallGraph_ImportAsBindingThroughItself(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
	}{
		{"self", map[string]string{"pkg/__init__.py": "import pkg.c.c as c\n", "pkg/c/__init__.py": "from . import c\n"}},
		{"mutual", map[string]string{"pkg/__init__.py": "import pkg.d.c as c\nimport pkg.c.d as d\n", "pkg/c/__init__.py": "from . import c, d\n",
			"pkg/c/d.py": "", "pkg/d/__init__.py": "from . import c\n", "pkg/d/c.py": "def load(x):\n    return x\n"}},
	} {
		files := map[string]string{"pkg/c/c.py": "def load(x):\n    return x\n", "c.py": "import pkg.c.c\n\ndef go():\n    return pkg.c.c.load(1)\n"}
		maps.Copy(files, tc.files)
		res := mustCallGraph(t, files)
		goC, load := funcSCIP("c", nil, "go", 0), funcSCIP("pkg/c/c", nil, "load", 1)
		if !hasEdge(res.Edges, goC, load) && !symbolSet(res.Escaped)[load] {
			t.Fatalf("%s: %s unreachable; edges %v, escaped %v", tc.name, load, res.Edges, res.Escaped)
		}
	}
}

// An import-as chain one dot deep is its own top attribute: it must not stand in for the
// restart a deeper chain under it needs, wherever else in the program it is imported.
func TestCallGraph_ImportAsChainUnderOneDotChain(t *testing.T) {
	s4 := func(outer string) map[string]string {
		return map[string]string{
			"pkg/__init__.py": "from . import r\nfrom . import alt2 as r\nfrom . import sub\n" + outer + "\n", "pkg/sub/__init__.py": "", "pkg/sub/a.py": "from ..impl import f as g\n",
			"pkg/alt/__init__.py": "import pkg.r.y as a\n", "pkg/r/__init__.py": "", "pkg/r/y.py": "from ..impl import f as g\n",
			"pkg/alt2/__init__.py": "from . import y\n", "pkg/alt2/y.py": "from ..v import vuln as g\n",
			"c.py": "import pkg.sub.a\n\ndef go():\n    return pkg.sub.a.g(1)\n"}
	}
	s4n := s4("from . import alt as sub")
	s4n["tools/__init__.py"] = ""
	s4n["tools/other.py"] = "import pkg.alt as zz\n"
	for _, tc := range []struct {
		name  string
		files map[string]string
	}{
		{"site prefix bound by a one-dot import-as", s4("import pkg.alt as sub")},
		{"site prefix bound by from-import, one-dot import-as elsewhere", s4n},
		{"import-as leaf through a rebound prefix", map[string]string{
			"pkg/__init__.py": "from . import r\nfrom . import alt2 as r\n", "pkg/r/__init__.py": "", "pkg/r/y.py": "from ..impl import f\n",
			"pkg/alt2/__init__.py": "from ..v import vuln as y\n", "pkg/m.py": "import pkg.r.y as g\n",
			"c.py": "import pkg.m\n\ndef go():\n    return pkg.m.g(1)\n"}},
		{"chained visit before the unchained one", map[string]string{
			"pkg/__init__.py":     "from . import r\nfrom . import alt2 as r\nfrom . import sub\nfrom . import w\nimport pkg.w.v as sub\nfrom . import alt as sub\n",
			"pkg/sub/__init__.py": "", "pkg/sub/a.py": "from ..impl import f as g\n", "pkg/w/__init__.py": "from .. import alt as v\n", "pkg/w/v.py": "",
			"pkg/alt/__init__.py": "import pkg.r.y as a\n", "pkg/r/__init__.py": "", "pkg/r/y.py": "from ..impl import f as g\n",
			"pkg/alt2/__init__.py": "from . import y\n", "pkg/alt2/y.py": "from ..v import vuln as g\n",
			"c.py": "import pkg.sub.a\n\ndef go():\n    return pkg.sub.a.g(1)\n"}},
		{"one-dot import-as leaf over a deeper chain", map[string]string{
			"pkg/__init__.py": "from . import r\nfrom . import alt2 as r\nfrom . import f\nimport pkg.r.y as f\n", "pkg/f.py": "", "pkg/r/__init__.py": "", "pkg/r/y.py": "from ..impl import f\n",
			"pkg/alt2/__init__.py": "from ..v import vuln as y\n", "pkg/m.py": "import pkg.f as g\n", "c.py": "import pkg.m\n\ndef go():\n    return pkg.m.g(1)\n"}},
	} {
		files := map[string]string{"pkg/impl.py": "def f(x):\n    return x\n", "pkg/v.py": "def vuln(x):\n    return x\n"}
		maps.Copy(files, tc.files)
		res := mustCallGraph(t, files)
		goC, vuln := funcSCIP("c", nil, "go", 0), funcSCIP("pkg/v", nil, "vuln", 1)
		if !hasEdge(res.Edges, goC, vuln) && !symbolSet(res.Escaped)[vuln] {
			t.Errorf("%s: %s unreachable; edges %v, escaped %v", tc.name, vuln, res.Edges, res.Escaped)
		}
	}
}
