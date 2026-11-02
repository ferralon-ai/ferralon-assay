package pythonanalysis

import (
	"maps"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
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
		{name: "nested star import of a dependency", a: reexport + "from .x import *\n", c: bare, callee: "g", listed: true,
			extra: map[string]string{"pkg/x.py": "from .y import *\n", "pkg/y.py": "from os.path import *\n"}},
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

// A site through a module attribute that holds another module (pkg.sub.a.g.h, where a.py
// binds g to pkg.alt.y) reaches what that module binds h to, a re-export as well as a def.
func TestCallGraph_ModuleAttributeHoldingAModule(t *testing.T) {
	site := "import pkg.sub.a\n\ndef go():\n    return pkg.sub.a.g.h(1)\n"
	subRebound := map[string]string{"pkg/sub/__init__.py": "from . import a\nfrom pkg import x as a\n", "pkg/alt/__init__.py": "from . import y\n"}
	with := func(base map[string]string, kv ...string) map[string]string {
		files := maps.Clone(base)
		for i := 0; i < len(kv); i += 2 {
			files[kv[i]] = kv[i+1]
		}
		return files
	}
	for _, tc := range []struct {
		name  string
		files map[string]string
	}{
		{"attribute bound by from-import", map[string]string{"pkg/sub/a.py": "from pkg.alt import y as g\n", "pkg/alt/__init__.py": "from . import y\n", "c.py": site}},
		{"rebound submodule, attribute bound by import-as", with(subRebound, "pkg/x.py", "import pkg.alt.y as g\n", "c.py", site)},
		{"rebound submodule, attribute bound by from-import", with(subRebound, "pkg/x.py", "from pkg.alt import y as g\n", "c.py", site)},
		{"attribute bound by import-as through a rebound package", map[string]string{
			"pkg/__init__.py": "from . import r\nfrom . import alt as r\n", "pkg/x.py": "import pkg.r.y as g\n",
			"pkg/r/__init__.py": "", "pkg/r/y.py": "from ..impl import f as h\n", "pkg/alt/__init__.py": "from . import y\n",
			"c.py": "import pkg.x\n\ndef go():\n    return pkg.x.g.h(1)\n"}},
	} {
		for _, reexport := range []bool{true, false} {
			files := map[string]string{"pkg/impl.py": "def f(x):\n    return x\n", "pkg/v.py": "def vuln(x):\n    return x\n", "pkg/sub/a.py": "from ..impl import f as g\n"}
			maps.Copy(files, tc.files)
			want := funcSCIP("pkg/v", nil, "vuln", 1)
			files["pkg/alt/y.py"] = "from ..v import vuln as h\n"
			if !reexport {
				want = funcSCIP("pkg/alt/y", nil, "h", 1)
				files["pkg/alt/y.py"] = "def h(x):\n    return x\n"
			}
			res := mustCallGraph(t, files)
			goC := funcSCIP("c", nil, "go", 0)
			if !hasEdge(res.Edges, goC, want) && !symbolSet(res.Escaped)[want] {
				t.Errorf("%s (re-export %v): %s unreachable; edges %v, escaped %v", tc.name, reexport, want, res.Edges, res.Escaped)
			}
		}
	}
	// A site whose function does not hold the binding gets no edge; the binding made in
	// another scope still escapes the re-export's source.
	files := map[string]string{"pkg/impl.py": "def f(x):\n    return x\n", "pkg/v.py": "def vuln(x):\n    return x\n", "pkg/sub/a.py": "from ..impl import f as g\n",
		"pkg/alt/__init__.py": "from . import y\n", "pkg/alt/y.py": "from ..v import vuln as h\n",
		"c.py": "def setup():\n    global pkg\n    import pkg.sub.a\n\ndef go():\n    return pkg.sub.a.g.h(1)\n"}
	maps.Copy(files, with(subRebound, "pkg/x.py", "from pkg.alt import y as g\n"))
	res := mustCallGraph(t, files)
	if vuln := funcSCIP("pkg/v", nil, "vuln", 1); !symbolSet(res.Escaped)[vuln] {
		t.Errorf("binding in another scope: %s not escaped; escaped %v", vuln, res.Escaped)
	}
	// A star import in the caller leaves the head undecided, so the edge comes from the
	// site's own leaves: the re-export's source, not only an escape.
	files = map[string]string{"pkg/impl.py": "def f(x):\n    return x\n", "pkg/v.py": "def vuln(x):\n    return x\n", "pkg/util.py": "X = 1\n",
		"pkg/sub/a.py": "from pkg.alt import y as g\n", "pkg/alt/__init__.py": "from . import y\n", "pkg/alt/y.py": "from ..v import vuln as h\n",
		"c.py": "from pkg.util import *\nimport pkg.sub.a\n\ndef go():\n    return pkg.sub.a.g.h(1)\n"}
	res = mustCallGraph(t, files)
	if goC, vuln := funcSCIP("c", nil, "go", 0), funcSCIP("pkg/v", nil, "vuln", 1); !hasEdge(res.Edges, goC, vuln) {
		t.Errorf("head undecided: no edge to %s; edges %v", vuln, res.Edges)
	}
}

// TestCallGraph_HeadBoundByCallersStarImport: a chain whose head only the caller's star import binds (from pkg.m import *, then g.h(1),
// where pkg/m.py binds g to pkg.alt.y) reaches what that module binds h to, a re-export as
// well as a def.
func TestCallGraph_HeadBoundByCallersStarImport(t *testing.T) {
	star := func(expr string) string {
		return "from pkg.m import *\n\ndef go():\n    return " + expr + "\n"
	}
	for _, tc := range []struct {
		name  string
		files map[string]string
	}{
		{"attribute bound by from-import", map[string]string{"pkg/m.py": "from pkg.alt import y as g\n", "c.py": star("g.h(1)")}},
		{"module bound by from-import", map[string]string{"pkg/m.py": "from pkg.alt import y\n", "c.py": star("y.h(1)")}},
		{"attribute bound by import-as", map[string]string{"pkg/m.py": "import pkg.alt.y as g\n", "c.py": star("g.h(1)")}},
		{"top package bound by import", map[string]string{"pkg/m.py": "import pkg.alt.y\n", "c.py": star("pkg.alt.y.h(1)")}},
		{"package attribute through a middle", map[string]string{"pkg/m.py": "from pkg import alt as g\n", "c.py": star("g.y.h(1)")}},
		{"through the module's own star import", map[string]string{"pkg/m.py": "from pkg.n import *\n", "pkg/n.py": "from pkg.alt import y as g\n", "c.py": star("g.h(1)")}},
		{"star import after one two routes reach", map[string]string{"pkg/a.py": "from pkg.b import *\n", "pkg/b.py": "X = 1\n", "pkg/m.py": "from pkg.alt import y as g\n",
			"c.py": "from pkg.a import *\nfrom pkg.b import *\nfrom pkg.m import *\n\ndef go():\n    return g.h(1)\n"}},
		{"star imports in a cycle", map[string]string{"pkg/m.py": "from pkg.n import *\nfrom pkg.alt import y as g\n", "pkg/n.py": "from pkg.m import *\n", "c.py": star("g.h(1)")}},
		{"star import of a package", map[string]string{"pkg/m/__init__.py": "from pkg.alt import y as g\n", "c.py": star("g.h(1)")}},
		{"loaded submodule of a package", map[string]string{"pkg/m/__init__.py": "", "pkg/m/a.py": "from pkg.alt import y as g\n",
			"c.py": "import pkg.m.a\n" + star("a.g.h(1)")}},
		{"loaded submodule through the module's own star import", map[string]string{"pkg/m.py": "from pkg.alt import *\n", "pkg/alt/__init__.py": "",
			"c.py": "import pkg.alt.y\n" + star("y.h(1)")}},
		{"site in a nested def", map[string]string{"pkg/m.py": "from pkg.alt import y as g\n",
			"c.py": "from pkg.m import *\n\ndef go():\n    def inner():\n        return g.h(1)\n    return inner()\n"}},
		{"statement that binds the name in a comprehension too", map[string]string{"pkg/m.py": "from pkg.alt import y as g\n",
			"c.py": star("g.h(1) or [g for g in ()]")}},
	} {
		for _, reexport := range []bool{true, false} {
			files := map[string]string{"pkg/__init__.py": "", "pkg/v.py": "def vuln(x):\n    return x\n", "pkg/alt/__init__.py": "from . import y\n",
				"pkg/other.py": "def h(x):\n    return x\n"}
			maps.Copy(files, tc.files)
			want := funcSCIP("pkg/v", nil, "vuln", 1)
			files["pkg/alt/y.py"] = "from ..v import vuln as h\n"
			if !reexport {
				want = funcSCIP("pkg/alt/y", nil, "h", 1)
				files["pkg/alt/y.py"] = "def h(x):\n    return x\n"
			}
			res := mustCallGraph(t, files)
			goC := funcSCIP("c", nil, "go", 0)
			if !hasEdge(res.Edges, goC, want) && !symbolSet(res.Escaped)[want] {
				t.Errorf("%s (re-export %v): %s unreachable; edges %v, escaped %v", tc.name, reexport, want, res.Edges, res.Escaped)
			}
		}
	}
	files := map[string]string{"pkg/__init__.py": "", "pkg/v.py": "def vuln(x):\n    return x\n", "pkg/alt/__init__.py": "from . import y\n",
		"pkg/alt/y.py": "from ..v import vuln as h\n", "pkg/m.py": "from pkg.alt import y as g\n", "c.py": star("g.h(1)")}
	goC, vuln := funcSCIP("c", nil, "go", 0), funcSCIP("pkg/v", nil, "vuln", 1)
	// The star import leaves the head undecided, so the edge comes from the site's leaves.
	if res := mustCallGraph(t, files); !hasEdge(res.Edges, goC, vuln) {
		t.Errorf("head bound by the star import: no edge to %s; edges %v", vuln, res.Edges)
	}
	// A parameter decides the head, so the star import's binding draws no edge.
	files["c.py"] = "from pkg.m import *\n\ndef go(g):\n    return g.h(1)\n"
	if res := mustCallGraph(t, files); hasEdge(res.Edges, funcSCIP("c", nil, "go", 1), vuln) {
		t.Errorf("head bound by a parameter: edge to %s; edges %v", vuln, res.Edges)
	}
	// So does a comprehension variable, or a class body's binding.
	files["pkg/impl.py"], files["pkg/other.py"] = "def f(x):\n    return x\n", "from .impl import f as h\n"
	files["c.py"] = "from pkg.m import *\nfrom pkg import other\n\ndef go():\n    return [g.h(1) for g in (other,)]\n"
	if res := mustCallGraph(t, files); hasEdge(res.Edges, goC, vuln) {
		t.Errorf("head bound by a comprehension variable: edge to %s; edges %v", vuln, res.Edges)
	}
	files["c.py"] = "from pkg.m import *\nfrom pkg import other\n\nclass K:\n    g = other\n    r = g.h(1)\n"
	for _, e := range mustCallGraph(t, files).Edges {
		if e.Callee.SCIP == vuln {
			t.Errorf("head bound by the class body: edge %v", e)
		}
	}
	// A star-imported module that binds no such name gives the head nothing, though a package
	// binds the module's name to another (importing pkg.m replaces that attribute).
	files["pkg/__init__.py"], files["pkg/m.py"], files["pkg/alt/__init__.py"] = "from . import alt as m\n", "X = 1\n", "from . import y\nfrom . import y as g\n"
	files["c.py"] = "from pkg.m import *\nfrom pkg import other\ng = other\n\ndef go():\n    return g.h(1)\n"
	if res := mustCallGraph(t, files); hasEdge(res.Edges, goC, vuln) {
		t.Errorf("head the star-imported module cannot bind: edge to %s; edges %v", vuln, res.Edges)
	}
	// Nor does one whose only star import binds no such name.
	files["pkg/m.py"], files["pkg/n.py"] = "from pkg.n import *\n", "X = 1\n"
	if res := mustCallGraph(t, files); hasEdge(res.Edges, goC, vuln) {
		t.Errorf("head the star-imported module's star import cannot bind: edge to %s; edges %v", vuln, res.Edges)
	}
}

// TestCallGraph_GlobalImportInADef: an import in a def that declares the name global binds
// the module's attribute, so a site in another module that reaches the attribute (by import,
// through a module attribute, a package's submodule name or a star import) reaches what the
// import binds. The module also binds the name another way, so the site stays listed and the
// target escapes; where a caller's star import binds the chain's head, the site draws the
// edge instead. Where the module binds the name at module level as well, both targets stay
// reached. An import in a def without the declaration binds only the def's name.
func TestCallGraph_GlobalImportInADef(t *testing.T) {
	globalG := "def init():\n    global g\n    from pkg.alt import y as g\n"
	globalH := "def init():\n    global h\n    from ..v import vuln as h\n"
	chainSite := "import pkg.sub.a\n\ndef go():\n    return pkg.sub.a.g.h(1)\n"
	for _, tc := range []struct {
		name  string
		files map[string]string
		// local: the def does not declare the name global, so vuln must not escape.
		local bool
		// both: the module binds the name at module level as well, so pkg/impl.f must be reached too.
		both bool
	}{
		{name: "attribute through an imported module", files: map[string]string{"pkg/sub/a.py": globalG, "c.py": chainSite}},
		{name: "attribute assigned None first", files: map[string]string{"pkg/sub/a.py": "g = None\n" + globalG, "c.py": chainSite}},
		{name: "attribute by from-import", files: map[string]string{"pkg/sub/a.py": globalG, "c.py": "from pkg.sub.a import g\n\ndef go():\n    return g.h(1)\n"}},
		{name: "attribute through a from-imported module", files: map[string]string{"pkg/sub/a.py": globalG, "c.py": "from pkg.sub import a\n\ndef go():\n    return a.g.h(1)\n"}},
		{name: "attribute bound by import-as", files: map[string]string{"pkg/sub/a.py": "def init():\n    global g\n    import pkg.alt.y as g\n", "c.py": chainSite}},
		{name: "function by from-import", files: map[string]string{"pkg/sub/a.py": globalH, "c.py": "from pkg.sub.a import h\n\ndef go():\n    return h(1)\n"}},
		{name: "function beside a def of the name", files: map[string]string{"pkg/sub/a.py": "def h(x):\n    return x\n" + globalH, "c.py": "import pkg.sub.a\n\ndef go():\n    return pkg.sub.a.h(1)\n"}},
		{name: "function as a value", files: map[string]string{"pkg/sub/a.py": globalH, "c.py": "from pkg.sub import a\n\ndef go():\n    cb = a.h\n    return cb(1)\n"}},
		{name: "function by the caller's star import", files: map[string]string{"pkg/sub/a.py": globalH, "c.py": "from pkg.sub.a import *\n\ndef go():\n    return h(1)\n"}},
		{name: "attribute by the caller's star import", files: map[string]string{"pkg/sub/a.py": globalG, "c.py": "from pkg.sub.a import *\n\ndef go():\n    return g.h(1)\n"}},
		{name: "re-exported by from-import", files: map[string]string{"pkg/sub/a.py": "from pkg.sub.b import g\n", "pkg/sub/b.py": globalG, "c.py": "from pkg.sub.a import g\n\ndef go():\n    return g.h(1)\n"}},
		{name: "re-exported by star import", files: map[string]string{"pkg/sub/a.py": "from pkg.sub.b import *\n", "pkg/sub/b.py": globalG, "c.py": chainSite}},
		{name: "package rebinding its submodule's name", files: map[string]string{"pkg/sub/__init__.py": "def init():\n    global a\n    from pkg import x as a\n",
			"pkg/sub/a.py": "from ..impl import f as g\n", "pkg/x.py": "from pkg.alt import y as g\n", "c.py": chainSite}},
		{name: "function bound at module level too", both: true, files: map[string]string{"pkg/sub/a.py": "from ..v import vuln as h\n\ndef init():\n    global h\n    from ..impl import f as h\n",
			"c.py": "from pkg.sub.a import h\n\ndef go():\n    return h(1)\n"}},
		{name: "attribute bound at module level too", both: true, files: map[string]string{"pkg/sub/a.py": "from pkg.alt import y as g\n\ndef init():\n    global g\n    from pkg.alt2 import z as g\n",
			"pkg/alt2/__init__.py": "from . import z\n", "pkg/alt2/z.py": "from ..impl import f as h\n", "c.py": chainSite}},
		{name: "import in a def without the declaration", local: true, files: map[string]string{"pkg/sub/a.py": "def init():\n    from ..v import vuln as h\n",
			"c.py": "from pkg.sub.a import h\n\ndef go():\n    return h(1)\n"}},
	} {
		files := map[string]string{"pkg/impl.py": "def f(x):\n    return x\n", "pkg/v.py": "def vuln(x):\n    return x\n",
			"pkg/alt/__init__.py": "from . import y\n", "pkg/alt/y.py": "from ..v import vuln as h\n"}
		maps.Copy(files, tc.files)
		res := mustCallGraph(t, files)
		goC, vuln := funcSCIP("c", nil, "go", 0), funcSCIP("pkg/v", nil, "vuln", 1)
		if reached := hasEdge(res.Edges, goC, vuln) || symbolSet(res.Escaped)[vuln]; reached == tc.local {
			t.Errorf("%s: %s reached = %v, want %v; edges %v, escaped %v", tc.name, vuln, reached, !tc.local, res.Edges, res.Escaped)
		}
		if f := funcSCIP("pkg/impl", nil, "f", 1); tc.both && !hasEdge(res.Edges, goC, f) && !symbolSet(res.Escaped)[f] {
			t.Errorf("%s: %s not reached; edges %v, escaped %v", tc.name, f, res.Edges, res.Escaped)
		}
	}
}

// TestCallGraph_ModuleHeldByAssignment: a module attribute that holds a module by
// assignment, or by a store from another module, is not an import binding the site can
// follow, so the site stays listed. The held module is used as a value, so what its own
// first-party imports bind escapes, followed on through each module so bound.
func TestCallGraph_ModuleHeldByAssignment(t *testing.T) {
	chainSite := "import pkg.sub.a\n\ndef go():\n    return pkg.sub.a.g.h(1)\n"
	for _, tc := range []struct {
		name  string
		files map[string]string
		// unheld: nothing hands the module over, so vuln must not escape.
		unheld bool
	}{
		{name: "assigned an imported module", files: map[string]string{"pkg/sub/a.py": "from pkg.alt import y\ng = y\n", "c.py": chainSite}},
		{name: "assigned a dotted module", files: map[string]string{"pkg/sub/a.py": "import pkg.alt.y\ng = pkg.alt.y\n", "c.py": chainSite}},
		{name: "assigned a module's attribute", files: map[string]string{"pkg/sub/a.py": "from pkg import alt\ng = alt.y\n", "c.py": chainSite}},
		{name: "assigned, by from-import", files: map[string]string{"pkg/sub/a.py": "from pkg.alt import y\ng = y\n", "c.py": "from pkg.sub.a import g\n\ndef go():\n    return g.h(1)\n"}},
		{name: "assigned, by the caller's star import", files: map[string]string{"pkg/sub/a.py": "from pkg.alt import y\ng = y\n", "c.py": "from pkg.sub.a import *\n\ndef go():\n    return g.h(1)\n"}},
		{name: "assigned in a def that declares it global", files: map[string]string{"pkg/sub/a.py": "from pkg.alt import y\n\ndef init():\n    global g\n    g = y\n", "c.py": chainSite}},
		{name: "assigned a package, read through its submodule", files: map[string]string{"pkg/sub/a.py": "from pkg import alt\ng = alt\n", "c.py": "import pkg.sub.a\n\ndef go():\n    return pkg.sub.a.g.y.h(1)\n"}},
		{name: "assigned a module that imports a module", files: map[string]string{"pkg/sub/a.py": "from pkg import alt2\ng = alt2\n", "pkg/alt2.py": "from pkg.alt import y\n", "c.py": "import pkg.sub.a\n\ndef go():\n    return pkg.sub.a.g.y.h(1)\n"}},
		{name: "assigned a module that imports a namespace package's module", files: map[string]string{"pkg/sub/a.py": "from pkg.alt import y\ng = y\n", "pkg/alt/y.py": "import pkg.w\n", "pkg/w.py": "from pkg.v import vuln as h\n", "c.py": "import pkg.sub.a\n\ndef go():\n    return pkg.sub.a.g.pkg.w.h(1)\n"}},
		{name: "assigned a module that imports a namespace package", files: map[string]string{"pkg/sub/a.py": "from pkg.alt import y\ng = y\n", "pkg/alt/y.py": "from pkg import ns\n", "pkg/ns/m.py": "from pkg.v import vuln as h\n", "c.py": "import pkg.sub.a\nimport pkg.ns.m\n\ndef go():\n    return pkg.sub.a.g.ns.m.h(1)\n"}},
		{name: "stored from another module", files: map[string]string{"pkg/sub/a.py": "", "d.py": "import pkg.sub.a\nfrom pkg.alt import y\npkg.sub.a.g = y\n", "c.py": "import d\n" + chainSite}},
		{name: "stored through a from-imported module", files: map[string]string{"pkg/sub/a.py": "", "d.py": "from pkg.sub import a\nfrom pkg.alt import y\na.g = y\n", "c.py": "import d\n" + chainSite}},
		{name: "stored by setattr", files: map[string]string{"pkg/sub/a.py": "", "d.py": "from pkg.sub import a\nfrom pkg.alt import y\nsetattr(a, 'g', y)\n", "c.py": "import d\n" + chainSite}},
		{name: "module not handed over", unheld: true, files: map[string]string{"pkg/sub/a.py": "from pkg.alt import y\ng = 1\n", "c.py": "import pkg.sub.a\n\ndef go():\n    return pkg.sub.a.g(1)\n"}},
	} {
		files := map[string]string{"pkg/v.py": "def vuln(x):\n    return x\n",
			"pkg/alt/__init__.py": "from . import y\n", "pkg/alt/y.py": "from ..v import vuln as h\n"}
		maps.Copy(files, tc.files)
		res := mustCallGraph(t, files)
		goC, vuln := funcSCIP("c", nil, "go", 0), funcSCIP("pkg/v", nil, "vuln", 1)
		if reached := hasEdge(res.Edges, goC, vuln) || symbolSet(res.Escaped)[vuln]; reached == tc.unheld {
			t.Errorf("%s: %s reached = %v, want %v; edges %v, escaped %v", tc.name, vuln, reached, !tc.unheld, res.Edges, res.Escaped)
		}
		if listed := slices.ContainsFunc(res.Unresolved, func(u plugin.UnresolvedCall) bool { return u.Caller.SCIP == goC }); !tc.unheld && !listed {
			t.Errorf("%s: site not listed; unresolved %+v", tc.name, res.Unresolved)
		}
	}
}

// TestCallGraph_ValueChainThroughBoundModule: a dotted value whose attribute a module binds
// to another module by import ("a.g.h", where a holds "from pkg.alt import y as g") hands
// over what the rest of the chain names in that module, so the function it lands on must
// escape.
func TestCallGraph_ValueChainThroughBoundModule(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		// unreached: the chain lands on another function, so vuln must not escape.
		unreached bool
	}{
		{name: "value two deep", files: map[string]string{"c.py": "from pkg.sub import a\n\ndef go():\n    cb = a.g.h\n    return cb(1)\n"}},
		{name: "argument two deep", files: map[string]string{"c.py": "from pkg.sub import a\n\ndef run(f):\n    return f(1)\n\ndef go():\n    return run(a.g.h)\n"}},
		{name: "bound module as a value", files: map[string]string{"c.py": "from pkg.sub import a\n\ndef go():\n    m = a.g\n    return m.h(1)\n"}},
		{name: "three deep", files: map[string]string{"pkg/sub/a.py": "from pkg import alt as g\n", "c.py": "from pkg.sub import a\n\ndef go():\n    cb = a.g.y.h\n    return cb(1)\n"}},
		{name: "module re-exported by a third module", files: map[string]string{"pkg/sub/a.py": "from pkg.alt2 import y as g\n", "pkg/alt2.py": "from pkg.alt import y\n", "c.py": "from pkg.sub import a\n\ndef go():\n    cb = a.g.h\n    return cb(1)\n"}},
		{name: "bound by a global import in a def", files: map[string]string{"pkg/sub/a.py": "def init():\n    global g\n    from pkg.alt import y as g\n", "c.py": "from pkg.sub import a\n\ndef go():\n    cb = a.g.h\n    return cb(1)\n"}},
		{name: "bound to a top-level module", files: map[string]string{"pkg/sub/a.py": "import top as g\n", "top.py": "from pkg.v import vuln as h\n", "c.py": "from pkg.sub import a\n\ndef go():\n    cb = a.g.h\n    return cb(1)\n"}},
		{name: "bound two ways, the module last", files: map[string]string{"pkg/sub/a.py": "import os\nif os.environ.get('X'):\n    from pkg.other import z as g\nelse:\n    from pkg.alt import y as g\n", "pkg/other/z.py": "def h(x):\n    return x\n", "c.py": "from pkg.sub import a\n\ndef go():\n    cb = a.g.h\n    return cb(1)\n"}},
		{name: "bound two ways, the module first", files: map[string]string{"pkg/sub/a.py": "import os\nif os.environ.get('X'):\n    from pkg.alt import y as g\nelse:\n    from pkg.other import z as g\n", "pkg/other/z.py": "def h(x):\n    return x\n", "c.py": "from pkg.sub import a\n\ndef go():\n    cb = a.g.h\n    return cb(1)\n"}},
		{name: "same dotted path through a function's alias first", files: map[string]string{"pkg/__init__.py": "from .v import vuln\n", "b.py": "from pkg import vuln as x\n\ndef bo():\n    return x.__call__\n", "c.py": "import pkg\n\ndef go():\n    return pkg.vuln.__call__\n"}},
		{name: "chain lands on another function", unreached: true, files: map[string]string{"pkg/alt/y.py": "from ..v import vuln as h\n\ndef other(x):\n    return x\n", "c.py": "from pkg.sub import a\n\ndef go():\n    cb = a.g.other\n    return cb(1)\n"}},
		{name: "import cycle", unreached: true, files: map[string]string{"pkg/sub/a.py": "from pkg.b import x as g\n", "pkg/b.py": "from pkg.sub.a import g as x\n", "c.py": "from pkg.sub import a\n\ndef go():\n    cb = a.g.h\n    return cb(1)\n"}},
	} {
		files := map[string]string{"pkg/v.py": "def vuln(x):\n    return x\n", "pkg/sub/a.py": "from pkg.alt import y as g\n",
			"pkg/alt/__init__.py": "from . import y\n", "pkg/alt/y.py": "from ..v import vuln as h\n"}
		maps.Copy(files, tc.files)
		res := mustCallGraph(t, files)
		goC, vuln := funcSCIP("c", nil, "go", 0), funcSCIP("pkg/v", nil, "vuln", 1)
		if reached := hasEdge(res.Edges, goC, vuln) || symbolSet(res.Escaped)[vuln]; reached == tc.unreached {
			t.Errorf("%s: %s reached = %v, want %v; edges %v, escaped %v", tc.name, vuln, reached, !tc.unreached, res.Edges, res.Escaped)
		}
	}
}
