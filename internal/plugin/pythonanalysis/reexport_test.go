package pythonanalysis

import (
	"maps"
	"testing"
)

// TestCallGraph_ReexportRebinding: a site that imports a name through a module re-exporting
// it keeps its alias edge, and is listed when that module may bind the name another way: an
// assignment, a star import that may bind it, a store through a module object, or a package
// attribute stored with another module. A plain re-export, a None fallback, a star import
// that cannot bind the name, or a store of another name leaves the site complete.
func TestCallGraph_ReexportRebinding(t *testing.T) {
	impl := funcSCIP("pkg/impl", nil, "f", 1)
	goC := funcSCIP("c", nil, "go", 0)
	const reexport = "from .impl import f as g\n"
	const bare = "from pkg.a import g\n\ndef go():\n    return g(1)\n"
	const fromPkg = "from pkg import a\n\ndef go():\n    return a.g(1)\n"
	cases := []struct {
		name string
		// a is pkg/a.py, c is c.py (the site); extra adds files.
		a, c   string
		extra  map[string]string
		callee string
		listed bool
	}{
		{name: "assigned after the re-export", a: reexport + "from .v import vuln\ng = vuln\n", c: bare, callee: "g", listed: true},
		{name: "star import that binds the name", a: reexport + "from .x import *\n", c: bare, callee: "g", listed: true,
			extra: map[string]string{"pkg/x.py": "from .v import vuln as g\n"}},
		{name: "star import of a dependency", a: reexport + "from os.path import *\n", c: bare, callee: "g", listed: true},
		{name: "stored through the module object", a: reexport, c: bare, callee: "g", listed: true,
			extra: map[string]string{"b.py": "import pkg.a\nfrom pkg.v import vuln\npkg.a.g = vuln\n"}},
		{name: "re-exported twice, assigned at the end", a: "from .b import g\n", c: bare, callee: "g", listed: true,
			extra: map[string]string{"pkg/b.py": reexport + "from .v import vuln\ng = vuln\n"}},
		{name: "qualified through a from-imported module that assigns", a: reexport + "from .v import vuln\ng = vuln\n", c: fromPkg, callee: "a.g", listed: true},
		{name: "from-imported package attribute stored with another module", a: reexport, c: fromPkg, callee: "a.g", listed: true,
			extra: map[string]string{"b.py": "import pkg\nimport pkg.x\npkg.a = pkg.x\n", "pkg/x.py": "from .v import vuln as g\n"}},
		{name: "aliased import of a package attribute stored with another module", a: reexport, c: "import pkg.a as m\n\ndef go():\n    return m.g(1)\n", callee: "m.g", listed: true,
			extra: map[string]string{"b.py": "import pkg\nimport pkg.x\npkg.a = pkg.x\n", "pkg/x.py": "from .v import vuln as g\n"}},

		{name: "plain re-export", a: reexport, c: bare, callee: "g"},
		{name: "re-export with a None fallback", a: "try:\n    from .impl import f as g\nexcept ImportError:\n    g = None\n", c: bare, callee: "g"},
		{name: "star import that cannot bind the name", a: reexport + "from .x import *\n", c: bare, callee: "g",
			extra: map[string]string{"pkg/x.py": "def h(x):\n    return x\n"}},
		{name: "another name stored through the module object", a: reexport, c: bare, callee: "g",
			extra: map[string]string{"b.py": "import pkg.a\nfrom pkg.v import vuln\npkg.a.h = vuln\n"}},
		{name: "qualified through a from-imported module", a: reexport, c: fromPkg, callee: "a.g"},
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
			res := mustCallGraph(t, files)
			if !hasEdge(res.Edges, goC, impl) {
				t.Fatalf("missing alias edge %s -> %s; edges %v", goC, impl, res.Edges)
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
