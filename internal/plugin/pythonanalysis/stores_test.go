package pythonanalysis

import (
	"maps"
	"strings"
	"testing"
)

// TestCallGraph_ModuleObjectStores: a store into a module's namespace through a module
// object is another binding of the name it stores, so a site in that module calling the name
// keeps its alias edge and is listed, and so is a site elsewhere that reads the name from the
// module. A module handed over whole may have any name rebound. A read, a comparison, a
// subscript or attribute store, a delete, or a store into another module or from test code
// binds nothing, and the site stays complete.
func TestCallGraph_ModuleObjectStores(t *testing.T) {
	impl := funcSCIP("pkg/impl", nil, "f", 1)
	vuln := funcSCIP("pkg/v", nil, "vuln", 1)
	goA := funcSCIP("pkg/a", nil, "go", 0)
	goC := funcSCIP("c", nil, "go", 0)
	const src = "from .impl import f as g\n\ndef go():\n    return g(1)\n"
	cases := []struct {
		name string
		// src is pkg/a.py when set; b is b.py, the storing module.
		src   string
		b     string
		extra map[string]string
		// qualified moves the site to c.py, written as callee.
		qualified bool
		callee    string
		listed    bool
	}{
		{name: "store from another module", b: "import pkg.a\nfrom pkg.v import vuln\npkg.a.g = vuln\n", listed: true},
		{name: "store through a from-imported module", b: "from pkg import a\nfrom pkg.v import vuln\na.g = vuln\n", listed: true},
		{name: "store by the module into itself", src: "from .impl import f as g\nimport pkg.a as me\nfrom .v import vuln\nme.g = vuln\n\ndef go():\n    return g(1)\n", listed: true},
		{name: "store in a def", b: "from pkg import a\nfrom pkg.v import vuln\n\ndef patch():\n    a.g = vuln\n", listed: true},
		{name: "store in a tuple target", b: "from pkg import a\nfrom pkg.v import vuln\na.g, x = vuln, 1\n", listed: true},
		{name: "store in a chained assignment", b: "from pkg import a\nfrom pkg.v import vuln\nx = a.g = vuln\n", listed: true},
		{name: "annotated store", b: "from pkg import a\nfrom pkg.v import vuln\na.g: object = vuln\n", listed: true},
		{name: "augmented store", b: "from pkg import a\nfrom pkg.v import vuln\na.g |= vuln\n", listed: true},
		{name: "shift augmented store", b: "from pkg import a\nfrom pkg.v import vuln\na.g >>= vuln\n", listed: true},
		{name: "for target", b: "from pkg import a\nfrom pkg.v import vuln\nfor a.g in [vuln]:\n    pass\n", listed: true},
		{name: "with target", b: "from pkg import a\nfrom pkg.v import vuln\nwith vuln() as a.g:\n    pass\n", listed: true},
		{name: "setattr on the module", b: "import pkg.a\nfrom pkg.v import vuln\nsetattr(pkg.a, 'g', vuln)\n", listed: true},
		{name: "module passed whole", b: "from pkg import a\n\ndef reg(register):\n    register(a)\n", listed: true},
		{name: "module namespace updated", b: "from pkg import a\nfrom pkg.v import vuln\na.__dict__.update(g=vuln)\n", listed: true},
		{name: "module __setattr__ called", b: "from pkg import a\nfrom pkg.v import vuln\na.__setattr__('g', vuln)\n", listed: true},
		{name: "module from a literal dynamic import", b: "import importlib\nfrom pkg.v import vuln\nm = importlib.import_module('pkg.a')\nm.g = vuln\n", listed: true},
		{name: "store through a module attribute", b: "from pkg import reg\nfrom pkg.v import vuln\nreg.mod.g = vuln\n", extra: map[string]string{"pkg/reg.py": "from . import a as mod\n"}, listed: true},
		{name: "package bound whole, then stored into a submodule", b: "import pkg.a\nimport pkg\nfrom pkg.v import vuln\nm = pkg\nm.a.g = vuln\n", listed: true},
		{name: "package passed whole to a patcher", b: "import pkg.a\nimport pkg\nfrom pkg.v import vuln\n\ndef patch(p):\n    p.a.g = vuln\n\npatch(pkg)\n", listed: true},
		{name: "submodule reached by getattr on the package", b: "import pkg.a\nimport pkg\nfrom pkg.v import vuln\ngetattr(pkg, 'a').g = vuln\n", listed: true},
		{name: "module bound by an import of a module passed whole", b: "from pkg import reg\n\ndef reg_all(register):\n    register(reg)\n", extra: map[string]string{"pkg/reg.py": "from . import a as mod\n"}, listed: true},
		{name: "qualified site after the package is passed whole", b: "import pkg\n\ndef reg(register):\n    register(pkg)\n", qualified: true, callee: "a.g", listed: true},
		{name: "qualified site after a store", b: "from pkg import a\nfrom pkg.v import vuln\na.g = vuln\n", qualified: true, callee: "a.g", listed: true},
		{name: "qualified site through a stored module", b: "import pkg\npkg.a = object()\n", extra: map[string]string{"pkg/__init__.py": "from . import a\n"}, qualified: true, callee: "pkg.a.g", listed: true},
		{name: "store of another name", b: "from pkg import a\na.h = 1\n"},
		{name: "store into another module", b: "from pkg import other\nfrom pkg.v import vuln\nother.g = vuln\n", extra: map[string]string{"pkg/other.py": "g = 1\n"}},
		{name: "store from test code", b: "", extra: map[string]string{"tests/test_a.py": "from pkg import a\nfrom pkg.v import vuln\na.g = vuln\n"}},
		{name: "read of the attribute", b: "from pkg import a\nx = a.g\n"},
		{name: "comparison of the attribute", b: "from pkg import a\nfrom pkg.v import vuln\nif a.g == vuln:\n    pass\n"},
		{name: "store into a subscript of the attribute", b: "from pkg import a\nfrom pkg.v import vuln\na.g[0] = vuln\n"},
		{name: "store into an attribute of the attribute", b: "from pkg import a\nfrom pkg.v import vuln\na.g.x = vuln\n"},
		{name: "store into an object the module binds", b: "from pkg import a\nfrom pkg.v import vuln\na.obj.g = vuln\n", src: "from .impl import f as g\nobj = object()\n\ndef go():\n    return g(1)\n"},
		{name: "iteration over the attribute", b: "from pkg import a\nfor x in a.g:\n    pass\n"},
		{name: "delete of the attribute", b: "from pkg import a\ndel a.g\n"},
		{name: "qualified site with no store", b: "from pkg import a\na.h = 1\n", qualified: true, callee: "a.g"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{
				"pkg/__init__.py": "",
				"pkg/impl.py":     "def f(x):\n    return x\n",
				"pkg/v.py":        "def vuln(x):\n    return x\n",
				"pkg/a.py":        src,
			}
			if tc.src != "" {
				files["pkg/a.py"] = tc.src
			}
			if tc.b != "" {
				files["b.py"] = tc.b
			}
			caller, callee := goA, "g"
			if tc.qualified {
				caller, callee = goC, tc.callee
				files["c.py"] = "import pkg.a\nfrom pkg import a\n\ndef go():\n    return " + tc.callee + "(1)\n"
			}
			maps.Copy(files, tc.extra)
			res := mustCallGraph(t, files)
			if !hasEdge(res.Edges, caller, impl) {
				t.Fatalf("missing alias edge %s -> %s; edges %v", caller, impl, res.Edges)
			}
			listed := false
			for _, u := range res.Unresolved {
				if u.Caller.SCIP == caller && u.Callee == callee && len(u.Targets) == 0 {
					listed = true
				}
			}
			if listed != tc.listed {
				t.Fatalf("%s(1) listed = %v, want %v; unresolved %v", callee, listed, tc.listed, res.Unresolved)
			}
			if tc.listed && !tc.qualified && tc.b != "" && strings.Contains(tc.b, "vuln") && !readerReaches(res, caller, vuln) {
				t.Fatalf("%s does not reach %s; edges %v, escaped %v", caller, vuln, res.Edges, res.Escaped)
			}
		})
	}
}
