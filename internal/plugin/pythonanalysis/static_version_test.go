package pythonanalysis

import (
	"maps"
	"path/filepath"
	"testing"
)

// setuptools and flit_core read a dynamic version (and flit a dynamic description) from the
// module without importing it when it holds the value as a plain string literal, so a local
// build that does resolves; one whose module this cannot place, read, or find a literal in
// withholds, as the import it falls back to runs code from the tree.
func TestResolveVersions_StaticVersion(t *testing.T) {
	const (
		project  = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"jinja2>=3.1\"]\n"
		jinjaUV  = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
		uvSync   = "#!/bin/sh\nuv sync --locked\n"
		literal  = "__version__ = \"1.2.0\"\n"
		docVer   = "\"\"\"The lib.\"\"\"\n\nimport os\n\n__version__ = \"1.2.0\"\n"
		setupBE  = "[build-system]\nrequires = [\"setuptools>=77\"]\nbuild-backend = \"setuptools.build_meta\"\n"
		flitBE   = "[build-system]\nrequires = [\"flit_core>=3.4\"]\nbuild-backend = \"flit_core.buildapi\"\n"
		attrVer  = "[tool.setuptools.dynamic]\nversion = { attr = \"lib.__version__\" }\n"
		dynVer   = "[project]\nname = \"lib\"\ndynamic = [\"version\"]\n"
		dynBoth  = "[project]\nname = \"lib\"\ndynamic = [\"version\", \"description\"]\n"
		setupLib = dynVer + setupBE + attrVer
	)
	lock := func(dir string) string {
		return "version = 1\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n\n" +
			"[[package]]\nname = \"lib\"\nversion = \"1.2.0\"\nsource = { directory = \"" + dir + "\" }\n\n" + jinjaUV
	}
	tree := func(files map[string]string) map[string]string {
		out := map[string]string{"pyproject.toml": project, "uv.lock": lock("lib"), "install.sh": uvSync}
		maps.Copy(out, files)
		return out
	}
	// The layout of EstrellaXD/Auto_Bangumi's backend: an sdk built from a src directory beside it.
	sdk := map[string]string{"pyproject.toml": project, "uv.lock": lock("sdk"), "install.sh": uvSync,
		"sdk/pyproject.toml": "[project]\nname = \"ab-sdk\"\ndynamic = [\"version\"]\n" + setupBE +
			"[tool.setuptools]\npackage-dir = { \"\" = \"../src\" }\npackages = [\"ab_sdk\"]\n" +
			"[tool.setuptools.dynamic]\nversion = { attr = \"ab_sdk.SDK_VERSION\" }\n",
		"src/ab_sdk/__init__.py": "\"\"\"SDK.\"\"\"\n\nfrom .client import Client\n\nSDK_VERSION = \"0.6.0\"\n\n__all__ = [\"SDK_VERSION\", \"Client\"]\n"}
	with := func(files map[string]string, k, v string) map[string]string {
		out := maps.Clone(files)
		out[k] = v
		return out
	}
	tests := []struct {
		name  string
		files map[string]string
		links map[string]string // a symlink at each key to the path its value names from root
		want  bool              // jinja2 resolved
	}{
		{"setuptools, attr in the package beside the manifest", tree(map[string]string{"lib/pyproject.toml": setupLib,
			"lib/lib/__init__.py": docVer}), nil, true},
		{"setuptools, attr in a module of the package", tree(map[string]string{"lib/pyproject.toml": dynVer + setupBE +
			"[tool.setuptools.dynamic]\nversion = { attr = \"lib.about.__version__\" }\n", "lib/lib/__init__.py": "",
			"lib/lib/about.py": literal}), nil, true},
		{"setuptools, attr in a single-file module", tree(map[string]string{"lib/pyproject.toml": setupLib,
			"lib/lib.py": literal}), nil, true},
		{"setuptools, attr under a discovered src layout", tree(map[string]string{"lib/pyproject.toml": setupLib,
			"lib/src/lib/__init__.py": literal}), nil, true},
		{"setuptools, attr under a package-dir outside the project", sdk, nil, true},
		{"setuptools, attr under a package-dir entry for the package", tree(map[string]string{"lib/pyproject.toml": setupLib +
			"[tool.setuptools.package-dir]\nlib = \"code\"\n", "lib/code/__init__.py": literal}), nil, true},
		{"setuptools, a dynamic readme beside a literal version", tree(map[string]string{"lib/pyproject.toml": setupLib +
			"readme = { file = \"README.md\" }\n", "lib/lib/__init__.py": literal}), nil, true},
		{"flit, version and description from the package", tree(map[string]string{"lib/pyproject.toml": dynBoth + flitBE,
			"lib/lib/__init__.py": docVer}), nil, true},
		{"flit, version from a module under src named by tool.flit.module", tree(map[string]string{"lib/pyproject.toml": dynVer + flitBE +
			"[tool.flit.module]\nname = \"core\"\n", "lib/src/core.py": literal}), nil, true},
		{"flit, a project name with a dash", tree(map[string]string{"lib/pyproject.toml": "[project]\nname = \"my-lib\"\ndynamic = [\"version\"]\n" + flitBE,
			"lib/my_lib/__init__.py": literal}), nil, true},

		{"setuptools, version from a call", tree(map[string]string{"lib/pyproject.toml": setupLib,
			"lib/lib/__init__.py": "from ._v import get\n__version__ = get()\n"}), nil, false},
		{"setuptools, version from an f-string", tree(map[string]string{"lib/pyproject.toml": setupLib,
			"lib/lib/__init__.py": "__version__ = f\"{1}.0\"\n"}), nil, false},
		{"setuptools, version annotated", tree(map[string]string{"lib/pyproject.toml": setupLib,
			"lib/lib/__init__.py": "__version__: str = \"1.2.0\"\n"}), nil, false},
		{"setuptools, version rebound after the literal", tree(map[string]string{"lib/pyproject.toml": setupLib,
			"lib/lib/__init__.py": literal + "__version__ = __version__ + \".dev\"\n"}), nil, false},
		{"setuptools, version bound only in a block", tree(map[string]string{"lib/pyproject.toml": setupLib,
			"lib/lib/__init__.py": "if True:\n    __version__ = \"1.2.0\"\n"}), nil, false},
		{"setuptools, version imported", tree(map[string]string{"lib/pyproject.toml": setupLib,
			"lib/lib/__init__.py": "from ._v import __version__\n"}), nil, false},
		{"setuptools, version split across literals", tree(map[string]string{"lib/pyproject.toml": setupLib,
			"lib/lib/__init__.py": "__version__ = \"1.\" \"2\"\n"}), nil, false},
		{"setuptools, version with an escape", tree(map[string]string{"lib/pyproject.toml": setupLib,
			"lib/lib/__init__.py": "__version__ = \"\\x31.2\"\n"}), nil, false},
		{"setuptools, a module encoded other than UTF-8", tree(map[string]string{"lib/pyproject.toml": setupLib,
			"lib/lib/__init__.py": "# -*- coding: latin-1 -*-\n" + literal}), nil, false},
		{"setuptools, no module there", tree(map[string]string{"lib/pyproject.toml": setupLib}), nil, false},
		{"setuptools, the module both beside the manifest and under src", tree(map[string]string{"lib/pyproject.toml": setupLib,
			"lib/lib/__init__.py": literal, "lib/src/lib/__init__.py": literal}), nil, false},
		{"setuptools, src there and the module beside the manifest", tree(map[string]string{"lib/pyproject.toml": setupLib,
			"lib/lib/__init__.py": literal, "lib/src/other.py": "\n"}), nil, false},
		{"setuptools, a packages.find table", tree(map[string]string{"lib/pyproject.toml": setupLib +
			"[tool.setuptools.packages.find]\nwhere = [\"src\"]\n", "lib/lib/__init__.py": literal}), nil, false},
		{"setuptools, ext-modules", tree(map[string]string{"lib/pyproject.toml": setupLib +
			"[[tool.setuptools.ext-modules]]\nname = \"lib._c\"\nsources = [\"c.c\"]\n", "lib/lib/__init__.py": literal}), nil, false},
		{"setuptools, a package-dir that climbs after a name", tree(map[string]string{"lib/pyproject.toml": setupLib +
			"[tool.setuptools.package-dir]\n\"\" = \"x/../../src\"\n", "src/lib/__init__.py": literal}), nil, false},
		{"setuptools, an attr with more than the name", tree(map[string]string{"lib/pyproject.toml": dynVer + setupBE +
			"[tool.setuptools.dynamic]\nversion = { attr = \"lib.__version__\", file = \"V\" }\n", "lib/lib/__init__.py": literal}), nil, false},
		{"setuptools, attr on another dynamic key", tree(map[string]string{"lib/pyproject.toml": setupLib +
			"description = { attr = \"lib.DESC\" }\n", "lib/lib/__init__.py": literal + "DESC = \"d\"\n"}), nil, false},
		{"setuptools, the module through a symlinked directory", tree(map[string]string{"lib/pyproject.toml": setupLib,
			"elsewhere/__init__.py": literal}), map[string]string{"lib/lib": "elsewhere"}, false},
		{"setuptools, setup.py beside a literal version", tree(map[string]string{"lib/pyproject.toml": setupLib,
			"lib/lib/__init__.py": literal, "lib/setup.py": "import setuptools\nsetuptools.setup()\n"}), nil, false},
		{"flit, a dynamic description and no docstring", tree(map[string]string{"lib/pyproject.toml": dynBoth + flitBE,
			"lib/lib/__init__.py": literal}), nil, false},
		{"flit, the module both beside the manifest and under src", tree(map[string]string{"lib/pyproject.toml": dynVer + flitBE,
			"lib/lib.py": literal, "lib/src/lib/__init__.py": literal}), nil, false},
		{"flit, a dashed name with its spelling there too", tree(map[string]string{"lib/pyproject.toml": "[project]\nname = \"my-lib\"\ndynamic = [\"version\"]\n" + flitBE,
			"lib/my_lib/__init__.py": literal, "lib/my-lib/x.txt": "x\n"}), nil, false},
		{"flit, a project name with capitals", tree(map[string]string{"lib/pyproject.toml": "[project]\nname = \"Lib\"\ndynamic = [\"version\"]\n" + flitBE,
			"lib/lib/__init__.py": literal}), nil, false},
		{"setuptools, the module also installed by pip -r", with(tree(map[string]string{"lib/pyproject.toml": setupLib,
			"lib/lib/__init__.py": "# jinja2==3.1.2\n" + literal}), "install.sh", uvSync+"pip install -r lib/lib/__init__.py\n"), nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := writeTree(t, tt.files)
			for l, target := range tt.links {
				link(t, root, l, filepath.Join(root, target))
			}
			r := resolveVersion(t, root, "jinja2")
			if !r.Found || r.Match.Resolved != tt.want || r.Partiality.Complete != tt.want {
				t.Fatalf("jinja2 = %+v partiality %+v, want resolved and complete %v", r.Match, r.Partiality, tt.want)
			}
		})
	}
}

func TestStaticAssigned(t *testing.T) {
	tests := []struct {
		name, src, attr string
		docstring       bool
		want            bool
	}{
		{"plain", "__version__ = \"1.0\"\n", "__version__", false, true},
		{"single quotes and a comment", "__version__ = '1.0'  # bump\n", "__version__", false, true},
		{"after imports and other names", "import os\nversion_info = (1, 0)\n__version__ = \"1.0\"\n", "__version__", false, true},
		{"named inside strings elsewhere", "__version__ = \"1.0\"\n__all__ = [\"__version__\"]\n", "__version__", false, true},
		{"a longer name sharing the prefix", "__version_tuple__ = get()\n__version__ = \"1.0\"\n", "__version__", false, true},
		{"BOM and CRLF", "\xEF\xBB\xBF__version__ = \"1.0\"\r\n", "__version__", false, true},
		{"utf-8 cookie", "# coding: utf-8\n__version__ = \"1.0\"\n", "__version__", false, true},
		{"docstring only", "\"\"\"The module.\"\"\"\n", "", true, true},
		{"docstring then version", "'''Doc.\n\nMore.'''\n__version__ = \"1.0\"\n", "__version__", true, true},
		{"indented use", "def f():\n    return __version__\n__version__ = \"1.0\"\n", "__version__", false, true},

		{"absent", "VERSION = \"1.0\"\n", "__version__", false, false},
		{"empty", "", "__version__", false, false},
		{"empty with docstring", "", "", true, false},
		{"a name", "__version__ = VERSION\n", "__version__", false, false},
		{"chained", "__version__ = VERSION = \"1.0\"\n", "__version__", false, false},
		{"tuple target", "__version__, x = \"1.0\", 2\n", "__version__", false, false},
		{"augmented", "__version__ = \"1.0\"\n__version__ += \"+x\"\n", "__version__", false, false},
		{"bytes", "__version__ = b\"1.0\"\n", "__version__", false, false},
		{"raw", "__version__ = r\"1.0\"\n", "__version__", false, false},
		{"triple-quoted", "__version__ = \"\"\"1.0\"\"\"\n", "__version__", false, false},
		{"empty literal", "__version__ = \"\"\n", "__version__", false, false},
		{"whitespace literal", "__version__ = \"  \"\n", "__version__", false, false},
		{"unterminated", "__version__ = \"1.0\n", "__version__", false, false},
		{"continued", "__version__ = \\\n    \"1.0\"\n", "__version__", false, false},
		{"parenthesised", "__version__ = (\"1.0\")\n", "__version__", false, false},
		{"semicolon", "__version__ = \"1.0\"; x = 1\n", "__version__", false, false},
		{"del", "__version__ = \"1.0\"\ndel __version__\n", "__version__", false, false},
		{"latin-1 cookie on line two", "#!/usr/bin/env python\n# vim: set fileencoding=latin-1 :\n__version__ = \"1.0\"\n", "__version__", false, false},
		{"invalid UTF-8", "__version__ = \"1.0\xff\"\n", "__version__", false, false},
		{"form feed", "\f__version__ = \"1.0\"\n", "__version__", false, false},
		{"lone CR", "x = 1\r__version__ = \"1.0\"\n", "__version__", false, false},
		{"docstring missing", "__version__ = \"1.0\"\n", "__version__", true, false},
		{"docstring after code", "import os\n\"\"\"Doc.\"\"\"\n", "", true, false},
		{"docstring an f-string", "f\"\"\"Doc {x}.\"\"\"\n", "", true, false},
		{"docstring concatenated", "\"Doc.\" \"More.\"\n", "", true, false},
		{"docstring empty", "\"\"\"\"\"\"\n", "", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := staticAssigned([]byte(tt.src), tt.attr, tt.docstring); got != tt.want {
				t.Fatalf("staticAssigned(%q, %q, %v) = %v, want %v", tt.src, tt.attr, tt.docstring, got, tt.want)
			}
		})
	}
}

func TestLeadingUpOnly(t *testing.T) {
	for s, want := range map[string]bool{
		"": true, "src": true, "../src": true, "../../lib/src": true, "./src": true,
		"/abs": false, "src/../x": false, "a/../../src": false, "src/*": false, "~/src": false, "$X/src": false, "a\\b": false,
	} {
		if got := leadingUpOnly(s); got != want {
			t.Errorf("leadingUpOnly(%q) = %v, want %v", s, got, want)
		}
	}
}
