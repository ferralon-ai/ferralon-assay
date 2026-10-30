package pythonanalysis

import (
	"maps"
	"path/filepath"
	"testing"
)

// uv sync, poetry install and pdm sync build every local directory the lock names, a path
// dependency or a uv workspace member, through that directory's own backend, so code from the
// tree that runs there withholds every pin, as it does for the root; a source this cannot
// resolve to a manifest read here withholds too, and one built by a backend that runs nothing
// from the tree still resolves.
func TestResolveVersions_LocalBuilds(t *testing.T) {
	const (
		project = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"jinja2>=3.1\"]\n"
		member  = "[project]\nname = \"lib\"\nversion = \"0.1.0\"\n"
		setupPy = "import subprocess\nsubprocess.run([\"pip\", \"install\", \"jinja2==3.1.2\"])\n"
		jinjaUV = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
		jinjaPy = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\n"
	)
	backend := func(b string) string {
		return member + "[build-system]\nrequires = [\"x\"]\nbuild-backend = \"" + b + "\"\n"
	}
	uvLock := func(source string) string {
		return "version = 1\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n\n" +
			"[[package]]\nname = \"lib\"\nversion = \"0.1.0\"\nsource = " + source + "\n\n" + jinjaUV
	}
	poetryLock := func(source string) string {
		return "[[package]]\nname = \"lib\"\nversion = \"0.1.0\"\ndevelop = true\n\n[package.source]\n" + source + "\n\n" + jinjaPy
	}
	pdmLock := func(fields string) string {
		return "[metadata]\ngroups = [\"default\"]\n\n[[package]]\nname = \"lib\"\nversion = \"0.1.0\"\n" + fields + "\n\n" + jinjaPy
	}
	workspace := project + "[tool.uv.workspace]\nmembers = [\"packages/*\"]\n"
	dynamic := func(b, tool string) string {
		return "[project]\nname = \"lib\"\ndynamic = [\"version\"]\n[build-system]\nrequires = [\"x\"]\nbuild-backend = \"" + b + "\"\n" + tool
	}
	// A member run on its own, from a lock beside its manifest.
	inMember := map[string]string{
		"packages/lib/pyproject.toml": "[project]\nname = \"lib\"\nversion = \"0.1.0\"\ndependencies = [\"jinja2>=3.1\"]\n" +
			"[build-system]\nrequires = [\"x\"]\nbuild-backend = \"uv_build\"\n",
		"packages/lib/uv.lock":    "version = 1\n[[package]]\nname = \"lib\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n\n" + jinjaUV,
		"packages/lib/install.sh": "#!/bin/sh\nuv sync --locked\n",
	}
	locks := map[string]string{"uv": "uv.lock", "poetry": "poetry.lock", "pdm": "pdm.lock"}
	commands := map[string]string{"uv": "uv sync --locked", "poetry": "poetry install", "pdm": "pdm sync"}
	tests := []struct {
		name, tool, pyproject, lock string
		files                       map[string]string // more files in the tree
		dockerfile                  string            // when set, the build is this Dockerfile instead of install.sh
		want                        bool              // jinja2 resolved
	}{
		// uv: workspace members and path sources.
		{"uv, member with setup.py", "uv", project, uvLock(`{ editable = "packages/lib" }`),
			map[string]string{"packages/lib/pyproject.toml": backend("setuptools.build_meta"), "packages/lib/setup.py": setupPy}, "", false},
		{"uv, member with no backend named and setup.py", "uv", project, uvLock(`{ editable = "packages/lib" }`),
			map[string]string{"packages/lib/pyproject.toml": member, "packages/lib/setup.py": setupPy}, "", false},
		{"uv, member with an unknown backend", "uv", project, uvLock(`{ editable = "packages/lib" }`),
			map[string]string{"packages/lib/pyproject.toml": backend("maturin")}, "", false},
		{"uv, member with no pyproject.toml", "uv", project, uvLock(`{ editable = "packages/lib" }`),
			map[string]string{"packages/lib/setup.py": setupPy}, "", false},
		{"uv, directory source with a hatchling hook", "uv", project, uvLock(`{ directory = "lib" }`),
			map[string]string{"lib/pyproject.toml": backend("hatchling.build") + "[tool.hatch.build.hooks.custom]\n"}, "", false},
		{"uv, virtual member that asks to be built", "uv", project, uvLock(`{ virtual = "packages/lib" }`),
			map[string]string{"packages/lib/pyproject.toml": backend("setuptools.build_meta"), "packages/lib/setup.py": setupPy}, "", false},
		{"uv, source archive", "uv", project, uvLock(`{ path = "dist/lib-0.1.0.tar.gz" }`), nil, "", false},
		{"uv, source outside the build", "uv", project, uvLock(`{ editable = "../lib" }`), nil, "", false},
		{"uv, unknown source kind", "uv", project, uvLock(`{ vendored = "lib" }`), nil, "", false},
		{"uv, member copied in with setup.py", "uv", project, uvLock(`{ editable = "packages/lib" }`),
			map[string]string{"packages/lib/pyproject.toml": member, "packages/lib/setup.py": setupPy},
			"FROM python:3.12\nWORKDIR /app\nCOPY . .\nRUN uv sync --locked\n", false},
		{"uv, member manifest left out of the image", "uv", project, uvLock(`{ editable = "packages/lib" }`),
			map[string]string{"packages/lib/pyproject.toml": backend("uv_build")},
			"FROM python:3.12\nWORKDIR /app\nCOPY pyproject.toml uv.lock ./\nRUN uv sync --locked\n", false},
		{"uv, run from a member over the workspace lock", "uv", workspace, uvLock(`{ editable = "packages/lib" }`),
			map[string]string{"packages/lib/pyproject.toml": backend("uv_build")},
			"FROM python:3.12\nWORKDIR /app\nCOPY . .\nWORKDIR /app/packages/lib\nRUN uv sync --locked\n", false},
		{"uv, run from a member over its own lock", "uv", workspace, uvLock(`{ editable = "packages/lib" }`), inMember, "", false},
		{"uv, run from a member copied in over its own lock", "uv", workspace, uvLock(`{ editable = "packages/lib" }`), inMember,
			"FROM python:3.12\nWORKDIR /app\nCOPY . .\nWORKDIR /app/packages/lib\nRUN uv sync --locked\n", false},
		{"uv, a path with .. after a named part", "uv", project, uvLock(`{ editable = "packages/../lib" }`),
			map[string]string{"lib/pyproject.toml": backend("uv_build")}, "", false},
		{"uv, a local source with another key", "uv", project, uvLock(`{ editable = "lib", subdirectory = "sub" }`),
			map[string]string{"lib/pyproject.toml": backend("uv_build")}, "", false},

		// Version sources that run code from the tree.
		{"uv, member with flit_core and a dynamic version", "uv", project, uvLock(`{ editable = "lib" }`),
			map[string]string{"lib/pyproject.toml": dynamic("flit_core.buildapi", "")}, "", false},
		{"uv, member with flit_core and no project table", "uv", project, uvLock(`{ editable = "lib" }`),
			map[string]string{"lib/pyproject.toml": "[tool.flit.metadata]\nmodule = \"lib\"\n[build-system]\nrequires = [\"x\"]\nbuild-backend = \"flit_core.buildapi\"\n"}, "", false},
		{"uv, member with a hatchling code version", "uv", project, uvLock(`{ editable = "lib" }`),
			map[string]string{"lib/pyproject.toml": dynamic("hatchling.build", "[tool.hatch.version]\nsource = \"code\"\npath = \"lib/v.py\"\n")}, "", false},
		{"uv, member with a pdm-backend call version", "uv", project, uvLock(`{ editable = "lib" }`),
			map[string]string{"lib/pyproject.toml": dynamic("pdm.backend", "[tool.pdm.version]\nsource = \"call\"\ngetter = \"lib.v:get\"\n")}, "", false},
		{"uv, member with a pdm-backend version_format", "uv", project, uvLock(`{ editable = "lib" }`),
			map[string]string{"lib/pyproject.toml": dynamic("pdm.backend", "[tool.pdm.version]\nsource = \"scm\"\nversion_format = \"lib.v:fmt\"\n")}, "", false},
		{"uv, member with a setuptools attr version", "uv", project, uvLock(`{ editable = "lib" }`),
			map[string]string{"lib/pyproject.toml": dynamic("setuptools.build_meta", "[tool.setuptools.dynamic]\nversion = { attr = \"lib.__version__\" }\n")}, "", false},

		// poetry: path dependencies.
		{"poetry, directory with setup.py", "poetry", project, poetryLock("type = \"directory\"\nurl = \"lib\""),
			map[string]string{"lib/setup.py": setupPy}, "", false},
		{"poetry, directory with a poetry-core build script", "poetry", project, poetryLock("type = \"directory\"\nurl = \"lib\""),
			map[string]string{"lib/pyproject.toml": backend("poetry.core.masonry.api") + "[tool.poetry]\nbuild = \"build.py\"\n"}, "", false},
		{"poetry, source archive", "poetry", project, poetryLock("type = \"file\"\nurl = \"dist/lib-0.1.0.tar.gz\""), nil, "", false},
		{"poetry, directory outside the build", "poetry", project, poetryLock("type = \"directory\"\nurl = \"../lib\""), nil, "", false},
		{"poetry, the project's own directory", "poetry", project, poetryLock("type = \"directory\"\nurl = \".\""), nil, "", false},
		{"poetry, unknown source type", "poetry", project, poetryLock("type = \"vendored\"\nurl = \"lib\""), nil, "", false},

		// pdm: path dependencies.
		{"pdm, path with pdm_build.py", "pdm", project, pdmLock("path = \"./lib\"\neditable = true"),
			map[string]string{"lib/pyproject.toml": backend("pdm.backend"), "lib/pdm_build.py": "def pdm_build_initialize(context):\n    pass\n"}, "", false},
		{"pdm, path with setup.py", "pdm", project, pdmLock("path = \"./lib\""),
			map[string]string{"lib/pyproject.toml": backend("setuptools.build_meta"), "lib/setup.py": setupPy}, "", false},
		{"pdm, source archive", "pdm", project, pdmLock("path = \"./dist/lib-0.1.0.tar.gz\""), nil, "", false},
		{"pdm, file url", "pdm", project, pdmLock("url = \"file:///${PROJECT_ROOT}/lib\""), nil, "", false},
		{"pdm, subdirectory with setup.py", "pdm", project, pdmLock("path = \"./repo\"\nsubdirectory = \"lib\""),
			map[string]string{"repo/pyproject.toml": backend("uv_build"), "repo/lib/pyproject.toml": backend("setuptools.build_meta"), "repo/lib/setup.py": setupPy}, "", false},
		{"pdm, run from a member over its own lock", "pdm", project + "[tool.pdm.workspace]\nmembers = [\"packages/*\"]\n", pdmLock("path = \"./lib\""),
			map[string]string{"lib/pyproject.toml": backend("flit_core.buildapi"),
				"packages/lib/pyproject.toml": "[project]\nname = \"m\"\nversion = \"0.1.0\"\ndependencies = [\"jinja2>=3.1\"]\n",
				"packages/lib/pdm.lock":       "[metadata]\ngroups = [\"default\"]\n\n" + jinjaPy, "packages/lib/install.sh": "#!/bin/sh\npdm sync\n"}, "", false},
		{"pdm, subdirectory not a string", "pdm", project, pdmLock("path = \"./lib\"\nsubdirectory = 1"),
			map[string]string{"lib/pyproject.toml": backend("uv_build")}, "", false},

		// Guards: a backend that runs nothing from the tree, or a source no build reads here.
		{"uv, workspace root with no member locked", "uv", workspace, uvLock(`{ registry = "https://pypi.org/simple" }`), nil, "", true},
		{"uv, member with uv_build", "uv", workspace, uvLock(`{ editable = "packages/lib" }`),
			map[string]string{"packages/lib/pyproject.toml": backend("uv_build")}, "", true},
		{"uv, virtual member with setup.py", "uv", workspace, uvLock(`{ virtual = "packages/lib" }`),
			map[string]string{"packages/lib/pyproject.toml": member, "packages/lib/setup.py": setupPy}, "", true},
		{"uv, wheel", "uv", project, uvLock(`{ path = "dist/lib-0.1.0-py3-none-any.whl" }`), nil, "", true},
		{"uv, git source", "uv", project, uvLock(`{ git = "https://github.com/o/lib?rev=v1#abc" }`), nil, "", true},
		{"uv, member copied in clean", "uv", workspace, uvLock(`{ editable = "packages/lib" }`),
			map[string]string{"packages/lib/pyproject.toml": backend("flit_core.buildapi")},
			"FROM python:3.12\nWORKDIR /app\nCOPY . .\nRUN uv sync --locked\n", true},
		{"poetry, directory with poetry-core", "poetry", project, poetryLock("type = \"directory\"\nurl = \"lib\""),
			map[string]string{"lib/pyproject.toml": backend("poetry.core.masonry.api"), "lib/setup.py": setupPy}, "", true},
		{"poetry, wheel", "poetry", project, poetryLock("type = \"file\"\nurl = \"dist/lib-0.1.0-py3-none-any.whl\""), nil, "", true},
		{"poetry, git and index sources", "poetry", project, poetryLock("type = \"git\"\nurl = \"https://github.com/o/lib\"") +
			"\n[[package]]\nname = \"m\"\nversion = \"1\"\n\n[package.source]\ntype = \"legacy\"\nurl = \"https://example.com/simple\"\n", nil, "", true},
		{"pdm, path with flit_core", "pdm", project, pdmLock("path = \"./lib\""),
			map[string]string{"lib/pyproject.toml": backend("flit_core.buildapi")}, "", true},
		{"pdm, wheel", "pdm", project, pdmLock("path = \"./dist/lib-0.1.0-py3-none-any.whl\""), nil, "", true},
		{"pdm, index url", "pdm", project, pdmLock("url = \"https://example.com/lib-0.1.0.tar.gz\""), nil, "", true},
		{"pdm, subdirectory with flit_core", "pdm", project, pdmLock("path = \"./repo\"\nsubdirectory = \"lib\""),
			map[string]string{"repo/lib/pyproject.toml": backend("flit_core.buildapi")}, "", true},
		{"uv, git source with a subdirectory", "uv", project, uvLock(`{ git = "https://github.com/o/lib?subdirectory=lib#abc", subdirectory = "lib" }`), nil, "", true},
		{"uv, run from a member over its own lock with no workspace", "uv", project, uvLock(`{ registry = "https://pypi.org/simple" }`), inMember, "", true},
		{"uv, member with a hatchling regex version", "uv", project, uvLock(`{ editable = "lib" }`),
			map[string]string{"lib/pyproject.toml": dynamic("hatchling.build", "[tool.hatch.version]\npath = \"lib/__init__.py\"\n")}, "", true},
		{"uv, member with a pdm-backend scm version", "uv", project, uvLock(`{ editable = "lib" }`),
			map[string]string{"lib/pyproject.toml": dynamic("pdm.backend", "[tool.pdm.version]\nsource = \"scm\"\n")}, "", true},
		{"uv, member with a setuptools file version", "uv", project, uvLock(`{ editable = "lib" }`),
			map[string]string{"lib/pyproject.toml": dynamic("setuptools.build_meta", "[tool.setuptools.dynamic]\nversion = { file = \"VERSION\" }\n")}, "", true},
		{"uv, member with flit_core and a static version", "uv", project, uvLock(`{ editable = "lib" }`),
			map[string]string{"lib/pyproject.toml": backend("flit_core.buildapi")}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"pyproject.toml": tt.pyproject, locks[tt.tool]: tt.lock}
			switch {
			case tt.dockerfile != "":
				files["Dockerfile"] = tt.dockerfile
			default:
				files["install.sh"] = "#!/bin/sh\n" + commands[tt.tool] + "\n"
			}
			for k, v := range tt.files {
				files[k] = v
			}
			r := resolveVersion(t, writeTree(t, files), "jinja2")
			if !r.Found || r.Match.Resolved != tt.want || r.Partiality.Complete != tt.want {
				t.Fatalf("jinja2 = %+v partiality %+v, want resolved and complete %v", r.Match, r.Partiality, tt.want)
			}
		})
	}
}

// A source the lock names through .. is built from the directory that path reaches from the
// project, so one inside the build is checked like any other, whether the build runs in the
// tree or in an image that copies both.
func TestResolveVersions_LocalBuildsAbove(t *testing.T) {
	const (
		project = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"jinja2>=3.1\"]\n"
		lib     = "[project]\nname = \"lib\"\nversion = \"0.1.0\"\n[build-system]\nrequires = [\"x\"]\nbuild-backend = "
		setupPy = "import subprocess\nsubprocess.run([\"pip\", \"install\", \"jinja2==3.1.2\"])\n"
		uvLock  = "version = 1\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n\n" +
			"[[package]]\nname = \"lib\"\nversion = \"0.1.0\"\nsource = { editable = \"../lib\" }\n\n" +
			"[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
		jinjaPy    = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\n"
		poetryLock = "[[package]]\nname = \"lib\"\nversion = \"0.1.0\"\ndevelop = true\n\n[package.source]\ntype = \"directory\"\nurl = \"../lib\"\n\n" + jinjaPy
		pdmLock    = "[metadata]\ngroups = [\"default\"]\n\n[[package]]\nname = \"lib\"\nversion = \"0.1.0\"\npath = \"../lib\"\n\n" + jinjaPy
		image      = "FROM python:3.12\nWORKDIR /src\nCOPY . .\nWORKDIR /src/app\nRUN uv sync --locked\n"
	)
	tests := []struct {
		name  string
		files map[string]string
		want  bool // jinja2 resolved
	}{
		{"uv, sibling with setup.py", map[string]string{"app/uv.lock": uvLock, "app/install.sh": "#!/bin/sh\nuv sync --locked\n",
			"lib/pyproject.toml": lib + "\"setuptools.build_meta\"\n", "lib/setup.py": setupPy}, false},
		{"uv, sibling a script writes into", map[string]string{"app/uv.lock": uvLock,
			"app/install.sh": "#!/bin/sh\nmkdir -p ../lib/gen\nuv sync --locked\n", "lib/pyproject.toml": lib + "\"hatchling.build\"\n"}, false},
		{"uv, sibling named by an absolute path", map[string]string{"app/uv.lock": uvLock,
			"app/install.sh": "#!/bin/sh\nmkdir -p /opt/lib/gen\nuv sync --locked\n", "lib/pyproject.toml": lib + "\"hatchling.build\"\n"}, false},
		{"uv, sibling copied in with setup.py", map[string]string{"app/uv.lock": uvLock, "Dockerfile": image,
			"lib/pyproject.toml": lib + "\"setuptools.build_meta\"\n", "lib/setup.py": setupPy}, false},
		{"uv, sibling left out of the image", map[string]string{"app/uv.lock": uvLock, "lib/pyproject.toml": lib + "\"uv_build\"\n",
			"Dockerfile": "FROM python:3.12\nWORKDIR /src/app\nCOPY app .\nRUN uv sync --locked\n"}, false},
		{"poetry, sibling with setup.py", map[string]string{"app/poetry.lock": poetryLock, "app/install.sh": "#!/bin/sh\npoetry install\n",
			"lib/setup.py": setupPy}, false},

		{"uv, sibling with uv_build", map[string]string{"app/uv.lock": uvLock, "app/install.sh": "#!/bin/sh\nuv sync --locked\n",
			"lib/pyproject.toml": lib + "\"uv_build\"\n"}, true},
		{"uv, sibling copied in clean", map[string]string{"app/uv.lock": uvLock, "Dockerfile": image,
			"lib/pyproject.toml": lib + "\"flit_core.buildapi\"\n"}, true},
		{"poetry, sibling with poetry-core", map[string]string{"app/poetry.lock": poetryLock, "app/install.sh": "#!/bin/sh\npoetry install\n",
			"lib/pyproject.toml": lib + "\"poetry.core.masonry.api\"\n"}, true},
		{"pdm, sibling with flit_core", map[string]string{"app/pdm.lock": pdmLock, "app/install.sh": "#!/bin/sh\npdm sync\n",
			"lib/pyproject.toml": lib + "\"flit_core.buildapi\"\n"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"app/pyproject.toml": project}
			for k, v := range tt.files {
				files[k] = v
			}
			r := resolveVersion(t, writeTree(t, files), "jinja2")
			if !r.Found || r.Match.Resolved != tt.want || r.Partiality.Complete != tt.want {
				t.Fatalf("jinja2 = %+v partiality %+v, want resolved and complete %v", r.Match, r.Partiality, tt.want)
			}
		})
	}
}

// A build also runs code from the tree through what it reads beyond the lock: a build
// requirement uv lowers through tool.uv.sources or one written as a direct reference, a
// pylock.toml pdm prefers to pdm.lock, a manifest mounted into the image, or the parents of a
// directory reached through a symlink, which a tool walks physically. Each withholds; the
// same files without the channel still resolve.
func TestResolveVersions_BuildInputs(t *testing.T) {
	const (
		project = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"jinja2>=3.1\"]\n"
		setupPy = "import subprocess\nsubprocess.run([\"pip\", \"install\", \"jinja2==3.1.2\"])\n"
		jinjaUV = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
		jinjaPy = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\n"
		uvBuild = "[build-system]\nrequires = [\"uv_build\"]\nbuild-backend = \"uv_build\"\n"
		helper  = "[build-system]\nrequires = [\"uv_build\", \"helper\"]\nbuild-backend = \"uv_build\"\n"
		pylock  = "lock-version = \"1.0\"\ncreated-by = \"pdm\"\n[[packages]]\nname = \"jinja2\"\nversion = \"3.1.2\"\n"
		pdmLock = "[metadata]\ngroups = [\"default\"]\n\n" + jinjaPy
		uvSync  = "#!/bin/sh\nuv sync --locked\n"
		pdmPy   = project + "[tool.pdm]\ndistribution = false\n[tool.pdm.lock]\nformat = \"pylock\"\n"
	)
	uvLock := func(extra string) string {
		return "version = 1\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n\n" + extra + jinjaUV
	}
	lib := uvLock("[[package]]\nname = \"lib\"\nversion = \"0.1.0\"\nsource = { directory = \"lib\" }\n\n")
	evil := uvLock("[[package]]\nname = \"evil\"\nversion = \"0.1.0\"\nsource = { editable = \"evil\" }\n\n")
	member := "[project]\nname = \"lib\"\nversion = \"1\"\n"
	nested := uvLock("[[package]]\nname = \"lib\"\nversion = \"0.1.0\"\nsource = { directory = \"libs/lib\" }\n\n")
	underWorkspace := map[string]string{"pyproject.toml": project, "uv.lock": nested, "libs/lib/pyproject.toml": member + helper,
		"libs/pyproject.toml": "[project]\nname = \"libs\"\nversion = \"1\"\n[tool.uv.workspace]\nmembers = [\"lib\"]\n" +
			"[tool.uv.sources]\nhelper = { path = \"../helper\" }\n", "helper/setup.py": setupPy}
	with := func(files map[string]string, k, v string) map[string]string {
		out := maps.Clone(files)
		out[k] = v
		return out
	}
	pdmSource := func(url string) string {
		return project + "[tool.pdm]\ndistribution = false\n[[tool.pdm.source]]\nname = \"x\"\nurl = \"" + url + "\"\n"
	}
	tests := []struct {
		name  string
		files map[string]string
		links map[string]string // a symlink at each key to the path its value names from root
		want  bool              // jinja2 resolved
	}{
		{"uv, root build requirement in tool.uv.sources", map[string]string{"pyproject.toml": project + helper +
			"[tool.uv.sources]\nhelper = { path = \"helper\" }\n", "uv.lock": uvLock(""), "install.sh": uvSync, "helper/setup.py": setupPy}, nil, false},
		{"uv, member build requirement in its tool.uv.sources", map[string]string{"pyproject.toml": project, "uv.lock": lib, "install.sh": uvSync,
			"lib/pyproject.toml": member + helper + "[tool.uv.sources]\nhelper = { path = \"../helper\" }\n", "helper/setup.py": setupPy}, nil, false},
		{"uv, member build requirement in the root's tool.uv.sources", map[string]string{"pyproject.toml": project +
			"[tool.uv.sources]\nHelper_ = { path = \"helper\" }\n", "uv.lock": lib, "install.sh": uvSync,
			"lib/pyproject.toml": member + helper, "helper/setup.py": setupPy}, nil, false},
		{"uv, member build requirement as a direct reference", map[string]string{"pyproject.toml": project, "uv.lock": lib, "install.sh": uvSync,
			"lib/pyproject.toml": member + "[build-system]\nrequires = [\"uv_build\", \"helper @ file:///app/helper\"]\nbuild-backend = \"uv_build\"\n",
			"helper/setup.py":    setupPy}, nil, false},
		{"uv, member build requirements not a list", map[string]string{"pyproject.toml": project, "uv.lock": lib, "install.sh": uvSync,
			"lib/pyproject.toml": member + "[build-system]\nrequires = \"uv_build\"\nbuild-backend = \"uv_build\"\n"}, nil, false},
		{"uv, extra-build-dependencies in the manifest", map[string]string{"pyproject.toml": project + uvBuild +
			"[tool.uv.extra-build-dependencies]\napp = [\"helper\"]\n", "uv.lock": uvLock(""), "install.sh": uvSync}, nil, false},
		{"uv, extra-build-dependencies in uv.toml", map[string]string{"pyproject.toml": project + uvBuild,
			"uv.toml": "[extra-build-dependencies]\napp = [\"helper\"]\n", "uv.lock": uvLock(""), "install.sh": uvSync}, nil, false},
		{"pdm, pylock.toml written by the script", map[string]string{"pyproject.toml": pdmPy, "pdm.lock": pdmLock,
			"ci/lock.data": pylock, "install.sh": "#!/bin/sh\ncp ci/lock.data pylock.toml\npdm sync\n"}, nil, false},
		{"pdm, pylock.toml copied into the image", map[string]string{"pyproject.toml": pdmPy, "pdm.lock": pdmLock, "ci/lock.data": pylock,
			"Dockerfile": "FROM python:3.12\nWORKDIR /app\nCOPY pyproject.toml pdm.lock ./\nCOPY ci/lock.data pylock.toml\nRUN pdm sync\n"}, nil, false},
		{"pdm, absolute subdirectory", map[string]string{"pyproject.toml": project, "install.sh": "#!/bin/sh\npdm sync\n",
			"pdm.lock":                "[metadata]\ngroups = [\"default\"]\n\n[[package]]\nname = \"lib\"\nversion = \"0.1.0\"\npath = \"./repo\"\nsubdirectory = \"/abs\"\n\n" + jinjaPy,
			"repo/abs/pyproject.toml": member + "[build-system]\nrequires = [\"x\"]\nbuild-backend = \"flit_core.buildapi\"\n"}, nil, false},
		{"uv, run through a symlinked directory", map[string]string{"app/pyproject.toml": project + uvBuild, "app/uv.lock": uvLock(""),
			"install.sh": "#!/bin/sh\ncd app/link\nuv sync --locked\n", "ws/pyproject.toml": project + "[tool.uv.workspace]\nmembers = []\n",
			"ws/uv.lock": evil, "ws/m/x.txt": "x\n", "ws/evil/setup.py": setupPy}, map[string]string{"app/link": "ws/m"}, false},
		{"uv, image workdir through a symlinked directory", map[string]string{"app/pyproject.toml": project + uvBuild, "app/uv.lock": uvLock(""),
			"Dockerfile":        "FROM python:3.12\nWORKDIR /src\nCOPY . .\nWORKDIR /src/app/link\nRUN uv sync --locked\n",
			"ws/pyproject.toml": project + "[tool.uv.workspace]\nmembers = []\n", "ws/uv.lock": evil, "ws/m/x.txt": "x\n", "ws/evil/setup.py": setupPy},
			map[string]string{"app/link": "ws/m"}, false},
		{"uv, workspace root mounted above a member", map[string]string{"packages/lib/pyproject.toml": project + uvBuild, "packages/lib/uv.lock": uvLock(""),
			"Dockerfile": "FROM python:3.12\nCOPY packages/lib /app/packages/lib\nWORKDIR /app/packages/lib\n" +
				"RUN --mount=type=bind,source=ci/pyproject.toml,target=/app/pyproject.toml --mount=type=bind,source=ci/uv.lock,target=/app/uv.lock " +
				"--mount=type=bind,source=ci/evil,target=/app/evil uv sync --locked\n",
			"ci/pyproject.toml": project + "[tool.uv.workspace]\nmembers = [\"packages/*\"]\n", "ci/uv.lock": evil, "ci/evil/setup.py": setupPy}, nil, false},
		{"poetry, manifest mounted over the one copied", map[string]string{"pyproject.toml": project, "poetry.lock": jinjaPy,
			"ci/pyproject.toml": project + "[tool.poetry]\nbuild = \"build.py\"\n",
			"Dockerfile":        "FROM python:3.12\nWORKDIR /app\nCOPY . .\nRUN --mount=type=bind,source=ci/pyproject.toml,target=/app/pyproject.toml poetry install\n"}, nil, false},
		{"uv, a source under a workspace root between it and the manifest", with(underWorkspace, "install.sh", uvSync), nil, false},
		{"uv, a source under a workspace root copied into the image", with(underWorkspace, "Dockerfile",
			"FROM python:3.12\nWORKDIR /app\nCOPY . .\nRUN uv sync --locked\n"), nil, false},
		{"uv, extra-build-dependencies in a root uv does not build", map[string]string{"pyproject.toml": project +
			"[tool.uv.extra-build-dependencies]\nlib = [\"helper\"]\n", "uv.lock": lib, "install.sh": uvSync, "lib/pyproject.toml": member + uvBuild}, nil, false},
		{"uv, extra-build-dependencies in a virtual root", map[string]string{"pyproject.toml": project + uvBuild +
			"[tool.uv]\npackage = false\n[tool.uv.extra-build-dependencies]\nlib = [\"helper\"]\n", "uv.lock": lib, "install.sh": uvSync,
			"lib/pyproject.toml": member + uvBuild}, nil, false},
		{"uv, find-links into the tree", map[string]string{"pyproject.toml": project + uvBuild + "[tool.uv]\nfind-links = [\"wheels\"]\n",
			"uv.lock": uvLock(""), "install.sh": uvSync}, nil, false},
		{"uv, an index served from the tree", map[string]string{"pyproject.toml": project + uvBuild +
			"[[tool.uv.index]]\nname = \"local\"\nurl = \"./idx\"\n", "uv.lock": uvLock(""), "install.sh": uvSync}, nil, false},
		{"uv, extra-build-variables", map[string]string{"pyproject.toml": project + uvBuild +
			"[tool.uv.extra-build-variables]\napp = { PYTHONPATH = \"hack\" }\n", "uv.lock": uvLock(""), "install.sh": uvSync}, nil, false},
		{"uv, an override as a direct reference", map[string]string{"pyproject.toml": project + uvBuild +
			"[tool.uv]\noverride-dependencies = [\"uv_build @ file:///app/hack\"]\n", "uv.lock": uvLock(""), "install.sh": uvSync}, nil, false},
		{"uv, member find-links into the tree", map[string]string{"pyproject.toml": project, "uv.lock": lib, "install.sh": uvSync,
			"lib/pyproject.toml": member + uvBuild + "[tool.uv]\nfind-links = [\"../wheels\"]\n"}, nil, false},
		{"pdm, a source served from the tree", map[string]string{"pyproject.toml": pdmSource("file:///app/wheels"), "pdm.lock": pdmLock,
			"install.sh": "#!/bin/sh\npdm sync\n"}, nil, false},
		{"uv, uv.toml above the manifest", map[string]string{"app/pyproject.toml": project + uvBuild, "app/uv.lock": uvLock(""),
			"uv.toml": "native-tls = true\n", "install.sh": "#!/bin/sh\ncd app\nuv sync --locked\n"}, nil, false},
		{"uv, a uv config copied into the image under another name", map[string]string{"pyproject.toml": project + uvBuild, "uv.lock": uvLock(""),
			"ci/settings": "native-tls = true\n", "Dockerfile": "FROM python:3.12\nWORKDIR /app\nCOPY . .\nCOPY ci/settings /etc/uv/uv.toml\nRUN uv sync --locked\n"},
			nil, false},
		{"uv, find-links in a pyproject.toml above the manifest", map[string]string{"app/pyproject.toml": project + uvBuild, "app/uv.lock": uvLock(""),
			"pyproject.toml": "[tool.uv]\nfind-links = [\"wheels\"]\n", "install.sh": "#!/bin/sh\ncd app\nuv sync --locked\n"}, nil, false},
		{"uv, extra-build-variables in a pyproject.toml above the manifest in an image", map[string]string{"app/pyproject.toml": project + uvBuild,
			"app/uv.lock": uvLock(""), "pyproject.toml": "[tool.uv.extra-build-variables]\napp = { PYTHONPATH = \"hack\" }\n",
			"Dockerfile": "FROM python:3.12\nCOPY . /src\nWORKDIR /src/app\nRUN uv sync --locked\n"}, nil, false},
		{"pdm, an override served from the tree", map[string]string{"pyproject.toml": project + "[tool.pdm]\ndistribution = false\n" +
			"[tool.pdm.resolution.overrides]\npdm-backend = \"file:///${PROJECT_ROOT}/be\"\n", "pdm.lock": pdmLock, "install.sh": "#!/bin/sh\npdm sync\n"}, nil, false},
		{"pdm, tool.pdm.options turning off build isolation", map[string]string{"pyproject.toml": pdmPy +
			"[tool.pdm.options]\nsync = [\"--no-isolation\"]\n", "pdm.lock": pdmLock, "install.sh": "#!/bin/sh\npdm sync\n"}, nil, false},
		{"pdm, pdm.toml beside the manifest", map[string]string{"pyproject.toml": pdmPy, "pdm.lock": pdmLock,
			"pdm.toml": "build_isolation = false\n", "install.sh": "#!/bin/sh\npdm sync\n"}, nil, false},
		{"pdm, .pdm.toml beside the manifest", map[string]string{"pyproject.toml": pdmPy, "pdm.lock": pdmLock,
			".pdm.toml": "build_isolation = false\n", "install.sh": "#!/bin/sh\npdm sync\n"}, nil, false},
		{"pdm, a user config copied into the image", map[string]string{"pyproject.toml": pdmPy, "pdm.lock": pdmLock, "ci/pdm.cfg": "build_isolation = false\n",
			"Dockerfile": "FROM python:3.12\nWORKDIR /app\nCOPY . .\nCOPY ci/pdm.cfg /root/.config/pdm/config.toml\nRUN pdm sync\n"}, nil, false},
		{"pdm, a site config copied into the image", map[string]string{"pyproject.toml": pdmPy, "pdm.lock": pdmLock, "ci/pdm.cfg": "build_isolation = false\n",
			"Dockerfile": "FROM python:3.12\nWORKDIR /app\nCOPY . .\nCOPY ci/pdm.cfg /etc/xdg/pdm/config.toml\nRUN pdm sync\n"}, nil, false},
		{"pdm, the config directory moved by the script", map[string]string{"pyproject.toml": pdmPy, "pdm.lock": pdmLock, "ci/pdm.cfg": "build_isolation = false\n",
			"install.sh": "#!/bin/sh\nexport XDG_CONFIG_HOME=/app/ci\npdm sync\n"}, nil, false},
		{"pdm, a Windows user config", map[string]string{"pyproject.toml": pdmPy, "pdm.lock": pdmLock, "ci/pdm.cfg": "build_isolation = false\n",
			"install.sh": "#!/bin/sh\ncp ci/pdm.cfg \"$LOCALAPPDATA/pdm/pdm/config.toml\"\npdm sync\n"}, nil, false},
		{"pdm, a macOS user config", map[string]string{"pyproject.toml": pdmPy, "pdm.lock": pdmLock, "ci/pdm.cfg": "build_isolation = false\n",
			"install.sh": "#!/bin/sh\ncp ci/pdm.cfg \"$HOME/Library/Application Support/pdm/config.toml\"\npdm sync\n"}, nil, false},
		{"uv, the config directory moved by the script", map[string]string{"pyproject.toml": project + uvBuild, "uv.lock": uvLock(""),
			"ci/settings": "native-tls = true\n", "install.sh": "#!/bin/sh\nexport XDG_CONFIG_HOME=/opt/conf\nuv sync --locked\n"}, nil, false},
		{"uv, an index that is not a list", map[string]string{"pyproject.toml": project + uvBuild +
			"[tool.uv]\nindex = \"https://idx.example/simple\"\n", "uv.lock": uvLock(""), "install.sh": uvSync}, nil, false},
		{"uv, an inline index entry that is not a table", map[string]string{"pyproject.toml": project + uvBuild +
			"[tool.uv]\nindex = [\"https://idx.example/simple\"]\n", "uv.lock": uvLock(""), "install.sh": uvSync}, nil, false},
		{"uv, an index with no url", map[string]string{"pyproject.toml": project + uvBuild +
			"[[tool.uv.index]]\nname = \"x\"\n", "uv.lock": uvLock(""), "install.sh": uvSync}, nil, false},
		{"uv, overrides that are not a list", map[string]string{"pyproject.toml": project + uvBuild +
			"[tool.uv]\noverride-dependencies = \"uv_build @ file:///app/hack\"\n", "uv.lock": uvLock(""), "install.sh": uvSync}, nil, false},
		{"uv, a lock source of two kinds", map[string]string{"pyproject.toml": project, "install.sh": uvSync,
			"uv.lock":             uvLock("[[package]]\nname = \"evil\"\nversion = \"0.1.0\"\nsource = { registry = \"https://pypi.org/simple\", editable = \"evil\" }\n\n"),
			"evil/pyproject.toml": member, "evil/setup.py": setupPy}, nil, false},
		{"uv, member with flit_core and a dynamic description", map[string]string{"pyproject.toml": project, "uv.lock": lib, "install.sh": uvSync,
			"lib/pyproject.toml": "[project]\nname = \"lib\"\nversion = \"1\"\ndynamic = [\"description\"]\n" +
				"[build-system]\nrequires = [\"flit_core\"]\nbuild-backend = \"flit_core.buildapi\"\n"}, nil, false},
		{"uv, no lock beside the manifest", map[string]string{"app/pyproject.toml": project + uvBuild, "uv.lock": uvLock(""),
			"install.sh": "#!/bin/sh\ncd app\nuv sync --locked\n"}, nil, false},

		{"uv, build requirements from the index beside unrelated sources", map[string]string{"pyproject.toml": project + helper +
			"[tool.uv.sources]\nother = { path = \"other\" }\n", "uv.lock": uvLock(""), "install.sh": uvSync}, nil, true},
		{"uv, uv.toml that holds no build requirements, which the walk does not read", map[string]string{"pyproject.toml": project + uvBuild,
			"uv.toml": "native-tls = true\n", "uv.lock": uvLock(""), "install.sh": uvSync}, nil, false},
		{"pdm, pylock format with none written", map[string]string{"pyproject.toml": pdmPy, "pdm.lock": pdmLock,
			"install.sh": "#!/bin/sh\npdm sync\n"}, nil, true},
		{"uv, a source under a directory that declares no workspace", with(with(underWorkspace, "install.sh", uvSync),
			"libs/pyproject.toml", "[project]\nname = \"libs\"\nversion = \"1\"\n"), nil, true},
		{"uv, indexes over https and settings that leave the build alone", map[string]string{"pyproject.toml": project + uvBuild +
			"[tool.uv]\nindex-url = \"https://pypi.example/simple\"\nfind-links = [\"https://pypi.example/wheels\"]\n" +
			"constraint-dependencies = [\"markupsafe<3\"]\nnative-tls = true\n[[tool.uv.index]]\nname = \"x\"\nurl = \"https://idx.example/simple\"\n",
			"uv.lock": uvLock(""), "install.sh": uvSync}, nil, true},
		{"uv, an inline index table over https", map[string]string{"pyproject.toml": project + uvBuild +
			"[tool.uv]\nindex = [{ name = \"x\", url = \"https://idx.example/simple\" }]\n", "uv.lock": uvLock(""), "install.sh": uvSync}, nil, true},
		{"uv, a pyproject.toml above the manifest with settings that leave the build alone", map[string]string{"app/pyproject.toml": project + uvBuild,
			"app/uv.lock": uvLock(""), "pyproject.toml": "[project]\nname = \"top\"\nversion = \"1\"\n[tool.uv]\nnative-tls = true\n",
			"install.sh": "#!/bin/sh\ncd app\nuv sync --locked\n"}, nil, true},
		{"pdm, a source over https", map[string]string{"pyproject.toml": pdmSource("https://pypi.example/simple"), "pdm.lock": pdmLock,
			"install.sh": "#!/bin/sh\npdm sync\n"}, nil, true},
		{"uv, a symlink off the path the build runs in", map[string]string{"app/pyproject.toml": project + uvBuild, "app/uv.lock": uvLock(""),
			"install.sh": "#!/bin/sh\ncd app\nuv sync --locked\n", "ws/x.txt": "x\n"}, map[string]string{"docs": "ws"}, true},
		{"uv, a cache mounted in the image", map[string]string{"pyproject.toml": project + uvBuild, "uv.lock": uvLock(""),
			"Dockerfile": "FROM python:3.12\nWORKDIR /app\nCOPY . .\nRUN --mount=type=cache,target=/root/.cache/uv uv sync --locked\n"}, nil, true},
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
