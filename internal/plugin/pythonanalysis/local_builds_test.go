package pythonanalysis

import "testing"

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
