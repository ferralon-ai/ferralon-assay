package pythonanalysis

import "testing"

// uv sync, poetry install and pdm sync build and install the root project, so code from the
// tree that runs in that build, or a plugin the tool loads, may install a package the lock
// does not name: each withholds every pin, while a root built by a backend that runs nothing
// from the tree still resolves.
func TestResolveVersions_RootBuild(t *testing.T) {
	const (
		project = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"jinja2>=3.1\"]\n"
		lockUV  = "version = 1\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\nsource = { editable = \".\" }\n\n" +
			"[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\nsource = { registry = \"https://pypi.org/simple\" }\n"
		lockPoetry = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\n"
		lockPDM    = "[metadata]\ngroups = [\"default\"]\n\n[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\n"
		setupPy    = "import subprocess\nsubprocess.run([\"pip\", \"install\", \"jinja2==3.1.2\"])\n"
		hook       = "def pdm_build_initialize(context):\n    pass\n"
	)
	backend := func(b string) string {
		return project + "[build-system]\nrequires = [\"x\"]\nbuild-backend = \"" + b + "\"\n"
	}
	locks := map[string][2]string{
		"uv":     {"uv.lock", lockUV},
		"poetry": {"poetry.lock", lockPoetry},
		"pdm":    {"pdm.lock", lockPDM},
	}
	commands := map[string]string{"uv": "uv sync --locked", "poetry": "poetry install", "pdm": "pdm sync"}
	// before is what install.sh runs ahead of the install, by row.
	before := map[string]string{
		"pdm, .pdm-plugins written by the script":           "mkdir -p .pdm-plugins\n",
		"poetry, .poetry/plugins written by the script":     "mkdir -p .poetry/plugins\n",
		"poetry, a script naming another plugins directory": "pytest tests/plugins\n",
	}
	tests := []struct {
		name, tool, pyproject string
		files                 map[string]string // more files in the tree
		dockerfile            string            // when set, the build is this Dockerfile instead of install.sh
		want                  bool              // jinja2 resolved
	}{
		// poetry: a build script, plugins it installs or loads.
		{"poetry, build script", "poetry", project + "[tool.poetry]\nbuild = \"build.py\"\n", map[string]string{"build.py": setupPy}, "", false},
		{"poetry, build script table", "poetry", project + "[tool.poetry.build]\nscript = \"build.py\"\n", map[string]string{"build.py": setupPy}, "", false},
		{"poetry, requires-plugins", "poetry", project + "[tool.poetry.requires-plugins]\npoetry-plugin-export = \">=1.8\"\n", nil, "", false},
		{"poetry, .poetry/plugins committed", "poetry", project, map[string]string{".poetry/plugins/p.py": "x = 1\n"}, "", false},
		{"poetry, .poetry/plugins copied in", "poetry", project, map[string]string{".poetry/plugins/p.py": "x = 1\n"},
			"FROM python:3.12\nWORKDIR /app\nCOPY . .\nRUN poetry install\n", false},
		{"poetry, .poetry/plugins written by the script", "poetry", project, nil, "", false},

		// pdm: in-tree plugins, then the root's PEP 517 backend.
		{"pdm, .pdm-plugins", "pdm", project, map[string]string{".pdm-plugins/lib/p.py": "x = 1\n"}, "", false},
		{"pdm, setup.py, no build-system", "pdm", project, map[string]string{"setup.py": setupPy}, "", false},
		{"pdm, setuptools with setup.py", "pdm", backend("setuptools.build_meta"), map[string]string{"setup.py": setupPy}, "", false},
		{"pdm, legacy setuptools with setup.py", "pdm", backend("setuptools.build_meta:__legacy__"), map[string]string{"setup.py": setupPy}, "", false},
		{"pdm, backend-path", "pdm", project + "[build-system]\nrequires = []\nbuild-backend = \"flit_core.buildapi\"\nbackend-path = [\"_build\"]\n", nil, "", false},
		{"pdm, unknown backend", "pdm", backend("maturin"), nil, "", false},
		{"pdm, pdm-backend with pdm_build.py", "pdm", backend("pdm.backend"), map[string]string{"pdm_build.py": hook}, "", false},
		{"pdm, pdm-backend custom-hook", "pdm", backend("pdm.backend") + "[tool.pdm.build]\ncustom-hook = \"hooks.py\"\n", nil, "", false},
		{"pdm, pdm-backend run-setuptools", "pdm", backend("pdm.backend") + "[tool.pdm.build]\nrun-setuptools = true\n", nil, "", false},
		{"pdm, hatchling build hook", "pdm", backend("hatchling.build") + "[tool.hatch.build.hooks.custom]\n", nil, "", false},
		{"pdm, hatchling target hook", "pdm", backend("hatchling.build") + "[tool.hatch.build.targets.wheel.hooks.vcs]\n", nil, "", false},
		{"pdm, hatchling metadata hook", "pdm", backend("hatchling.build") + "[tool.hatch.metadata.hooks.custom]\n", nil, "", false},
		{"pdm, hatchling with hatch_build.py", "pdm", backend("hatchling.build"), map[string]string{"hatch_build.py": hook}, "", false},
		{"pdm, hatchling with a hook in hatch.toml", "pdm", backend("hatchling.build"),
			map[string]string{"hatch.toml": "[build.hooks.custom]\npath = \"tools/hook.py\"\n", "tools/hook.py": hook}, "", false},
		{"pdm, setuptools cmdclass", "pdm", backend("setuptools.build_meta") + "[tool.setuptools.cmdclass]\nbuild_py = \"tools.b:B\"\n", nil, "", false},
		{"pdm, setuptools with a setup.cfg cmdclass", "pdm", backend("setuptools.build_meta"),
			map[string]string{"setup.cfg": "[options]\ncmdclass =\n    build_py = tools.b:B\n"}, "", false},
		{"pdm, library package-type over distribution false", "pdm", project + "[tool.pdm]\npackage-type = \"library\"\ndistribution = false\n",
			map[string]string{"setup.py": setupPy}, "", false},
		{"pdm, poetry-core build script", "pdm", backend("poetry.core.masonry.api") + "[tool.poetry]\nbuild = \"build.py\"\n", nil, "", false},
		{"pdm, setup.py copied in", "pdm", project, map[string]string{"setup.py": setupPy},
			"FROM python:3.12\nWORKDIR /app\nCOPY pyproject.toml pdm.lock setup.py ./\nRUN pdm sync\n", false},
		{"pdm, a stage copied to .pdm-plugins", "pdm", project, nil,
			"FROM python:3.12 AS b\nFROM python:3.12\nWORKDIR /app\nCOPY pyproject.toml pdm.lock ./\nCOPY --from=b /p .pdm-plugins\nRUN pdm sync\n", false},
		{"pdm, plugins copied to .pdm-plugins", "pdm", project, map[string]string{"plugins/p.py": "x = 1\n"},
			"FROM python:3.12\nWORKDIR /app\nCOPY pyproject.toml pdm.lock ./\nCOPY plugins .pdm-plugins/lib\nRUN pdm sync\n", false},
		{"pdm, .pdm-plugins written by the script", "pdm", project, nil, "", false},
		{"pdm, setup.py from a stage built on the source", "pdm", project, map[string]string{"setup.py": setupPy},
			"FROM python:3.12 AS src\nWORKDIR /app\nCOPY . .\nFROM src\nWORKDIR /app\nCOPY pyproject.toml pdm.lock ./\nRUN pdm sync\n", false},
		{"pdm, setup.py copied to a destination not known", "pdm", project, map[string]string{"setup.py": setupPy},
			"FROM python:3.12\nARG D=/app\nWORKDIR /app\nCOPY setup.py $D/\nCOPY pyproject.toml pdm.lock ./\nRUN pdm sync\n", false},
		{"pdm, the context bind-mounted beside the manifest", "pdm", project, map[string]string{"setup.py": setupPy},
			"FROM python:3.12\nWORKDIR /app\nCOPY pyproject.toml pdm.lock ./\nRUN --mount=type=bind,source=.,target=/app pdm sync\n", false},
		{"pdm, .pdm-plugins when distribution is false", "pdm", project + "[tool.pdm]\ndistribution = false\n", map[string]string{".pdm-plugins/lib/p.py": "x = 1\n"}, "", false},

		// uv: the root's PEP 517 backend.
		{"uv, setuptools with setup.py", "uv", backend("setuptools.build_meta"), map[string]string{"setup.py": setupPy}, "", false},
		{"uv, unknown backend", "uv", backend("scikit_build_core.build"), nil, "", false},
		{"uv, package forced on with setup.py", "uv", project + "[tool.uv]\npackage = true\n", map[string]string{"setup.py": setupPy}, "", false},

		// Guards: a backend that runs nothing from the tree, or no root build.
		{"poetry, setup.py its builder never runs", "poetry", backend("poetry.core.masonry.api"), map[string]string{"setup.py": setupPy}, "", true},
		{"pdm, no build-system and no setup.py", "pdm", project, nil, "", true},
		{"pdm, setuptools without setup.py", "pdm", backend("setuptools.build_meta"), nil, "", true},
		{"pdm, pdm-backend", "pdm", backend("pdm.backend"), nil, "", true},
		{"pdm, hatchling", "pdm", backend("hatchling.build") + "[tool.hatch.build.targets.wheel]\npackages = [\"src/app\"]\n", nil, "", true},
		{"pdm, flit_core", "pdm", backend("flit_core.buildapi"), nil, "", true},
		{"pdm, poetry-core", "pdm", backend("poetry.core.masonry.api"), nil, "", true},
		{"pdm, distribution false with setup.py", "pdm", project + "[tool.pdm]\ndistribution = false\n", map[string]string{"setup.py": setupPy}, "", true},
		{"pdm, setup.py left out of the image", "pdm", project, map[string]string{"setup.py": setupPy},
			"FROM python:3.12\nWORKDIR /app\nCOPY pyproject.toml pdm.lock ./\nRUN pdm sync\n", true},
		{"pdm, whole context copied with nothing there", "pdm", project, nil,
			"FROM python:3.12\nWORKDIR /app\nCOPY . .\nRUN --mount=type=cache,target=/root/.cache/pdm pdm sync\n", true},
		{"pdm, application package-type with setup.py", "pdm", project + "[tool.pdm]\npackage-type = \"application\"\n",
			map[string]string{"setup.py": setupPy}, "", true},
		{"poetry, a script naming another plugins directory", "poetry", project, nil, "", true},
		{"uv, no build-system with setup.py", "uv", project, map[string]string{"setup.py": setupPy}, "", true},
		{"uv, uv_build with a stub setup.py", "uv", backend("uv_build"), map[string]string{"setup.py": setupPy}, "", true},
		{"uv, package false with setup.py", "uv", project + "[tool.uv]\npackage = false\n", map[string]string{"setup.py": setupPy}, "", true},
		{"uv, package false over a build-system with setup.py", "uv", backend("setuptools.build_meta") + "[tool.uv]\npackage = false\n",
			map[string]string{"setup.py": setupPy}, "", true},
		{"uv, setuptools without setup.py", "uv", backend("setuptools.build_meta"), nil, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lock := locks[tt.tool]
			files := map[string]string{"pyproject.toml": tt.pyproject, lock[0]: lock[1]}
			switch {
			case tt.dockerfile != "":
				files["Dockerfile"] = tt.dockerfile
			default:
				files["install.sh"] = "#!/bin/sh\n" + before[tt.name] + commands[tt.tool] + "\n"
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
