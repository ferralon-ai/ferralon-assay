package pythonanalysis

import "testing"

// poetry and pdm read settings from a config file and POETRY_*/PDM_* variables: one that only
// moves where and how the tool makes the environment leaves the lock's pins standing, while one
// that names an index, a build setting or a key past the allow-list withholds them.
func TestResolveVersions_ToolConfig(t *testing.T) {
	const (
		project    = "[project]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"jinja2>=3.1\"]\n"
		poetryCore = project + "[build-system]\nrequires = [\"poetry-core\"]\nbuild-backend = \"poetry.core.masonry.api\"\n"
		lockPoetry = "[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\n"
		lockPDM    = "[metadata]\ngroups = [\"default\"]\n\n[[package]]\nname = \"jinja2\"\nversion = \"3.1.4\"\n"
	)
	source := func(s string) string { return poetryCore + "[[tool.poetry.source]]\n" + s }
	tests := []struct {
		name, tool string
		pyproject  string            // defaults to poetryCore for poetry, project for pdm
		files      map[string]string // more files in the tree
		script     string            // install.sh, or a Dockerfile when it starts with FROM
		want       bool              // jinja2 resolved
	}{
		// Config files in the tree.
		{"poetry.toml, environment settings", "poetry", "",
			map[string]string{"poetry.toml": "[virtualenvs]\nin-project = true\ncreate = false\n[installer]\nparallel = true\n"}, "poetry install", true},
		{"poetry.toml, dotted keys", "poetry", "", map[string]string{"poetry.toml": "virtualenvs.in-project = true\n"}, "poetry install", true},
		{"poetry.toml, installer.no-binary", "poetry", "", map[string]string{"poetry.toml": "[installer]\nno-binary = [\":all:\"]\n"}, "poetry install", false},
		{"poetry.toml, a repository", "poetry", "", map[string]string{"poetry.toml": "[repositories.x]\nurl = \"https://x.test/simple\"\n"}, "poetry install", false},
		{"poetry.toml, an unknown key", "poetry", "", map[string]string{"poetry.toml": "[virtualenvs]\nfuture = 1\n"}, "poetry install", false},
		{"poetry.toml, a table where a setting is", "poetry", "", map[string]string{"poetry.toml": "[virtualenvs.create]\nx = 1\n"}, "poetry install", false},
		{"poetry.toml, undecodable", "poetry", "", map[string]string{"poetry.toml": "[virtualenvs\n"}, "poetry install", false},
		{"poetry.toml in a subdirectory", "poetry", "", map[string]string{"sub/poetry.toml": "[installer]\nno-binary = [\":all:\"]\n"}, "poetry install", false},
		{"pypoetry/config.toml in the tree", "poetry", "", map[string]string{".config/pypoetry/config.toml": "[installer]\nno-binary = [\":all:\"]\n"}, "poetry install", false},
		{"pypoetry/auth.toml in the tree", "poetry", "", map[string]string{"cfg/pypoetry/auth.toml": "[http-basic.x]\nusername = \"u\"\n"}, "poetry install", false},
		{"pdm.toml, environment settings", "pdm", "", map[string]string{"pdm.toml": "[venv]\nin_project = true\n[python]\nuse_venv = true\n"}, "pdm sync", true},
		{"pdm.toml, an index", "pdm", "", map[string]string{"pdm.toml": "[pypi]\nurl = \"https://x.test/simple\"\n"}, "pdm sync", false},
		{"pdm.toml, use_uv", "pdm", "", map[string]string{"pdm.toml": "use_uv = true\n"}, "pdm sync", false},
		{".pdm.toml, an index", "pdm", "", map[string]string{".pdm.toml": "[pypi]\nurl = \"https://x.test/simple\"\n"}, "pdm sync", false},
		{".pdm.toml, environment settings", "pdm", "", map[string]string{".pdm.toml": "[venv]\nin_project = true\n"}, "pdm sync", true},
		{"pdm/config.toml in the tree", "pdm", "", map[string]string{"etc/pdm/config.toml": "[pypi]\nurl = \"https://x.test/simple\"\n"}, "pdm sync", false},

		// poetry config and pdm config in a script.
		{"poetry config, an environment setting", "poetry", "", nil, "poetry config virtualenvs.create false\npoetry install", true},
		{"poetry config --local", "poetry", "", nil, "poetry config --local virtualenvs.in-project true && poetry install", true},
		{"poetry config --unset", "poetry", "", nil, "poetry config --unset virtualenvs.path\npoetry install", true},
		{"poetry config, installer.no-binary", "poetry", "", nil, "poetry config installer.no-binary :all:\npoetry install", false},
		{"poetry config, a repository", "poetry", "", nil, "poetry config repositories.x https://x.test/simple\npoetry install", false},
		{"poetry config --list", "poetry", "", nil, "poetry config --list\npoetry install", false},
		{"poetry config, two values", "poetry", "", nil, "poetry config virtualenvs.create false true\npoetry install", false},
		{"poetry config, another flag", "poetry", "", nil, "poetry config --migrate virtualenvs.create false\npoetry install", false},
		{"pdm config, an environment setting", "pdm", "", nil, "pdm config venv.in_project true\npdm sync", true},
		{"pdm config -l", "pdm", "", nil, "pdm config -l python.use_venv false\npdm sync", true},
		{"pdm config, an index", "pdm", "", nil, "pdm config pypi.url https://x.test/simple\npdm sync", false},
		{"pdm config, no key", "pdm", "", nil, "pdm config\npdm sync", false},

		// POETRY_* variables.
		{"POETRY_VIRTUALENVS_CREATE", "poetry", "", nil, "export POETRY_VIRTUALENVS_CREATE=false\npoetry install", true},
		{"POETRY_VIRTUALENVS_IN_PROJECT", "poetry", "", nil, "export POETRY_VIRTUALENVS_IN_PROJECT=true\npoetry install", true},
		{"POETRY_HOME and POETRY_VERSION", "poetry", "", nil,
			"FROM python:3.12\nENV POETRY_HOME=/opt/poetry POETRY_VERSION=2.1.0 POETRY_NO_INTERACTION=1\nWORKDIR /app\nCOPY . .\nRUN poetry install\n", true},
		{"POETRY_INSTALLER_NO_BINARY", "poetry", "", nil, "export POETRY_INSTALLER_NO_BINARY=:all:\npoetry install", false},
		{"POETRY_REPOSITORIES_X_URL", "poetry", "", nil, "export POETRY_REPOSITORIES_X_URL=https://x.test/simple\npoetry install", false},
		{"POETRY_CONFIG_DIR", "poetry", "", nil, "export POETRY_CONFIG_DIR=/cfg\npoetry install", false},

		// A config the script names.
		{"user config copied in", "poetry", "", map[string]string{"cfg.toml": "x = 1\n"},
			"FROM python:3.12\nWORKDIR /app\nCOPY cfg.toml /root/.config/pypoetry/config.toml\nCOPY . .\nRUN poetry install\n", false},
		{"XDG_CONFIG_HOME moved", "poetry", "", nil, "export XDG_CONFIG_HOME=/cfg\npoetry install", false},
		{"pdm user config named", "pdm", "", nil, "cp cfg.toml ~/.config/pdm/config.toml\npdm sync", false},
		{"a config named, no poetry install", "poetry", "",
			map[string]string{"requirements.txt": "jinja2==3.1.4\n"}, "echo ~/.config/pypoetry/config.toml\npip install -r requirements.txt", true},
		{"a config named beside poetry config and poetry install", "poetry", "", nil, "poetry config virtualenvs.create false\necho poetry.toml\npoetry install", false},
		{"a config named, poetry config and no poetry install", "poetry", "", map[string]string{"requirements.txt": "jinja2==3.1.4\n"},
			"poetry config virtualenvs.create false\necho poetry.toml\npip install -r requirements.txt", true},
		{"pdm user config on Windows", "pdm", "", map[string]string{"ci/pdm.cfg": "[pypi]\nurl = \"https://x.test/simple\"\n"},
			"copy ci\\pdm.cfg %LOCALAPPDATA%\\pdm\\pdm\\config.toml\npdm sync", false},
		{"pdm site config on Windows", "pdm", "", map[string]string{"ci/pdm.cfg": "[pypi]\nurl = \"https://x.test/simple\"\n"},
			"copy ci\\pdm.cfg %PROGRAMDATA%\\pdm\\pdm\\config.toml\npdm sync", false},
		{"poetry config directory on Windows", "poetry", "", map[string]string{"ci/poetrycfg/cfg": "x"},
			"xcopy ci\\poetrycfg %APPDATA%\\pypoetry\\ /E\npoetry install", false},

		{"macOS config directory copied in", "poetry", "", map[string]string{"ci/poetrycfg/cfg": "x"},
			"cp -r ci/poetrycfg \"$HOME/Library/Application Support/pypoetry\"\npoetry install", false},
		{"macOS config directory copied in, shell-escaped", "poetry", "", map[string]string{"ci/poetrycfg/cfg": "x"},
			"cp -r ci/poetrycfg ~/Library/Application\\ Support/pypoetry\npoetry install", false},
		{"LOCALAPPDATA config directory copied in", "poetry", "", map[string]string{"ci/poetrycfg/cfg": "x"},
			"xcopy ci\\poetrycfg %LOCALAPPDATA%\\pypoetry\\ /E\npoetry install", false},
		{"ProgramData config directory copied in", "poetry", "", map[string]string{"ci/poetrycfg/cfg": "x"},
			"xcopy ci\\poetrycfg %PROGRAMDATA%\\pypoetry\\ /E\npoetry install", false},
		{"poetry config directory on Windows, braced", "poetry", "", map[string]string{"ci/poetrycfg/cfg": "x"},
			"cp -r ci/poetrycfg \"${APPDATA}/pypoetry\"\npoetry install", false},
		{"ProgramData config directory copied in, braced", "poetry", "", map[string]string{"ci/poetrycfg/cfg": "x"},
			"cp -r ci/poetrycfg ${PROGRAMDATA}/pypoetry\npoetry install", false},
		{"HOME moved", "poetry", "", nil, "FROM python:3.12\nENV HOME /cfg\nWORKDIR /app\nCOPY . .\nRUN poetry install\n", false},
		{"platformdirs' Windows override", "poetry", "", nil, "export WIN_PD_OVERRIDE_ROAMING_APPDATA=C:\\cfg\npoetry install", false},

		// tool.poetry.source.
		{"source over https", "poetry", source("name = \"x\"\nurl = \"https://x.test/simple\"\n"), nil, "poetry install", true},
		{"source PyPI without a url", "poetry", source("name = \"PyPI\"\npriority = \"primary\"\n"), nil, "poetry install", true},
		{"source from a path", "poetry", source("name = \"x\"\nurl = \"./wheels\"\n"), nil, "poetry install", false},
		{"source over file", "poetry", source("name = \"x\"\nurl = \"file:///wheels\"\n"), nil, "poetry install", false},
		{"source without a url", "poetry", source("name = \"x\"\n"), nil, "poetry install", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{}
			switch tt.tool {
			case "poetry":
				files["pyproject.toml"], files["poetry.lock"] = poetryCore, lockPoetry
			default:
				files["pyproject.toml"], files["pdm.lock"] = project, lockPDM
			}
			if tt.pyproject != "" {
				files["pyproject.toml"] = tt.pyproject
			}
			switch {
			case len(tt.script) > 5 && tt.script[:5] == "FROM ":
				files["Dockerfile"] = tt.script
			default:
				files["install.sh"] = "#!/bin/sh\n" + tt.script + "\n"
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
