package pythonanalysis

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// poetrySettings are the poetry config keys that leave what poetry install installs as
// poetry.lock records it: where and how poetry makes the environment, where it caches, and how
// it talks to the network. Anything else (installer.no-binary, installer.only-binary and
// installer.build-config-settings, which change which builds run and how; repositories and
// their credentials; solver and re-resolve settings; a key added after this list) withholds.
// virtualenvs.prefer-active-python and virtualenvs.options.no-setuptools are poetry 1.x's.
var poetrySettings = map[string]bool{
	"cache-dir": true, "virtualenvs.create": true, "virtualenvs.in-project": true, "virtualenvs.path": true,
	"virtualenvs.prompt": true, "virtualenvs.use-poetry-python": true, "virtualenvs.prefer-active-python": true,
	"virtualenvs.options.always-copy": true, "virtualenvs.options.system-site-packages": true,
	"virtualenvs.options.no-pip": true, "virtualenvs.options.no-setuptools": true,
	"requests.max-retries": true, "installer.parallel": true, "installer.max-workers": true, "keyring.enabled": true,
}

// pdmSettings are the pdm config keys that leave what pdm sync installs as pdm.lock records it:
// where and how pdm makes the environment, where it caches and logs, and how it talks to the
// network. Anything else (an index under pypi or repository, build_isolation, use_uv, which
// hands the install to uv and its own config, lock.format, strategy, global_project, a key
// added after this list) withholds.
var pdmSettings = map[string]bool{
	"cache_dir": true, "log_dir": true, "check_update": true, "request_timeout": true,
	"install.parallel": true, "install.cache": true, "install.cache_method": true,
	"python.use_venv": true, "python.use_pyenv": true, "python.providers": true, "python.install_root": true,
	"venv.location": true, "venv.in_project": true, "venv.prompt": true, "venv.with_pip": true,
	"scripts.show_header": true,
}

// poetryEnvKeeps are the POETRY_* variables that install nothing poetry.lock does not record:
// one per poetrySettings key, as poetry names it (POETRY_ and the key upper-cased, with . and
// - as _), POETRY_REQUESTS_TIMEOUT, and the installer's POETRY_HOME, POETRY_VERSION and
// POETRY_NO_INTERACTION, which pick where poetry itself lives, which poetry release runs, and
// whether it prompts.
var poetryEnvKeeps = func() map[string]bool {
	keeps := map[string]bool{"POETRY_HOME": true, "POETRY_VERSION": true, "POETRY_NO_INTERACTION": true, "POETRY_REQUESTS_TIMEOUT": true}
	for k := range poetrySettings {
		keeps["POETRY_"+strings.NewReplacer(".", "_", "-", "_").Replace(strings.ToUpper(k))] = true
	}
	return keeps
}()

// toolConfigNamedRE matches, in a script surface's text, a poetry or pdm config file or the
// directory either reads its user or site config from (poetry.toml, pdm.toml and .pdm.toml,
// pypoetry/config.toml or auth.toml, pdm/config.toml, a pypoetry or pdm directory under
// .config, Application Support or /etc/xdg, a quote or not closing the base, or on a line that
// names AppData or ProgramData however the path is built), or a variable that moves where they
// look (configHomeMoved, platformdirs' WIN_PD_OVERRIDE_*). A poetry
// install or pdm sync reads the settings there, so an allowed one withholds where a script
// names one (versionSurfaces). POETRY_CONFIG_DIR and PDM_CONFIG_FILE fall under laneEnvRE.
var toolConfigNamedRE = regexp.MustCompile(`(?i)poetry\.toml|pdm\.toml|pypoetry[\\/](?:config|auth)\.toml|pdm[\\/]config\.toml|` +
	`(?:\.config|application\\? support|/etc/xdg)["']?[\\/](?:pypoetry|pdm)\b|(?:appdata|programdata)[^\n]*?\b(?:pypoetry|pdm)\b|` +
	`win_pd_override_|` + configHomeMoved)

// toolConfigName reports which tool reads a file of this lowercased base name in directory dir
// as its config: poetry its project poetry.toml and its user config.toml or auth.toml under
// pypoetry, pdm its project pdm.toml (.pdm.toml before 2.0) and its user or site config.toml
// under pdm.
func toolConfigName(lower, dir string) (string, bool) {
	switch {
	case lower == "poetry.toml", dir == "pypoetry" && (lower == "config.toml" || lower == "auth.toml"):
		return "poetry", true
	case lower == "pdm.toml", lower == ".pdm.toml", dir == "pdm" && lower == "config.toml":
		return "pdm", true
	}
	return "", false
}

// toolConfigClean reports whether the file at path, a config toolConfigName names, decodes and
// sets only that tool's settings (poetrySettings, pdmSettings).
func toolConfigClean(path string) bool {
	tool, ok := toolConfigName(strings.ToLower(filepath.Base(path)), strings.ToLower(filepath.Base(filepath.Dir(path))))
	if !ok {
		return false
	}
	data, err := readRegular(path)
	if err != nil {
		return false
	}
	var doc map[string]any
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return false
	}
	settings := poetrySettings
	if tool == "pdm" {
		settings = pdmSettings
	}
	return settingsOnly(doc, "", settings)
}

// settingsOnly reports whether every value under table, its keys prefixed by prefix, sits at a
// dotted key settings names, and is not itself a table.
func settingsOnly(table map[string]any, prefix string, settings map[string]bool) bool {
	for k, v := range table {
		key := prefix + k
		sub, table := v.(map[string]any)
		if settings[key] && !table {
			continue
		}
		if !table || !settingsOnly(sub, key+".", settings) {
			return false
		}
	}
	return true
}

// configSet reports whether poetry config's or pdm config's arguments, after config, set or
// unset one key settings names: the key, then its values, with only the given flags.
func configSet(args []string, flags map[string]bool, settings map[string]bool) bool {
	var key string
	values := 0
	for _, a := range args {
		switch {
		case flags[a]:
		case strings.HasPrefix(a, "-"):
			return false
		case key == "":
			key = a
		default:
			values++
		}
	}
	return settings[key] && values <= 1
}

// poetryConfigFlags and pdmConfigFlags are the flags poetry config and pdm config may carry:
// the project's config file to write (pdm's -g runs against the global project), unset or
// delete, and quiet or non-interactive output.
var (
	poetryConfigFlags = map[string]bool{"--local": true, "--unset": true, "-n": true, "--no-interaction": true, "-q": true, "--quiet": true}
	pdmConfigFlags    = map[string]bool{"-l": true, "--local": true, "-g": true, "--global": true, "-d": true, "--delete": true, "-q": true, "--quiet": true}
)

// poetrySourcesRemote reports whether every tool.poetry.source the manifest names, which poetry
// resolves build requirements from, is served over http(s), not from the tree. A source named
// PyPI takes no url: poetry refuses one.
func poetrySourcesRemote(doc rootProject) bool {
	for _, src := range doc.Tool.Poetry.Source {
		url, ok := src["url"]
		if !ok {
			if name, _ := src["name"].(string); strings.EqualFold(name, "pypi") {
				continue
			}
			return false
		}
		if !remoteURLs(url) {
			return false
		}
	}
	return true
}
