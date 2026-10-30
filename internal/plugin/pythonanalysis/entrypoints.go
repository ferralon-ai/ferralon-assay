package pythonanalysis

import (
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

// Declared entrypoints.
//
// A launcher runs code no import names: an installed console script calls the function its
// entry point names, gunicorn or uvicorn imports the app module a Procfile or Dockerfile
// command names, and `python -m` runs a module. The lane reads those declarations so that
// the module they name is production code even when its file name reads like a test
// (load_test.py), and so that the callable an entry point names is a root.
//
// Declarations are read from:
//   - pyproject.toml: [project.scripts], [project.gui-scripts], every
//     [project.entry-points.<group>] but a test runner's plugin group (testPluginGroup),
//     and [tool.poetry.scripts];
//   - setup.cfg: every [options.entry_points] group but a test runner's;
//   - setup.py: every string literal shaped like an entry point ("name = pkg.mod:attr")
//     outside a test runner's group;
//   - a Django or gunicorn setting: a literal WSGI_APPLICATION, ASGI_APPLICATION or
//     wsgi_app assignment (annotated or not) at the start of a line;
//   - launch commands: a WSGI/ASGI server's app argument (gunicorn, uvicorn, hypercorn,
//     daphne, granian, waitress-serve, uwsgi) and celery's --app, in a Procfile,
//     Dockerfile, compose file, Kubernetes manifest, deployment config, shell script,
//     Makefile or supervisor program; a uwsgi ini's module or wsgi-file; a serverless or
//     SAM function's handler;
//   - `python -m mod`, `python file.py`, `streamlit run`, `fastapi run`, flask's --app and
//     FLASK_APP (also from .flaskenv) only in a production launch file (every one above
//     but a shell script or Makefile, which runs those for tests and tooling as often as
//     for production). A module run as a script that imports unittest or pytest is a test
//     suite run by hand (a Dockerfile matrix running `python -m test_jobs`), not
//     production.
//
// A declaration made inside a test directory, or in a launch file named for tests or CI
// (docker-compose.test.yml, Dockerfile.ci), describes test tooling and is skipped.

// entrypoint is one declared launch target: an import path relative to the declaring
// file's directory, and the dotted callable within it ("" when the module itself runs).
type entrypoint struct {
	dir    string // declaring directory relative to the build root, slash form
	module string // slash import path ("pkg/mod")
	attr   string // dotted attribute ("main", "Cli.run"), or ""
	file   bool   // module came from a file path, not a dotted name
	script bool   // run as a script (python -m, python file.py), not by a server or loader
}

// declaredEntrypoints reads every launch declaration under root. unread is true when a
// declaring file exists but cannot be read.
func declaredEntrypoints(root string) (eps []entrypoint, unread bool) {
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDir(d.Name()) && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		kind := launchFileKind(d.Name())
		if kind == launchNone {
			return nil
		}
		dir := ""
		if rel, relErr := filepath.Rel(root, filepath.Dir(p)); relErr == nil && rel != "." {
			dir = filepath.ToSlash(rel)
		}
		if inTestDir(dir) || kind >= launchDeploy && testLaunchName(d.Name()) {
			return nil
		}
		data, readErr := readRegular(p)
		if readErr != nil {
			unread = unread || !absent(readErr)
			return nil
		}
		text := string(data)
		var found []entrypoint
		switch kind {
		case launchPyproject:
			found = pyprojectEntrypoints(data)
		case launchSetupCfg:
			found = setupCfgEntrypoints(data)
		case launchSetupPy:
			found = setupPyEntrypoints(text)
		case launchDeploy:
			found = commandEntrypoints(text, true)
		case launchScript:
			found = commandEntrypoints(text, false)
		case launchConf:
			if strings.Contains(text, "[program:") {
				found = commandEntrypoints(text, true)
			}
		case launchIni:
			if strings.Contains(text, "[program:") {
				found = commandEntrypoints(text, true)
			}
			found = append(found, uwsgiIniEntrypoints(text)...)
		case launchYAML:
			found = yamlEntrypoints(d.Name(), text)
		}
		for _, ep := range found {
			ep.dir = path.Clean(path.Join(dir, ep.dir))
			if ep.dir == "." {
				ep.dir = ""
			}
			eps = append(eps, ep)
		}
		return nil
	})
	return eps, unread
}

type launchKind int

const (
	launchNone launchKind = iota
	launchPyproject
	launchSetupCfg
	launchSetupPy
	// The kinds from launchDeploy on are launch files, skipped when named for tests.
	launchDeploy // a file whose commands run in production
	launchScript // a shell script or Makefile
	launchConf   // a .conf file, read when it is a supervisor program table
	launchIni    // an .ini file, read when it is a uwsgi config or supervisor program table
	launchYAML   // any other YAML file, read when it is a manifest that launches code
)

// launchFileKind classes a file by name.
func launchFileKind(name string) launchKind {
	lower := strings.ToLower(name)
	yaml := strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
	switch {
	case name == "pyproject.toml":
		return launchPyproject
	case name == "setup.cfg":
		return launchSetupCfg
	case name == "setup.py":
		return launchSetupPy
	case strings.HasPrefix(name, "Procfile"), strings.HasPrefix(name, "Dockerfile"),
		strings.HasPrefix(name, "Containerfile"), strings.HasSuffix(lower, ".dockerfile"),
		strings.Contains(lower, "compose") && yaml,
		lower == "app.yaml", lower == "app.yml", lower == "fly.toml", lower == "render.yaml",
		lower == "railway.toml", lower == "railway.json", strings.HasSuffix(lower, ".service"),
		name == ".flaskenv":
		return launchDeploy
	case strings.HasSuffix(lower, ".sh"), name == "Makefile", strings.HasSuffix(lower, ".mk"):
		return launchScript
	case strings.HasSuffix(lower, ".conf"):
		return launchConf
	case strings.HasSuffix(lower, ".ini"):
		return launchIni
	case yaml:
		return launchYAML
	}
	return launchNone
}

// testLaunchName reports whether a launch file's name marks it as test or CI tooling: a
// word of it, split at dots, dashes and underscores, is test, tests, testing, ci or e2e.
func testLaunchName(name string) bool {
	words := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool { return r == '.' || r == '-' || r == '_' })
	return slices.ContainsFunc(words, func(w string) bool {
		switch w {
		case "test", "tests", "testing", "ci", "e2e":
			return true
		}
		return false
	})
}

// testPluginGroup reports whether an entry-point group registers a test runner's plugins.
func testPluginGroup(group string) bool {
	return group == "pytest11" || group == "hypothesis" || strings.HasPrefix(group, "nose.plugins")
}

// pyprojectEntrypoints reads pyproject.toml's script and entry-point tables. A file that
// does not decode declares nothing here.
func pyprojectEntrypoints(data []byte) []entrypoint {
	var doc struct {
		Project struct {
			Scripts     map[string]string            `toml:"scripts"`
			GUIScripts  map[string]string            `toml:"gui-scripts"`
			EntryPoints map[string]map[string]string `toml:"entry-points"`
		} `toml:"project"`
		Tool struct {
			Poetry struct {
				Scripts map[string]interface{} `toml:"scripts"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if toml.Unmarshal(data, &doc) != nil {
		return nil
	}
	var specs []string
	for _, s := range doc.Project.Scripts {
		specs = append(specs, s)
	}
	for _, s := range doc.Project.GUIScripts {
		specs = append(specs, s)
	}
	for group, eps := range doc.Project.EntryPoints {
		if testPluginGroup(group) {
			continue
		}
		for _, s := range eps {
			specs = append(specs, s)
		}
	}
	for _, v := range doc.Tool.Poetry.Scripts {
		switch v := v.(type) {
		case string:
			specs = append(specs, v)
		case map[string]interface{}:
			// {callable = "pkg.mod:attr"} or {reference = "pkg.mod:attr", type = "console"}
			for _, k := range []string{"callable", "reference"} {
				if s, ok := v[k].(string); ok {
					specs = append(specs, s)
				}
			}
		}
	}
	return specEntrypoints(specs)
}

// setupCfgEntrypoints reads setup.cfg's [options.entry_points]: each option is a group,
// and each line of its value a "name = pkg.mod:attr" entry.
func setupCfgEntrypoints(data []byte) []entrypoint {
	sections, ok := readCfg(data)
	if !ok {
		return nil
	}
	var specs []string
	for _, sec := range sections {
		if sec.name != "options.entry_points" {
			continue
		}
		for _, o := range sec.options {
			if testPluginGroup(o.key) {
				continue
			}
			for _, line := range o.lines {
				if _, spec, ok := strings.Cut(line, "="); ok {
					specs = append(specs, spec)
				}
			}
		}
	}
	return specEntrypoints(specs)
}

// entryLine is an entry-point definition as setup.py writes it in a string literal.
var entryLine = regexp.MustCompile(`^\s*[\w.-]+(?:\s*\[[^\]]*\])?\s*=\s*([A-Za-z_][\w.]*\s*:\s*[A-Za-z_][\w.]*)\s*(?:\[[^\]]*\])?\s*$`)

// setupPyEntrypoints reads every string literal of setup.py, or line of one, shaped like an
// entry point. The module:attr colon is required, so an unrelated "key = value" string does
// not match. A literal's group is the dict key ('pytest11': [...]), keyword (pytest11=[...])
// or ini header ("[pytest11]") before it, and a test runner's group is skipped.
func setupPyEntrypoints(src string) []entrypoint {
	clean, lits := stripPythonLiterals(src)
	cr := []rune(clean)
	var specs []string
	group, prev := "", 0
	for _, start := range slices.Sorted(maps.Keys(lits)) {
		gap := string(cr[prev:start])
		if strings.ContainsRune(gap, ']') {
			group = ""
		}
		if m := keywordList.FindStringSubmatch(gap); m != nil {
			group = m[1]
		}
		lit := lits[start]
		prev = lit.end
		next := lit.end
		for next < len(cr) && strings.ContainsRune(" \t\r\n", cr[next]) {
			next++
		}
		if next < len(cr) && cr[next] == ':' {
			group = lit.body
			continue
		}
		g := group
		for _, line := range strings.Split(lit.body, "\n") {
			if t := strings.TrimSpace(line); strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
				g = strings.TrimSpace(t[1 : len(t)-1])
				continue
			}
			if m := entryLine.FindStringSubmatch(line); m != nil && !testPluginGroup(g) {
				specs = append(specs, m[1])
			}
		}
	}
	return specEntrypoints(specs)
}

// keywordList is a keyword argument opening a list at the end of the text before a literal
// (pytest11=[).
var keywordList = regexp.MustCompile(`([A-Za-z_]\w*)\s*=\s*\[\s*$`)

var (
	// settingLine is a WSGI/ASGI application setting, annotated or not, at the start of a
	// line of stripped source, up to the blanked literal it assigns.
	settingLine = regexp.MustCompile(`(?m)^(?:WSGI_APPLICATION|ASGI_APPLICATION|wsgi_app)[ \t]*(?::[^=\n]*)?=[ \t]*_`)
	settingSpec = regexp.MustCompile(`^[A-Za-z_][\w.]*(?::[A-Za-z_][\w.]*)?$`)
)

// settingEntrypoints reads the application a Django settings module or gunicorn config
// names, from its stripped source and literals, so a docstring that quotes a setting names
// nothing. Django's dotted form ends in the attribute, so its last segment is the attr.
func settingEntrypoints(clean string, lits map[int]strLiteral) []entrypoint {
	var eps []entrypoint
	for _, loc := range settingLine.FindAllStringIndex(clean, -1) {
		lit, ok := lits[utf8.RuneCountInString(clean[:loc[1]-1])]
		if !ok || !settingSpec.MatchString(lit.body) {
			continue
		}
		spec := lit.body
		if !strings.Contains(spec, ":") {
			if i := strings.LastIndexByte(spec, '.'); i > 0 {
				spec = spec[:i] + ":" + spec[i+1:]
			}
		}
		eps = append(eps, specEntrypoints([]string{spec})...)
	}
	return eps
}

// specEntrypoints parses each "pkg.mod:attr [extras]" spec, dropping any that is not one.
func specEntrypoints(specs []string) []entrypoint {
	var eps []entrypoint
	for _, s := range specs {
		if ep, ok := parseEntrySpec(s); ok {
			eps = append(eps, ep)
		}
	}
	return eps
}

var (
	dottedName = regexp.MustCompile(`^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*$`)
	// appSpec is a server's "pkg.mod:attr" argument; a factory call ("create_app()") may
	// follow the attribute, cut short where a quoted argument splits the word.
	appSpec = regexp.MustCompile(`^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*):([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)(?:\(.*)?$`)
)

// parseEntrySpec parses "pkg.mod", "pkg.mod:attr" or "pkg.mod:attr [extra]".
func parseEntrySpec(s string) (entrypoint, bool) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '['); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	mod, attr, _ := strings.Cut(s, ":")
	mod, attr = strings.TrimSpace(mod), strings.TrimSpace(attr)
	if !dottedName.MatchString(mod) || attr != "" && !dottedName.MatchString(attr) {
		return entrypoint{}, false
	}
	return entrypoint{module: strings.ReplaceAll(mod, ".", "/"), attr: attr}, true
}

// wsgiServers are launchers whose positional argument is an application spec.
var wsgiServers = map[string]bool{
	"gunicorn": true, "uvicorn": true, "hypercorn": true, "daphne": true, "granian": true,
	"waitress-serve": true,
}

// shellSeparators end one command on a line.
var shellSeparators = map[string]bool{"&&": true, "||": true, ";": true, "|": true, "&": true}

// commandEntrypoints reads the launch commands in text. deploy admits the script forms
// (python -m, python file.py, streamlit/fastapi run), which only a production launch file
// runs reliably.
func commandEntrypoints(text string, deploy bool) []entrypoint {
	text = strings.NewReplacer("\\\r\n", " ", "\\\n", " ").Replace(text)
	var eps []entrypoint
	for _, line := range yamlCommandLines(strings.Split(text, "\n")) {
		toks := commandTokens(line)
		for i := 0; i < len(toks); i++ {
			eps = append(eps, launchAt(toks, i, deploy)...)
		}
	}
	return eps
}

// yamlCommandLines joins a YAML command:, args: or entrypoint: key and the block-list items
// under it into one line, and a command: with the args: that follows it, so a manifest's
// launch reads as one command. A list item that is a mapping ("- name: web") ends the list.
func yamlCommandLines(lines []string) []string {
	var out []string
	joining := false
	for _, line := range lines {
		t := strings.TrimSpace(line)
		key := strings.TrimSpace(strings.TrimPrefix(t, "- "))
		isKey := strings.HasPrefix(key, "command:") || strings.HasPrefix(key, "args:") || strings.HasPrefix(key, "entrypoint:")
		switch {
		case joining && strings.HasPrefix(key, "args:"):
			out[len(out)-1] += " " + strings.TrimPrefix(key, "args:")
			continue
		case joining && !isKey && strings.HasPrefix(t, "- ") && !strings.Contains(t, ": ") && !strings.HasSuffix(t, ":"):
			out[len(out)-1] += " " + strings.TrimPrefix(t, "- ")
			continue
		}
		joining = isKey
		out = append(out, line)
	}
	return out
}

// commandTokens splits a command line into words, reading a Dockerfile or YAML exec-form
// list ("["gunicorn", "app:app"]") as the words it lists.
func commandTokens(line string) []string {
	return strings.FieldsFunc(line, func(r rune) bool {
		switch r {
		case ' ', '\t', '\r', '[', ']', '"', '\'', ',':
			return true
		}
		return false
	})
}

// launchAt reads the launch that starts at toks[i], if any.
func launchAt(toks []string, i int, deploy bool) []entrypoint {
	tok := toks[i]
	if deploy {
		if v, ok := strings.CutPrefix(tok, "FLASK_APP="); ok {
			return flaskAppSpec(v)
		}
		// FLASK_APP: app.py (YAML), ENV FLASK_APP app.py (a Dockerfile's legacy form)
		if (tok == "FLASK_APP:" || tok == "FLASK_APP" && i > 0 && toks[i-1] == "ENV") && i+1 < len(toks) {
			return flaskAppSpec(toks[i+1])
		}
	}
	// A supervisor program writes its launch as command=gunicorn ...
	tok = strings.TrimPrefix(tok, "command=")
	name := tok[strings.LastIndexByte(tok, '/')+1:]
	if !launcherName(name) || installing(toks, i) {
		return nil
	}
	args := commandArgs(toks, i+1)
	switch {
	case wsgiServers[name]:
		return serverApp(name, args)
	case name == "uwsgi":
		return uwsgiApp(args)
	case name == "celery" || deploy && name == "flask":
		return appFlag(args)
	case isPythonExe(name):
		return pythonLaunch(args, deploy)
	case deploy && (name == "streamlit" || name == "fastapi"):
		if len(args) >= 2 && (args[0] == "run" || args[0] == "dev") {
			return scriptFile(args[1])
		}
	}
	return nil
}

// launcherName reports whether a command name is one launchAt reads.
func launcherName(name string) bool {
	switch name {
	case "uwsgi", "celery", "flask", "streamlit", "fastapi":
		return true
	}
	return wsgiServers[name] || isPythonExe(name)
}

// installing reports whether the command toks[i] is a word of installs packages (pip
// install gunicorn, poetry add uvicorn) rather than running them.
func installing(toks []string, i int) bool {
	for j := i - 1; j >= 0 && !shellSeparators[toks[j]]; j-- {
		if toks[j] == "install" || toks[j] == "add" {
			return true
		}
	}
	return false
}

// pythonLaunch reads what a python command runs: the module of -m, or the script file,
// after any interpreter options (-u, -W ignore). A server or celery run with -m is read as
// that launcher; flask, a plain module and a script only when deploy holds.
func pythonLaunch(args []string, deploy bool) []entrypoint {
	for k := 0; k < len(args); k++ {
		switch a := args[k]; {
		case a == "-m":
			if k+1 >= len(args) {
				return nil
			}
			mod, rest := args[k+1], args[k+2:]
			switch {
			case wsgiServers[mod]:
				return serverApp(mod, rest)
			case mod == "celery" || deploy && mod == "flask":
				return appFlag(rest)
			case deploy:
				if ep, ok := parseEntrySpec(mod); ok && ep.attr == "" {
					ep.script = true
					return []entrypoint{ep}
				}
			}
			return nil
		case a == "-c":
			return nil
		case a == "-W" || a == "-X":
			k++
		case strings.HasPrefix(a, "-"):
		default:
			if deploy {
				return scriptFile(a)
			}
			return nil
		}
	}
	return nil
}

// commandArgs is the words after toks[i-1] up to the end of that command.
func commandArgs(toks []string, i int) []string {
	j := i
	for j < len(toks) && !shellSeparators[toks[j]] {
		j++
	}
	return toks[i:j]
}

// isPythonExe reports whether a command name is a Python interpreter (python, python3,
// python3.12).
func isPythonExe(name string) bool {
	v, ok := strings.CutPrefix(name, "python")
	return ok && strings.Trim(v, "0123456789.") == ""
}

// serverValueFlags are the WSGI/ASGI servers' options that take the next word as their
// value, which is then neither an application spec (--bind unix:app.sock) nor gunicorn's
// module (-k gevent). An option not listed is read as taking no value (--reload).
var serverValueFlags = map[string]bool{
	// gunicorn
	"-c": true, "--config": true, "-b": true, "--bind": true, "--backlog": true, "-w": true,
	"--workers": true, "-k": true, "--worker-class": true, "--threads": true,
	"--worker-connections": true, "--max-requests": true, "--max-requests-jitter": true,
	"-t": true, "--timeout": true, "--graceful-timeout": true, "--keep-alive": true,
	"--limit-request-line": true, "--limit-request-fields": true,
	"--limit-request-field_size": true, "-e": true, "--env": true, "--pythonpath": true,
	"--reload-engine": true, "--reload-extra-file": true, "-p": true, "--pid": true,
	"--worker-tmp-dir": true, "-u": true, "--user": true, "-g": true, "--group": true,
	"-m": true, "--umask": true, "--forwarded-allow-ips": true, "--access-logfile": true,
	"--access-logformat": true, "--error-logfile": true, "--log-file": true,
	"--log-level": true, "--logger-class": true, "--log-config": true,
	"--log-config-json": true, "--log-syslog-to": true, "--log-syslog-prefix": true,
	"--log-syslog-facility": true, "--statsd-host": true, "--statsd-prefix": true,
	"--dogstatsd-tags": true, "-n": true, "--name": true, "--keyfile": true,
	"--certfile": true, "--ssl-version": true, "--cert-reqs": true, "--ca-certs": true,
	"--ciphers": true, "--paste": true, "--proxy-allow-from": true,
	// uvicorn, hypercorn, daphne, granian
	"--host": true, "--port": true, "--uds": true, "--fd": true, "--loop": true,
	"--http": true, "--ws": true, "--lifespan": true, "--env-file": true, "--root-path": true,
	"--limit-concurrency": true, "--limit-max-requests": true, "--timeout-keep-alive": true,
	"--ssl-keyfile": true, "--ssl-certfile": true, "--ssl-ca-certs": true,
	"--reload-dir": true, "--reload-include": true, "--reload-exclude": true,
	"--header": true, "--interface": true, "--blocking-threads": true,
	"--access-log": true, "-v": true, "--verbosity": true, "--unix-socket": true,
	"--endpoint": true, "--ssl-keyfile-password": true, "--ssl-ciphers": true,
	// waitress-serve
	"--listen": true, "--unix-socket-perms": true, "--url-scheme": true,
	"--url-prefix": true, "--ident": true, "--recv-bytes": true, "--send-bytes": true,
	"--outbuf-overflow": true, "--inbuf-overflow": true, "--connection-limit": true,
	"--cleanup-interval": true, "--channel-timeout": true, "--max-request-header-size": true,
	"--max-request-body-size": true, "--trusted-proxy": true, "--trusted-proxy-count": true,
	"--trusted-proxy-headers": true,
}

// serverApp reads a WSGI/ASGI server's application argument: any "pkg.mod:attr" word, or,
// for gunicorn and waitress-serve, which default the attribute, the first dotted word that
// is no option or option value. --chdir and --app-dir move the directory the module is
// read from.
func serverApp(name string, args []string) []entrypoint {
	dir, module := "", ""
	var eps []entrypoint
	for k := 0; k < len(args); k++ {
		a := args[k]
		if strings.HasPrefix(a, "-") {
			flag, v, inline := strings.Cut(a, "=")
			switch {
			case flag == "--app" && inline:
				a = v
			case flag == "--chdir" || flag == "--app-dir":
				if !inline && k+1 < len(args) {
					k++
					v = args[k]
				}
				dir = v
				continue
			case !inline && serverValueFlags[flag]:
				k++
				continue
			default:
				continue
			}
		}
		if m := appSpec.FindStringSubmatch(a); m != nil {
			eps = append(eps, entrypoint{module: strings.ReplaceAll(m[1], ".", "/"), attr: m[2]})
		} else if module == "" && dottedName.MatchString(a) {
			module = a
		}
	}
	if len(eps) == 0 && module != "" && (name == "gunicorn" || name == "waitress-serve") {
		eps = append(eps, entrypoint{module: strings.ReplaceAll(module, ".", "/")})
	}
	for i := range eps {
		eps[i].dir = launchDir(dir)
	}
	return eps
}

// uwsgiApp reads uwsgi's --module (a "pkg.mod:attr" or dotted module) and --wsgi-file.
func uwsgiApp(args []string) []entrypoint {
	for k, a := range args {
		flag, v, inline := strings.Cut(a, "=")
		if !inline {
			if k+1 >= len(args) {
				continue
			}
			v = args[k+1]
		}
		switch flag {
		case "--module", "-w":
			if ep, ok := parseEntrySpec(v); ok {
				return []entrypoint{ep}
			}
		case "--wsgi-file":
			return pyFile(v)
		}
	}
	return nil
}

// uwsgiIniEntrypoints reads a uwsgi ini's [uwsgi] section: module (or wsgi), a
// "pkg.mod:attr" or a dotted module whose attribute callable names, else wsgi-file, read
// from chdir.
func uwsgiIniEntrypoints(text string) []entrypoint {
	vals := map[string]string{}
	in := false
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			in = t == "[uwsgi]"
			continue
		}
		if k, v, ok := strings.Cut(t, "="); in && ok && !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, ";") {
			if k = strings.TrimSpace(k); vals[k] == "" {
				vals[k] = strings.TrimSpace(v)
			}
		}
	}
	var eps []entrypoint
	module := vals["module"]
	if module == "" {
		module = vals["wsgi"]
	}
	if ep, ok := parseEntrySpec(module); ok {
		if ep.attr == "" && dottedName.MatchString(vals["callable"]) {
			ep.attr = vals["callable"]
		}
		eps = []entrypoint{ep}
	} else if f := vals["wsgi-file"]; f != "" {
		eps = pyFile(f)
	}
	for i := range eps {
		eps[i].dir = launchDir(vals["chdir"])
	}
	return eps
}

// handlerLine is a serverless or SAM function's handler: "path/to/module.function".
var handlerLine = regexp.MustCompile(`(?m)^[ \t-]*[Hh]andler:[ \t]*['"]?([A-Za-z_][\w/.]*)\.([A-Za-z_]\w*)['"]?[ \t]*(?:#.*)?\r?$`)

// yamlEntrypoints reads a YAML file that launches code: a serverless or SAM template's
// function handlers, and a Kubernetes manifest's container commands.
func yamlEntrypoints(name, text string) []entrypoint {
	var eps []entrypoint
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "serverless.") || strings.Contains(text, "AWS::Serverless::Function") || strings.Contains(text, "AWS::Lambda::Function") {
		for _, m := range handlerLine.FindAllStringSubmatch(text, -1) {
			if mod := strings.ReplaceAll(m[1], ".", "/"); !strings.Contains(mod, "//") {
				eps = append(eps, entrypoint{module: mod, attr: m[2]})
			}
		}
	}
	if strings.Contains(text, "containers:") {
		eps = append(eps, commandEntrypoints(text, true)...)
	}
	return eps
}

// appFlag reads celery's or flask's -A/--app value.
func appFlag(args []string) []entrypoint {
	for k, a := range args {
		v, inline := strings.CutPrefix(a, "--app=")
		if !inline {
			if a != "-A" && a != "--app" || k+1 >= len(args) {
				continue
			}
			v = args[k+1]
		}
		return flaskAppSpec(v)
	}
	return nil
}

// flaskAppSpec reads a FLASK_APP or --app value: a file path or a "pkg.mod[:attr]" spec, with
// an optional factory call.
func flaskAppSpec(v string) []entrypoint {
	if strings.HasSuffix(v, ".py") {
		return pyFile(v)
	}
	if i := strings.IndexByte(v, '('); i >= 0 {
		v = v[:i]
	}
	if ep, ok := parseEntrySpec(v); ok {
		return []entrypoint{ep}
	}
	return nil
}

// scriptFile is pyFile for a file run as a script.
func scriptFile(p string) []entrypoint {
	eps := pyFile(p)
	for i := range eps {
		eps[i].script = true
	}
	return eps
}

// pyFile reads a run file path ("src/load_test.py", "/app/main.py") as the module it is.
func pyFile(p string) []entrypoint {
	if !strings.HasSuffix(p, ".py") {
		return nil
	}
	mod := strings.TrimSuffix(path.Clean(strings.TrimPrefix(p, "./")), ".py")
	mod = strings.TrimSuffix(mod, "/__init__")
	if mod == "" || mod == "." || strings.HasPrefix(mod, "../") {
		return nil
	}
	return []entrypoint{{module: mod, file: true}}
}

// launchDir is a --chdir value as a directory relative to the declaring file's ("" when
// absolute or outside it, so the module is read from the declaring directory).
func launchDir(d string) string {
	d = path.Clean(d)
	if d == "." || path.IsAbs(d) || strings.HasPrefix(d, "../") || d == ".." {
		return ""
	}
	return d
}

// entryFiles is the files a declared entrypoint may run: the module under the declaring
// directory, under its src/ directory, or at the build root, else any module whose path
// ends in it below no test directory. A module that runs on its own (no attribute) may be a
// package, which runs its __main__. An absolute file path ("/app/main.py") names the
// modules of its longest trailing run of segments some file's path ends in.
func (prog *program) entryFiles(ep entrypoint) []int {
	exact := func(mod string) []int {
		var out []int
		for _, i := range prog.byModule[mod] {
			if prog.files[i].module == mod {
				out = append(out, i)
			}
		}
		if ep.attr == "" && !ep.file {
			for _, i := range prog.byModule[mod+"/__main__"] {
				if prog.files[i].module == mod+"/__main__" {
					out = append(out, i)
				}
			}
		}
		return out
	}
	mod := strings.TrimPrefix(ep.module, "/")
	if !strings.HasPrefix(ep.module, "/") {
		for _, cand := range []string{path.Join(ep.dir, mod), path.Join(ep.dir, "src", mod), mod} {
			if out := exact(cand); len(out) > 0 {
				return out
			}
		}
	}
	// A name no exact path matches (an image's WORKDIR, a layout the lane does not model)
	// falls back to the files ending in it, but never through a test directory the name
	// does not itself give: a bare "server" or "api" would otherwise promote every
	// tests/.../server the repo holds, while a named ab_test stays found under web/.
	segs := strings.Split(mod, "/")
	for k := range segs {
		suffix := strings.Join(segs[k:], "/")
		if files := prog.byModule[suffix]; len(files) > 0 {
			var out []int
			for _, i := range files {
				if m := prog.files[i].module; m == suffix || !inTestDir(strings.TrimSuffix(m, "/"+suffix)) {
					out = append(out, i)
				}
			}
			return out
		}
	}
	return nil
}

// resolveEntrypoints records the declared entrypoints on the program: each file they may
// run is production code (entryModules), and each callable they name is a root
// (entryRoots). A callable the module binds by a first-party import is followed to its
// declaration.
func (prog *program) resolveEntrypoints(eps []entrypoint) {
	prog.entryModules = map[string]bool{}
	seen := map[string]bool{}
	for _, ep := range eps {
		for _, i := range prog.entryFiles(ep) {
			if ep.script && importsTestFramework(prog.files[i].imports) {
				continue
			}
			prog.entryModules[prog.files[i].module] = true
			if ep.attr != "" {
				prog.rootEntryAttr(i, strings.Split(ep.attr, "."), seen, map[string]bool{})
			}
		}
	}
}

// rootEntryAttr roots the declaration attr names in file i: a function, or a method of a
// class in it. A top-level name the file imports from first-party code is followed there,
// to the module of that exact path when one exists, and each module the chain passes
// through to the declaration is production code, since the launcher imports it. It
// reports whether the declaration was found.
func (prog *program) rootEntryAttr(i int, attr []string, seen, visited map[string]bool) bool {
	f := &prog.files[i]
	key := f.module + ":" + strings.Join(attr, ".")
	if visited[key] {
		return false
	}
	visited[key] = true
	found := false
	for _, fd := range f.decls {
		if fd.name == attr[len(attr)-1] && slices.Equal(fd.enclosing, attr[:len(attr)-1]) {
			found = true
			if s := fd.scip(); !seen[s] {
				seen[s] = true
				prog.entryRoots = append(prog.entryRoots, fd)
			}
		}
	}
	if !found {
		for _, p := range f.fpBinds[""][attr[0]] {
			mod, leaf := parentModule(p), p[strings.LastIndexByte(p, '/')+1:]
			next := append([]string{leaf}, attr[1:]...)
			files := prog.byModule[mod]
			if exact := slices.DeleteFunc(slices.Clone(files), func(j int) bool { return prog.files[j].module != mod }); len(exact) > 0 {
				files = exact
			}
			for _, j := range files {
				found = prog.rootEntryAttr(j, next, seen, visited) || found
			}
		}
	}
	if found {
		prog.entryModules[f.module] = true
	}
	return found
}

// importsTestFramework reports whether a file imports unittest or pytest.
func importsTestFramework(imports []string) bool {
	return slices.ContainsFunc(imports, func(m string) bool {
		top, _, _ := strings.Cut(m, ".")
		return top == "unittest" || top == "pytest"
	})
}
