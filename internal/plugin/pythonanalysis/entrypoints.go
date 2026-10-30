package pythonanalysis

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

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
//     [project.entry-points.<group>] but pytest11 (a test-runner plugin), and
//     [tool.poetry.scripts];
//   - setup.cfg: every [options.entry_points] group but pytest11;
//   - setup.py: every string literal shaped like an entry point ("name = pkg.mod:attr");
//   - a Django or gunicorn setting: a literal WSGI_APPLICATION, ASGI_APPLICATION or
//     wsgi_app assignment at the start of a line;
//   - launch commands: a WSGI/ASGI server's app argument (gunicorn, uvicorn, hypercorn,
//     daphne, granian, waitress-serve, uwsgi), celery's and flask's --app, and FLASK_APP,
//     in a Procfile, Dockerfile, compose file, deployment config, shell script, Makefile
//     or supervisor program;
//   - `python -m mod`, `python file.py`, `streamlit run` and `fastapi run` only in a
//     Procfile, Dockerfile, compose file, deployment config or supervisor program, since
//     a shell script or Makefile runs those for tests and tooling as often as for
//     production. A module run this way that imports unittest or pytest is a test suite
//     run by hand (a Dockerfile matrix running `python -m test_jobs`), not production.
//
// A declaration made inside a test directory describes test tooling and is skipped.

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
		if inTestDir(dir) {
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
	launchDeploy // a file whose commands run in production
	launchScript // a shell script or Makefile
	launchConf   // a .conf file, read when it is a supervisor program table
)

// launchFileKind classes a file by name.
func launchFileKind(name string) launchKind {
	lower := strings.ToLower(name)
	switch {
	case name == "pyproject.toml":
		return launchPyproject
	case name == "setup.cfg":
		return launchSetupCfg
	case name == "setup.py":
		return launchSetupPy
	case strings.HasPrefix(name, "Procfile"), strings.HasPrefix(name, "Dockerfile"),
		strings.HasPrefix(name, "Containerfile"), strings.HasSuffix(lower, ".dockerfile"),
		strings.Contains(lower, "compose") && (strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")),
		lower == "app.yaml", lower == "app.yml", lower == "fly.toml", lower == "render.yaml",
		lower == "railway.toml", lower == "railway.json", strings.HasSuffix(lower, ".service"):
		return launchDeploy
	case strings.HasSuffix(lower, ".sh"), name == "Makefile", strings.HasSuffix(lower, ".mk"):
		return launchScript
	case strings.HasSuffix(lower, ".conf"):
		return launchConf
	}
	return launchNone
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
		if group == "pytest11" {
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
			if o.key == "pytest11" {
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
// not match.
func setupPyEntrypoints(src string) []entrypoint {
	_, lits := stripPythonLiterals(src)
	var specs []string
	for _, lit := range lits {
		for _, line := range strings.Split(lit.body, "\n") {
			if m := entryLine.FindStringSubmatch(line); m != nil {
				specs = append(specs, m[1])
			}
		}
	}
	return specEntrypoints(specs)
}

// settingLine is a literal WSGI/ASGI application setting at the start of a line.
var settingLine = regexp.MustCompile(`(?m)^(?:WSGI_APPLICATION|ASGI_APPLICATION|wsgi_app)\s*=\s*['"]([A-Za-z_][\w.]*(?::[A-Za-z_][\w.]*)?)['"]`)

// settingEntrypoints reads the application a Django settings module or gunicorn config
// names. Django's dotted form ends in the attribute, so its last segment is the attr.
func settingEntrypoints(src string) []entrypoint {
	var eps []entrypoint
	for _, m := range settingLine.FindAllStringSubmatch(src, -1) {
		spec := m[1]
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
	// follow the attribute.
	appSpec = regexp.MustCompile(`^([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*):([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)(?:\(.*\))?$`)
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
	for _, line := range strings.Split(text, "\n") {
		toks := commandTokens(line)
		for i := 0; i < len(toks); i++ {
			eps = append(eps, launchAt(toks, i, deploy)...)
		}
	}
	return eps
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
	if v, ok := strings.CutPrefix(tok, "FLASK_APP="); ok {
		return flaskAppSpec(v)
	}
	if tok == "FLASK_APP:" && i+1 < len(toks) {
		return flaskAppSpec(toks[i+1])
	}
	// A supervisor program writes its launch as command=gunicorn ...
	tok = strings.TrimPrefix(tok, "command=")
	name := tok[strings.LastIndexByte(tok, '/')+1:]
	args := commandArgs(toks, i+1)
	switch {
	case wsgiServers[name]:
		return serverApp(name, args)
	case name == "uwsgi":
		return uwsgiApp(args)
	case name == "celery" || name == "flask":
		return appFlag(args)
	case isPythonExe(name):
		if len(args) >= 2 && args[0] == "-m" {
			switch {
			case wsgiServers[args[1]]:
				return serverApp(args[1], args[2:])
			case args[1] == "celery" || args[1] == "flask":
				return appFlag(args[2:])
			case deploy:
				if ep, ok := parseEntrySpec(args[1]); ok && ep.attr == "" {
					ep.script = true
					return []entrypoint{ep}
				}
			}
			return nil
		}
		if deploy {
			for _, a := range args {
				if !strings.HasPrefix(a, "-") {
					return scriptFile(a)
				}
			}
		}
	case deploy && (name == "streamlit" || name == "fastapi"):
		if len(args) >= 2 && (args[0] == "run" || args[0] == "dev") {
			return scriptFile(args[1])
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

// serverApp reads a WSGI/ASGI server's application argument: any "pkg.mod:attr" word, or,
// for gunicorn and waitress-serve, which default the attribute, a dotted module as the
// last word when the word before it is no flag that may take it as a value. --chdir and
// --app-dir move the directory the module is read from.
func serverApp(name string, args []string) []entrypoint {
	dir := ""
	var eps []entrypoint
	for k, a := range args {
		switch {
		case a == "--chdir" || a == "--app-dir":
			if k+1 < len(args) {
				dir = args[k+1]
			}
			continue
		case strings.HasPrefix(a, "--chdir="):
			dir = strings.TrimPrefix(a, "--chdir=")
			continue
		case strings.HasPrefix(a, "--app-dir="):
			dir = strings.TrimPrefix(a, "--app-dir=")
			continue
		}
		if m := appSpec.FindStringSubmatch(strings.TrimPrefix(a, "--app=")); m != nil {
			eps = append(eps, entrypoint{module: strings.ReplaceAll(m[1], ".", "/"), attr: m[2]})
		}
	}
	if len(eps) == 0 && (name == "gunicorn" || name == "waitress-serve") && len(args) > 0 {
		last := args[len(args)-1]
		if dottedName.MatchString(last) && (len(args) == 1 || !strings.HasPrefix(args[len(args)-2], "-")) {
			eps = append(eps, entrypoint{module: strings.ReplaceAll(last, ".", "/")})
		}
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
// directory, under its src/ directory, or at the build root, else any module that is not
// test code whose path ends in it. A module that runs on its own (no attribute) may be a
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
	// falls back to the files ending in it, but never to a test module: a bare "server" or
	// "api" would otherwise promote every tests/.../server the repo holds.
	segs := strings.Split(mod, "/")
	for k := range segs {
		if files := prog.byModule[strings.Join(segs[k:], "/")]; len(files) > 0 {
			var out []int
			for _, i := range files {
				if !isTestModule(prog.files[i].module) {
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
// class in it. A top-level name the file imports from first-party code is followed there.
func (prog *program) rootEntryAttr(i int, attr []string, seen, visited map[string]bool) {
	f := &prog.files[i]
	key := f.module + ":" + strings.Join(attr, ".")
	if visited[key] {
		return
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
	if found {
		return
	}
	for _, p := range f.fpBinds[""][attr[0]] {
		mod, leaf := parentModule(p), p[strings.LastIndexByte(p, '/')+1:]
		next := append([]string{leaf}, attr[1:]...)
		for _, j := range prog.byModule[mod] {
			prog.rootEntryAttr(j, next, seen, visited)
		}
	}
}

// importsTestFramework reports whether a file imports unittest or pytest.
func importsTestFramework(imports []string) bool {
	return slices.ContainsFunc(imports, func(m string) bool {
		top, _, _ := strings.Cut(m, ".")
		return top == "unittest" || top == "pytest"
	})
}
