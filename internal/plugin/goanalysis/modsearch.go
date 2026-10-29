package goanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/mod/modfile"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// moduleSearchTimeout bounds a module search, downloads included. A module not read by then is
// left out of the result, as unreadable.
var moduleSearchTimeout = 5 * time.Minute

// listedModule is one module of `go list -m -json all`.
type listedModule struct {
	Path    string
	Version string
	Main    bool
	Dir     string
	Replace *struct {
		Path    string
		Version string
		Dir     string
	}
}

// searchBuildModules searches the source of every module in buildDir's build list for a
// declaration named like one of symbols, for an advisory on pkgPath. It returns nil when the
// search does not apply or cannot start: no symbols, a module in the build holds pkgPath, GOFLAGS
// may change the module list or the source the build compiles (goflagsBlock), or the build list
// cannot be listed (a vendored build, for one).
//
// A module whose source is not in the module cache is downloaded the way the go command would,
// honoring the caller's GOPROXY, GOPRIVATE, GONOSUMDB and GOFLAGS, and verified against go.sum
// and the checksum database. A module that fails to download, verify or parse, or that is not
// read before moduleSearchTimeout, is left out of Searched.
func searchBuildModules(ctx context.Context, buildDir, pkgPath string, symbols []string) *plugin.ModuleSearch {
	names := symbolNames(symbols)
	if pkgPath == "" || len(names) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, moduleSearchTimeout)
	defer cancel()
	if goflagsBlockSearch(ctx, buildDir) {
		return nil
	}
	mods, err := listModules(ctx, buildDir)
	if err != nil {
		return nil
	}
	for _, m := range mods {
		if pathHolds(m.Path, pkgPath) || m.Replace != nil && pathHolds(m.Replace.Path, pkgPath) {
			return nil
		}
	}
	downloaded := downloadModules(ctx, buildDir, mods)

	res := &plugin.ModuleSearch{Searched: []string{}}
	for _, m := range mods {
		dir := sourceDir(m, downloaded)
		if dir == "" {
			continue
		}
		declares, err := declaresName(ctx, dir, names)
		if err != nil {
			continue
		}
		res.Searched = append(res.Searched, m.Path)
		if m.Replace != nil && m.Replace.Version != "" {
			res.Searched = append(res.Searched, m.Replace.Path)
		}
		if declares {
			res.Declaring = append(res.Declaring, m.Path)
		}
	}
	slices.Sort(res.Searched)
	res.Searched = slices.Compact(res.Searched)
	slices.Sort(res.Declaring)
	return res
}

// symbolNames returns the bare names advisory symbols declare: "Func", "Type.Method",
// "(*Type).Method" and "pkg.Func" all name their last element.
func symbolNames(symbols []string) map[string]bool {
	names := make(map[string]bool, len(symbols))
	for _, s := range symbols {
		if i := strings.LastIndexByte(s, '.'); i >= 0 {
			s = s[i+1:]
		}
		if s = strings.Trim(s, "(*)"); s != "" {
			names[s] = true
		}
	}
	return names
}

// searchSafeGoflags are the go command flags GOFLAGS may set without changing what the module
// search reads for the build: the module list `go list -m all` answers, and every .go file of
// each module whatever its build constraints (declaresName). Build tags, platform, compiler,
// instrumentation (-race, -cover, -asan, -msan), PGO and linker or compiler options pick among or
// compile that source, and test flags only run what was built; neither changes the list or the
// files. Every other flag blocks the search, so a flag the go command adds later fails closed.
// Left out on purpose: -modfile (another module list), -overlay (other file contents), -toolexec
// (a wrapper that can rewrite or add source as it compiles), -linkshared and -pkgdir (packages
// built from source the build does not show), and -C. -mod is decided by its value (goflagsBlock).
var searchSafeGoflags = map[string]bool{
	// build
	"a": true, "asan": true, "asmflags": true, "buildmode": true, "buildvcs": true,
	"compiler": true, "cover": true, "covermode": true, "coverpkg": true, "gccgoflags": true,
	"gcflags": true, "installsuffix": true, "json": true, "ldflags": true, "modcacherw": true,
	"msan": true, "n": true, "p": true, "pgo": true, "race": true, "tags": true, "trimpath": true,
	"v": true, "work": true, "x": true,
	// test
	"bench": true, "benchmem": true, "benchtime": true, "count": true, "cpu": true,
	"failfast": true, "fullpath": true, "parallel": true, "run": true, "short": true,
	"shuffle": true, "skip": true, "timeout": true, "vet": true,
}

// goflagsBlock reports whether goflags, a GOFLAGS value, may make the build compile a module list
// or file contents the module search does not read: it names a flag searchSafeGoflags does not
// list, or -mod with any value but readonly. -mod=mod lets the build add modules `go list -m all`
// did not list, and -mod=vendor compiles vendor/, which the search does not read. GOFLAGS is split
// as the go command splits it, quotes included; one it would reject (a value set apart from its
// flag, as in "-mod mod", or an unterminated quote) blocks.
func goflagsBlock(goflags string) bool {
	fields, ok := splitGoflags(goflags)
	if !ok {
		return true
	}
	for _, f := range fields {
		name, ok := strings.CutPrefix(f, "-")
		if !ok {
			return true
		}
		name = strings.TrimPrefix(name, "-")
		name, value, hasValue := strings.Cut(name, "=")
		if name == "mod" {
			if !hasValue || value != "readonly" {
				return true
			}
		} else if !searchSafeGoflags[name] {
			return true
		}
	}
	return false
}

// splitGoflags splits GOFLAGS into fields the way the go command does (cmd/internal/quoted.Split):
// on spaces, tabs and newlines, a field that opens with a single or double quote running to the
// matching quote. It reports false for an unterminated quote.
func splitGoflags(s string) ([]string, bool) {
	isSpace := func(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }
	var fields []string
	for {
		for len(s) > 0 && isSpace(s[0]) {
			s = s[1:]
		}
		if len(s) == 0 {
			return fields, true
		}
		if q := s[0]; q == '"' || q == '\'' {
			i := strings.IndexByte(s[1:], q)
			if i < 0 {
				return nil, false
			}
			fields = append(fields, s[1:1+i])
			s = s[2+i:]
			continue
		}
		i := 0
		for i < len(s) && !isSpace(s[i]) {
			i++
		}
		fields = append(fields, s[:i])
		s = s[i:]
	}
}

// modsearchGo runs a go command and returns its standard output. Tests replace it to observe the
// commands a module search issues.
var modsearchGo = func(cmd *exec.Cmd) ([]byte, error) { return cmd.Output() }

// goCommand is a go command run in buildDir under the environment the program load runs under
// (programEnv), so the build list it reads is the one the resolution index was loaded from.
func goCommand(ctx context.Context, buildDir string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = buildDir
	cmd.Env, _, _ = programEnv(ctx, buildDir)
	return cmd
}

// buildKey is the run cache key of a go command's answer for buildDir, which depends on the
// build and the environment programEnv derives from the process's.
func buildKey(buildDir string, extra ...string) []string {
	return append(append([]string{buildDir}, extra...), os.Environ()...)
}

// goflagsBlockSearch reports whether the GOFLAGS the go command uses in buildDir, from the
// environment or the go env file, may make the build compile a module list or file contents the
// search does not read (goflagsBlock). GOFLAGS that cannot be read blocks the search. It is read
// once per build per scan; a read cut short by ctx is not kept.
func goflagsBlockSearch(ctx context.Context, buildDir string) bool {
	b, err := runCached(ctx, "goflagsblock", buildKey(buildDir), func() ([]byte, error) {
		out, err := modsearchGo(goCommand(ctx, buildDir, "env", "GOFLAGS"))
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			return []byte("true"), nil
		}
		if goflagsBlock(string(out)) {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	})
	return err != nil || string(b) != "false"
}

// dependencyHolds reports whether a module of buildDir's build list other than the main module
// holds import path p: the module holding it with the longest path, by its own path or its
// replacement's, is not the main module. A vendored build, whose build list the go command does not
// list, is read from vendor/modules.txt. A build list that cannot be read holds nothing.
func dependencyHolds(ctx context.Context, buildDir, p string) bool {
	ctx, cancel := context.WithTimeout(ctx, moduleSearchTimeout)
	defer cancel()
	mods, err := listModules(ctx, buildDir)
	if err != nil {
		if mods, err = vendoredModules(buildDir); err != nil {
			return false
		}
	}
	held, main := 0, false
	for _, m := range mods {
		paths := []string{m.Path}
		if m.Replace != nil {
			paths = append(paths, m.Replace.Path)
		}
		for _, path := range paths {
			if len(path) > held && pathHolds(path, p) {
				held, main = len(path), m.Main
			}
		}
	}
	return held > 0 && !main
}

// vendoredModules reads a vendored build's module list: the main module from go.mod, and every
// module vendor/modules.txt records, with its replacement.
func vendoredModules(buildDir string) ([]listedModule, error) {
	data, err := os.ReadFile(filepath.Join(buildDir, "go.mod"))
	if err != nil {
		return nil, err
	}
	main := modfile.ModulePath(data)
	if main == "" {
		return nil, fmt.Errorf("%s/go.mod declares no module", buildDir)
	}
	txt, err := os.ReadFile(filepath.Join(buildDir, "vendor", "modules.txt"))
	if err != nil {
		return nil, err
	}
	mods := []listedModule{{Path: main, Main: true}}
	for _, line := range strings.Split(string(txt), "\n") {
		// "# path [version] [=> replacement [version]]"; "##" lines annotate the module above.
		rest, ok := strings.CutPrefix(line, "# ")
		if !ok {
			continue
		}
		mod, repl, replaced := strings.Cut(rest, " => ")
		f := strings.Fields(mod)
		if len(f) == 0 {
			continue
		}
		m := listedModule{Path: f[0]}
		if rf := strings.Fields(repl); replaced && len(rf) > 0 {
			m.Replace = &struct {
				Path    string
				Version string
				Dir     string
			}{Path: rf[0]}
		}
		mods = append(mods, m)
	}
	return mods, nil
}

// pathHolds reports whether module path mod holds import path p, ignoring case.
func pathHolds(mod, p string) bool {
	return len(p) >= len(mod) && strings.EqualFold(p[:len(mod)], mod) && (len(p) == len(mod) || p[len(mod)] == '/')
}

// moduleListing is what `go list -m -json all` answered for a build: its modules, or why it
// listed none.
type moduleListing struct {
	Modules []listedModule
	Err     string
}

// listModules lists buildDir's build list once per build per scan, through the run cache: every
// advisory resolved against the build reads the same list. A listing the go command refused is
// kept as that refusal; one cut short by ctx is not kept, so a later advisory lists again.
func listModules(ctx context.Context, buildDir string) ([]listedModule, error) {
	b, err := runCached(ctx, "modlist", buildKey(buildDir), func() ([]byte, error) {
		var l moduleListing
		out, err := modsearchGo(goCommand(ctx, buildDir, "list", "-m", "-json", "all"))
		if err == nil {
			l.Modules, err = decodeModules(out)
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			l.Err = err.Error()
		}
		return json.Marshal(l)
	})
	if err != nil {
		return nil, err
	}
	var l moduleListing
	if err := json.Unmarshal(b, &l); err != nil {
		return nil, fmt.Errorf("decode cached module list: %w", err)
	}
	if l.Err != "" {
		return nil, errors.New(l.Err)
	}
	return l.Modules, nil
}

func decodeModules(out []byte) ([]listedModule, error) {
	var mods []listedModule
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var m listedModule
		if err := dec.Decode(&m); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		mods = append(mods, m)
	}
	return mods, nil
}

// downloadTarget is the path@version a module's source is downloaded as: its replacement's when a
// replace by another module substitutes one, "" when there is nothing to download.
func downloadTarget(m listedModule) string {
	switch {
	case m.Main:
		return ""
	case m.Replace != nil && m.Replace.Version != "":
		return m.Replace.Path + "@" + m.Replace.Version
	case m.Replace != nil:
		return "" // a directory replace: its source is on disk or nowhere
	case m.Version != "":
		return m.Path + "@" + m.Version
	}
	return ""
}

func sourceDir(m listedModule, downloaded map[string]string) string {
	if m.Replace != nil {
		if m.Replace.Dir != "" {
			return m.Replace.Dir
		}
	} else if m.Dir != "" {
		return m.Dir
	}
	return downloaded[downloadTarget(m)]
}

// downloadModules downloads the modules whose source is not on disk and returns the directory of
// each one that downloaded and verified, keyed by path@version. The answer is kept once per build
// per scan, unless the download could not start or ctx cut it short: a later search then downloads
// again.
func downloadModules(ctx context.Context, buildDir string, mods []listedModule) map[string]string {
	var args []string
	for _, m := range mods {
		if mv := downloadTarget(m); mv != "" && sourceDir(m, nil) == "" {
			args = append(args, mv)
		}
	}
	if len(args) == 0 {
		return nil
	}
	var unfinished map[string]string
	b, err := runCached(ctx, "moddownload", buildKey(buildDir, args...), func() ([]byte, error) {
		dirs, err := download(ctx, buildDir, args)
		if err != nil {
			unfinished = dirs
			return nil, err
		}
		return json.Marshal(dirs)
	})
	if err != nil {
		return unfinished
	}
	var dirs map[string]string
	if json.Unmarshal(b, &dirs) != nil {
		return nil
	}
	return dirs
}

// download runs `go mod download` for args against a copy of buildDir's go.mod and go.sum, so the
// checksums it records never land in the checkout. It returns the modules it read, and an error
// when it could not start or ctx cut it short.
func download(ctx context.Context, buildDir string, args []string) (map[string]string, error) {
	tmp, err := os.MkdirTemp("", "assay-modsearch")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	modfile := filepath.Join(tmp, "build.mod")
	if err := copyFile(filepath.Join(buildDir, "go.mod"), modfile); err != nil {
		return nil, err
	}
	if err := copyFile(filepath.Join(buildDir, "go.sum"), filepath.Join(tmp, "build.sum")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	// A module that fails to download is reported in its own JSON entry and makes the command
	// exit non-zero, so the output is read whatever the exit status. A checksum mismatch stops the
	// command before it reports any module, which leaves every module it was to download unread.
	out, _ := modsearchGo(goCommand(ctx, buildDir, append([]string{"mod", "download", "-json", "-modfile=" + modfile}, args...)...))
	dirs := make(map[string]string, len(args))
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var m struct {
			Path, Version, Dir, Error string
		}
		if dec.Decode(&m) != nil {
			break
		}
		if m.Error == "" && m.Dir != "" {
			dirs[m.Path+"@"+m.Version] = m.Dir
		}
	}
	return dirs, ctx.Err()
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o600)
}

// declaresName reports whether a module's source rooted at dir declares a function, method,
// variable or constant with one of names. It reads every .go file the module's packages can
// compile, whatever its build constraints: test files, testdata, vendor, directories the go
// command ignores (leading '.' or '_') and nested modules are not part of the module. A file that
// does not parse, or a symbolic link to a .go file or a directory, is an error, since what it
// declares is unknown.
func declaresName(ctx context.Context, dir string, names map[string]bool) (bool, error) {
	found := false
	fset := token.NewFileSet()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if fi, err := os.Stat(path); strings.HasSuffix(path, ".go") || err != nil || fi.IsDir() {
				return fmt.Errorf("symbolic link %s", path)
			}
			return nil
		}
		if d.IsDir() {
			if path == dir {
				return nil
			}
			if n := d.Name(); n == "testdata" || n == "vendor" || strings.HasPrefix(n, ".") || strings.HasPrefix(n, "_") {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		if declares(f, names) {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found, err
}

func declares(f *ast.File, names map[string]bool) bool {
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if names[d.Name.Name] {
				return true
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					for _, n := range vs.Names {
						if names[n.Name] {
							return true
						}
					}
				}
			}
		}
	}
	return false
}
