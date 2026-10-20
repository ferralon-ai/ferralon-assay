package jsanalysis

import (
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// stylesheetExtensions are the extensions a relative import can name and, under stock bundler
// tooling, load no package code. A CSS Modules file (x.module.css) ends in one of them.
var stylesheetExtensions = map[string]bool{".css": true, ".scss": true, ".sass": true, ".less": true}

// stylesheetRunsNoCode reports whether rel, the build-relative target of a relative import in
// fromModule, is a stylesheet whose load runs no code this lane leaves wholly unaccounted for. That
// holds only when it has a stylesheet extension, it is a regular file in the build tree, the
// importing module's package is a stock Create React App (stockCRAPackage), and neither the tree nor
// any directory above it holds anything that can change what a stylesheet import loads. Under
// react-scripts a stylesheet import runs only the loader runtime, which the caller still declares
// (stylesheetRuntime). Any other toolchain, or a config the lane does not parse, can route the
// extension to any loader.
func (rs *resolver) stylesheetRunsNoCode(fromModule, rel string) bool {
	return stylesheetExtensions[path.Ext(rel)] && rs.regularInTree(rel) &&
		rs.stockCRAPackage(fromModule) && !rs.prog.styleToolingPresent()
}

// stylesheetRuntime is the limit a stylesheet import leaves under react-scripts: each import runs
// the loader runtime the build emits for it (style-loader and css-loader in development,
// mini-css-extract-plugin's chunk loading in production, inside webpack's module runtime). That
// code is package code this lane does not read, so advisories on those packages stay held. It
// injects styles and calls back into no first-party code, so it can reach no other package.
func stylesheetRuntime() plugin.ScopedReason {
	return plugin.ScopedReason{
		Reason:  plugin.PartialReasonUninspectablePackage,
		Package: "pkg:npm/style-loader",
		Targets: []string{"pkg:npm/css-loader", "pkg:npm/mini-css-extract-plugin", "pkg:npm/style-loader", "pkg:npm/webpack"},
	}
}

// stockCRAPackage reports whether the nearest package.json at or above fromModule's directory,
// inside the build tree, declares a stock Create React App: it depends on the published
// react-scripts (registryRange), every
// script runs react-scripts with a plain subcommand and plain flags, and it has no top-level key
// outside craManifestKeys. A missing, unreadable or undecodable manifest does not qualify.
func (rs *resolver) stockCRAPackage(fromModule string) bool {
	dir := path.Dir(fromModule)
	for {
		file := filepath.Join(rs.prog.root, filepath.FromSlash(dir), "package.json")
		if _, err := os.Lstat(file); err == nil {
			data, ok := readInRoot(rs.prog.root, file, maxStyleManifest)
			return ok && stockCRAManifest(data)
		}
		if dir == "." || dir == "" {
			return false
		}
		dir = path.Dir(dir)
	}
}

// craManifestKeys are the top-level package.json keys a stock Create React App manifest may carry.
// None of them changes what a stylesheet import loads; jest is admitted only with craJestKeys.
var craManifestKeys = map[string]bool{
	"name": true, "version": true, "private": true, "description": true, "license": true,
	"author": true, "contributors": true, "repository": true, "homepage": true, "bugs": true,
	"keywords": true, "proxy": true, "engines": true, "eslintConfig": true, "browserslist": true,
	"dependencies": true, "devDependencies": true, "scripts": true, "jest": true,
}

// craJestKeys are the jest overrides that neither map a module nor transform one.
var craJestKeys = map[string]bool{
	"testEnvironment": true, "clearMocks": true, "resetMocks": true, "resetModules": true,
	"restoreMocks": true, "collectCoverageFrom": true, "coveragePathIgnorePatterns": true,
	"coverageReporters": true, "coverageThreshold": true, "displayName": true, "testMatch": true,
	"transformIgnorePatterns": true, "watchPathIgnorePatterns": true,
}

func stockCRAManifest(data []byte) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) != nil || m == nil {
		return false
	}
	for k := range m {
		if !craManifestKeys[k] {
			return false
		}
	}
	if raw, ok := m["jest"]; ok {
		var jest map[string]json.RawMessage
		if json.Unmarshal(raw, &jest) != nil {
			return false
		}
		for k := range jest {
			if !craJestKeys[k] {
				return false
			}
		}
	}
	cra := false
	for _, field := range []string{"dependencies", "devDependencies"} {
		raw, ok := m[field]
		if !ok {
			continue
		}
		var deps map[string]json.RawMessage
		if json.Unmarshal(raw, &deps) != nil {
			return false
		}
		if v, has := deps["react-scripts"]; has {
			var r string
			if json.Unmarshal(v, &r) != nil || !registryRange(r) {
				return false
			}
			cra = true
		}
	}
	if !cra {
		return false
	}
	if raw, ok := m["scripts"]; ok {
		var scripts map[string]string
		if json.Unmarshal(raw, &scripts) != nil {
			return false
		}
		for _, v := range scripts {
			if !reactScriptsCommand(v) {
				return false
			}
		}
	}
	return true
}

// registryRange reports whether a dependency version is a plain semver range, which installs the
// published package; an alias (npm:), a path, a URL or a git ref can install a fork.
func registryRange(v string) bool {
	return strings.TrimSpace(v) != "" && strings.Trim(v, "0123456789.^~<>=xX* |-") == ""
}

// reactScriptsCommand reports whether a script is "react-scripts <start|build|test|eject>"
// followed only by --flags that load nothing: no shell syntax, and no flag that names a config,
// a require hook or a loader.
func reactScriptsCommand(script string) bool {
	f := strings.Fields(script)
	if len(f) < 2 || f[0] != "react-scripts" {
		return false
	}
	switch f[1] {
	case "start", "build", "test", "eject":
	default:
		return false
	}
	for _, flag := range f[2:] {
		name, _, _ := strings.Cut(strings.TrimPrefix(flag, "--"), "=")
		if !strings.HasPrefix(flag, "--") || name == "" || strings.ContainsAny(flag, "$`;&|<>()\\\"'") {
			return false
		}
		for _, w := range []string{"config", "require", "loader", "import", "preload"} {
			if strings.Contains(strings.ToLower(name), w) {
				return false
			}
		}
	}
	return true
}

// regularInTree reports whether the build-relative path rel names a regular file the build-tree
// walk visits at its real path: it resolves inside the root, through no node_modules or
// site-packages directory. A symlink on the way counts only when its target is such a place,
// as the walk reads a symlinked directory only through its target.
func (rs *resolver) regularInTree(rel string) bool {
	realRoot, err := filepath.EvalSymlinks(rs.prog.root)
	if err != nil {
		return false
	}
	real, err := filepath.EvalSymlinks(filepath.Join(rs.prog.root, filepath.FromSlash(rel)))
	if err != nil {
		return false
	}
	under, err := filepath.Rel(realRoot, real)
	if err != nil || under == "." || under == ".." || strings.HasPrefix(under, ".."+string(filepath.Separator)) {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(under), "/") {
		if buildtree.Skipped(part) {
			return false
		}
	}
	fi, err := os.Stat(real)
	return err == nil && fi.Mode().IsRegular()
}

// styleToolingPresent reports, once per program, whether the build tree, or a directory above it
// (styleToolingAbove), holds anything that can change what a stylesheet import loads. Presence
// counts; nothing is parsed beyond a package.json's top-level keys and script words. It counts:
//   - a bundler, framework or test-runner config, by name and in any case: anything named
//     *webpack* (which covers an ejected Create React App's config/), esbuild*, gatsby-*,
//     .babelrc*, .parcelrc, .umirc*, config-overrides.js, angular.json, or a
//     <styleToolingConfigs>.config.* file;
//   - a package.json with a browser, babel, alias or browserify key or a jest.transform; one
//     that depends on a bundler, build wrapper or require hook (styleToolingTools); one with a
//     script that runs one, names a config, preloads a module or sets NODE_OPTIONS; or one that
//     cannot be read or decoded;
//   - a directory the walk cannot read, or a symlinked directory whose target the walk does not
//     itself read (one that leaves the tree included). A symlink to a file needs no rule of its
//     own: a config is recognised by its name, and a package.json that resolves outside the
//     tree cannot be read.
func (p *program) styleToolingPresent() bool {
	if p.styleTooling == nil {
		present := styleToolingIn(p.root)
		p.styleTooling = &present
	}
	return *p.styleTooling
}

func styleToolingIn(root string) bool {
	realRoot, rootErr := filepath.EvalSymlinks(root)
	if rootErr != nil {
		return true
	}
	walked := map[string]bool{}
	var linkedDirs []string
	present := false
	_ = buildtree.Walk(root, func(e buildtree.Entry, err error) error {
		switch {
		case err != nil:
			present = true
		case e.Skipped:
			return nil
		case e.Symlink && isDirPath(e.Path):
			linkedDirs = append(linkedDirs, e.Path)
			return nil
		case styleToolingName(e.D.Name()):
			present = true
		case e.D.IsDir():
			if rel, err := filepath.Rel(root, e.Path); err == nil {
				walked[filepath.Join(realRoot, rel)] = true
			}
			return nil
		case e.D.Name() == "package.json":
			present = styleToolingManifest(root, e.Path)
		}
		if present {
			return filepath.SkipAll
		}
		return nil
	})
	if present || styleToolingAbove(realRoot) {
		return true
	}
	for _, link := range linkedDirs {
		if target, err := filepath.EvalSymlinks(link); err != nil || !walked[target] {
			return true
		}
	}
	return false
}

// styleToolingConfigs are the config base names, before ".config.", that count wherever
// they appear, compared case-insensitively.
var styleToolingConfigs = []string{
	"vite", "rollup", "rspack", "rsbuild", "craco", "next", "nuxt", "svelte", "astro", "babel",
	"vue", "jest", "remix", "snowpack", "quasar", "parcel",
}

func styleToolingName(name string) bool {
	name = strings.ToLower(name)
	switch {
	case strings.Contains(name, "webpack"), strings.HasPrefix(name, "esbuild"),
		strings.HasPrefix(name, ".babelrc"), strings.HasPrefix(name, "gatsby-"),
		strings.HasPrefix(name, ".umirc"), name == ".parcelrc", name == "config-overrides.js",
		name == "angular.json":
		return true
	}
	for _, c := range styleToolingConfigs {
		if strings.HasPrefix(name, c+".config.") {
			return true
		}
	}
	return false
}

// styleToolingTools are the bundlers, build wrappers and require hooks whose presence in a
// dependency or a script means a stylesheet import may be routed to a loader the lane does not
// know. A script also counts when it names a config file or preloads a module.
var styleToolingTools = []string{
	"webpack", "esbuild", "vite", "rollup", "parcel", "browserify", "rsbuild", "rspack", "craco",
	"react-app-rewired", "customize-cra", "vue-cli-service", "@vue/cli", "gatsby", "nuxt", "umi",
	"require-hook", "css-modules", "@babel/register",
}

// styleToolingScriptFlags are script tokens that name a config or preload code.
var styleToolingScriptFlags = []string{"--config", "-c", "-r", "--require", "--loader", "--experimental-loader", "--import"}

func styleToolingScript(script string) bool {
	if strings.Contains(script, "NODE_OPTIONS") {
		return true
	}
	for _, tok := range strings.Fields(script) {
		tok = strings.Trim(tok, `"'`)
		flag, _, _ := strings.Cut(tok, "=")
		for _, f := range styleToolingScriptFlags {
			if flag == f {
				return true
			}
		}
		if tok == "next" || styleToolingDependency(tok) {
			return true
		}
	}
	return false
}

func styleToolingDependency(name string) bool {
	name = strings.ToLower(name)
	for _, t := range styleToolingTools {
		if name == t || strings.HasPrefix(name, t+"-") || strings.HasPrefix(name, "@"+t+"/") ||
			strings.Contains(name, "/"+t) || (len(t) > 4 && strings.Contains(name, t)) {
			return true
		}
	}
	return name == "next"
}

// styleToolingManifest reports whether the package.json at file declares a stylesheet
// transform, a bundler, a build wrapper or a require hook, or cannot be read or decoded.
func styleToolingManifest(root, file string) bool {
	data, ok := readInRoot(root, file, maxStyleManifest)
	if !ok {
		return true
	}
	return styleToolingManifestData(data)
}

func styleToolingManifestData(data []byte) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) != nil || m == nil {
		return true
	}
	for _, key := range []string{"browser", "babel", "alias", "browserify"} {
		if _, ok := m[key]; ok {
			return true
		}
	}
	if raw, ok := m["jest"]; ok {
		var jest map[string]json.RawMessage
		if json.Unmarshal(raw, &jest) != nil {
			return true
		}
		if _, ok := jest["transform"]; ok {
			return true
		}
	}
	for _, field := range []string{"scripts", "dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		raw, ok := m[field]
		if !ok {
			continue
		}
		var entries map[string]json.RawMessage
		if json.Unmarshal(raw, &entries) != nil {
			return true
		}
		for name, v := range entries {
			if field != "scripts" && styleToolingDependency(name) {
				return true
			}
			if field == "scripts" {
				var script string
				if json.Unmarshal(v, &script) != nil || styleToolingScript(script) {
					return true
				}
			}
		}
	}
	return false
}

// styleToolingAbove reports whether a directory above the build root, up to and including the
// first one holding .git, holds a package.json or a tooling config: a build run from the root
// can read either (a workspace root's manifest, a config found by walking up).
func styleToolingAbove(realRoot string) bool {
	dir := realRoot
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return false
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
		entries, err := os.ReadDir(dir)
		if err != nil {
			return true
		}
		for _, e := range entries {
			if e.Name() == "package.json" || styleToolingName(e.Name()) {
				return true
			}
		}
	}
}

// maxStyleManifest bounds the read of a package.json the tooling check inspects.
const maxStyleManifest = 1 << 20

func isDirPath(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// readInRoot reads file when its real path lies under root's real path, it is a regular
// file, and it holds at most limit bytes; otherwise it reports false.
func readInRoot(root, file string, limit int64) ([]byte, bool) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, false
	}
	if !buildtree.Inside(realRoot, file) {
		return nil, false
	}
	real, err := filepath.EvalSymlinks(file)
	if err != nil {
		return nil, false
	}
	// O_NONBLOCK keeps a FIFO from blocking the open; the fstat then rejects it.
	f, err := os.OpenFile(real, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, false
	}
	return data, true
}
