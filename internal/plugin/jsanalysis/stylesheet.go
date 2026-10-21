package jsanalysis

import (
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"unicode"

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
	return stylesheetExtensions[path.Ext(rel)] && regularInTree(rs.prog.root, rel) &&
		stockCRAPackage(rs.prog.root, fromModule) && !rs.prog.styleToolingPresent()
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

// stockCRAPackage reports whether fromModule lies under the src directory of the package whose
// package.json is nearest at or above it, inside the build tree, and that package.json declares a
// stock Create React App: it depends on the published react-scripts (registryRange), every script
// is a reactScriptsCommand, and it has no top-level key outside craManifestKeys. react-scripts
// compiles only src, so a module elsewhere is built by something else. A missing, unreadable or
// undecodable manifest does not qualify.
func stockCRAPackage(root, fromModule string) bool {
	dir := path.Dir(fromModule)
	for {
		file := filepath.Join(root, filepath.FromSlash(dir), "package.json")
		if _, err := os.Lstat(file); err == nil {
			if !strings.HasPrefix(fromModule, path.Join(dir, "src")+"/") {
				return false
			}
			data, ok := readInRoot(root, file, maxStyleManifest)
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
// published package; an alias (npm:), a path (".", "./x"), a URL, a git ref or a tag can install
// a fork or something unpinned.
func registryRange(v string) bool {
	return strings.ContainsAny(v, "0123456789xX*") && !strings.HasPrefix(v, ".") &&
		strings.Trim(v, "0123456789.^~<>=xX* |-") == ""
}

// reactScriptsCommand reports whether a script is the single command
// "react-scripts <start|build|test|eject>" followed only by reactScriptsFlags.
func reactScriptsCommand(script string) bool {
	words, ok := scriptWords(script)
	return ok && len(words) > 0 && words[0] == "react-scripts" && reactScriptsArgs(words[1:])
}

// reactScriptsFlags are the react-scripts and jest flags that neither name a module nor change
// how one is resolved or transformed. Any other flag (jest's --resolver, --preset, --setupFiles,
// --config and the like) disqualifies.
var reactScriptsFlags = map[string]bool{
	"--watchAll": true, "--watchAll=true": true, "--watchAll=false": true, "--watch": true,
	"--coverage": true, "--ci": true, "--passWithNoTests": true, "--silent": true, "--verbose": true,
	"--runInBand": true, "--env=jsdom": true, "--env=node": true, "--profile": true, "--stats": true,
}

func reactScriptsArgs(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "start", "build", "test", "eject":
	default:
		return false
	}
	for _, a := range args[1:] {
		if !reactScriptsFlags[a] {
			return false
		}
	}
	return true
}

// regularInTree reports whether the build-relative path rel names a regular file the build-tree
// walk visits at its real path: it resolves inside the root, through no node_modules or
// site-packages directory. A symlink on the way counts only when its target is such a place,
// as the walk reads a symlinked directory only through its target.
func regularInTree(root, rel string) bool {
	_, ok := realInTree(root, rel)
	return ok
}

// realInTree is regularInTree that also returns the file's real path relative to the root.
func realInTree(root, rel string) (string, bool) {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", false
	}
	real, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return "", false
	}
	under, err := filepath.Rel(realRoot, real)
	if err != nil || under == "." || under == ".." || strings.HasPrefix(under, ".."+string(filepath.Separator)) {
		return "", false
	}
	for _, part := range strings.Split(filepath.ToSlash(under), "/") {
		if buildtree.Skipped(part) {
			return "", false
		}
	}
	fi, err := os.Stat(real)
	return filepath.ToSlash(under), err == nil && fi.Mode().IsRegular()
}

// styleToolingPresent reports, once per program, whether the build tree, or a directory above it
// (styleToolingAbove), holds anything that can change what a stylesheet import loads. Presence
// counts; nothing is parsed beyond a package.json's top-level keys and script words and an
// .npmrc's keys. It counts:
//   - a bundler, framework or test-runner config, by name and in any case: any name containing
//     webpack (which covers an ejected Create React App's config/), esbuild*, vitest.*,
//     gatsby-*, .babelrc*, .parcelrc, .umirc*, .storybook, bunfig.toml, nodemon.json,
//     config-overrides.js, angular.json, or a <styleToolingConfigs>.config.* file;
//   - a package manager hook or override: pnpm-workspace.yaml, .pnpmfile.*, .yarnrc*, .pnp.*,
//     a patches directory, an .npmrc setting an npmrcHookKeys key;
//   - a first-party module outside a stock Create React App's src that loads a package off
//     serverRuntimePackages (importsUnlisted);
//   - a package.json with a key in styleToolingKeys or a jest key outside craJestKeys; one named
//     as a styleToolingPackage, which a workspace links in place of the published one; one that
//     depends on a bundler, build wrapper, test runner or require hook (styleToolingTools), or on
//     anything through a version that is not a registryRange; one with a script that is not an
//     allowedScript; or one that cannot be read or decoded;
//   - a directory the walk cannot read, or a symlinked directory whose target the walk does not
//     itself read (one that leaves the tree included). A symlink to a file needs no rule of its
//     own: a config is recognised by its name, and a package.json that resolves outside the
//     tree cannot be read.
func (p *program) styleToolingPresent() bool {
	if p.styleTooling == nil {
		present := styleToolingIn(p.root) || p.importsUnlisted()
		p.styleTooling = &present
	}
	return *p.styleTooling
}

// importsUnlisted reports whether a first-party module outside every stock Create React App's
// src loads anything but a Node builtin, a relative file outside those src directories, or a
// serverRuntimePackages package. Such a module runs under node, not react-scripts, and a package
// off that list may compile the app's source with its own stylesheet rule, whatever script starts
// it. Every other package counts, so one missing from the list costs the exemption, never
// soundness. A module under a stock app's src is compiled for the browser and runs no bundler.
func (p *program) importsUnlisted() bool {
	inSrc := map[string]bool{}
	craSrc := func(module string) bool {
		v, ok := inSrc[module]
		if !ok {
			v = stockCRAPackage(p.root, module)
			inSrc[module] = v
		}
		return v
	}
	for _, mi := range p.modules {
		if craSrc(mi.module) {
			continue
		}
		for _, ls := range mi.bindings.specifiers {
			switch spec := ls.spec; {
			case strings.HasPrefix(spec, "."):
				// A relative load into an app's src runs that module under node too.
				target := path.Join(path.Dir(mi.module), spec)
				if craSrc(target) || craSrc(target+"/index") {
					return true
				}
			case spec == "" || spec[0] == '/':
				return true
			case isNodeBuiltin(spec):
			default:
				if name, _ := splitBareSpecifier(spec); !serverRuntimePackages[name] {
					return true
				}
			}
		}
	}
	return false
}

// serverRuntimePackages are the server runtime libraries a full-stack Create React App's own
// server code may load: none of them bundles, compiles or transforms source.
var serverRuntimePackages = map[string]bool{
	"axios": true, "bcrypt": true, "bcryptjs": true, "body-parser": true, "cloudinary": true,
	"colors": true, "compression": true, "connect-mongo": true, "cookie-parser": true, "cors": true,
	"debug": true, "dotenv": true, "express": true, "express-async-handler": true,
	"express-rate-limit": true, "express-session": true, "express-validator": true, "helmet": true,
	"http-errors": true, "joi": true, "jsonwebtoken": true, "mongodb": true, "mongoose": true,
	"morgan": true, "multer": true, "nodemailer": true, "passport": true, "passport-jwt": true,
	"passport-local": true, "slugify": true, "socket.io": true, "stripe": true, "uuid": true,
	"validator": true,
}

// styleToolingPackage reports whether an in-tree package.json of this name, linked by a workspace
// in place of the published package, can decide what a stylesheet import loads: react-scripts, a
// package its webpack config builds the stylesheet pipeline from, or a styleToolingTools entry.
// Names are matched exactly.
func styleToolingPackage(name string) bool {
	name = strings.ToLower(name)
	switch name {
	case "react-scripts", "react-dev-utils", "mini-css-extract-plugin", "css-loader", "style-loader",
		"sass-loader", "postcss-loader", "resolve-url-loader", "babel-loader", "file-loader",
		"url-loader", "babel-preset-react-app", "@babel/core", "postcss", "postcss-preset-env",
		"postcss-flexbugs-fixes", "postcss-normalize", "sass", "less", "next":
		return true
	}
	return slices.Contains(styleToolingTools, name)
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
		case e.D.Name() == ".npmrc":
			present = npmrcHooks(root, e.Path)
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
		strings.HasPrefix(name, "vitest."), strings.HasPrefix(name, ".babelrc"),
		strings.HasPrefix(name, "gatsby-"), strings.HasPrefix(name, ".umirc"),
		strings.HasPrefix(name, ".pnpmfile."), strings.HasPrefix(name, ".yarnrc"),
		strings.HasPrefix(name, ".pnp."), name == ".parcelrc", name == ".storybook",
		name == "bunfig.toml", name == "nodemon.json", name == "pnpm-workspace.yaml",
		name == "patches", name == "config-overrides.js", name == "angular.json":
		return true
	}
	for _, c := range styleToolingConfigs {
		if strings.HasPrefix(name, c+".config.") {
			return true
		}
	}
	return false
}

// styleToolingTools are the bundlers, build wrappers, test runners and require hooks whose
// presence in a dependency means a stylesheet import may be routed to a loader the lane does not
// know, whether a script or a CI step runs them.
var styleToolingTools = []string{
	"webpack", "esbuild", "vite", "vitejs", "vitest", "rollup", "parcel", "browserify", "rsbuild",
	"rspack", "craco", "react-app-rewired", "customize-cra", "vue-cli-service", "@vue/cli",
	"gatsby", "nuxt", "umi", "storybook", "bun", "require-hook", "css-modules", "ignore-styles",
	"@babel/register",
}

// styleToolingKeys are the package.json keys that remap or rewrite what a module resolves to,
// or that configure a runner to preload code.
var styleToolingKeys = []string{
	"browser", "babel", "alias", "browserify", "resolutions", "overrides", "pnpm",
	"patchedDependencies", "nodemonConfig",
}

// scriptEnv are the environment assignments a script may lead with; none of them makes node or a
// package manager load a module. BROWSER is admitted only as none: react-dev-utils runs a .js value
// with node.
var scriptEnv = map[string]bool{
	"NODE_ENV": true, "NPM_CONFIG_PRODUCTION": true, "PORT": true, "CI": true,
	"GENERATE_SOURCEMAP": true, "BROWSER": true,
}

// scriptPreloadFlags are words that name a config or preload code, rejected anywhere in a
// command, including among the arguments node hands to the script it runs.
var scriptPreloadFlags = []string{"--config", "-c", "-r", "--require", "--loader", "--experimental-loader", "--import"}

// scriptSite is where a package.json script is declared: the build root, the manifest's
// directory, and the names of the scripts the manifest declares.
type scriptSite struct {
	root, dir string
	scripts   map[string]bool
	walk      *sourceWalk
}

// declares reports whether the manifest a package-manager command runs against (the site's own,
// or the one in its --prefix/--cwd directory) declares script. yarn classic runs a binary of that
// name when no script has it.
func (site scriptSite) declares(prefix, script string) bool {
	if prefix == "" {
		return site.scripts[script]
	}
	data, ok := readInRoot(site.root, filepath.Join(site.dir, filepath.FromSlash(prefix), "package.json"), maxStyleManifest)
	if !ok {
		return false
	}
	var m struct {
		Scripts map[string]json.RawMessage `json:"scripts"`
	}
	if json.Unmarshal(data, &m) != nil {
		return false
	}
	_, ok = m.Scripts[script]
	return ok
}

// runsParsed reports whether file, run from the site's directory by a runner that hands files
// with exts extensions to node, is a module the source walk parses, so that importsUnlisted reads
// what it loads: a regular in-tree file (realInTree) with such an extension, or named without one
// and found as such a .js file, under no directory the walk skips, outside every stock Create
// React App's src, and at a real path the walk itself lists (sourceWalk), which drops a .d.ts file
// and a name spelled in another case than the one on disk.
func (site scriptSite) runsParsed(file string, exts map[string]bool) bool {
	rel, err := filepath.Rel(site.root, filepath.Join(site.dir, filepath.FromSlash(file)))
	if err != nil {
		return false
	}
	rel = filepath.ToSlash(rel)
	if path.Ext(rel) == "" {
		if _, err := os.Lstat(filepath.Join(site.root, filepath.FromSlash(rel))); err == nil {
			return false // node runs an extensionless file, or a directory's entry point, as it is
		}
		rel += ".js"
	}
	under, ok := realInTree(site.root, rel)
	if !ok || !exts[path.Ext(rel)] || !exts[path.Ext(under)] ||
		stockCRAPackage(site.root, rel) || stockCRAPackage(site.root, under) {
		return false
	}
	for _, part := range strings.Split(rel+"/"+under, "/") {
		if skipDir(part) {
			return false
		}
	}
	return site.walk.lists(site.root, under)
}

// nodemonExtensions are the extensions nodemon hands to node; it runs a .ts file through ts-node,
// which loads what tsconfig.json names first.
var nodemonExtensions = map[string]bool{".js": true, ".mjs": true, ".cjs": true}

// sourceWalk holds the files the source walk (jsFiles) lists under a build root, computed once.
type sourceWalk struct {
	files map[string]bool
	done  bool
}

// lists reports whether the walk of root lists the root-relative path rel.
func (w *sourceWalk) lists(root, rel string) bool {
	if !w.done {
		w.done = true
		if files, err := jsFiles(root); err == nil {
			w.files = map[string]bool{}
			for _, f := range files {
				w.files[f] = true
			}
		}
	}
	return w.files[filepath.Join(root, filepath.FromSlash(rel))]
}

// allowedScript reports whether every command in a package.json script, joined only by &&, is
// one this lane knows loads no stylesheet through other tooling:
//   - a reactScriptsCommand;
//   - node running a file the source walk parses (runsParsed) with no flag before it, or nodemon
//     running a .js, .mjs or .cjs one with nothing else (nodemon reads its own options after the
//     file);
//   - npm, yarn or pnpm running, starting or testing a script that the manifest it runs against
//     declares (and which is itself checked there), or installing, with packageManagerFlags only
//     and no --prefix/--cwd into node_modules;
//   - concurrently, at the top level only, running allowed commands;
//   - echo, or exit with a status.
//
// Each may lead with scriptEnv assignments. Shell expansion, redirection, pipes, escapes, a path
// leaving the tree, and a scriptPreloadFlags word all disqualify.
func allowedScript(script string, site scriptSite) bool {
	return allowedCommands(script, true, site)
}

func allowedCommands(script string, top bool, site scriptSite) bool {
	words, ok := scriptWords(script)
	if !ok || len(words) == 0 {
		return false
	}
	start := 0
	for i := 0; i <= len(words); i++ {
		if i < len(words) && words[i] != "&&" {
			continue
		}
		if !allowedCommand(words[start:i], top, site) {
			return false
		}
		start = i + 1
	}
	return true
}

func allowedCommand(w []string, top bool, site scriptSite) bool {
	for len(w) > 0 {
		name, value, assign := strings.Cut(w[0], "=")
		if !assign {
			break
		}
		if !scriptEnv[name] || (name == "BROWSER" && value != "none") {
			return false
		}
		w = w[1:]
	}
	if len(w) == 0 {
		return false
	}
	for _, word := range w {
		flag, _, _ := strings.Cut(word, "=")
		if strings.Contains(word, "..") || strings.HasPrefix(word, "/") || strings.HasPrefix(word, "~") ||
			slices.Contains(scriptPreloadFlags, flag) {
			return false
		}
	}
	switch w[0] {
	case "react-scripts":
		return reactScriptsArgs(w[1:])
	case "node":
		return len(w) > 1 && !strings.HasPrefix(w[1], "-") && site.runsParsed(w[1], jsExtensions)
	case "nodemon":
		return len(w) == 2 && !strings.HasPrefix(w[1], "-") && site.runsParsed(w[1], nodemonExtensions)
	case "npm", "yarn", "pnpm":
		script, prefix, ok := packageManagerArgs(w[1:])
		if !ok {
			return false
		}
		for _, part := range strings.Split(prefix, "/") {
			if buildtree.Skipped(part) {
				return false
			}
		}
		return script == "" || site.declares(prefix, script)
	case "concurrently":
		if !top || len(w) == 1 {
			return false
		}
		for _, cmd := range w[1:] {
			if !concurrentlyFlags[cmd] && !allowedCommands(cmd, false, site) {
				return false
			}
		}
		return true
	case "echo":
		return true
	case "exit":
		return len(w) == 2 && strings.Trim(w[1], "0123456789") == "" && w[1] != ""
	}
	return false
}

// concurrentlyFlags are concurrently's flags that take no value.
var concurrentlyFlags = map[string]bool{"-k": true, "--kill-others": true, "--kill-others-on-fail": true, "-r": true, "--raw": true}

// packageManagerFlags are the package-manager flags that load nothing. --prefix and --cwd take
// the next word as a directory; --prefix=dir is the same.
var packageManagerFlags = map[string]bool{
	"--prefix": true, "--cwd": true, "--silent": true, "-s": true, "--if-present": true,
	"--production": true, "--legacy-peer-deps": true, "--no-audit": true,
}

// packageManagerArgs reports whether a package-manager invocation runs a named script (run,
// run-script), or starts, tests or installs, with packageManagerFlags only, and returns the script
// it runs ("" for an install) and its --prefix/--cwd directory. Nothing may be appended to the
// script it runs, and nothing may be installed by name.
func packageManagerArgs(args []string) (script, prefix string, ok bool) {
	if len(args) == 0 {
		return "", "", false
	}
	positional := 0
	switch args[0] {
	case "run", "run-script":
		positional = 1
	case "start", "test":
		script = args[0]
	case "install", "ci", "i":
	default:
		return "", "", false
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		flag, value, valued := strings.Cut(a, "=")
		switch {
		case strings.HasPrefix(a, "-"):
			if !packageManagerFlags[flag] || (valued && flag != "--prefix" && flag != "--cwd") {
				return "", "", false
			}
			if !valued && (a == "--prefix" || a == "--cwd") {
				if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
					return "", "", false
				}
				i++
				value = args[i]
			}
			if flag == "--prefix" || flag == "--cwd" {
				if prefix != "" {
					return "", "", false
				}
				prefix = value
			}
		case positional > 0:
			positional--
			script = a
		default:
			return "", "", false
		}
	}
	return script, prefix, positional == 0
}

// scriptWords splits a script into words as a shell would, honouring single and double quotes,
// with "&&" as a word of its own. It reports false for an unterminated quote, an escape, any
// character a shell expands, redirects or pipes on, and any other use of &.
func scriptWords(script string) ([]string, bool) {
	if strings.ContainsAny(script, "$`;|<>()\\*?!\n") {
		return nil, false
	}
	var words []string
	var cur strings.Builder
	var quote rune
	inWord := false
	for _, r := range script {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote, inWord = r, true
		case r == ' ' || r == '\t':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if quote != 0 {
		return nil, false
	}
	if inWord {
		words = append(words, cur.String())
	}
	for _, w := range words {
		if w != "&&" && strings.Contains(w, "&") {
			return nil, false
		}
	}
	return words, true
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
	return styleToolingManifestData(root, filepath.Dir(file), data)
}

func styleToolingManifestData(root, dir string, data []byte) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) != nil || m == nil {
		return true
	}
	for _, key := range styleToolingKeys {
		if _, ok := m[key]; ok {
			return true
		}
	}
	if raw, ok := m["name"]; ok {
		var name string
		if json.Unmarshal(raw, &name) != nil || styleToolingPackage(name) ||
			serverRuntimePackages[strings.ToLower(name)] {
			return true
		}
	}
	if raw, ok := m["jest"]; ok {
		var jest map[string]json.RawMessage
		if json.Unmarshal(raw, &jest) != nil {
			return true
		}
		for k := range jest {
			if !craJestKeys[k] {
				return true
			}
		}
	}
	site := scriptSite{root: root, dir: dir, scripts: map[string]bool{}, walk: &sourceWalk{}}
	if raw, ok := m["scripts"]; ok {
		var scripts map[string]json.RawMessage
		if json.Unmarshal(raw, &scripts) != nil {
			return true
		}
		for name := range scripts {
			site.scripts[name] = true
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
			var s string
			if json.Unmarshal(v, &s) != nil {
				return true
			}
			if field == "scripts" {
				if !allowedScript(s, site) {
					return true
				}
			} else if styleToolingDependency(name) || !registryRange(s) {
				return true
			}
		}
	}
	return false
}

// styleToolingAbove reports whether a directory above the build root, up to and including the
// first one holding a .git directory, holds a package.json or a tooling config: a build run from
// the root can read either (a workspace root's manifest, a config found by walking up). A .git
// file marks a submodule or a linked worktree, whose enclosing directories a build still reads.
func styleToolingAbove(realRoot string) bool {
	dir := realRoot
	for {
		if fi, err := os.Lstat(filepath.Join(dir, ".git")); err == nil && fi.IsDir() {
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
			if e.Name() == "package.json" || styleToolingName(e.Name()) ||
				(e.Name() == ".npmrc" && npmrcHooks(dir, filepath.Join(dir, e.Name()))) {
				return true
			}
		}
	}
}

// npmrcHookKeys are the .npmrc settings that make a package manager load code of the project's
// choosing into a script (node-options), run a hook file or another shell, or read further config.
var npmrcHookKeys = map[string]bool{
	"node-options": true, "pnpmfile": true, "global-pnpmfile": true, "script-shell": true,
	"shell": true, "onload-script": true, "userconfig": true, "globalconfig": true,
}

// npmrcHooks reports whether the .npmrc at file sets an npmrcHookKeys key, may set one through a
// key npm rewrites, or cannot be read. npm, pnpm and yarn classic all read a project .npmrc. Lines
// end at \n or \r, and a line starting with '#' or ';' is a comment. A key loses one pair of
// enclosing quotes, as npm's ini parser removes them, and is then compared more loosely than npm
// does: case-insensitively, with _ as -. A key npm may rewrite to another (a quote, escape or
// ${…} substitution left in it, or any non-ASCII character such as a byte-order mark) counts as a
// hook key, whatever it spells.
func npmrcHooks(root, file string) bool {
	data, ok := readInRoot(root, file, maxStyleManifest)
	if !ok {
		return true
	}
	for _, line := range strings.FieldsFunc(string(data), func(r rune) bool { return r == '\n' || r == '\r' }) {
		key, _, _ := strings.Cut(line, "=")
		if t := strings.TrimLeft(key, " \t"); strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if strings.ContainsFunc(key, func(r rune) bool { return r > unicode.MaxASCII }) {
			return true
		}
		key = strings.TrimSpace(key)
		if len(key) >= 2 && (key[0] == '"' || key[0] == '\'') && key[len(key)-1] == key[0] {
			key = key[1 : len(key)-1]
		}
		if strings.ContainsAny(key, "\"'\\$") {
			return true
		}
		key = strings.ReplaceAll(strings.ToLower(strings.TrimSuffix(key, "[]")), "_", "-")
		if npmrcHookKeys[key] {
			return true
		}
	}
	return false
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
