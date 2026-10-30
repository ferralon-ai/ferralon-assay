// ferralon-assay/pipeline/bazel_sdk.go
//
// Which Go SDK a Bazel build of the subject compiles with, as far as go.mod can say. Under Bazel
// (rules_go) the SDK comes from the workspace, not from a module-mode go command, so go.mod's
// directives bound it only when the workspace reads its version from that very go.mod
// (go_sdk.from_file). Everything this file cannot read with certainty resolves to bazelSDKUnbound,
// which takes no floor: a missing floor only withholds disqualifications.
package pipeline

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// bazelSDKBinding is how a Bazel workspace around the subject's module relates its Go SDK to the
// module's go.mod.
type bazelSDKBinding int

const (
	// bazelSDKNone: no Bazel workspace marker at or above the module root, up to the checkout root.
	// The directives bind as they do for a module-mode go command.
	bazelSDKNone bazelSDKBinding = iota
	// bazelSDKUnbound: a Bazel workspace whose SDK this code cannot tie to the module's go.mod.
	// go.mod bounds nothing about it.
	bazelSDKUnbound
	// bazelSDKFromGoMod: the root MODULE.bazel's one SDK declaration is
	// go_sdk.from_file(go_mod = <this module's go.mod>), so the SDK release is the one rules_go
	// reads from it, and bazelFromFileVersion floors it.
	bazelSDKFromGoMod
)

var bazelWorkspaceMarkers = []string{"MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel"}

// goSDKExtension matches a binding of rules_go's go_sdk module extension, under either of the
// repository names rules_go is published as, with no further arguments. The binding's name is
// group 1. dev_dependency = True drops the binding's tags under --ignore_dev_dependency, and
// isolate = True keeps its toolchains unregistered, so either leaves rules_go's default SDK.
var goSDKExtension = regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*use_extension\s*\(\s*"@(?:rules_go|io_bazel_rules_go)//go:extensions\.bzl"\s*,\s*"go_sdk"\s*,?\s*\)`)

// useExtensionCall and useExtensionLiteral match a use_extension call, and one whose first
// argument is a string literal.
var (
	useExtensionCall    = regexp.MustCompile(`\buse_extension\s*\(`)
	useExtensionLiteral = regexp.MustCompile(`\buse_extension\s*\(\s*"`)
)

// includeCall and registerToolchainsCall match the MODULE.bazel calls that can bring in SDK
// declarations or toolchains this does not read.
var (
	includeCall            = regexp.MustCompile(`\binclude\s*\(`)
	registerToolchainsCall = regexp.MustCompile(`\bregister_toolchains\s*\(`)
)

// registerGoToolchains is the one register_toolchains call a module may make beside from_file: the
// go_sdk extension's own toolchains. Any other can register a Go toolchain ahead of them.
var registerGoToolchains = regexp.MustCompile(`\bregister_toolchains\s*\(\s*"@go_toolchains//:all"\s*,?\s*\)`)

// bazelrcSDKFlags are the flags that change which Go SDK a Bazel build selects or whether the root
// module's go_sdk tags apply: rules_go's sdk_version and sdk_name settings (go/toolchain:sdk_), an
// extra toolchain, a dev-dependency drop, or a repository or module override.
var bazelrcSDKFlags = []string{"go/toolchain:sdk_", "extra_toolchains", "ignore_dev_dependency", "override_repository", "override_module"}

// resolveBazelSDK classifies the Bazel workspace around moduleRoot (bazelSDKBinding). Only one shape
// is bazelSDKFromGoMod: exactly one workspace directory up to checkoutRoot; in it a MODULE.bazel and
// no WORKSPACE, WORKSPACE.bazel or WORKSPACE.bzlmod with content (any of which could register an SDK
// under --enable_workspace); no tools/bazel wrapper, which the launcher runs in Bazel's place; no
// .bazelrc setting a bazelrcSDKFlags flag or a main-repository build setting; no include() and no
// register_toolchains other than @go_toolchains//:all; every go_sdk binding recognized, without
// arguments, and named only where it is bound, tagged or passed to use_repo; and across them exactly
// one SDK tag, a from_file whose only arguments are an optional name and a go_mod label naming
// moduleRoot's go.mod. A download, host or wrap tag, a go_work, goos/goarch or any other argument,
// or a label that resolves elsewhere is bazelSDKUnbound. Flags given on the CI command line are
// outside what this reads.
func resolveBazelSDK(moduleRoot, checkoutRoot string) bazelSDKBinding {
	if moduleRoot == "" {
		return bazelSDKNone
	}
	var workspaces []string
	dir := filepath.Clean(moduleRoot)
	stop := filepath.Clean(checkoutRoot)
	for {
		for _, marker := range bazelWorkspaceMarkers {
			if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
				workspaces = append(workspaces, dir)
				break
			}
		}
		parent := filepath.Dir(dir)
		if dir == stop || parent == dir || checkoutRoot == "" {
			break
		}
		dir = parent
	}
	switch len(workspaces) {
	case 0:
		return bazelSDKNone
	case 1:
	default:
		return bazelSDKUnbound
	}
	ws := workspaces[0]
	for _, legacy := range []string{"WORKSPACE", "WORKSPACE.bazel", "WORKSPACE.bzlmod"} {
		data, err := os.ReadFile(filepath.Join(ws, legacy))
		if err == nil && strings.TrimSpace(stripStarlarkComments(string(data))) != "" {
			return bazelSDKUnbound
		}
		if err != nil && !os.IsNotExist(err) {
			return bazelSDKUnbound
		}
	}
	data, err := os.ReadFile(filepath.Join(ws, "MODULE.bazel"))
	if err != nil {
		return bazelSDKUnbound
	}
	module := stripStarlarkComments(string(data))
	mainRepos, ok := mainRepoNames(module)
	if !ok || hasBazelWrapper(ws) || bazelrcSetsSDK(ws, ".bazelrc", 0, mainRepos) {
		return bazelSDKUnbound
	}
	if goModLabelFromModule(module, ws) != filepath.Join(filepath.Clean(moduleRoot), "go.mod") {
		return bazelSDKUnbound
	}
	return bazelSDKFromGoMod
}

// goModLabelFromModule returns the file the root module's single go_sdk.from_file(go_mod = ...)
// names, resolved against the workspace directory ws, or "" when the module's SDK declarations are
// not exactly that one tag in a form this reads.
func goModLabelFromModule(src, ws string) string {
	if includeCall.MatchString(src) ||
		len(registerToolchainsCall.FindAllStringIndex(src, -1)) != len(registerGoToolchains.FindAllStringIndex(src, -1)) {
		return ""
	}
	// Every use_extension names its file as a literal, and every one that names rules_go's is a
	// binding goSDKExtension recognized, so no SDK tag hides behind a binding this did not read.
	bindings := goSDKExtension.FindAllStringSubmatch(src, -1)
	if len(bindings) == 0 ||
		len(useExtensionLiteral.FindAllStringIndex(src, -1)) != len(useExtensionCall.FindAllStringIndex(src, -1)) ||
		len(bindings) != strings.Count(src, `//go:extensions.bzl"`) {
		return ""
	}
	// Every bare mention of a binding's name is its binding, a tag on it or the first argument to
	// use_repo, so no alias (pinned = go_sdk) carries a tag this does not count.
	code := blankStarlarkStrings(src)
	bound := map[string]int{}
	for _, b := range bindings {
		bound[b[1]]++
	}
	var args []string
	for name, n := range bound {
		quoted := regexp.QuoteMeta(name)
		tagged := len(regexp.MustCompile(`\b`+quoted+`\s*\.`).FindAllStringIndex(code, -1))
		repos := len(regexp.MustCompile(`use_repo\(\s*`+quoted+`\s*[,)]`).FindAllStringIndex(code, -1))
		if len(regexp.MustCompile(`\b`+quoted+`\b`).FindAllStringIndex(code, -1)) != n+tagged+repos {
			return ""
		}
		uses := regexp.MustCompile(`\b` + quoted + `\s*\.\s*([A-Za-z_]+)\s*\(([^()]*)\)`)
		if len(uses.FindAllStringIndex(src, -1)) != tagged {
			return ""
		}
		for _, use := range uses.FindAllStringSubmatch(src, -1) {
			switch use[1] {
			case "nogo":
			case "from_file":
				args = append(args, use[2])
			default:
				return ""
			}
		}
	}
	if len(args) != 1 {
		return ""
	}
	label := ""
	for _, arg := range strings.Split(args[0], ",") {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}
		key, value, ok := strings.Cut(arg, "=")
		if !ok {
			return ""
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "name":
		case "go_mod":
			if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
				return ""
			}
			label = value[1 : len(value)-1]
		default:
			return ""
		}
	}
	return resolveRootLabel(label, ws)
}

// resolveRootLabel resolves a main-repository label (//pkg:file, @//pkg:file or @@//pkg:file) to a
// path under ws, or "" for any other spelling.
func resolveRootLabel(label, ws string) string {
	for _, prefix := range []string{"@@//", "@//", "//"} {
		if rest, ok := strings.CutPrefix(label, prefix); ok {
			pkg, name, ok := strings.Cut(rest, ":")
			if !ok || name == "" || strings.Contains(pkg+name, "..") {
				return ""
			}
			return filepath.Join(ws, filepath.FromSlash(pkg), filepath.FromSlash(name))
		}
	}
	return ""
}

// moduleCall matches the root module() call, moduleArgs its arguments, and moduleRepoName and
// moduleNameArg its name and repo_name arguments as string literals and in any form.
var (
	moduleCall     = regexp.MustCompile(`\bmodule\s*\(`)
	moduleArgs     = regexp.MustCompile(`\bmodule\s*\(([^()]*)\)`)
	moduleRepoName = regexp.MustCompile(`\b(?:name|repo_name)\s*=\s*"([^"]*)"`)
	moduleNameArg  = regexp.MustCompile(`\b(?:name|repo_name)\s*=`)
)

// mainRepoNames returns the repository names a label in the main repository can carry: the empty
// one (//pkg, @//pkg, @@//pkg) and the root module's name and repo_name. ok is false when a
// module() call is not in a form this reads.
func mainRepoNames(module string) (map[string]bool, bool) {
	names := map[string]bool{"": true}
	calls := moduleArgs.FindAllStringSubmatch(module, -1)
	if len(calls) != len(moduleCall.FindAllStringIndex(module, -1)) {
		return nil, false
	}
	for _, call := range calls {
		named := moduleRepoName.FindAllStringSubmatch(call[1], -1)
		if len(named) != len(moduleNameArg.FindAllStringIndex(call[1], -1)) {
			return nil, false
		}
		for _, m := range named {
			names[m[1]] = true
		}
	}
	return names, true
}

// hasBazelWrapper reports whether ws has a tools/bazel wrapper (tools/bazel or tools/bazel.<ext>),
// which the Bazel launcher and bazelisk run in Bazel's place with any flags it adds, or a
// .bazeliskrc that moves bazelisk's wrapper directory elsewhere.
func hasBazelWrapper(ws string) bool {
	if rc, err := os.ReadFile(filepath.Join(ws, ".bazeliskrc")); err == nil {
		if strings.Contains(string(rc), "BAZELISK_WRAPPER_DIRECTORY") {
			return true
		}
	} else if !os.IsNotExist(err) {
		return true
	}
	entries, err := os.ReadDir(filepath.Join(ws, "tools"))
	if err != nil {
		return !os.IsNotExist(err)
	}
	for _, e := range entries {
		if e.Name() == "bazel" || strings.HasPrefix(e.Name(), "bazel.") {
			return true
		}
	}
	return false
}

// bazelrcSetsSDK reports whether the bazelrc file name under ws, or a %workspace% file it imports,
// sets one of bazelrcSDKFlags or a build setting in the main repository (whose alias of a rules_go
// setting this does not follow), or imports a file this cannot read. A missing top-level .bazelrc
// sets nothing. Lines are read as Bazel's rc_file.cc reads them: a trailing backslash continues the
// line and bazelrcWords splits it. try-import-if-bazel-version is followed like try-import, whatever
// version it names.
func bazelrcSetsSDK(ws, name string, depth int, mainRepos map[string]bool) bool {
	if depth > 8 || strings.Contains(name, "..") {
		return true
	}
	data, err := os.ReadFile(filepath.Join(ws, filepath.FromSlash(name)))
	if err != nil {
		return depth > 0 || !os.IsNotExist(err)
	}
	src := strings.NewReplacer("\\\r\n", "", "\\\n", "").Replace(string(data))
	for _, line := range strings.Split(src, "\n") {
		words := bazelrcWords(line)
		if len(words) == 0 {
			continue
		}
		var rel string
		switch words[0] {
		case "import", "try-import":
			if len(words) != 2 {
				return true
			}
			rel = words[1]
		case "try-import-if-bazel-version":
			if len(words) != 3 {
				return true
			}
			rel = words[2]
		default:
			for _, word := range words[1:] {
				if setsSDKFlag(word, mainRepos) {
					return true
				}
			}
			continue
		}
		rel, ok := strings.CutPrefix(rel, "%workspace%/")
		if !ok {
			return true
		}
		if words[0] != "import" {
			if _, err := os.Stat(filepath.Join(ws, filepath.FromSlash(rel))); os.IsNotExist(err) {
				continue
			}
		}
		if bazelrcSetsSDK(ws, rel, depth+1, mainRepos) {
			return true
		}
	}
	return false
}

// setsSDKFlag reports whether a bazelrc option word names one of bazelrcSDKFlags, or is a build
// setting (--[no]@repo//pkg:name or --[no]//pkg:name) whose repository is one of mainRepos.
func setsSDKFlag(word string, mainRepos map[string]bool) bool {
	for _, flag := range bazelrcSDKFlags {
		if strings.Contains(word, flag) {
			return true
		}
	}
	label, ok := strings.CutPrefix(word, "--")
	if !ok {
		return false
	}
	label = strings.TrimPrefix(label, "no")
	if !strings.HasPrefix(label, "@") && !strings.HasPrefix(label, "//") {
		return false
	}
	repo, _, ok := strings.Cut(strings.TrimLeft(label, "@"), "//")
	return !ok || mainRepos[repo]
}

// bazelrcWords splits a bazelrc line into words as Bazel's blaze_util::Tokenize does: words are
// separated by space, tab, CR or LF; a quote groups up to its match and is dropped; a backslash
// takes the next byte literally; an unquoted # ends the line.
func bazelrcWords(line string) []string {
	var words []string
	var word strings.Builder
	quote := byte(0)
	flush := func() {
		if word.Len() > 0 {
			words = append(words, word.String())
			word.Reset()
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\':
			if i+1 < len(line) {
				i++
				word.WriteByte(line[i])
			}
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				word.WriteByte(c)
			}
		case c == '#':
			flush()
			return words
		case c == '"' || c == '\'':
			quote = c
		case strings.IndexByte(" \t\r\n", c) >= 0:
			flush()
		default:
			word.WriteByte(c)
		}
	}
	flush()
	return words
}

// Byte classes starlarkMask assigns.
const (
	starlarkCode byte = iota
	starlarkString
	starlarkComment
)

// starlarkMask classifies each byte of src as code, string contents (between the quotes, which stay
// code) or comment. It reads single-, double- and triple-quoted strings with backslash escapes.
func starlarkMask(src string) []byte {
	mask := make([]byte, len(src))
	for i := 0; i < len(src); {
		c := src[i]
		switch {
		case c == '#':
			for ; i < len(src) && src[i] != '\n'; i++ {
				mask[i] = starlarkComment
			}
		case c == '"' || c == '\'':
			delim := src[i : i+1]
			if strings.HasPrefix(src[i:], strings.Repeat(delim, 3)) {
				delim = strings.Repeat(delim, 3)
			}
			i += len(delim)
			for i < len(src) && !strings.HasPrefix(src[i:], delim) && (len(delim) == 3 || src[i] != '\n') {
				mask[i] = starlarkString
				if src[i] == '\\' && i+1 < len(src) {
					i++
					mask[i] = starlarkString
				}
				i++
			}
			i += len(delim)
		default:
			i++
		}
	}
	return mask
}

// blankStarlarkStrings replaces the contents of string literals with spaces, keeping the quotes and
// line breaks, so a name inside a string does not read as a reference.
func blankStarlarkStrings(src string) string {
	return maskStarlark(src, starlarkString)
}

// stripStarlarkComments replaces # comments outside string literals with spaces.
func stripStarlarkComments(src string) string {
	return maskStarlark(src, starlarkComment)
}

func maskStarlark(src string, class byte) string {
	b := []byte(src)
	for i, m := range starlarkMask(src) {
		if m == class && b[i] != '\n' {
			b[i] = ' '
		}
	}
	return string(b)
}

// bazelFromFileVersion is the floor go.mod sets beside go_sdk.from_file. rules_go's from_file reads
// the `toolchain` line when there is one, otherwise the `go` line (go/private/go_mod.bzl,
// version_from_go_mod), and does not require the toolchain line to be at or above the go line. The
// same repository is often built and tested with the go command too, where the toolchain line binds
// nothing under GOTOOLCHAIN=local and the go line binds only per goLineFloor. The floor is the lower
// of the two builds' releases: the binding go line, or the toolchain line when it is lower. "" when
// either build has none.
func bazelFromFileVersion(in toolchainInputs) (string, string) {
	goLine := goLineFloor(in)
	if goLine == "" {
		return "", ""
	}
	if in.toolchainDirective == "" {
		return goLine, ToolchainSourceGoDirective
	}
	toolchain, ok := parseGoToolchainVersion(in.toolchainDirective)
	if !ok {
		return "", ""
	}
	if floor, _ := parseGoToolchainVersion(goLine); compareGoToolchain(toolchain, floor) < 0 {
		return in.toolchainDirective, ToolchainSourceToolchainDirective
	}
	return goLine, ToolchainSourceGoDirective
}
