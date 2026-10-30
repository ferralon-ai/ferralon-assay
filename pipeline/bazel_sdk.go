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
	// reads from it (bazelFromFileVersion).
	bazelSDKFromGoMod
)

var bazelWorkspaceMarkers = []string{"MODULE.bazel", "WORKSPACE", "WORKSPACE.bazel"}

// goSDKExtension matches a binding of rules_go's go_sdk module extension, under either of the
// repository names rules_go is published as, with no further arguments. The binding's name is
// group 1. dev_dependency = True drops the binding's tags under --ignore_dev_dependency, and
// isolate = True keeps its toolchains unregistered, so either leaves rules_go's default SDK.
var goSDKExtension = regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*use_extension\(\s*"@(?:rules_go|io_bazel_rules_go)//go:extensions\.bzl"\s*,\s*"go_sdk"\s*,?\s*\)`)

// useExtensionLiteral matches a use_extension call whose first argument is a string literal.
var useExtensionLiteral = regexp.MustCompile(`use_extension\(\s*"`)

// registerGoToolchains is the one register_toolchains call a module may make beside from_file: the
// go_sdk extension's own toolchains. Any other can register a Go toolchain ahead of them.
var registerGoToolchains = regexp.MustCompile(`register_toolchains\(\s*"@go_toolchains//:all"\s*,?\s*\)`)

// bazelrcSDKFlags are the flags that change which Go SDK a Bazel build selects or whether the root
// module's go_sdk tags apply: rules_go's sdk_version setting, an extra toolchain, a dev-dependency
// drop, or a repository or module override.
var bazelrcSDKFlags = []string{"sdk_version", "extra_toolchains", "ignore_dev_dependency", "override_repository", "override_module"}

// resolveBazelSDK classifies the Bazel workspace around moduleRoot (bazelSDKBinding). Only one shape
// is bazelSDKFromGoMod: exactly one workspace directory up to checkoutRoot; in it a MODULE.bazel and
// no WORKSPACE, WORKSPACE.bazel or WORKSPACE.bzlmod with content (any of which could register an SDK
// under --enable_workspace); no .bazelrc setting a bazelrcSDKFlags flag; no include() and no
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
	if bazelrcSetsSDK(ws, ".bazelrc", 0) {
		return bazelSDKUnbound
	}
	data, err := os.ReadFile(filepath.Join(ws, "MODULE.bazel"))
	if err != nil {
		return bazelSDKUnbound
	}
	if goModLabelFromModule(stripStarlarkComments(string(data)), ws) != filepath.Join(filepath.Clean(moduleRoot), "go.mod") {
		return bazelSDKUnbound
	}
	return bazelSDKFromGoMod
}

// goModLabelFromModule returns the file the root module's single go_sdk.from_file(go_mod = ...)
// names, resolved against the workspace directory ws, or "" when the module's SDK declarations are
// not exactly that one tag in a form this reads.
func goModLabelFromModule(src, ws string) string {
	if strings.Contains(src, "include(") ||
		strings.Count(src, "register_toolchains(") != len(registerGoToolchains.FindAllStringIndex(src, -1)) {
		return ""
	}
	// Every use_extension names its file as a literal, and every one that names rules_go's is a
	// binding goSDKExtension recognized, so no SDK tag hides behind a binding this did not read.
	bindings := goSDKExtension.FindAllStringSubmatch(src, -1)
	if len(bindings) == 0 ||
		len(useExtensionLiteral.FindAllStringIndex(src, -1)) != strings.Count(src, "use_extension(") ||
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

// bazelrcSetsSDK reports whether the bazelrc file name under ws, or a %workspace% file it imports,
// sets one of bazelrcSDKFlags, or imports a file this cannot read. A missing top-level .bazelrc sets
// nothing.
func bazelrcSetsSDK(ws, name string, depth int) bool {
	if depth > 8 || strings.Contains(name, "..") {
		return true
	}
	data, err := os.ReadFile(filepath.Join(ws, filepath.FromSlash(name)))
	if err != nil {
		return depth > 0 || !os.IsNotExist(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, flag := range bazelrcSDKFlags {
			if strings.Contains(line, flag) {
				return true
			}
		}
		verb, target, _ := strings.Cut(line, " ")
		if verb != "import" && verb != "try-import" {
			continue
		}
		rel, ok := strings.CutPrefix(strings.TrimSpace(target), "%workspace%/")
		if !ok {
			return true
		}
		if verb == "try-import" {
			if _, err := os.Stat(filepath.Join(ws, filepath.FromSlash(rel))); os.IsNotExist(err) {
				continue
			}
		}
		if bazelrcSetsSDK(ws, rel, depth+1) {
			return true
		}
	}
	return false
}

// blankStarlarkStrings replaces the contents of string literals with spaces, keeping the quotes, so
// a name inside a string does not read as a reference.
func blankStarlarkStrings(src string) string {
	b := []byte(src)
	var quote byte
	for i := 0; i < len(b); i++ {
		switch {
		case quote != 0:
			if b[i] == '\\' && i+1 < len(b) {
				b[i], b[i+1] = ' ', ' '
				i++
			} else if b[i] == quote {
				quote = 0
			} else if b[i] != '\n' {
				b[i] = ' '
			}
		case b[i] == '"' || b[i] == '\'':
			quote = b[i]
		}
	}
	return string(b)
}

// stripStarlarkComments drops # comments outside string literals.
func stripStarlarkComments(src string) string {
	var b strings.Builder
	var quote byte
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case quote != 0:
			if c == '\\' && i+1 < len(src) {
				b.WriteByte(c)
				i++
				c = src[i]
			} else if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			if i < len(src) {
				b.WriteByte('\n')
			}
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
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
