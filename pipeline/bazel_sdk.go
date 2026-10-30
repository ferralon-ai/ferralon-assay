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
// repository names rules_go is published as. The binding's name is group 1.
var goSDKExtension = regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*use_extension\(\s*"@(?:rules_go|io_bazel_rules_go)//go:extensions\.bzl"\s*,\s*"go_sdk"\s*[,)]`)

// useExtensionLiteral matches a use_extension call whose first argument is a string literal.
var useExtensionLiteral = regexp.MustCompile(`use_extension\(\s*"`)

// resolveBazelSDK classifies the Bazel workspace around moduleRoot (bazelSDKBinding). Only one shape
// is bazelSDKFromGoMod: exactly one workspace directory up to checkoutRoot; in it a MODULE.bazel and
// no WORKSPACE, WORKSPACE.bazel or WORKSPACE.bzlmod with content (any of which could register an SDK
// under --enable_workspace); no include(); every go_sdk binding recognized; and across them exactly
// one SDK tag, a from_file whose only arguments are an optional name and a go_mod label naming
// moduleRoot's go.mod. A download, host or wrap tag, a go_work, goos/goarch or any other argument,
// or a label that resolves elsewhere is bazelSDKUnbound.
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
	if goModLabelFromModule(stripStarlarkComments(string(data)), ws) != filepath.Join(filepath.Clean(moduleRoot), "go.mod") {
		return bazelSDKUnbound
	}
	return bazelSDKFromGoMod
}

// goModLabelFromModule returns the file the root module's single go_sdk.from_file(go_mod = ...)
// names, resolved against the workspace directory ws, or "" when the module's SDK declarations are
// not exactly that one tag in a form this reads.
func goModLabelFromModule(src, ws string) string {
	if strings.Contains(src, "include(") {
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
	var args []string
	for _, b := range bindings {
		uses := regexp.MustCompile(`\b` + regexp.QuoteMeta(b[1]) + `\s*\.\s*([A-Za-z_]+)\s*\(([^()]*)\)`)
		if len(uses.FindAllStringIndex(src, -1)) != len(regexp.MustCompile(`\b`+regexp.QuoteMeta(b[1])+`\s*\.`).FindAllStringIndex(src, -1)) {
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

// bazelFromFileVersion is the SDK version rules_go's go_sdk.from_file reads from go.mod
// (go/private/go_mod.bzl, version_from_go_mod): the `toolchain` line when there is one, otherwise
// the `go` line. It does not require the toolchain line to be at or above the go line, so the
// module-mode floor (their maximum) can sit above the SDK the build uses.
func bazelFromFileVersion(in toolchainInputs) (string, string) {
	if in.toolchainDirective != "" {
		return in.toolchainDirective, ToolchainSourceToolchainDirective
	}
	return in.goDirective, ToolchainSourceGoDirective
}
