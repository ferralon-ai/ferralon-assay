package goanalysis

import (
	"context"
	"fmt"
	"go/build"
	"go/build/constraint"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// writeTree lays out files under a fresh directory, path → contents.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// TestWithholdForLeftOutFiles: govulncheck never traces a file the build left out, so a file for
// another platform or behind a tag that may call into the refuted module withholds the refutation.
func TestWithholdForLeftOutFiles(t *testing.T) {
	base := map[string]string{
		"go.mod": "module example.com/m\n\ngo 1.22\n\nrequire (\n\texample.com/vulnmod v0.0.0\n\texample.com/dep v0.0.0\n\texample.com/other v0.0.0\n\texample.com/lib v0.0.0\n)\n\n" +
			"replace (\n\texample.com/vulnmod => ./_vulnmod\n\texample.com/dep => ./_dep\n\texample.com/other => ./_other\n\texample.com/lib => ./_lib\n)\n",
		"main.go":             "package main\n\nimport \"example.com/vulnmod\"\n\nfunc main() { vulnmod.Safe() }\n",
		"mid/mid.go":          "package mid\n\nimport \"example.com/vulnmod\"\n\nfunc Call() { vulnmod.Bad() }\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Safe() {}\n\nfunc Bad() {}\n",
		"_dep/go.mod":         "module example.com/dep\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n",
		"_dep/dep.go":         "package dep\n\nimport \"example.com/vulnmod\"\n\nfunc Call() { vulnmod.Bad() }\n",
		"_other/go.mod":       "module example.com/other\n\ngo 1.22\n",
		"_other/other.go":     "package other\n\nfunc Call() {}\n",
		"plain/plain.go":      "package plain\n\nfunc Call() {}\n",
		// lib is a loaded dependency module that reaches the module.
		"uselib/uselib.go": "package uselib\n\nimport \"example.com/lib\"\n\nfunc Call() { lib.Call() }\n",
		"_lib/go.mod":      "module example.com/lib\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n",
		"_lib/lib.go":      "package lib\n\nimport \"example.com/vulnmod\"\n\nfunc Call() {}\n\nfunc use() { vulnmod.Bad() }\n",
	}
	// leftOut is a file of plain, a loaded package that does not reach the module.
	leftOut := func(constraint, imp string) string {
		return "//go:build " + constraint + "\n\npackage plain\n\nimport _ \"" + imp + "\"\n"
	}
	cases := []struct {
		name  string
		files map[string]string
		// unestablished: the load is not established to run under the build's toolchain.
		unestablished bool
		withheld      bool
	}{
		{"no file left out", nil, false, false},
		{"a tagged file imports the module", map[string]string{"plain/prod.go": leftOut("prod", "example.com/vulnmod")}, false, true},
		{"another platform's file imports the module", map[string]string{"plain/run_plan9.go": "package plain\n\nimport _ \"example.com/vulnmod\"\n"}, false, true},
		{"a tagged file imports a loaded package that imports the module", map[string]string{"plain/prod.go": leftOut("prod", "example.com/m/mid")}, false, true},
		{"a tagged file imports an unloaded module that requires the module", map[string]string{"plain/prod.go": leftOut("prod", "example.com/dep")}, false, true},
		{"a tagged file imports an unloaded module that does not require it", map[string]string{"plain/prod.go": leftOut("prod", "example.com/other")}, false, false},
		{"a tagged file imports only the standard library, against a module refutation", map[string]string{"plain/prod.go": leftOut("prod", "net/http")}, false, false},
		{"an ignore-tagged file is never built", map[string]string{"plain/gen.go": leftOut("ignore", "example.com/vulnmod")}, false, false},
		{"a tagged file imports nothing but its package reaches the module", map[string]string{"mid/mid_prod.go": "//go:build prod\n\npackage mid\n\nfunc init() { Call() }\n"}, false, true},
		{"a tagged file names another package than the one that reaches the module", map[string]string{"mid/tools.go": "//go:build tools\n\npackage tools\n"}, false, false},
		{"another platform's file of a dependency calls its own package's helper", map[string]string{"_lib/lib_windows.go": "package lib\n\nfunc init() { use() }\n"}, false, true},
		{"another platform's file of the module itself", map[string]string{"_vulnmod/vulnmod_windows.go": "package vulnmod\n\nfunc init() { Bad() }\n"}, false, true},
		{"a tagged file imports nothing and its package does not reach the module", map[string]string{"plain/plain_prod.go": "//go:build prod\n\npackage plain\n\nfunc init() { Call() }\n"}, false, false},
		{"a tagged package wholly left out imports the module", map[string]string{"prodonly/p.go": "//go:build prod\n\npackage prodonly\n\nimport _ \"example.com/vulnmod\"\n"}, false, true},
		{"a file only a newer Go release builds", map[string]string{"plain/new.go": leftOut("go1.999", "example.com/vulnmod")}, false, false},
		{"a file only an older Go release builds", map[string]string{"plain/old.go": leftOut("!go1.1", "example.com/vulnmod")}, false, false},
		{"a file only an older Go release builds, toolchain not established", map[string]string{"plain/old.go": leftOut("!go1.1", "example.com/vulnmod")}, true, true},
		{"a release tag the build satisfies and a platform that could select it", map[string]string{"plain/p.go": leftOut("go1.1 && plan9", "example.com/vulnmod")}, false, true},
		{"an older release or a platform that could select it", map[string]string{"plain/p.go": leftOut("!go1.1 || plan9", "example.com/vulnmod")}, false, true},
		{"a newer release on another platform", map[string]string{"plain/p.go": leftOut("go1.999 && plan9", "example.com/vulnmod")}, false, false},
		{"a tag spelled like a release tag the go command never sets", map[string]string{"plain/p.go": leftOut("plan9 && !go1.01", "example.com/vulnmod")}, false, true},
		{"a constraint no release satisfies", map[string]string{"plain/p.go": leftOut("go1.1 && !go1.1", "example.com/vulnmod")}, false, true},
		{"go1.0 is not a release tag the go command sets", map[string]string{"plain/p.go": leftOut("plan9 && !go1.0", "example.com/vulnmod")}, false, true},
		{"a misplaced plus-build line does not constrain the file", map[string]string{"plain/p_windows.go": "// +build go1.999\npackage plain\n\nimport _ \"example.com/vulnmod\"\n"}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{}
			for k, v := range base {
				files[k] = v
			}
			for k, v := range tc.files {
				files[k] = v
			}
			dir := writeTree(t, files)
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			load.buildGoVersion = load.goVersion // the subject's toolchain, known and the load's
			release := load.buildRelease()
			if release == nil {
				t.Fatalf("load not established under the build's toolchain (loaded %q, build %q)", load.goVersion, load.buildGoVersion)
			}
			if tc.unestablished {
				release = nil
			}
			refuted := plugin.ReachabilityResult{
				Partiality: plugin.Complete(),
				Refutation: &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/example.com/vulnmod"},
			}
			res := withholdForLeftOutFiles(context.Background(), refuted, vulnScan{}, load.Packages, release, dir, append(os.Environ(), "GOWORK=off"))
			if withheld := res.Refutation == nil; withheld != tc.withheld {
				t.Fatalf("withheld = %v, want %v", withheld, tc.withheld)
			}
			if declared := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonExcludedFiles); declared != tc.withheld {
				t.Errorf("excluded_files declared = %v, want %v (partiality %+v)", declared, tc.withheld, res.Partiality)
			}
		})
	}
}

// TestWithholdForLeftOutFiles_StandardLibrary: against a refutation of the standard library, a
// left-out file counts when it reaches one of the advisory's vulnerable packages, directly or
// through other packages, loaded or not. A file reaching only other standard-library packages
// does not count, so another platform's file importing syscall leaves the refutation standing.
func TestWithholdForLeftOutFiles_StandardLibrary(t *testing.T) {
	base := map[string]string{
		"go.mod": "module example.com/m\n\ngo 1.22\n\nrequire (\n\texample.com/webdep v0.0.0\n\texample.com/other v0.0.0\n\texample.com/tagdep v0.0.0\n\tlocalx v0.0.0\n\tgolang.org/x/net v0.0.0\n)\n\n" +
			"replace (\n\texample.com/webdep => ./_webdep\n\texample.com/other => ./_other\n\texample.com/tagdep => ./_tagdep\n\tlocalx => ./_localx\n\tgolang.org/x/net => ./_xnet\n)\n",
		"main.go":           "package main\n\nfunc main() {}\n",
		"_webdep/go.mod":    "module example.com/webdep\n\ngo 1.22\n",
		"_webdep/webdep.go": "package webdep\n\nimport \"net/http\"\n\nfunc Serve() { _ = http.ListenAndServe(\":0\", nil) }\n",
		"_other/go.mod":     "module example.com/other\n\ngo 1.22\n",
		"_other/other.go":   "package other\n\nimport \"strings\"\n\nfunc Call() string { return strings.ToUpper(\"x\") }\n",
		// tagdep reaches the vulnerable package only under the prod tag.
		"_tagdep/go.mod":         "module example.com/tagdep\n\ngo 1.22\n",
		"_tagdep/tagdep.go":      "package tagdep\n\nfunc Serve() {}\n",
		"_tagdep/tagdep_prod.go": "//go:build prod\n\npackage tagdep\n\nimport \"net/http\"\n\nfunc init() { _ = http.ListenAndServe(\":0\", nil) }\n",
		// localx's module path has no dot, and it imports the module's own golang.org/x/net/http/httpguts, which
		// imports the vulnerable package, unlike the standard library's vendored copy.
		"_localx/go.mod":                  "module localx\n\ngo 1.22\n\nrequire golang.org/x/net v0.0.0\n",
		"_localx/localx.go":               "package localx\n\nimport \"golang.org/x/net/http/httpguts\"\n\nfunc Call() { httpguts.Serve() }\n",
		"_xnet/go.mod":                    "module golang.org/x/net\n\ngo 1.22\n",
		"_xnet/http/httpguts/httpguts.go": "package httpguts\n\nimport \"net/http\"\n\nfunc Serve() { _ = http.ListenAndServe(\":0\", nil) }\n",
	}
	leftOut := func(constraint, imp string) string {
		return "//go:build " + constraint + "\n\npackage main\n\nimport _ \"" + imp + "\"\n"
	}
	useStd := func(imp, use string) string {
		return "package main\n\nimport \"" + imp + "\"\n\nfunc main() { _ = " + use + " }\n"
	}
	// web is a loaded first-party package that imports the vulnerable package.
	web := map[string]string{"web/web.go": "package web\n\nimport \"net/http\"\n\nfunc Serve() { _ = http.ListenAndServe(\":0\", nil) }\n"}
	httpVuln := []string{"net/http"}
	cases := []struct {
		name       string
		files      map[string]string
		vulnerable []string
		withheld   bool
	}{
		{"no file left out", nil, httpVuln, false},
		{"a tagged file calls the vulnerable package, which nothing loaded imports", map[string]string{
			"prod.go": "//go:build prod\n\npackage main\n\nimport \"net/http\"\n\nfunc init() { _ = http.ListenAndServe(\":0\", nil) }\n",
		}, httpVuln, true},
		{"a tagged file imports the vulnerable package, which the build loaded", merge(web, map[string]string{"prod.go": leftOut("prod", "net/http")}), httpVuln, true},
		{"a tagged file imports a loaded package that imports the vulnerable package", merge(web, map[string]string{"prod.go": leftOut("prod", "example.com/m/web")}), httpVuln, true},
		{"a tagged file imports an unloaded standard package that imports the vulnerable package", map[string]string{"prod.go": leftOut("prod", "net/http/httputil")}, httpVuln, true},
		{"a tagged file imports an unloaded module that imports the vulnerable package", map[string]string{"prod.go": leftOut("prod", "example.com/webdep")}, httpVuln, true},
		// crypto/tls imports vendored golang.org/x/crypto packages.
		{"a tagged file imports an unloaded standard package whose imports include vendored ones", map[string]string{"prod.go": leftOut("prod", "crypto/tls")}, httpVuln, false},
		{"a tagged file imports an unloaded module that reaches the vulnerable package only under the file's own tag", map[string]string{
			"prod.go": "//go:build prod\n\npackage main\n\nimport \"example.com/tagdep\"\n\nfunc init() { tagdep.Serve() }\n",
		}, httpVuln, true},
		{"a tagged file imports an unloaded module whose path has no dot and whose golang.org/x import reaches the vulnerable package", map[string]string{"prod.go": leftOut("prod", "localx")}, httpVuln, true},
		{"a tagged file imports an unloaded module that does not import the vulnerable package", map[string]string{"prod.go": leftOut("prod", "example.com/other")}, httpVuln, false},
		{"a tagged file imports a standard-library path no port lists", map[string]string{"prod.go": leftOut("prod", "net/nosuch")}, httpVuln, true},
		{"a tagged file imports nothing but its package reaches the vulnerable package", merge(web, map[string]string{
			"web/web_prod.go": "//go:build prod\n\npackage web\n\nfunc init() { Serve() }\n",
		}), httpVuln, true},
		{"another platform's file imports only syscall", map[string]string{"run_windows.go": "package main\n\nimport _ \"syscall\"\n"}, httpVuln, false},
		{"a tagged file imports only an unrelated standard package", map[string]string{"prod.go": leftOut("prod", "strings")}, httpVuln, false},
		{"the vulnerable packages are unknown, so any standard import counts", map[string]string{"prod.go": leftOut("prod", "strings")}, nil, true},
		{"an ignore-tagged file is never built", map[string]string{"gen.go": leftOut("ignore", "net/http")}, httpVuln, false},
		// Only Windows builds of os import internal/syscall/windows; elsewhere os's Windows files are left out.
		{"another platform's file of a loaded standard package imports the vulnerable package", map[string]string{"main.go": useStd("os", "os.Args")}, []string{"internal/syscall/windows"}, true},
		{"the vulnerable standard package is loaded and its other platforms' files are left out", map[string]string{"main.go": useStd("crypto/x509", "x509.ParseCertificate")}, []string{"crypto/x509"}, true},
		// net's other platforms' files import golang.org/x packages, which resolve to the standard library's vendored copies.
		{"no other platform's file of a loaded standard package reaches the vulnerable package", map[string]string{"main.go": useStd("net", "net.Dial")}, httpVuln, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(base, tc.files))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			refuted := plugin.ReachabilityResult{
				Partiality: plugin.Complete(),
				Refutation: &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/stdlib"},
			}
			scanned := vulnScan{imports: map[string][]string{"stdlib": tc.vulnerable}}
			res := withholdForLeftOutFiles(context.Background(), refuted, scanned, load.Packages, load.buildRelease(), dir, append(os.Environ(), "GOWORK=off"))
			if withheld := res.Refutation == nil; withheld != tc.withheld {
				t.Fatalf("withheld = %v, want %v", withheld, tc.withheld)
			}
			if declared := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonExcludedFiles); declared != tc.withheld {
				t.Errorf("excluded_files declared = %v, want %v (partiality %+v)", declared, tc.withheld, res.Partiality)
			}
		})
	}
}

// TestWithholdForLeftOutFiles_VulnerablePackages: when the advisory names the module's vulnerable
// packages, a left-out file counts only when it may reach one of them, directly or through other
// packages under any build configuration; the module's other packages, and their own left-out
// files, do not count. What cannot be read counts.
func TestWithholdForLeftOutFiles_VulnerablePackages(t *testing.T) {
	base := map[string]string{
		"go.mod": "module example.com/m\n\ngo 1.22\n\nrequire (\n\texample.com/vulnmod v0.0.0\n\texample.com/usesafe v0.0.0\n\texample.com/tagdep v0.0.0\n\texample.com/broken v0.0.0\n\tlocaldep v0.0.0\n)\n\n" +
			"replace (\n\texample.com/vulnmod => ./_vulnmod\n\texample.com/usesafe => ./_usesafe\n\texample.com/tagdep => ./_tagdep\n\texample.com/broken => ./_broken\n\tlocaldep => ./_localdep\n)\n",
		"main.go":                "package main\n\nimport \"example.com/vulnmod/blake\"\n\nfunc main() { blake.Sum() }\n",
		"_vulnmod/go.mod":        "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/ssh/ssh.go":    "package ssh\n\nfunc Dial() {}\n",
		"_vulnmod/blake/b.go":    "package blake\n\nfunc Sum() {}\n",
		"_vulnmod/wrap/wrap.go":  "package wrap\n\nimport \"example.com/vulnmod/ssh\"\n\nfunc Call() { ssh.Dial() }\n",
		"_usesafe/go.mod":        "module example.com/usesafe\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n",
		"_usesafe/usesafe.go":    "package usesafe\n\nimport \"example.com/vulnmod/blake\"\n\nfunc Call() { blake.Sum() }\n",
		"_tagdep/go.mod":         "module example.com/tagdep\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n",
		"_tagdep/tagdep.go":      "package tagdep\n\nfunc Call() {}\n",
		"_tagdep/tagdep_prod.go": "//go:build prod\n\npackage tagdep\n\nimport \"example.com/vulnmod/ssh\"\n\nfunc init() { ssh.Dial() }\n",
		"_broken/go.mod":         "module example.com/broken\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n",
		"_broken/broken.go":      "package broken\n\nimport (\n",
		// localdep's module path has no dot, like a standard-library path.
		"_localdep/go.mod":      "module localdep\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n",
		"_localdep/localdep.go": "package localdep\n\nimport \"example.com/vulnmod/ssh\"\n\nfunc Call() { ssh.Dial() }\n",
	}
	leftOut := func(imp string) map[string]string {
		return map[string]string{"prod.go": "//go:build prod\n\npackage main\n\nimport _ \"" + imp + "\"\n"}
	}
	ssh := []string{"example.com/vulnmod/ssh"}
	cases := []struct {
		name        string
		files       map[string]string
		vulnerable  []string
		wholeModule bool
		withheld    bool
	}{
		{"no file left out", nil, ssh, false, false},
		{"a tagged file imports the vulnerable package", leftOut("example.com/vulnmod/ssh"), ssh, false, true},
		{"a tagged file imports another package of the module", leftOut("example.com/vulnmod/blake"), ssh, false, false},
		{"a tagged file imports an unloaded package of the module that imports the vulnerable package", leftOut("example.com/vulnmod/wrap"), ssh, false, true},
		{"another platform's file of a loaded package of the module", map[string]string{"_vulnmod/blake/b_amd64.go": "package blake\n\nfunc init() { Sum() }\n"}, ssh, false, false},
		{"another platform's file of a loaded package of the module imports the vulnerable package", map[string]string{
			"_vulnmod/blake/b_windows.go": "package blake\n\nimport \"example.com/vulnmod/ssh\"\n\nfunc init() { ssh.Dial() }\n",
		}, ssh, false, true},
		{"a tagged file imports an unloaded module that imports only another package of the module", leftOut("example.com/usesafe"), ssh, false, false},
		{"a tagged file imports an unloaded module that imports the vulnerable package only under its own tag", leftOut("example.com/tagdep"), ssh, false, true},
		{"a tagged file imports an unloaded module that cannot be parsed", leftOut("example.com/broken"), ssh, false, true},
		{"a tagged file imports a package of the module that does not exist", leftOut("example.com/vulnmod/nosuch"), ssh, false, true},
		{"the advisory lists no vulnerable package", leftOut("example.com/vulnmod/blake"), nil, false, true},
		{"the advisory also lists the whole module", leftOut("example.com/vulnmod/blake"), ssh, true, true},
		{"a tagged file imports a module whose path has no dot and that imports the vulnerable package", leftOut("localdep"), ssh, false, true},
		{"a tagged file imports an unrelated standard package", leftOut("strings"), ssh, false, false},
		{"a tagged file imports a path no module holds", leftOut("example.org/nowhere"), ssh, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(base, tc.files))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			refuted := plugin.ReachabilityResult{
				Partiality: plugin.Complete(),
				Refutation: &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/example.com/vulnmod"},
			}
			scanned := vulnScan{imports: map[string][]string{"example.com/vulnmod": tc.vulnerable}, wholeModule: map[string]bool{"example.com/vulnmod": tc.wholeModule}}
			res := withholdForLeftOutFiles(context.Background(), refuted, scanned, load.Packages, load.buildRelease(), dir, append(os.Environ(), "GOWORK=off"))
			if withheld := res.Refutation == nil; withheld != tc.withheld {
				t.Fatalf("withheld = %v, want %v", withheld, tc.withheld)
			}
			if declared := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonExcludedFiles); declared != tc.withheld {
				t.Errorf("excluded_files declared = %v, want %v (partiality %+v)", declared, tc.withheld, res.Partiality)
			}
		})
	}
}

// TestWithholdForLeftOutFiles_UnreadableModuleGraph: without the module graph a dotless import may
// be a module's, so even a standard-library import counts.
func TestWithholdForLeftOutFiles_UnreadableModuleGraph(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":              "module example.com/m\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
		"main.go":             "package main\n\nimport \"example.com/vulnmod/blake\"\n\nfunc main() { blake.Sum() }\n",
		"prod.go":             "//go:build prod\n\npackage main\n\nimport _ \"strings\"\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/ssh/ssh.go": "package ssh\n\nfunc Dial() {}\n",
		"_vulnmod/blake/b.go": "package blake\n\nfunc Sum() {}\n",
	})
	load, err := LoadProgram(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	refuted := plugin.ReachabilityResult{
		Partiality: plugin.Complete(),
		Refutation: &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/example.com/vulnmod"},
	}
	scanned := vulnScan{imports: map[string][]string{"example.com/vulnmod": {"example.com/vulnmod/ssh"}}}
	for _, tc := range []struct {
		name     string
		env      []string
		withheld bool
	}{
		{"graph read", nil, false},
		{"graph unreadable", []string{"GOFLAGS=-modfile=" + filepath.Join(dir, "nosuch.mod")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := append(append(os.Environ(), "GOWORK=off"), tc.env...)
			res := withholdForLeftOutFiles(context.Background(), refuted, scanned, load.Packages, load.buildRelease(), dir, env)
			if withheld := res.Refutation == nil; withheld != tc.withheld {
				t.Fatalf("withheld = %v, want %v", withheld, tc.withheld)
			}
		})
	}
}

// TestWithholdForLeftOutFiles_NoAdvisoryEntry: findings for a module with no OSV entry listing it name
// only the packages the build traced, so every package of the module counts.
func TestWithholdForLeftOutFiles_NoAdvisoryEntry(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":              "module example.com/m\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
		"main.go":             "package main\n\nfunc main() {}\n",
		"prod.go":             "//go:build prod\n\npackage main\n\nimport _ \"example.com/vulnmod/ssh\"\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/ssh/ssh.go": "package ssh\n\nfunc Dial() {}\n",
		"_vulnmod/blake/b.go": "package blake\n\nfunc Sum() {}\n",
	})
	load, err := LoadProgram(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	refuted := plugin.ReachabilityResult{
		Partiality: plugin.Complete(),
		Refutation: &plugin.Refutation{Basis: plugin.RefutationAnalyzerSymbolNotReached, Package: "pkg:golang/example.com/vulnmod"},
	}
	scanned := vulnScan{findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod/blake"}}}}}
	res := withholdForLeftOutFiles(context.Background(), refuted, scanned, load.Packages, load.buildRelease(), dir, append(os.Environ(), "GOWORK=off"))
	if res.Refutation != nil {
		t.Fatal("refutation stands, want it withheld")
	}
}

// TestSourceImports_ListFails: a package `go list` cannot place stays unread, so it counts.
func TestSourceImports_ListFails(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":     "module example.com/m\n\ngo 1.22\n",
		"dep/dep.go": "package dep\n\nimport _ \"strings\"\n",
	})
	all := func(constraint.Expr) bool { return true }
	env := append(os.Environ(), "GOWORK=off")

	src := sourceImports{}
	src.read(context.Background(), dir, env, []string{"example.com/m/dep"}, all)
	if got := src["example.com/m/dep"]; !slices.Equal(got, []string{"strings"}) {
		t.Fatalf("read imports = %v, want [strings]", got)
	}

	src = sourceImports{}
	src.read(context.Background(), dir, append(env, "GOFLAGS=-modfile="+filepath.Join(dir, "nosuch.mod")), []string{"example.com/m/dep"}, all)
	if got, ok := src["example.com/m/dep"]; ok {
		t.Fatalf("go list failed, yet the package was read: %v", got)
	}
}

// TestReconciledResult_WithholdsForLeftOutFiles runs govulncheck's findings through the same path
// Reachability takes once govulncheck returns, so it fails if the left-out-file guard is not
// applied there.
func TestReconciledResult_WithholdsForLeftOutFiles(t *testing.T) {
	base := map[string]string{
		"go.mod":              "module example.com/m\n\ngo 1.22\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
		"main.go":             "package main\n\nimport \"example.com/vulnmod\"\n\nfunc main() { vulnmod.Safe() }\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.22\n",
		"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Safe() {}\n\nfunc Bad() {}\n",
	}
	moduleFinding := vulnScan{findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod"}}}}}
	stdlibFinding := vulnScan{
		findings: []vulnFinding{{OSV: "GO-2", Trace: []vulnFrame{{Module: "stdlib", Version: "v1.22.0"}}}},
		imports:  map[string][]string{"stdlib": {"net/http"}},
	}
	newRelease := map[string]string{
		"new.go": "//go:build go1.999\n\npackage main\n\nimport \"example.com/vulnmod\"\n\nfunc init() { vulnmod.Bad() }\n",
	}
	cases := []struct {
		name    string
		files   map[string]string
		scanned vulnScan
		// buildGoVersion, when set, is the subject's toolchain; "loaded" names the load's own.
		buildGoVersion string
		withheld       bool
	}{
		{"module refutation, nothing left out", nil, moduleFinding, "", false},
		{"module refutation, a tagged file calls the module", map[string]string{
			"prod.go": "//go:build prod\n\npackage main\n\nimport \"example.com/vulnmod\"\n\nfunc init() { vulnmod.Bad() }\n",
		}, moduleFinding, "", true},
		{"module refutation, a file only a newer Go release builds calls the module", newRelease, moduleFinding, "loaded", false},
		{"module refutation, the same file, the build on another Go release", newRelease, moduleFinding, "go1.2", true},
		{"module refutation, the same file, the subject's toolchain unknown", newRelease, moduleFinding, "", true},
		{"standard-library refutation, nothing left out", nil, stdlibFinding, "", false},
		{"standard-library refutation, a tagged file calls the vulnerable package", map[string]string{
			"prod.go": "//go:build prod\n\npackage main\n\nimport \"net/http\"\n\nfunc init() { _ = http.ListenAndServe(\":0\", nil) }\n",
		}, stdlibFinding, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, merge(base, tc.files))
			load, err := LoadProgram(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			switch tc.buildGoVersion {
			case "":
			case "loaded":
				load.buildGoVersion = load.goVersion
			default:
				load.buildGoVersion = tc.buildGoVersion
			}
			res, err := reconciledResult(context.Background(), tc.scanned, dir, append(os.Environ(), "GOWORK=off"), func() (*LoadResult, error) { return load, nil }, plugin.LibraryEntrypoints{})
			if err != nil {
				t.Fatal(err)
			}
			if withheld := res.Refutation == nil; withheld != tc.withheld {
				t.Fatalf("refutation withheld = %v, want %v (result %+v)", withheld, tc.withheld, res)
			}
			if declared := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonExcludedFiles); declared != tc.withheld {
				t.Errorf("excluded_files declared = %v, want %v (partiality %+v)", declared, tc.withheld, res.Partiality)
			}
		})
	}
}

// TestReconciledResult_RunnerGoDiffers: a dedicated scan job runs the analyzer under the runner
// image's Go, not the build's. A go1.21 build scanned on a newer runner compiles a !go1.22 file that
// the runner's load leaves out, so that file withholds a refutation unless the subject's toolchain
// is known and is the load's.
func TestReconciledResult_RunnerGoDiffers(t *testing.T) {
	t.Setenv("GOTOOLCHAIN", "local")
	dir := writeTree(t, map[string]string{
		"go.mod":              "module example.com/m\n\ngo 1.21\n\nrequire example.com/vulnmod v0.0.0\n\nreplace example.com/vulnmod => ./_vulnmod\n",
		"main.go":             "package main\n\nimport \"example.com/vulnmod\"\n\nfunc main() { vulnmod.Safe() }\n",
		"old.go":              "//go:build !go1.22\n\npackage main\n\nimport \"example.com/vulnmod\"\n\nfunc init() { vulnmod.Bad() }\n",
		"_vulnmod/go.mod":     "module example.com/vulnmod\n\ngo 1.21\n",
		"_vulnmod/vulnmod.go": "package vulnmod\n\nfunc Safe() {}\n\nfunc Bad() {}\n",
	})
	runner, ok := parseGoRelease(goEnvVersion(context.Background(), dir, append(os.Environ(), "GOWORK=off")))
	if !ok || runner.major != 1 || runner.minor < 22 {
		t.Skipf("runner Go %v builds !go1.22 files", runner)
	}
	scanned := vulnScan{findings: []vulnFinding{{OSV: "GO-1", Trace: []vulnFrame{{Module: "example.com/vulnmod", Version: "v0.0.0", Package: "example.com/vulnmod"}}}}}
	cases := []struct {
		name string
		// toolchain is the subject's, as the request names it.
		toolchain string
		withheld  bool
	}{
		{"subject toolchain unknown", "", true},
		{"subject builds with go1.21", "go1.21.13", true},
		{"subject builds with the runner's Go", runner.toolchain(), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			load := func() (*LoadResult, error) { return loadForBuild(context.Background(), dir, tc.toolchain) }
			res, err := reconciledResult(context.Background(), scanned, dir, append(os.Environ(), "GOWORK=off"), load, plugin.LibraryEntrypoints{})
			if err != nil {
				t.Fatal(err)
			}
			if withheld := res.Refutation == nil; withheld != tc.withheld {
				t.Fatalf("refutation withheld = %v, want %v (result %+v)", withheld, tc.withheld, res)
			}
			if declared := slices.Contains(res.Partiality.Reasons, plugin.PartialReasonExcludedFiles); declared != tc.withheld {
				t.Errorf("excluded_files declared = %v, want %v (partiality %+v)", declared, tc.withheld, res.Partiality)
			}
		})
	}
}

// TestLoadResult_BuildRelease: the load's release counts as the build's only when both are known and
// name the same minor.
func TestLoadResult_BuildRelease(t *testing.T) {
	cases := []struct {
		loaded, build string
		want          *goRelease
	}{
		{"go1.25.3", "go1.25.3", &goRelease{1, 25, 3}},
		{"go1.25.3", "go1.25.0", &goRelease{1, 25, 3}},
		{"go1.25.3", "go1.24.9", nil},
		{"go1.25.3", "go2.25.3", nil},
		{"", "go1.25.3", nil},
		{"go1.25.3", "", nil},
		{"go1.25.3", "devel go1.25-abc123", nil},
	}
	for _, tc := range cases {
		got := (&LoadResult{goVersion: tc.loaded, buildGoVersion: tc.build}).buildRelease()
		if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
			t.Errorf("buildRelease(%q, %q) = %v, want %v", tc.loaded, tc.build, got, tc.want)
		}
	}
}

// TestLoadProgram_Toolchain: the load records the release the go command resolves for the build
// directory, and never establishes it as the build's: that go command is the analyzer's, which in a
// dedicated scan job is the runner image's Go, not the one the build compiles under.
func TestLoadProgram_Toolchain(t *testing.T) {
	t.Setenv("GOTOOLCHAIN", "auto")
	dir := writeTree(t, map[string]string{
		"go.mod":  "module example.com/m\n\ngo 1.22\n",
		"main.go": "package main\n\nfunc main() {}\n",
	})
	load, err := LoadProgram(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := goEnvVersion(context.Background(), dir, append(os.Environ(), "GOWORK=off")); load.goVersion != want || want == "" {
		t.Fatalf("loaded under %q, want %q", load.goVersion, want)
	}
	if load.buildRelease() != nil {
		t.Fatalf("toolchain established without the subject's (loaded %q, build %q)", load.goVersion, load.buildGoVersion)
	}
}

// TestLoadForBuild_SubjectToolchain: only a known subject toolchain is the build's, so a load with
// none, or under another minor, is not established as the build's.
func TestLoadForBuild_SubjectToolchain(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":  "module example.com/m\n\ngo 1.22\n",
		"main.go": "package main\n\nfunc main() {}\n",
	})
	load, err := loadForBuild(context.Background(), dir, "")
	if err != nil {
		t.Fatal(err)
	}
	r, ok := parseGoRelease(load.goVersion)
	if !ok {
		t.Fatalf("loaded under %q", load.goVersion)
	}
	for _, tc := range []struct {
		toolchain   string
		established bool
	}{
		{"", false},
		{r.toolchain(), true},
		{fmt.Sprintf("go%d.%d", r.major, r.minor+1), false},
	} {
		load, err := loadForBuild(context.Background(), dir, tc.toolchain)
		if err != nil {
			t.Fatal(err)
		}
		if got := load.buildRelease() != nil; got != tc.established {
			t.Errorf("subject toolchain %s: established = %v, want %v (loaded %q)", tc.toolchain, got, tc.established, load.goVersion)
		}
	}
}

// TestReleaseExcluded: a constraint is excluded by the release alone when it holds for some tags
// but for none with the release tags at the build's values, the build's own minor included.
func TestReleaseExcluded(t *testing.T) {
	r := goRelease{1, 26, 3}
	cases := []struct {
		expr string
		want bool
	}{
		{"go1.26", false},
		{"!go1.26", true},
		{"go1.27", true},
		{"!go1.27", false},
		{"go1.27 && plan9", true},
		{"go1.27 || plan9", false},
		{"go1.1 && !go1.1", false},
		{"plan9", false},
	}
	for _, tc := range cases {
		x, err := constraint.Parse("//go:build " + tc.expr)
		if err != nil {
			t.Fatal(err)
		}
		if got := releaseExcluded(x, r); got != tc.want {
			t.Errorf("releaseExcluded(%q, go1.26.3) = %v, want %v", tc.expr, got, tc.want)
		}
	}
}

// TestFileConstraint: the constraint read from a file's header admits the file under exactly the
// tags go/build admits it under.
func TestFileConstraint(t *testing.T) {
	headers := []string{
		"",
		"//go:build windows\n\n",
		"// +build windows\n\n",
		"// +build windows\n",
		"// +build windows\n// +build go1.999\n\n",
		"// +build windows\n\n// +build go1.999\n",
		"// +build windows linux,x\n\n",
		"//go:build x\n// +build windows\n\n",
		"// Copyright\n\n//go:build go1.999 || x\n\n// Package doc.\n",
		"/* block\n\n*/\n// +build windows\n\n",
		"/* block */ //go:build windows\n\n",
		"// doc\n// +build windows\n",
		"// +build !go1.1\n\n",
		"// +build windows\n/* block */\n\n",
	}
	assignments := []build.Context{
		{GOOS: "linux", GOARCH: "amd64", ReleaseTags: []string{"go1.1"}},
		{GOOS: "windows", GOARCH: "amd64", ReleaseTags: []string{"go1.1"}},
		{GOOS: "windows", GOARCH: "amd64", ReleaseTags: []string{"go1.1", "go1.999"}},
		{GOOS: "linux", GOARCH: "amd64", BuildTags: []string{"x"}},
	}
	for _, h := range headers {
		src := []byte(h + "package p\n")
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "p.go"), src, 0o644); err != nil {
			t.Fatal(err)
		}
		expr, err := fileConstraint(src)
		if err != nil {
			t.Fatalf("%q: %v", h, err)
		}
		for _, ctxt := range assignments {
			want, err := ctxt.MatchFile(dir, "p.go")
			if err != nil {
				t.Fatal(err)
			}
			tags := map[string]bool{ctxt.GOOS: true, ctxt.GOARCH: true}
			for _, tag := range slices.Concat(ctxt.ReleaseTags, ctxt.BuildTags) {
				tags[tag] = true
			}
			got := expr == nil || expr.Eval(func(tag string) bool { return tags[tag] })
			if got != want {
				t.Errorf("%q under %s %v %v: admitted = %v, go/build says %v", h, ctxt.GOOS, ctxt.ReleaseTags, ctxt.BuildTags, got, want)
			}
		}
	}
	for _, h := range []string{"//go:build windows\n//go:build linux\n\n", "//go:build (\n\n"} {
		if _, err := fileConstraint([]byte(h + "package p\n")); err == nil {
			t.Errorf("%q: no error, go/build rejects it", h)
		}
	}
}

// merge returns the union of file maps, later maps winning.
func merge(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

// TestGoflagsTags: GOFLAGS carries the build tags every spawned go command uses, and the last
// -tags flag wins.
func TestGoflagsTags(t *testing.T) {
	cases := []struct {
		goflags string
		want    []string
	}{
		{"", nil},
		{"-mod=mod", nil},
		{"-tags=prod", []string{"prod"}},
		{"--tags=prod,netgo -mod=mod", []string{"prod", "netgo"}},
		{"-tags=a -tags=b", []string{"b"}},
	}
	for _, tc := range cases {
		if got := goflagsTags([]string{"GOFLAGS=" + tc.goflags}); !slices.Equal(got, tc.want) {
			t.Errorf("goflagsTags(%q) = %q, want %q", tc.goflags, got, tc.want)
		}
	}
}
