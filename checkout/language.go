// internal/checkout/language.go
package checkout

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Language tags the source language a checked-out tree presents, derived from the
// tree's contents (not the request — the request schema carries no language). It is
// what makes checkout language-aware: a Go module and a Java source tree are both
// valid checkouts, but a Go-shaped guard (go.mod-required) wrongly rejects the latter.
const (
	LangGo      = "go"     // a Go module root: contains go.mod
	LangJava    = "java"   // a Java source tree: contains .java sources (optionally pom.xml/build.gradle)
	LangJS      = "js"     // a JS/TS source tree: contains .js/.ts/.jsx/.tsx (optionally package.json)
	LangPython  = "python" // a Python source tree: contains .py sources (optionally requirements.txt/pyproject.toml)
	LangDotNet  = "dotnet" // a .NET source tree: contains .cs sources or a .csproj/.sln project marker
	LangUnknown = ""       // no recognized source markers under the dir
)

// DetectLanguage classifies the checked-out tree at dir. A go.mod at the root makes it
// Go unconditionally (the module-root marker the Go vendoring / govulncheck setup keys on,
// and the reason checkout historically required go.mod) — Go is a module-root fact, not a
// file count, so this short-circuit is preserved exactly. Otherwise, detection is
// dominance-based: a single walk tallies source files per language across java / js /
// python / dotnet (applying the same skipSourceDir prune and the same extension rules as
// the historical per-language probes, including the .d.ts exclusion for JS and the
// .csproj/.sln/.fsproj/.vbproj markers for .NET), and the language with the MOST source
// files wins. This classifies a polyglot tree by its dominant language: a repo that is
// thousands of .py files plus a few hundred frontend .js files (e.g. Apache Airflow)
// detects as Python, not JS.
//
// Ties (equal source-file counts, including the all-zero case) fall back to the historical
// precedence order java > js > python > dotnet, so behavior stays deterministic and every
// single-language tree — which has a nonzero count in exactly one bucket — detects exactly
// as it did under the old first-match precedence. Zero source files in all four buckets
// yields LangUnknown — the caller treats that as "not a recognizable source tree" and
// errors (inv.5: never a silent half-checkout).
func DetectLanguage(dir string) string {
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		return LangGo
	}
	counts := countSources(dir)
	// Precedence order is also the tie-break order: iterate high→low precedence and keep a
	// strict-greater comparison so the first (highest-precedence) language wins on a tie.
	best := LangUnknown
	bestN := 0
	for _, c := range []struct {
		lang string
		n    int
	}{
		{LangJava, counts.java},
		{LangJS, counts.js},
		{LangPython, counts.python},
		{LangDotNet, counts.dotnet},
	} {
		if c.n > bestN {
			best = c.lang
			bestN = c.n
		}
	}
	return best
}

// sourceCounts tallies per-language source-file counts over a tree.
type sourceCounts struct {
	java, js, python, dotnet int
}

// countSources walks dir once and counts source files per language, skipping common
// build-output / VCS / virtualenv / dependency trees (skipSourceDir) so vendored or
// generated files do not skew dominance. A single WalkDir switches on file extension and
// increments the matching counter — one walk instead of five, which matters on large trees
// (4600+ files). The extension rules mirror the analysis packages' source notions
// (pythonanalysis.pythonFiles, javaanalysis.javaFiles, jsanalysis.jsFiles, dotnetanalysis)
// without importing them (internal/checkout must stay analysis-library-free): the .d.ts
// TypeScript-declaration exclusion for JS and the .csproj/.sln/.fsproj/.vbproj project
// markers for .NET are preserved.
func countSources(dir string) sourceCounts {
	var c sourceCounts
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree contributes no counts; keep walking siblings.
		}
		if d.IsDir() {
			if path != dir && skipSourceDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		switch {
		case strings.HasSuffix(name, ".java"):
			c.java++
		case strings.HasSuffix(name, ".py"):
			c.python++
		case strings.HasSuffix(name, ".d.ts"):
			// TypeScript declaration file: declares no bodies — not a JS source (excluded).
		default:
			switch filepath.Ext(name) {
			case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
				c.js++
			case ".cs", ".csproj", ".sln", ".fsproj", ".vbproj":
				c.dotnet++
			}
		}
		return nil
	})
	return c
}

// skipSourceDir reports whether a directory is build output / tooling state rather than
// source, so it is excluded from the language-source probes. It matches
// javaanalysis.skipDir / jsanalysis.skipDir (plus obj, .NET's intermediate-build dir).
func skipSourceDir(name string) bool {
	switch name {
	case "target", "build", "out", "bin", "obj", ".git", ".gradle", "node_modules", "dist", ".next",
		"__pycache__", ".venv", "venv", ".tox", "site-packages", ".eggs":
		return true
	default:
		return false
	}
}
