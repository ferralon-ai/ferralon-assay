package checkout

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
)

// Language tags the source language a checked-out tree presents, derived from the
// tree's contents (not the request — the request schema carries no language). It is
// what makes checkout language-aware: a Go module and a Java source tree are both
// valid checkouts, but a Go-shaped guard (go.mod-required) wrongly rejects the latter.
const (
	LangGo      = "go"      // a Go module root: contains go.mod
	LangJava    = "java"    // a Java source tree: contains .java sources (optionally pom.xml/build.gradle)
	LangKotlin  = "kotlin"  // a Kotlin source tree: contains .kt/.kts sources (optionally build.gradle.kts)
	LangJS      = "js"      // a JS/TS source tree: contains .js/.ts/.jsx/.tsx (optionally package.json)
	LangPython  = "python"  // a Python source tree: contains .py sources (optionally requirements.txt/pyproject.toml)
	LangDotNet  = "dotnet"  // a .NET source tree: contains .cs sources or a .csproj/.sln project marker
	LangCFamily = "cfamily" // a C/C++ source tree: contains .c/.cc/.cpp/.cxx/.c++ sources or .h/.hpp/.hh/.hxx headers
	LangUnknown = ""        // no recognized source markers under the dir
)

// DetectLanguage classifies the checked-out tree at dir. A go.mod anywhere within
// FindGoModuleRoot's bounded search below dir (at the root, or in a monorepo-shaped
// subdirectory such as target/ or src/) makes it Go unconditionally (the module-root marker
// the Go vendoring / govulncheck setup keys on, and the reason checkout historically required
// go.mod) — Go is a module-root fact, not a file count, so this short-circuit is preserved
// exactly; only WHERE it looks for the root has widened. Otherwise, detection is
// dominance-based: a single walk tallies source files per language across kotlin / java /
// js / python / dotnet / cfamily (applying the same skipSourceDir prune and the same extension rules as
// the historical per-language probes, including the .d.ts exclusion for JS and the
// .csproj/.sln/.fsproj/.vbproj markers for .NET), and the language with the MOST source
// files wins. This classifies a polyglot tree by its dominant language: a repo that is
// thousands of .py files plus a few hundred frontend .js files (e.g. Apache Airflow)
// detects as Python, not JS.
//
// Kotlin+Java interop rule: a Kotlin project routinely carries .java sources too (both
// compile to the same JVM bytecode the Kotlin lane's analyzer reads via javaanalysis), so
// this is the one pairing that needs an explicit, not merely positional, tie policy: Kotlin
// wins whenever its .kt/.kts count is >= the .java count, Java wins only when strictly
// dominant. Placing LangKotlin immediately ahead of LangJava in the precedence list below
// gives exactly that: on an equal count the earlier (Kotlin) entry keeps its
// already-strict-greater win, and Java only overtakes on a strictly larger count. This
// biases a mixed JVM tree toward the Kotlin lane rather than mis-routing a pure- or
// Kotlin-dominant tree to Java — a mixed tree resolving to Java is still soundly analyzable
// since both compile through the same substrate, so the cost of the bias is one-sided and
// small.
//
// Ties among the languages (equal source-file counts) fall back to the precedence order
// kotlin > java > js > python > dotnet > cfamily, so behavior stays deterministic and a
// single-language tree — which has a nonzero count in exactly one bucket — detects as that
// language. Zero source files in every bucket yields LangUnknown — the caller treats that
// as "not a recognizable source tree" and errors (inv.5: never a silent half-checkout).
func DetectLanguage(dir string) string {
	if _, ok := FindGoModuleRoot(dir); ok {
		return LangGo
	}
	counts := countSources(dir)
	// Precedence order is also the tie-break order: iterate high→low precedence and keep a
	// strict-greater comparison so the first (highest-precedence) language wins on a tie.
	// Kotlin sits immediately ahead of Java to implement the Kotlin+Java interop rule above.
	best := LangUnknown
	bestN := 0
	for _, c := range []struct {
		lang string
		n    int
	}{
		{LangKotlin, counts.kotlin},
		{LangJava, counts.java},
		{LangJS, counts.js},
		{LangPython, counts.python},
		{LangDotNet, counts.dotnet},
		{LangCFamily, counts.cfamily},
	} {
		if c.n > bestN {
			best = c.lang
			bestN = c.n
		}
	}
	return best
}

// goModuleSearchMaxDepth bounds how far below dir FindGoModuleRoot descends looking for a go.mod
// not at the root. depth 0 is dir itself (the historical root-only check); depth 1 covers the
// single-level monorepo shapes this mission exists for (target/go.mod, src/go.mod, cmd/x/go.mod);
// depth 4 leaves headroom for a deeper monorepo (e.g. apps/backend/services/x/go.mod) without
// turning the walk unbounded — language.go already reasons about trees of 4600+ files, so an
// unbounded descent is not acceptable here either.
const goModuleSearchMaxDepth = 4

// FindGoModuleRoot searches dir, then its subdirectories breadth-first up to
// goModuleSearchMaxDepth levels deep, for a go.mod file. It returns the directory containing the
// go.mod found at the SHALLOWEST depth; ties at that depth (more than one go.mod at the same
// depth — a genuine multi-module tree) break lexicographically by path, so selection is always
// deterministic. It returns ("", false) when no go.mod exists within the bound.
//
// This is a DIFFERENT question from countSources' source-dominance walk and deliberately does not
// share its skipSourceDir prune list: a module can legitimately live under a directory dominance
// excludes (e.g. a module under target/go.mod), and widening skipSourceDir itself would defeat the
// vendored-dominance reasoning that prune list exists for. The only directory this search skips is
// ".git" — never a module location, and potentially large.
func FindGoModuleRoot(dir string) (string, bool) {
	frontier := []string{dir}
	for depth := 0; depth <= goModuleSearchMaxDepth; depth++ {
		var matches []string
		var next []string
		for _, d := range frontier {
			if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
				matches = append(matches, d)
			}
			entries, err := os.ReadDir(d)
			if err != nil {
				continue
			}
			for _, e := range entries {
				if !e.IsDir() || e.Name() == ".git" {
					continue
				}
				next = append(next, filepath.Join(d, e.Name()))
			}
		}
		if len(matches) > 0 {
			sort.Strings(matches)
			return matches[0], true
		}
		frontier = next
	}
	return "", false
}

// NestedGoModules returns the directories below dir that hold a go.mod of their own and that dir's
// module graph does not include: modules the go command resolves on their own, so resolving dir's
// module never sees what they require. A module a go.work in dir lists, or one dir/go.mod requires
// and replaces with its directory, is in that graph and is not returned. Paths are slash-separated,
// relative to dir, and sorted. A limit above zero stops the walk once that many are found; zero or
// less finds them all.
//
// Unlike FindGoModuleRoot the walk is unbounded: a module four levels down hides its requirements
// as well as one a level down. It skips what the go command never treats as module source: ".git",
// "testdata", "vendor", and any directory whose name starts with "." or "_". A go.work or go.mod
// that cannot be read or parsed includes nothing, so every nested module stays named.
func NestedGoModules(dir string, limit int) []string {
	included := includedModuleDirs(dir)
	var found []string
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable subtree names no module; keep walking siblings.
		}
		if !d.IsDir() || path == dir {
			return nil
		}
		if name := d.Name(); name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			return filepath.SkipDir
		}
		if included[path] {
			return nil
		}
		if fi, err := os.Stat(filepath.Join(path, "go.mod")); err != nil || fi.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return nil //nolint:nilerr // a path outside dir cannot be named relative to it.
		}
		found = append(found, filepath.ToSlash(rel))
		if limit > 0 && len(found) >= limit {
			return fs.SkipAll
		}
		return nil
	})
	sort.Strings(found)
	return found
}

// includedModuleDirs returns the module directories dir's own module graph includes: every use
// directive of dir/go.work, and every directory dir/go.mod replaces a module it requires with.
func includedModuleDirs(dir string) map[string]bool {
	included := map[string]bool{}
	add := func(p string) {
		p = filepath.FromSlash(p)
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		included[filepath.Clean(p)] = true
	}
	if wf := parseIn(dir, "go.work", modfile.ParseWork); wf != nil {
		for _, u := range wf.Use {
			add(u.Path)
		}
	}
	if mf := parseIn(dir, "go.mod", modfile.Parse); mf != nil {
		required := make(map[string]bool, len(mf.Require))
		for _, r := range mf.Require {
			required[r.Mod.Path] = true
		}
		for _, r := range mf.Replace {
			if r.New.Version == "" && required[r.Old.Path] {
				add(r.New.Path)
			}
		}
	}
	return included
}

// parseIn reads dir/name and parses it with parse, returning nil when it is absent or unparseable.
func parseIn[T any](dir, name string, parse func(string, []byte, modfile.VersionFixer) (*T, error)) *T {
	path := filepath.Join(dir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	f, err := parse(path, data, nil)
	if err != nil {
		return nil
	}
	return f
}

// sourceCounts tallies per-language source-file counts over a tree.
type sourceCounts struct {
	kotlin, java, js, python, dotnet, cfamily int
}

// countSources walks dir once and counts source files per language, skipping common
// build-output / VCS / virtualenv / dependency trees (skipSourceDir) so vendored or
// generated files do not skew dominance. A single WalkDir switches on file extension and
// increments the matching counter — one walk instead of six, which matters on large trees
// (4600+ files). The extension rules mirror the analysis packages' source notions
// (pythonanalysis.pythonFiles, javaanalysis.javaFiles, jsanalysis.jsFiles, dotnetanalysis)
// without importing them (internal/checkout must stay analysis-library-free): the .d.ts
// TypeScript-declaration exclusion for JS and the .csproj/.sln/.fsproj/.vbproj project
// markers for .NET are preserved. .kt/.kts count toward Kotlin, not Java. The C-family
// bucket (.c/.cc/.cpp/.cxx/.c++ sources and .h/.hpp/.hh/.hxx headers) has no source-notion
// package to mirror.
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
		case strings.HasSuffix(name, ".kt"), strings.HasSuffix(name, ".kts"):
			c.kotlin++
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
			case ".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hpp", ".hh", ".hxx":
				// C and C++ share ONE detection bucket (LangCFamily): real repos mix C and C++
				// translation units under one build system, so a whole-tree C-vs-C++ split here
				// would force a classification the build reality does not respect. A .h header is
				// counted toward the family without deciding C vs C++ — that per-TU decision is the
				// compiler mode in compile_commands.json (ground truth), not decided here.
				c.cfamily++
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
