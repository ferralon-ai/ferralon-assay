package buildgraph

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// jvmPluginDirs are the JVM lanes, relative to the module root. Their dependency facts come from
// the build graph alone.
var jvmPluginDirs = []string{
	"internal/plugin/javaanalysis",
	"internal/plugin/kotlinanalysis",
	"internal/plugin/jvmingress",
	"cmd/assay-plugin-java",
	"cmd/assay-plugin-kotlin",
}

// buildFileReaders is every JVM plugin file allowed to name a Maven or Gradle build input, with
// what it reads one for. None reads a dependency or a version; those come from the graph.
var buildFileReaders = map[string]string{
	"internal/plugin/javaanalysis/launchentry.go":   "launch entry: the main class a POM or Gradle script names",
	"internal/plugin/javaanalysis/launchoptions.go": "launch options: JVM flags in .mvn/maven.config and the exec plugin's POM configuration",
	"internal/plugin/kotlinanalysis/launchentry.go": "launch entry: the main class a POM or Gradle script names",
	"internal/plugin/kotlinanalysis/modules.go":     "module discovery: the settings and build files that say where a module's sources are",
}

// TestJVMPluginsReadNoBuildInputs is the acceptance test of the build-graph cutover: outside
// buildFileReaders, no JVM plugin source holds a string literal naming a file Load counts as a
// Maven or Gradle build input. Reading one would be resolving what the tool already resolved.
//
// Demonstrated failure: adding `os.ReadFile(filepath.Join(dir, "gradle.lockfile"))` to
// internal/plugin/javaanalysis/graph.go makes this test fail with that file:line.
func TestJVMPluginsReadNoBuildInputs(t *testing.T) {
	maven := mavenInput(nil)
	names := func(v string) bool {
		v = strings.TrimPrefix(filepath.ToSlash(v), "/")
		if v == ".gradle" {
			return false // the Gradle cache directory, which source walks skip
		}
		name := path.Base(v)
		return gradleInput(v, name) || maven(v, name) || strings.HasPrefix(v, ".mvn/") || v == ".mvn"
	}
	var violations []string
	hits := map[string]bool{}
	fset := token.NewFileSet()
	for _, dir := range jvmPluginDirs {
		root := filepath.Join("..", filepath.FromSlash(dir))
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel("..", p)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			file, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil || !names(v) {
					return true
				}
				if _, ok := buildFileReaders[rel]; ok {
					hits[rel] = true
					return true
				}
				violations = append(violations, fmt.Sprintf("%s:%d: names build input %q; take it from the build graph", rel, fset.Position(lit.Pos()).Line, v))
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	sort.Strings(violations)
	for _, v := range violations {
		t.Error(v)
	}
	for rel := range buildFileReaders {
		if !hits[rel] {
			t.Errorf("%s is allowed to read build inputs but names none; drop it from buildFileReaders", rel)
		}
	}
}
