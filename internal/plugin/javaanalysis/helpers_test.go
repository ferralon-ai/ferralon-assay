package javaanalysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func hasStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// graphDep is one dependency node of a test graph. jar is the file's path; "" leaves the node
// without a file, as the graph records a pom.
type graphDep struct {
	group, artifact, version, scope, classifier, jar string
}

// testModule is a module at path whose root is com.example:<name>:1 and whose nodes are deps,
// each a direct dependency of the root.
func testModule(t *testing.T, path, name string, deps ...graphDep) buildgraph.Module {
	t.Helper()
	root := buildgraph.Node{Group: "com.example", Artifact: name, Version: "1", Type: "jar"}
	root.ID = buildgraph.NodeID(root.Group, root.Artifact, root.Type, "", root.Version)
	m := buildgraph.Module{ID: "com.example:" + name, Path: path, Root: root.ID, Nodes: []buildgraph.Node{root}}
	for _, d := range deps {
		typ := "jar"
		if d.jar == "" {
			typ = "pom"
		}
		scope := d.scope
		if scope == "" {
			scope = "compile"
		}
		n := buildgraph.Node{Group: d.group, Artifact: d.artifact, Version: d.version, Type: typ, Classifier: d.classifier, Scope: scope}
		n.ID = buildgraph.NodeID(n.Group, n.Artifact, n.Type, n.Classifier, n.Version)
		if d.jar != "" {
			n.File = &buildgraph.File{Path: d.jar, SHA256: fileSHA256(d.jar)}
		}
		m.Nodes = append(m.Nodes, n)
		m.Edges = append(m.Edges, buildgraph.Edge{From: root.ID, To: n.ID})
	}
	return m
}

// classpathCopy is project's copy for classpath cp, holding deps.
func classpathCopy(t *testing.T, project buildgraph.Module, cp string, deps ...graphDep) buildgraph.Module {
	t.Helper()
	c := testModule(t, project.Path, strings.TrimPrefix(project.ID, "com.example:"), deps...)
	c.ID = buildgraph.ClasspathCopyID(project.ID, cp)
	return c
}

// fileSHA256 is a file's digest, or a digest no file has when it cannot be read.
func fileSHA256(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return strings.Repeat("0", 64)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// graphOption writes g to a fresh file and returns the option handing it to the ops.
func graphOption(t *testing.T, tool string, modules ...buildgraph.Module) Option {
	t.Helper()
	return writeGraph(t, buildgraph.Graph{
		Schema:  buildgraph.Schema,
		Tool:    buildgraph.Tool{Name: tool, Version: "test"},
		JVM:     buildgraph.JVM{Version: "21.0.4"},
		Modules: modules,
	})
}

// writeGraph writes g to a fresh file and returns the option handing it to the ops.
func writeGraph(t *testing.T, g buildgraph.Graph) Option {
	t.Helper()
	b, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "graph.json")
	if err := os.WriteFile(file, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return WithBuildGraph(file)
}

// cacheGraph is the graph a Maven build at buildDir resolves when its dependencies are exactly
// the JARs under its project-local .m2/repository: one root module, each JAR a compile
// dependency at the coordinate its cache path names.
func cacheGraph(t *testing.T, buildDir string) Option {
	t.Helper()
	repo := filepath.Join(buildDir, ".m2", "repository")
	var deps []graphDep
	_ = filepath.WalkDir(repo, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".jar") {
			return nil
		}
		rel, _ := filepath.Rel(repo, p)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) < 4 {
			return nil
		}
		version, artifact := parts[len(parts)-2], parts[len(parts)-3]
		group := strings.Join(parts[:len(parts)-3], ".")
		classifier := strings.TrimSuffix(strings.TrimPrefix(parts[len(parts)-1], artifact+"-"+version), ".jar")
		deps = append(deps, graphDep{group: group, artifact: artifact, version: version, classifier: strings.TrimPrefix(classifier, "-"), jar: p})
		return nil
	})
	return graphOption(t, "maven", testModule(t, ".", "app", deps...))
}

// writeTree writes files (path→content, paths relative to a fresh temp dir) and returns the
// dir. A trivial .java file is always added so the tree is a recognizable Java source tree.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["src/App.java"] = "package x;\nclass App {}\n"
	for rel, content := range files {
		writeFile(t, filepath.Join(dir, rel), content)
	}
	return dir
}
