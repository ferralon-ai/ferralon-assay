package kotlinanalysis

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
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
)

// writeFileAt writes dir/name, creating dir.
func writeFileAt(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeBuildFile(t, dir, name, content)
}

func callsReadValue(b *kclassBuilder) []byte {
	return b.invokeVirtual(objectMapper, "readValue", readValueDesc)
}

const jacksonJarName = jacksonArtifact + "-" + jacksonVersion + ".jar"

// writeStartScript writes a Gradle unix start script at build/<rel> whose classpath is jars
// (each $APP_HOME/lib/<jar>) and whose launch class is mainClass.
func writeStartScript(t *testing.T, dir, rel string, jars []string, mainClass string) {
	t.Helper()
	entries := make([]string, len(jars))
	for i, j := range jars {
		entries[i] = "$APP_HOME/lib/" + j
	}
	script := "#!/bin/sh\nAPP_HOME=$( cd -P \"${APP_HOME:-./}..\" > /dev/null && printf '%s\\n' \"$PWD\" ) || exit\n\n" +
		"CLASSPATH=" + strings.Join(entries, ":") + "\n\n" +
		"set -- \\\n        -classpath \"$CLASSPATH\" \\\n        " + mainClass + " \\\n        \"$@\"\n\nexec \"$JAVACMD\" \"$@\"\n"
	p := filepath.Join(dir, "build", filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
}

// jvmOptsBuild is a jackson build whose main never calls the sink and whose start script's
// DEFAULT_JVM_OPTS line is opts (as Gradle quotes it).
func jvmOptsBuild(t *testing.T, opts string) string {
	t.Helper()
	dir := gradleJacksonBuild(t, "")
	writeMain(t, dir, func(b *kclassBuilder) []byte { return nil })
	writeStartScript(t, dir, "scripts/app", []string{jacksonJarName}, "com.example.MainKt")
	p := filepath.Join(dir, "build", "scripts", "app")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	script := strings.Replace(string(data), "\nCLASSPATH=", "\nDEFAULT_JVM_OPTS="+opts+"\n\nCLASSPATH=", 1)
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// graphDep is one dependency node of a test graph. jar is the file's path.
type graphDep struct {
	group, artifact, version, scope, jar string
}

// graphModule is a module at path whose root is com.example:<name>:1 and whose nodes are deps,
// each a direct dependency of the root at compile scope unless it names one.
func graphModule(path, name string, deps ...graphDep) buildgraph.Module {
	root := buildgraph.Node{Group: "com.example", Artifact: name, Version: "1", Type: "jar"}
	root.ID = buildgraph.NodeID(root.Group, root.Artifact, root.Type, "", root.Version)
	m := buildgraph.Module{ID: "com.example:" + name, Path: path, Root: root.ID, Nodes: []buildgraph.Node{root}}
	for _, d := range deps {
		scope := d.scope
		if scope == "" {
			scope = "compile"
		}
		n := buildgraph.Node{Group: d.group, Artifact: d.artifact, Version: d.version, Type: "jar", Scope: scope,
			File: &buildgraph.File{Path: d.jar, SHA256: fileSHA256(d.jar)}}
		n.ID = buildgraph.NodeID(n.Group, n.Artifact, n.Type, "", n.Version)
		m.Nodes = append(m.Nodes, n)
		m.Edges = append(m.Edges, buildgraph.Edge{From: root.ID, To: n.ID})
	}
	return m
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

// graphOption writes a Gradle graph of modules to a fresh file and returns the option handing
// it to the ops.
func graphOption(t *testing.T, modules ...buildgraph.Module) javaanalysis.Option {
	t.Helper()
	b, err := json.Marshal(buildgraph.Graph{
		Schema:   buildgraph.Schema,
		Tool:     buildgraph.Tool{Name: "gradle", Version: "test"},
		JVM:      buildgraph.JVM{Version: "21.0.4"},
		Modules:  modules,
		Complete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "graph.json")
	if err := os.WriteFile(file, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return javaanalysis.WithBuildGraph(file)
}

// cacheGraph is the graph a build at dir resolves when its dependencies are exactly the JARs
// under its build-local Gradle module cache and .m2/repository, plus extra: one root module, each
// JAR a compile dependency at the coordinate its cache path names. Digests are taken now, so a JAR
// rewritten after the call no longer matches.
func cacheGraph(t *testing.T, dir string, extra ...graphDep) javaanalysis.Option {
	t.Helper()
	return graphOption(t, cacheModule(dir, extra...))
}

// cacheModule is cacheGraph's one root module.
func cacheModule(dir string, extra ...graphDep) buildgraph.Module {
	deps := append([]graphDep(nil), extra...)
	gradle := filepath.Join(dir, ".gradle", "caches", "modules-2", "files-2.1")
	m2 := filepath.Join(dir, ".m2", "repository")
	for _, root := range []string{gradle, m2} {
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".jar") {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			parts := strings.Split(filepath.ToSlash(rel), "/")
			switch {
			case root == gradle && len(parts) == 5: // group/artifact/version/hash/file
				deps = append(deps, graphDep{group: parts[0], artifact: parts[1], version: parts[2], jar: p})
			case root == m2 && len(parts) >= 4: // group path/artifact/version/file
				n := len(parts)
				deps = append(deps, graphDep{group: strings.Join(parts[:n-3], "."), artifact: parts[n-3], version: parts[n-2], jar: p})
			}
			return nil
		})
	}
	return graphModule(".", "app", deps...)
}
