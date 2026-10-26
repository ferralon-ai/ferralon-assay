package javaanalysis

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
)

// TestBuildDependencyGraph_SplitPackages: the engine buildDependencyGraph assembles takes a
// JDK-named class as the JDK's only while no dependency JAR defines its package, and not at
// all (outside java/) while a dependency JAR the build graph names could not be read.
func TestBuildDependencyGraph_SplitPackages(t *testing.T) {
	const (
		fetcher = "com/evil/netkit/UrlFetcher"
		fetch   = "(Ljava/lang/String;)Ljava/lang/String;"
		option  = "com/sun/tools/javac/main/Option"
	)
	write := func(t *testing.T, pom string, mrOption bool, corruptGone bool, extra map[string][]byte) string {
		t.Helper()
		build := t.TempDir()
		if err := os.WriteFile(filepath.Join(build, "pom.xml"), []byte(pom), 0o644); err != nil {
			t.Fatal(err)
		}
		b := &cpb{}
		opt := b.mref(option, "values", "()[Lcom/sun/tools/javac/main/Option;")
		parsers := b.mref("javax/xml/parsers/SAXParserFactory", "newDefaultInstance", "()Ljavax/xml/parsers/SAXParserFactory;")
		classBytes := emitClass(b, fetcher, []mspec{
			{"fetch", fetch, []byte{0xB1}},
			{"opt", "()V", append(append([]byte{0xB8}, be2(opt)...), 0x57, 0xB1)},         // invokestatic; pop; return
			{"parsers", "()V", append(append([]byte{0xB8}, be2(parsers)...), 0x57, 0xB1)}, // invokestatic; pop; return
		})
		entries := map[string][]byte{fetcher + ".class": classBytes}
		if mrOption {
			entries["META-INF/versions/11/"+option+".class"] = classBytes
		}
		for n, data := range extra {
			entries[n] = data
		}
		p := filepath.Join(build, ".m2", "repository", "com", "evil", "netkit", "1.0.0", "netkit-1.0.0.jar")
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		zw := zip.NewWriter(f)
		for n, data := range entries {
			w, err := zw.Create(n)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if corruptGone {
			gone := filepath.Join(build, ".m2", "repository", "com", "other", "gone", "1.0.0", "gone-1.0.0.jar")
			if err := os.MkdirAll(filepath.Dir(gone), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(gone, []byte("PK\x03\x04 not a zip"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return build
	}
	withUncached := `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId><artifactId>app</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>com.evil</groupId><artifactId>netkit</artifactId><version>1.0.0</version></dependency>
    <dependency><groupId>com.other</groupId><artifactId>gone</artifactId><version>1.0.0</version></dependency>
  </dependencies>
</project>`
	sink := classfile.MethodRef{Owner: fetcher, Name: "fetch", Descriptor: fetch}
	for _, tc := range []struct {
		name     string
		pom      string
		mrOption bool
		corrupt  bool
		from     string
		want     depreach.Verdict
		extra    map[string][]byte
	}{
		{"a dependency JAR defines Option only under META-INF/versions/11/: unopened", netkitPom, true, false, "opt", depreach.Undetermined, nil},
		{"control: nothing defines com/sun/tools/javac/main, so Option is the JDK's", netkitPom, false, false, "opt", depreach.NotExploitable, nil},
		{"an uncached dependency JAR may define javax/xml/parsers: unopened", withUncached, false, false, "parsers", depreach.Undetermined, nil},
		{"a corrupt dependency JAR may define javax/xml/parsers: unopened", withUncached, false, true, "parsers", depreach.Undetermined, nil},
		{"control: every dependency JAR found, so javax/xml/parsers is the JDK's", netkitPom, false, false, "parsers", depreach.NotExploitable, nil},
		{"a dependency JAR nests BOOT-INF/lib/javac-shaded.jar: unopened", netkitPom, false, false, "opt", depreach.Undetermined,
			map[string][]byte{"BOOT-INF/lib/javac-shaded.jar": []byte("PK nested")}},
		{"a dependency JAR's manifest names Class-Path: javac-shaded.jar: unopened", netkitPom, false, false, "opt", depreach.Undetermined,
			map[string][]byte{"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\nClass-Path: javac-shaded.jar\n\n")}},
		{"control: a dependency JAR's manifest has no Class-Path, so Option is the JDK's", netkitPom, false, false, "opt", depreach.NotExploitable,
			map[string][]byte{"META-INF/MANIFEST.MF": []byte("Manifest-Version: 1.0\nCreated-By: test\n\n")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := write(t, tc.pom, tc.mrOption, tc.corrupt, tc.extra)
			deps := []graphDep{{group: "com.evil", artifact: "netkit", version: "1.0.0", jar: netkitJarPath(build)}}
			if tc.pom == withUncached {
				gone := filepath.Join(build, ".m2", "repository", "com", "other", "gone", "1.0.0", "gone-1.0.0.jar")
				deps = append(deps, graphDep{group: "com.other", artifact: "gone", version: "1.0.0", jar: gone})
			}
			dg, err := buildDependencyGraph(build, graphOption(t, "maven", testModule(t, ".", "app", deps...)))
			if err != nil {
				t.Fatalf("buildDependencyGraph: %v", err)
			}
			r := dg.Engine.Reach(classfile.MethodRef{Owner: fetcher, Name: tc.from, Descriptor: "()V"}, sink)
			if r.Verdict != tc.want {
				t.Fatalf("verdict %s, want %s (hazard %q, gaps %v)", r.Verdict, tc.want, r.HazardWhy, dg.Gaps)
			}
		})
	}
}
