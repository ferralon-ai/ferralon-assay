package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestReadRootPackage(t *testing.T) {
	cases := []struct {
		name     string
		language string
		files    map[string]string
		want     RootPackage
		wantOK   bool
	}{
		{
			name:     "go module, untagged",
			language: checkout.LangGo,
			files:    map[string]string{"go.mod": "module github.com/grafana/grafana\n\ngo 1.22\n"},
			want:     RootPackage{PURLType: "golang", Name: "github.com/grafana/grafana"},
			wantOK:   true,
		},
		{
			name:     "npm package",
			language: checkout.LangJS,
			files:    map[string]string{"package.json": `{"name":"next","version":"14.1.0"}`},
			want:     RootPackage{PURLType: "npm", Name: "next", Version: "14.1.0"},
			wantOK:   true,
		},
		{
			name:     "private npm package publishes nothing",
			language: checkout.LangJS,
			files:    map[string]string{"package.json": `{"name":"next","version":"14.1.0","private":true}`},
		},
		{
			name:     "pyproject with a literal version",
			language: checkout.LangPython,
			files:    map[string]string{"pyproject.toml": "[project]\nname = \"PyYAML\"\nversion = \"6.0.1\"\n"},
			want:     RootPackage{PURLType: "pypi", Name: "PyYAML", Version: "6.0.1"},
			wantOK:   true,
		},
		{
			name:     "pyproject with a hatch version file",
			language: checkout.LangPython,
			files: map[string]string{
				"pyproject.toml":      "[project]\nname = \"apache-airflow\"\ndynamic = [\"version\"]\n\n[tool.hatch.version]\npath = \"airflow/__init__.py\"\n",
				"airflow/__init__.py": "__version__ = \"2.9.0\"\n",
			},
			want:   RootPackage{PURLType: "pypi", Name: "apache-airflow", Version: "2.9.0"},
			wantOK: true,
		},
		{
			name:     "hatch version path outside the project is not read",
			language: checkout.LangPython,
			files:    map[string]string{"pyproject.toml": "[project]\nname = \"x\"\ndynamic = [\"version\"]\n\n[tool.hatch.version]\npath = \"../secret.py\"\n"},
			want:     RootPackage{PURLType: "pypi", Name: "x"},
			wantOK:   true,
		},
		{
			name:     "poetry",
			language: checkout.LangPython,
			files:    map[string]string{"pyproject.toml": "[tool.poetry]\nname = \"requests\"\nversion = \"2.31.0\"\n"},
			want:     RootPackage{PURLType: "pypi", Name: "requests", Version: "2.31.0"},
			wantOK:   true,
		},
		{
			name:     "setup.cfg with an attr version",
			language: checkout.LangPython,
			files:    map[string]string{"setup.cfg": "[metadata]\nname = flask\nversion = attr: flask.__version__\n"},
			want:     RootPackage{PURLType: "pypi", Name: "flask"},
			wantOK:   true,
		},
		{
			name:     "maven inherits group and version from the parent",
			language: checkout.LangJava,
			files: map[string]string{"pom.xml": `<project>
  <parent><groupId>org.springframework</groupId><version>5.3.20.RELEASE</version></parent>
  <artifactId>spring-web</artifactId>
</project>`},
			want:   RootPackage{PURLType: "maven", Name: "org.springframework:spring-web", Version: "5.3.20.RELEASE"},
			wantOK: true,
		},
		{
			name:     "maven version given by a property is not established",
			language: checkout.LangJava,
			files: map[string]string{"pom.xml": `<project>
  <groupId>org.springframework</groupId><artifactId>spring-web</artifactId>
  <version>${revision}</version>
  <properties><revision>6.1.2</revision></properties>
</project>`},
			want:   RootPackage{PURLType: "maven", Name: "org.springframework:spring-web"},
			wantOK: true,
		},
		{
			name:     "jenkins incrementals placeholder is not established",
			language: checkout.LangJava,
			files: map[string]string{"pom.xml": `<project>
  <parent><groupId>org.jenkins-ci.plugins</groupId><artifactId>plugin</artifactId><version>4.80</version></parent>
  <groupId>io.jenkins.plugins</groupId><artifactId>credentials</artifactId>
  <version>${changelist}</version>
  <properties><changelist>999999-SNAPSHOT</changelist></properties>
</project>`},
			want:   RootPackage{PURLType: "maven", Name: "io.jenkins.plugins:credentials"},
			wantOK: true,
		},
		{
			name:     "maven snapshot is not established",
			language: checkout.LangJava,
			files:    map[string]string{"pom.xml": `<project><groupId>g</groupId><artifactId>a</artifactId><version>2.5.1-SNAPSHOT</version></project>`},
			want:     RootPackage{PURLType: "maven", Name: "g:a"},
			wantOK:   true,
		},
		{
			name:     "maven version left as an unresolved property",
			language: checkout.LangJava,
			files:    map[string]string{"pom.xml": `<project><groupId>g</groupId><artifactId>a</artifactId><version>${missing}</version></project>`},
			want:     RootPackage{PURLType: "maven", Name: "g:a"},
			wantOK:   true,
		},
		{
			name:     "gradle",
			language: checkout.LangKotlin,
			files: map[string]string{
				"settings.gradle.kts": "rootProject.name = \"ktor-server\"\n",
				"build.gradle.kts":    "group = \"io.ktor\"\nversion = \"2.3.0\"\n",
			},
			want:   RootPackage{PURLType: "maven", Name: "io.ktor:ktor-server", Version: "2.3.0"},
			wantOK: true,
		},
		{
			name:     "gradle version set inside another block is not the project's",
			language: checkout.LangKotlin,
			files: map[string]string{
				"settings.gradle": "rootProject.name = 'web'\n",
				"build.gradle":    "group = 'com.example'\n\nnode {\n  version = '18.17.0'\n}\n",
			},
			want:   RootPackage{PURLType: "maven", Name: "com.example:web"},
			wantOK: true,
		},
		{
			name:     "gradle plugins block can set the version",
			language: checkout.LangKotlin,
			files: map[string]string{
				"settings.gradle.kts": "rootProject.name = \"web\"\n",
				"build.gradle.kts":    "plugins {\n  id(\"nebula.release\")\n}\n\ngroup = \"com.example\"\nversion = \"2.3.0\"\n",
			},
			want:   RootPackage{PURLType: "maven", Name: "com.example:web"},
			wantOK: true,
		},
		{
			name:     "gradle allprojects block can set the version",
			language: checkout.LangKotlin,
			files: map[string]string{
				"settings.gradle": "rootProject.name = 'web'\n",
				"build.gradle":    "group = 'com.example'\nversion = '2.3.0'\n\nallprojects {\n  repositories { mavenCentral() }\n}\n",
			},
			want:   RootPackage{PURLType: "maven", Name: "com.example:web"},
			wantOK: true,
		},
		{
			name:     "gradle version reassigned later is not established",
			language: checkout.LangKotlin,
			files: map[string]string{
				"settings.gradle": "rootProject.name = 'web'\n",
				"build.gradle":    "group = 'com.example'\nversion = '2.3.0'\nproject.version = '2.4.0'\n",
			},
			want:   RootPackage{PURLType: "maven", Name: "com.example:web"},
			wantOK: true,
		},
		{
			name:     "gradle interpolated version is not established",
			language: checkout.LangKotlin,
			files: map[string]string{
				"settings.gradle": "rootProject.name = 'web'\n",
				"build.gradle":    "group = 'com.example'\nversion = \"2.3.${patch}\"\n",
			},
			want:   RootPackage{PURLType: "maven", Name: "com.example:web"},
			wantOK: true,
		},
		{
			name:     "gradle task group is not the project group",
			language: checkout.LangKotlin,
			files: map[string]string{
				"settings.gradle": "rootProject.name = 'web'\n",
				"build.gradle":    "version = '2.3.0'\n\ntasks.register('lint') {\n  group = 'verification'\n}\n",
			},
		},
		{
			name:     "gradle with no project name publishes nothing",
			language: checkout.LangKotlin,
			files:    map[string]string{"build.gradle": "group = 'com.example'\nversion = '2.3.0'\n"},
		},
		{
			name:     "gradle with no group publishes nothing",
			language: checkout.LangKotlin,
			files:    map[string]string{"build.gradle.kts": "version = \"1.0\"\n"},
		},
		{
			name:     "npm placeholder version is not established",
			language: checkout.LangJS,
			files:    map[string]string{"package.json": `{"name":"next","version":"0.0.0-development"}`},
			want:     RootPackage{PURLType: "npm", Name: "next"},
			wantOK:   true,
		},
		{
			name:     "npm all-zero version is not established",
			language: checkout.LangJS,
			files:    map[string]string{"package.json": `{"name":"next","version":"0.0.0"}`},
			want:     RootPackage{PURLType: "npm", Name: "next"},
			wantOK:   true,
		},
		{
			name:     "pypi development version is not established",
			language: checkout.LangPython,
			files:    map[string]string{"pyproject.toml": "[project]\nname = \"PyYAML\"\nversion = \"6.0.2.dev0\"\n"},
			want:     RootPackage{PURLType: "pypi", Name: "PyYAML"},
			wantOK:   true,
		},
		{
			name:     "hatch version file assigning the version twice",
			language: checkout.LangPython,
			files: map[string]string{
				"pyproject.toml": "[project]\nname = \"x\"\ndynamic = [\"version\"]\n\n[tool.hatch.version]\npath = \"x/__init__.py\"\n",
				"x/__init__.py":  "__version__ = \"1.0.0\"\ntry:\n    from ._v import v\nexcept ImportError:\n    pass\n__version__ = \"1.0.1\"\n",
			},
			want:   RootPackage{PURLType: "pypi", Name: "x"},
			wantOK: true,
		},
		{
			name:     "setup.cfg version beside a setup.py",
			language: checkout.LangPython,
			files: map[string]string{
				"setup.cfg": "[metadata]\nname = flask\nversion = 3.0.0\n",
				"setup.py":  "from setuptools import setup\nsetup(version=compute())\n",
			},
			want:   RootPackage{PURLType: "pypi", Name: "flask"},
			wantOK: true,
		},
		{
			name:     "nuget package id",
			language: checkout.LangDotNet,
			files:    map[string]string{"Newtonsoft.Json.csproj": "<Project><PropertyGroup><PackageId>Newtonsoft.Json</PackageId><VersionPrefix>13.0.1</VersionPrefix></PropertyGroup></Project>"},
			want:     RootPackage{PURLType: "nuget", Name: "Newtonsoft.Json", Version: "13.0.1"},
			wantOK:   true,
		},
		{
			name:     "nuget version suffix makes a pre-release",
			language: checkout.LangDotNet,
			files:    map[string]string{"N.csproj": "<Project><PropertyGroup><PackageId>N</PackageId><VersionPrefix>13.0.1</VersionPrefix><VersionSuffix>beta1</VersionSuffix></PropertyGroup></Project>"},
			want:     RootPackage{PURLType: "nuget", Name: "N"},
			wantOK:   true,
		},
		{
			name:     "nuget conditional version",
			language: checkout.LangDotNet,
			files:    map[string]string{"N.csproj": "<Project><PropertyGroup><PackageId>N</PackageId><Version Condition=\"'$(CI)' == 'true'\">13.0.1</Version></PropertyGroup></Project>"},
			want:     RootPackage{PURLType: "nuget", Name: "N"},
			wantOK:   true,
		},
		{
			name:     "nuget version a Directory.Build.targets can override",
			language: checkout.LangDotNet,
			files: map[string]string{
				"N.csproj":                "<Project><PropertyGroup><PackageId>N</PackageId><Version>13.0.1</Version></PropertyGroup></Project>",
				"Directory.Build.targets": "<Project/>",
			},
			want:   RootPackage{PURLType: "nuget", Name: "N"},
			wantOK: true,
		},
		{
			name:     "several projects have no single root",
			language: checkout.LangDotNet,
			files:    map[string]string{"A.csproj": "<Project/>", "B.csproj": "<Project/>"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, tc.files)
			got, ok := ReadRootPackage(context.Background(), dir, tc.language)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("got %+v, %v; want %+v, %v", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestRootPackage_Matches(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":            "module example.com/app\n\ngo 1.22\n\nrequire example.com/app/dep v1.2.0\n\nreplace example.com/app/fork => ../fork\n",
		"go.sum":            "example.com/app/dep v1.2.0 h1:x=\nexample.com/app/old v0.1.0/go.mod h1:y=\n",
		"tools/gen/go.mod":  "module example.com/app/tools/gen\n",
		"internal/x/x.go":   "package x\n",
		"tools/gen/main.go": "package main\n",
	})
	gomod := RootPackage{PURLType: "golang", Name: "example.com/app", Version: "v3.0.0"}
	pypi := RootPackage{PURLType: "pypi", Name: "apache-airflow", Version: "2.9.0"}
	cases := []struct {
		name                    string
		root                    RootPackage
		module, coordinate, url string
		want                    bool
		wantVersion             string
	}{
		{"go module itself", gomod, "example.com/app", "", "", true, "v3.0.0"},
		{"go package inside the module", gomod, "example.com/app/internal/x", "", "", true, "v3.0.0"},
		{"go nested module", gomod, "example.com/app/tools/gen", "", "", false, ""},
		{"go package of a nested module", gomod, "example.com/app/tools/gen/sub", "", "", false, ""},
		{"go major version module", gomod, "example.com/app/v2", "", "", false, ""},
		{"go path sharing a prefix", gomod, "example.com/application", "", "", false, ""},
		{"go module required under the root path", gomod, "example.com/app/dep", "", "", false, ""},
		{"go package of a module required under the root path", gomod, "example.com/app/dep/sub", "", "", false, ""},
		{"go module replaced under the root path", gomod, "example.com/app/fork", "", "", false, ""},
		{"go module only go.sum records is ambiguous", gomod, "example.com/app/old/pkg", "", "", true, ""},
		{"pypi normalized name", pypi, "", "Apache_Airflow", "pkg:pypi/apache-airflow", true, "2.9.0"},
		{"another ecosystem", pypi, "", "apache-airflow", "pkg:npm/apache-airflow", false, ""},
		{"another package", pypi, "", "apache-airflow-providers-http", "", false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if v, got := tc.root.Matches(dir, tc.module, tc.coordinate, tc.url); got != tc.want || v != tc.wantVersion {
				t.Fatalf("Matches = %q, %v; want %q, %v", v, got, tc.wantVersion, tc.want)
			}
		})
	}
}

// gitTree commits dir and tags HEAD with tags. Identity is passed per command; no config is written.
func gitTree(t *testing.T, dir string, tags ...string) {
	t.Helper()
	if !checkout.GitAvailable() {
		t.Skip("git not available")
	}
	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("add", "-A")
	run("commit", "-q", "-m", "init")
	for _, tag := range tags {
		run("tag", tag)
	}
}

func TestGoRootPackage_VersionIsTheModuleTagAtHead(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"go.mod":         "module example.com/app\n",
		"sub/go.mod":     "module example.com/app/sub\n",
		"sub/sub.go":     "package sub\n",
		"cmd/app/app.go": "package main\n",
	})
	gitTree(t, dir, "v1.2.0", "v1.10.0", "sub/v0.3.0", "nightly")

	if got, _ := ReadRootPackage(context.Background(), dir, checkout.LangGo); got.Version != "v1.10.0" {
		t.Fatalf("root module version = %q, want v1.10.0", got.Version)
	}
	if got, _ := ReadRootPackage(context.Background(), filepath.Join(dir, "sub"), checkout.LangGo); got.Version != "v0.3.0" {
		t.Fatalf("nested module version = %q, want v0.3.0", got.Version)
	}
}

type rootAdvisorySource struct{ facts AdvisoryFacts }

func (s rootAdvisorySource) Lookup(string) (AdvisoryFacts, bool) { return s.facts, true }

// TestCodebaseInventory_AdjudicatesTheRootPackage: an advisory against the scanned project itself
// resolves to the project's own version, is marked root, and is not disqualified as absent from
// the manifest.
func TestCodebaseInventory_AdjudicatesTheRootPackage(t *testing.T) {
	cases := []struct {
		name        string
		files       map[string]string
		tags        []string
		facts       AdvisoryFacts
		wantVersion string
	}{
		{
			name:        "go advisory keyed at a package path",
			files:       map[string]string{"go.mod": "module example.com/app\n\ngo 1.22\n", "internal/x/x.go": "package x\n"},
			tags:        []string{"v1.4.0"},
			facts:       AdvisoryFacts{Module: "example.com/app/internal/x", PURL: "pkg:golang/example.com/app/internal/x"},
			wantVersion: "v1.4.0",
		},
		{
			name:  "go package whose module the root cannot be told apart from",
			files: map[string]string{"go.mod": "module example.com/app\n\ngo 1.22\n", "go.sum": "example.com/app/old v0.1.0/go.mod h1:y=\n", "main.go": "package main\n"},
			tags:  []string{"v1.4.0"},
			facts: AdvisoryFacts{Module: "example.com/app/old/pkg", PURL: "pkg:golang/example.com/app/old/pkg"},
		},
		{
			name:  "go module with no tag",
			files: map[string]string{"go.mod": "module example.com/app\n\ngo 1.22\n", "main.go": "package main\n"},
			facts: AdvisoryFacts{Module: "example.com/app", PURL: "pkg:golang/example.com/app"},
		},
		{
			name:        "npm",
			files:       map[string]string{"package.json": `{"name":"next","version":"14.1.0"}`, "index.js": "module.exports = 1\n"},
			facts:       AdvisoryFacts{Coordinate: "next", PURL: "pkg:npm/next"},
			wantVersion: "14.1.0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, tc.files)
			if tc.tags != nil {
				gitTree(t, dir, tc.tags...)
			}
			store := artifact.NewMemStore()
			c := &assessment.Assessment{ID: "case-root", Request: assessment.Request{
				Vulnerability: assessment.VulnRef{ID: "GHSA-root", Source: "corpus"},
				Codebase: assessment.CodebaseRef{
					Repo:        "acme/app",
					Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: dir},
				},
			}}
			src := rootAdvisorySource{facts: tc.facts}
			if err := (advisoryIntake{src: src}).Run(context.Background(), c, store); err != nil {
				t.Fatalf("advisory_intake: %v", err)
			}
			if err := (codebaseInventory{src: src}).Run(context.Background(), c, store); err != nil {
				t.Fatalf("codebase_inventory: %v", err)
			}
			arts, err := store.Query(c.ID, artifact.TypeInventory)
			if err != nil || len(arts) == 0 {
				t.Fatalf("no inventory artifact: %v", err)
			}
			var inv struct {
				ResolvedVersion string `json:"resolved_version"`
			}
			if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
				t.Fatal(err)
			}
			if !RootSubject(store, c.ID) || inv.ResolvedVersion != tc.wantVersion {
				t.Fatalf("root=%v version=%q, want root at %q", RootSubject(store, c.ID), inv.ResolvedVersion, tc.wantVersion)
			}
			if res := runDisqual(t, store, c.ID); res.Disqualified {
				t.Fatalf("root advisory disqualified: %+v", res)
			}
		})
	}
}
