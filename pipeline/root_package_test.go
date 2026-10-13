package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/plugin"
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
			name:     "maven inherits the group from a parent outside the checkout, but not its version",
			language: checkout.LangJava,
			files: map[string]string{"pom.xml": `<project>
  <parent><groupId>org.springframework</groupId><version>5.3.20.RELEASE</version></parent>
  <artifactId>spring-web</artifactId>
</project>`},
			want:   RootPackage{PURLType: "maven", Name: "org.springframework:spring-web"},
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
			name:     "nuget literal version is never established",
			language: checkout.LangDotNet,
			files:    map[string]string{"Newtonsoft.Json.csproj": "<Project><PropertyGroup><PackageId>Newtonsoft.Json</PackageId><Version>13.0.1</Version></PropertyGroup></Project>"},
			want:     RootPackage{PURLType: "nuget", Name: "Newtonsoft.Json"},
			wantOK:   true,
		},
		{
			name:     "gradle settings configuring every project before its script",
			language: checkout.LangJava,
			files: map[string]string{
				"build.gradle":    "group = 'com.example'\nversion = '1.2.3'\n",
				"settings.gradle": "rootProject.name = 'lib'\ngradle.beforeProject { p -> p.version = '2.0.0' }\n",
			},
			want:   RootPackage{PURLType: "maven", Name: "com.example:lib"},
			wantOK: true,
		},
		{
			name:     "gradle settings with an allprojects hook",
			language: checkout.LangJava,
			files: map[string]string{
				"build.gradle":    "group = 'com.example'\nversion = '1.2.3'\n",
				"settings.gradle": "rootProject.name = 'lib'\ngradle.allprojects { version = '2.0.0' }\n",
			},
			want:   RootPackage{PURLType: "maven", Name: "com.example:lib"},
			wantOK: true,
		},
		{
			name:     "gradle version reset with setVersion",
			language: checkout.LangJava,
			files: map[string]string{
				"build.gradle":    "group = 'com.example'\nversion = '1.2.3'\n\ntasks.register('x') {}\nsetVersion('1.2.3-SNAPSHOT')\n",
				"settings.gradle": "rootProject.name = 'lib'\n",
			},
			want:   RootPackage{PURLType: "maven", Name: "com.example:lib"},
			wantOK: true,
		},
		{
			name:     "gradle version set by name",
			language: checkout.LangJava,
			files: map[string]string{
				"build.gradle":    "group = 'com.example'\nversion = '1.2.3'\n\next { set('version', '2.0.0') }\n",
				"settings.gradle": "rootProject.name = 'lib'\n",
			},
			want:   RootPackage{PURLType: "maven", Name: "com.example:lib"},
			wantOK: true,
		},
		{
			name:     "poetry version under poetry-dynamic-versioning",
			language: checkout.LangPython,
			files:    map[string]string{"pyproject.toml": "[tool.poetry]\nname = \"x\"\nversion = \"1.2.3\"\n\n[tool.poetry-dynamic-versioning]\nenable = true\n"},
			want:     RootPackage{PURLType: "pypi", Name: "x"},
			wantOK:   true,
		},
		{
			name:     "poetry version under a versioning build backend",
			language: checkout.LangPython,
			files:    map[string]string{"pyproject.toml": "[build-system]\nrequires = [\"poetry-core\"]\nbuild-backend = \"poetry_dynamic_versioning.backend\"\n\n[tool.poetry]\nname = \"x\"\nversion = \"1.2.3\"\n"},
			want:     RootPackage{PURLType: "pypi", Name: "x"},
			wantOK:   true,
		},
		{
			name:     "hatch version from code, not the version file's text",
			language: checkout.LangPython,
			files: map[string]string{
				"pyproject.toml": "[project]\nname = \"x\"\ndynamic = [\"version\"]\n\n[tool.hatch.version]\nsource = \"code\"\npath = \"x/__init__.py\"\n",
				"x/__init__.py":  "__version__ = \"1.2.3\"\n__version__ += \".dev0\"\n",
			},
			want:   RootPackage{PURLType: "pypi", Name: "x"},
			wantOK: true,
		},
		{
			name:     "hatch version file read with a custom pattern",
			language: checkout.LangPython,
			files: map[string]string{
				"pyproject.toml": "[project]\nname = \"x\"\ndynamic = [\"version\"]\n\n[tool.hatch.version]\npath = \"x/__init__.py\"\npattern = \"VERSION = (?P<version>.+)\"\n",
				"x/__init__.py":  "__version__ = \"1.2.3\"\nVERSION = \"2.0.0\"\n",
			},
			want:   RootPackage{PURLType: "pypi", Name: "x"},
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

// TestGoPathOwner_ModulesOutsideTheRootGoMod: a module another go.mod in the tree declares, or a
// go.work at or above the build directory uses, owns its own paths wherever its directory sits; a
// go.work or go.mod that cannot be read leaves the owner ambiguous.
func TestGoPathOwner_ModulesOutsideTheRootGoMod(t *testing.T) {
	const gomod = "module example.com/x\n\ngo 1.22\n"
	root := RootPackage{PURLType: "golang", Name: "example.com/x", Version: "v3.0.0"}
	cases := []struct {
		name        string
		files       map[string]string
		buildDir    string
		module      string
		want        bool
		wantVersion string
	}{
		{"a go.work member in a directory not mirroring its path", map[string]string{
			"go.mod":                  gomod,
			"go.work":                 "go 1.22\n\nuse (\n\t.\n\t./modules/subthing\n)\n",
			"modules/subthing/go.mod": "module example.com/x/sub\n\ngo 1.22\n",
			"modules/subthing/sub.go": "package sub\n",
		}, "", "example.com/x/sub", false, ""},
		{"a nested module in a directory not mirroring its path", map[string]string{
			"go.mod":                  gomod,
			"modules/subthing/go.mod": "module example.com/x/sub\n\ngo 1.22\n",
		}, "", "example.com/x/sub/pkg", false, ""},
		{"a go.work above the build directory", map[string]string{
			"go.work":    "go 1.22\n\nuse (\n\t./app\n\t./lib\n)\n",
			"app/go.mod": gomod,
			"lib/go.mod": "module example.com/x/lib\n\ngo 1.22\n",
		}, "app", "example.com/x/lib", false, ""},
		{"a go.work that does not parse", map[string]string{
			"go.mod":  gomod,
			"go.work": "go 1.22\n\nuse (\n",
		}, "", "example.com/x/internal", true, ""},
		{"a go.work using a directory with no go.mod", map[string]string{
			"go.mod":  gomod,
			"go.work": "go 1.22\n\nuse (\n\t.\n\t./gone\n)\n",
		}, "", "example.com/x/internal", true, ""},
		{"a nested go.mod declaring no module", map[string]string{
			"go.mod":       gomod,
			"third/go.mod": "go 1.22\n",
		}, "", "example.com/x/internal", true, ""},
		{"a go.work using only the root", map[string]string{
			"go.mod":  gomod,
			"go.work": "go 1.22\n\nuse .\n",
		}, "", "example.com/x/internal", true, "v3.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(writeTree(t, tc.files), filepath.FromSlash(tc.buildDir))
			if v, got := root.Matches(dir, tc.module, "", ""); got != tc.want || v != tc.wantVersion {
				t.Fatalf("Matches = %q, %v; want %q, %v", v, got, tc.wantVersion, tc.want)
			}
		})
	}
}

// TestGradleRootPackage_VersionAllowlist: the version is read only when every statement that runs
// before publishing is on the allowlist: settings holds only rootProject.name, and the root script
// only literal group and version assignments and plain dependencies and repositories blocks.
func TestGradleRootPackage_VersionAllowlist(t *testing.T) {
	const (
		settings = "rootProject.name = 'lib'\n"
		script   = "group = 'com.example'\nversion = '1.2.3'\n"
		stock    = "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.5-bin.zip\n"
	)
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"only the assignments", nil, "1.2.3"},
		{"plain dependencies and repositories blocks", map[string]string{"build.gradle": script + "\nrepositories {\n  mavenCentral()\n}\ndependencies {\n  implementation 'org.slf4j:slf4j-api:2.0.9'\n  testImplementation(\"junit:junit:4.13.2\")\n}\n"}, "1.2.3"},
		{"comments beside the name", map[string]string{"settings.gradle": "// the library\nrootProject.name = 'lib' // its name\n"}, "1.2.3"},
		{"a stock wrapper", map[string]string{"gradle/wrapper/gradle-wrapper.properties": stock}, "1.2.3"},
		{"a stock wrapper with CRLF line endings", map[string]string{"gradle/wrapper/gradle-wrapper.properties": strings.ReplaceAll(stock, "\n", "\r\n")}, "1.2.3"},
		{"settings including a project", map[string]string{"settings.gradle": settings + "include 'sub'\n"}, ""},
		{"settings applying a script", map[string]string{"settings.gradle": settings + "apply from: 'version.gradle'\n"}, ""},
		{"settings with a plugins block", map[string]string{"settings.gradle": "plugins {\n  id 'com.example.versioning' version '1.0'\n}\n" + settings}, ""},
		{"settings with a projectsEvaluated hook", map[string]string{"settings.gradle": settings + "gradle.projectsEvaluated { rootProject.version = '2.0.0' }\n"}, ""},
		{"another top-level statement in the script", map[string]string{"build.gradle": script + "tasks.register('x') {}\n"}, ""},
		{"a dependencies block calling setVersion", map[string]string{"build.gradle": script + "dependencies {\n  setVersion '2.0.0'\n}\n"}, ""},
		{"an interpolated dependency", map[string]string{"build.gradle": script + "dependencies {\n  implementation \"org.slf4j:slf4j-api:$slf4j\"\n}\n"}, ""},
		{"a dependency with a closure", map[string]string{"build.gradle": script + "dependencies {\n  implementation('org.slf4j:slf4j-api:2.0.9') { transitive = false }\n}\n"}, ""},
		{"a repository other than a stock one", map[string]string{"build.gradle": script + "repositories {\n  maven { url 'https://repo.example.com' }\n}\n"}, ""},
		{"a buildSrc", map[string]string{"buildSrc/build.gradle": ""}, ""},
		{"a wrapper fetching a custom distribution", map[string]string{"gradle/wrapper/gradle-wrapper.properties": "distributionUrl=https\\://repo.example.com/gradle-8.5-custom.zip\n"}, ""},
		{"a wrapper naming two distributions", map[string]string{"gradle/wrapper/gradle-wrapper.properties": stock + stock}, ""},
		{"both build scripts", map[string]string{"build.gradle.kts": "group = \"com.example\"\nversion = \"1.2.3\"\n"}, ""},
		{"both settings files", map[string]string{"settings.gradle.kts": "rootProject.name = \"lib\"\n"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{"settings.gradle": settings, "build.gradle": script}
			for k, v := range tc.files {
				files[k] = v
			}
			got, ok := ReadRootPackage(context.Background(), writeTree(t, files), checkout.LangJava)
			if want := (RootPackage{PURLType: "maven", Name: "com.example:lib", Version: tc.want}); !ok || got != want {
				t.Fatalf("got %+v, %v; want %+v", got, ok, want)
			}
		})
	}
}

// TestGradleRootPackage_UnreadableWrapperIsNotStock: wrapper properties that are a FIFO, or a file
// that can't be opened, are refused without waiting on a writer, and the root keeps its name but
// not its version.
func TestGradleRootPackage_UnreadableWrapperIsNotStock(t *testing.T) {
	const stock = "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.5-bin.zip\n"
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, props string)
	}{
		{"a FIFO", func(t *testing.T, props string) {
			if err := syscall.Mkfifo(props, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"stock properties that can't be opened", func(t *testing.T, props string) {
			if os.Geteuid() == 0 {
				t.Skip("root ignores file permissions")
			}
			if err := os.WriteFile(props, []byte(stock), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(props, 0); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"settings.gradle": "rootProject.name = 'lib'\n",
				"build.gradle":    "group = 'com.example'\nversion = '1.2.3'\n",
			})
			props := filepath.Join(dir, "gradle", "wrapper", "gradle-wrapper.properties")
			if err := os.MkdirAll(filepath.Dir(props), 0o755); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, props)
			type result struct {
				pkg RootPackage
				ok  bool
			}
			done := make(chan result, 1)
			go func() {
				pkg, ok := ReadRootPackage(context.Background(), dir, checkout.LangJava)
				done <- result{pkg, ok}
			}()
			select {
			case r := <-done:
				if want := (RootPackage{PURLType: "maven", Name: "com.example:lib"}); !r.ok || r.pkg != want {
					t.Fatalf("got %+v, %v; want %+v", r.pkg, r.ok, want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("ReadRootPackage did not return: the wrapper properties were opened blocking")
			}
		})
	}
}

func TestGradleRootPackage_NameOnlyInACommentPublishesNothing(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"settings.gradle": "// rootProject.name = 'lib'\n",
		"build.gradle":    "group = 'com.example'\nversion = '1.2.3'\n",
	})
	if got, ok := ReadRootPackage(context.Background(), dir, checkout.LangJava); ok {
		t.Fatalf("got %+v, want no root", got)
	}
}

// TestMavenRootPackage_VersionWriters: the version is read only when every writer of it is in the
// checkout: no core extension from .mvn, no Maven wrapper fetching anything but a stock
// distribution, no <extensions> in the POM or any parent, and every parent a POM in the checkout
// whose coordinates match the declared ones.
func TestMavenRootPackage_VersionWriters(t *testing.T) {
	const (
		child     = "<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1.2.3</version></parent><artifactId>a</artifactId></project>"
		parent    = "<project><groupId>g</groupId><artifactId>parent</artifactId><version>1.2.3</version></project>"
		single    = "<project><groupId>g</groupId><artifactId>a</artifactId><version>1.2.3</version></project>"
		mvnwStock = "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.9/apache-maven-3.9.9-bin.zip\n"
	)
	cases := []struct {
		name  string
		files map[string]string
		dir   string
		want  string
	}{
		{"no parent", map[string]string{"pom.xml": single}, "", "1.2.3"},
		{"a parent in the checkout", map[string]string{"pom.xml": parent, "a/pom.xml": child}, "a", "1.2.3"},
		{"a parent at a relativePath directory", map[string]string{"build/parent/pom.xml": parent, "a/pom.xml": strings.Replace(child, "</parent>", "<relativePath>../build/parent</relativePath></parent>", 1)}, "a", "1.2.3"},
		{"an unrelated .mvn/maven.config", map[string]string{"pom.xml": single, ".mvn/maven.config": "-T 4\n"}, "", "1.2.3"},
		{"a parent in the checkout with extensions", map[string]string{"pom.xml": strings.Replace(parent, "</project>", "<build><extensions><extension><groupId>x</groupId><artifactId>y</artifactId><version>1</version></extension></extensions></build></project>", 1), "a/pom.xml": child}, "a", ""},
		{"a grandparent in the checkout with a plugin's extensions", map[string]string{
			"pom.xml":     "<project><groupId>g</groupId><artifactId>top</artifactId><version>1.2.3</version><build><plugins><plugin><artifactId>p</artifactId><extensions>true</extensions></plugin></plugins></build></project>",
			"m/pom.xml":   "<project><parent><groupId>g</groupId><artifactId>top</artifactId><version>1.2.3</version></parent><artifactId>parent</artifactId></project>",
			"m/a/pom.xml": child,
		}, "m/a", ""},
		{"a parent outside the checkout", map[string]string{"a/pom.xml": child}, "a", ""},
		{"a parent the POM takes from a repository", map[string]string{"pom.xml": parent, "a/pom.xml": strings.Replace(child, "</parent>", "<relativePath/></parent>", 1)}, "a", ""},
		{"a parent in the checkout with other coordinates", map[string]string{"pom.xml": strings.Replace(parent, "1.2.3", "1.2.4", 1), "a/pom.xml": child}, "a", ""},
		{"extensions in the POM itself", map[string]string{"pom.xml": strings.Replace(single, "</project>", "<build><extensions/></build></project>", 1)}, "", ""},
		{"a core extension in .mvn/extensions.xml", map[string]string{"pom.xml": single, ".mvn/extensions.xml": "<extensions/>"}, "", ""},
		{"a core extension named in .mvn/maven.config", map[string]string{"pom.xml": single, ".mvn/maven.config": "-Dmaven.ext.class.path=ext.jar\n"}, "", ""},
		{"a core extension named in .mvn/jvm.config", map[string]string{"pom.xml": single, ".mvn/jvm.config": "-Dmaven.ext.class.path=ext.jar\n"}, "", ""},
		{"a core extension in a .mvn above the project", map[string]string{"a/pom.xml": single, ".mvn/extensions.xml": "<extensions/>"}, "a", ""},
		{"a stock Maven wrapper", map[string]string{"pom.xml": single, ".mvn/wrapper/maven-wrapper.properties": mvnwStock}, "", "1.2.3"},
		{"a stock Maven wrapper with CRLF line endings and its JAR", map[string]string{"pom.xml": single, ".mvn/wrapper/maven-wrapper.properties": strings.ReplaceAll("# Licensed to the ASF\nwrapperVersion=3.3.2\n"+mvnwStock+"wrapperUrl=https://repo.maven.apache.org/maven2/org/apache/maven/wrapper/maven-wrapper/3.3.2/maven-wrapper-3.3.2.jar\n", "\n", "\r\n")}, "", "1.2.3"},
		{"a Maven wrapper fetching a custom distribution", map[string]string{"pom.xml": single, ".mvn/wrapper/maven-wrapper.properties": "distributionUrl=https://repo.example.com/apache-maven-3.9.9-custom-bin.zip\n"}, "", ""},
		{"a Maven wrapper fetching a custom wrapper JAR", map[string]string{"pom.xml": single, ".mvn/wrapper/maven-wrapper.properties": mvnwStock + "wrapperUrl=https://repo.example.com/maven-wrapper-3.3.2.jar\n"}, "", ""},
		{"a Maven wrapper naming two distributions", map[string]string{"pom.xml": single, ".mvn/wrapper/maven-wrapper.properties": mvnwStock + "distributionUrl = https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.8.8/apache-maven-3.8.8-bin.zip\n"}, "", ""},
		{"a Maven wrapper with an escaped key", map[string]string{"pom.xml": single, ".mvn/wrapper/maven-wrapper.properties": mvnwStock + "distribution\\Url=https://repo.example.com/apache-maven-3.9.9-bin.zip\n"}, "", ""},
		{"a Maven wrapper with a continued line", map[string]string{"pom.xml": single, ".mvn/wrapper/maven-wrapper.properties": "wrapperVersion=3.3.2\\\n" + mvnwStock}, "", ""},
		{"a Maven wrapper properties file that cannot be read", map[string]string{"pom.xml": single, ".mvn/wrapper/maven-wrapper.properties/x": ""}, "", ""},
		{"a Maven wrapper with no distribution", map[string]string{"pom.xml": single, ".mvn/wrapper/maven-wrapper.properties": "wrapperVersion=3.3.2\n"}, "", ""},
		{"a custom Maven wrapper above a .mvn of the project's own", map[string]string{"a/pom.xml": single, "a/.mvn/maven.config": "-T 4\n", ".mvn/wrapper/maven-wrapper.properties": "distributionUrl=https://repo.example.com/apache-maven-3.9.9-custom-bin.zip\n"}, "a", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, tc.files)
			gitTree(t, dir)
			got, ok := ReadRootPackage(context.Background(), filepath.Join(dir, tc.dir), checkout.LangJava)
			if !ok || got.Version != tc.want {
				t.Fatalf("got %+v, %v; want version %q", got, ok, tc.want)
			}
		})
	}
}

// TestMavenRootPackage_ParentOutsideTheRepository: a parent at ../pom.xml that lies above the
// repository is not in the checkout, even though the file exists.
func TestMavenRootPackage_ParentOutsideTheRepository(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"pom.xml":      "<project><groupId>g</groupId><artifactId>parent</artifactId><version>1.2.3</version></project>",
		"repo/pom.xml": "<project><parent><groupId>g</groupId><artifactId>parent</artifactId><version>1.2.3</version></parent><artifactId>a</artifactId></project>",
	})
	gitTree(t, filepath.Join(dir, "repo"))
	got, ok := ReadRootPackage(context.Background(), filepath.Join(dir, "repo"), checkout.LangJava)
	if !ok || got.Version != "" {
		t.Fatalf("got %+v, %v; want no version", got, ok)
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

// TestGoRootPackage_VersionIsTheModuleTagAtHead: the version is the one full semver tag at HEAD for
// the module. Tags that disagree leave it unknown, since the reader cannot tell which one the build
// publishes.
func TestGoRootPackage_VersionIsTheModuleTagAtHead(t *testing.T) {
	cases := []struct {
		name, dir string
		tags      []string
		want      string
	}{
		{"one version beside a non-version tag", "", []string{"v1.2.0", "nightly"}, "v1.2.0"},
		{"a nested module's prefixed tag", "sub", []string{"v1.2.0", "sub/v0.3.0"}, "v0.3.0"},
		{"two versions", "", []string{"v1.2.0", "v1.10.0"}, ""},
		{"two versions of a nested module", "sub", []string{"sub/v0.3.0", "sub/v0.4.0"}, ""},
		{"a shorthand tag beside its full version", "", []string{"v1.3", "v1.3.0"}, "v1.3.0"},
		{"a shorthand tag alone", "", []string{"v1.3"}, ""},
		{"a tag with build metadata", "", []string{"v1.3.0+meta"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"go.mod":         "module example.com/app\n",
				"sub/go.mod":     "module example.com/app/sub\n",
				"sub/sub.go":     "package sub\n",
				"cmd/app/app.go": "package main\n",
			})
			gitTree(t, dir, tc.tags...)
			if got, _ := ReadRootPackage(context.Background(), filepath.Join(dir, tc.dir), checkout.LangGo); got.Version != tc.want {
				t.Fatalf("version = %q, want %q", got.Version, tc.want)
			}
		})
	}
}

// TestGoRootPackage_TagLookupIgnoresTheGitEnvironment: the tag at HEAD is read from the repository
// holding the build directory, even when the environment points git at another one or stops its
// search short of it.
func TestGoRootPackage_TagLookupIgnoresTheGitEnvironment(t *testing.T) {
	cases := []struct {
		name, variable string
		value          func(other string) string
	}{
		{"GIT_DIR naming another repository", "GIT_DIR", func(other string) string { return filepath.Join(other, ".git") }},
		{"GIT_WORK_TREE naming another work tree", "GIT_WORK_TREE", func(other string) string { return other }},
		{"GIT_CEILING_DIRECTORIES above the build directory", "GIT_CEILING_DIRECTORIES", func(string) string { return "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := map[string]string{"go.mod": "module example.com/app\n", "sub/go.mod": "module example.com/app/sub\n", "sub/sub.go": "package sub\n"}
			dir, other := writeTree(t, tree), writeTree(t, tree)
			gitTree(t, dir, "sub/v0.3.0")
			gitTree(t, other, "sub/v0.9.0")
			value := tc.value(other)
			if value == "" {
				value = dir
			}
			t.Setenv(tc.variable, value)
			if got, _ := ReadRootPackage(context.Background(), filepath.Join(dir, "sub"), checkout.LangGo); got.Version != "v0.3.0" {
				t.Fatalf("version = %q, want v0.3.0", got.Version)
			}
		})
	}
}

// TestGoRootPackage_TagMajorMustMatchThePath: a tag at HEAD is the module's version only when the
// module path allows its major version, so a v2 module tagged v1.5.0 has no established version.
func TestGoRootPackage_TagMajorMustMatchThePath(t *testing.T) {
	cases := []struct {
		name, module string
		tags         []string
		want         string
	}{
		{"a v2 module tagged v1", "example.com/app/v2", []string{"v1.5.0"}, ""},
		{"a v2 module tagged v1 and v2", "example.com/app/v2", []string{"v1.5.0", "v2.1.0"}, "v2.1.0"},
		{"a module without a suffix tagged v2", "example.com/app", []string{"v2.0.0"}, ""},
		{"a module without a suffix tagged v0", "example.com/app", []string{"v0.4.0"}, "v0.4.0"},
		{"a gopkg.in module tagged another major", "gopkg.in/yaml.v3", []string{"v2.4.0"}, ""},
		{"a gopkg.in module tagged its major", "gopkg.in/yaml.v3", []string{"v3.0.1"}, "v3.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"go.mod": "module " + tc.module + "\n"})
			gitTree(t, dir, tc.tags...)
			if got, _ := ReadRootPackage(context.Background(), dir, checkout.LangGo); got.Version != tc.want {
				t.Fatalf("version = %q, want %q", got.Version, tc.want)
			}
		})
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
		plug        plugin.LanguagePlugin
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
		{
			name:  "pypi root with no established version is not ruled out by its own lockfile",
			files: map[string]string{"setup.cfg": "[metadata]\nname = flask\nversion = attr: flask.__version__\n", "requirements.txt": "click==8.1.0\n", "flask/__init__.py": "__version__ = '3.0.0'\n"},
			facts: AdvisoryFacts{Coordinate: "flask", PURL: "pkg:pypi/flask"},
			plug:  membershipStub{lang: "python", exhaustive: true},
		},
		{
			name:  "npm root with no version is not ruled out by its own lockfile",
			files: map[string]string{"package.json": `{"name":"next","dependencies":{"left-pad":"1.3.0"}}`, "index.js": "module.exports = 1\n"},
			facts: AdvisoryFacts{Coordinate: "next", PURL: "pkg:npm/next"},
			plug:  membershipStub{lang: "js", exhaustive: true},
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
			if err := (codebaseInventory{src: src, plugin: tc.plug}).Run(context.Background(), c, store); err != nil {
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
