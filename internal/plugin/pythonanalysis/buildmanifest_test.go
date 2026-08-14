package pythonanalysis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// writeFiles materialises a map of relative path → contents under a fresh temp dir and
// returns the dir. It is the fixture builder for the BuildManifest outcome tests.
func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(p), err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	return dir
}

// fullFixture declares every build-context input from a SINGLE source per field, so the C2
// control (remove requires-python) has exactly one field to remove to make the interpreter
// version undeterminable. requires-python is an exact "==" pin so Toolchain derives from it
// (no competing .python-version); uv.lock deliberately carries NO top-level requires-python,
// so the pyproject value is the only interpreter-version source.
func fullFixture() map[string]string {
	return map[string]string{
		"pyproject.toml": `[project]
name = "demo"
requires-python = "==3.11.4"
dependencies = ["jinja2==3.1.2"]

[project.optional-dependencies]
dev = ["pytest==7.4.0"]
test = ["coverage==7.3.0"]

[tool.uv]
environments = ["sys_platform == 'linux' and platform_machine == 'x86_64'"]
`,
		"uv.lock": `version = 1
revision = 3

[[package]]
name = "jinja2"
version = "3.1.2"
source = { registry = "https://pypi.org/simple" }
`,
		"constraints.txt": "jinja2==3.1.2\n",
	}
}

func TestBuildManifest_FullDeclarationIsComplete(t *testing.T) {
	dir := writeFiles(t, fullFixture())

	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}

	if !res.Partiality.Complete {
		t.Fatalf("want Complete manifest, got partial: %v", res.Partiality.Reasons)
	}
	// Every ecosystem-neutral field populated from declared metadata.
	if got, want := res.Runtime.Name, "python"; got != want {
		t.Errorf("Runtime.Name = %q, want %q", got, want)
	}
	if got, want := res.Runtime.Version, "==3.11.4"; got != want {
		t.Errorf("Runtime.Version = %q, want %q", got, want)
	}
	if got, want := res.Runtime.Toolchain, "3.11.4"; got != want {
		t.Errorf("Runtime.Toolchain = %q, want %q", got, want)
	}
	if got, want := res.Target, "linux/x86_64"; got != want {
		t.Errorf("Target = %q, want %q", got, want)
	}
	if !strings.Contains(res.Configuration, "extras=[dev,test]") {
		t.Errorf("Configuration = %q, want extras=[dev,test]", res.Configuration)
	}
	if !strings.Contains(res.Configuration, "constraints=[constraints.txt]") {
		t.Errorf("Configuration = %q, want constraints=[constraints.txt]", res.Configuration)
	}
	if got, want := res.ProjectRoot, dir; got != want {
		t.Errorf("ProjectRoot = %q, want %q", got, want)
	}
	if got, want := res.Resolver.Name, "uv"; got != want {
		t.Errorf("Resolver.Name = %q, want %q", got, want)
	}
	if got, want := res.Resolver.Command, "uv lock"; got != want {
		t.Errorf("Resolver.Command = %q, want %q", got, want)
	}
}

func TestBuildManifest_PartialNamesMissingInput(t *testing.T) {
	// No requires-python anywhere (pyproject omits it, uv.lock has no top-level
	// requires-python, no .python-version): the interpreter version is undeterminable.
	dir := writeFiles(t, map[string]string{
		"pyproject.toml": `[project]
name = "demo"
dependencies = ["jinja2==3.1.2"]
`,
		"uv.lock": `version = 1
revision = 3

[[package]]
name = "jinja2"
version = "3.1.2"
source = { registry = "https://pypi.org/simple" }
`,
	})

	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}

	if res.Partiality.Complete {
		t.Fatal("want partial manifest, got complete")
	}
	// The reason must NAME the missing input, not merely flag partiality.
	if !hasReasonContaining(res.Partiality.Reasons, "requires_python") {
		t.Errorf("partial reason %v does not name the missing requires_python input", res.Partiality.Reasons)
	}
	if !hasReasonContaining(res.Partiality.Reasons, plugin.PartialReasonEnvConditionUnresolved) {
		t.Errorf("partial reason %v is not rooted in the shared env_condition_unresolved code", res.Partiality.Reasons)
	}
	// Never a guessed interpreter version.
	if res.Runtime.Version != "" {
		t.Errorf("Runtime.Version = %q, want empty (undeterminable, never guessed)", res.Runtime.Version)
	}
	// A partial manifest still carries what IS declared (the resolver was detected).
	if res.Resolver.Name != "uv" {
		t.Errorf("Resolver.Name = %q, want uv", res.Resolver.Name)
	}
}

// TestBuildManifest_ControlRemovingRequiresPythonMovesToPartial is the C2 control: take the
// complete fixture, remove the SINGLE declared field that carries the interpreter version,
// and confirm the manifest moves to partial-with-reason rather than silently defaulting.
func TestBuildManifest_ControlRemovingRequiresPythonMovesToPartial(t *testing.T) {
	files := fullFixture()
	// Remove ONLY requires-python from the pyproject; every other declared field stays.
	files["pyproject.toml"] = strings.ReplaceAll(files["pyproject.toml"], "requires-python = \"==3.11.4\"\n", "")
	if strings.Contains(files["pyproject.toml"], "requires-python") {
		t.Fatal("control setup failed: requires-python still present in pyproject")
	}
	dir := writeFiles(t, files)

	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}

	if res.Partiality.Complete {
		t.Fatal("control: removing requires-python left the manifest complete (silent default)")
	}
	if !hasReasonContaining(res.Partiality.Reasons, "requires_python") {
		t.Errorf("control: partial reason %v does not name requires_python", res.Partiality.Reasons)
	}
	if res.Runtime.Version != "" {
		t.Errorf("control: Runtime.Version = %q, want empty (no silent default)", res.Runtime.Version)
	}
	// The other declared fields remain populated — only the interpreter version dropped.
	if res.Target != "linux/x86_64" {
		t.Errorf("control: Target = %q, want linux/x86_64 (unrelated field must survive)", res.Target)
	}
	if res.Resolver.Name != "uv" {
		t.Errorf("control: Resolver.Name = %q, want uv", res.Resolver.Name)
	}
}

// TestBuildManifest_LockfileRequiresPythonFallback documents the "lockfile environment
// metadata" source named in C2 outcome (b): with no pyproject requires-python, a uv.lock
// top-level requires-python still determines the interpreter version → complete.
func TestBuildManifest_LockfileRequiresPythonFallback(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"pyproject.toml": `[project]
name = "demo"
dependencies = ["jinja2==3.1.2"]
`,
		"uv.lock": `version = 1
revision = 3
requires-python = ">=3.9"

[[package]]
name = "jinja2"
version = "3.1.2"
source = { registry = "https://pypi.org/simple" }
`,
	})

	res, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("BuildManifest: %v", err)
	}
	if !res.Partiality.Complete {
		t.Fatalf("want complete via lockfile requires-python fallback, got partial: %v", res.Partiality.Reasons)
	}
	if got, want := res.Runtime.Version, ">=3.9"; got != want {
		t.Errorf("Runtime.Version = %q, want %q (from uv.lock)", got, want)
	}
	// A range requires-python is not a toolchain pin.
	if res.Runtime.Toolchain != "" {
		t.Errorf("Runtime.Toolchain = %q, want empty (range, not an exact pin)", res.Runtime.Toolchain)
	}
}

func TestBuildManifest_MissingBuildDirIsHardError(t *testing.T) {
	_, err := BuildManifest(context.Background(), plugin.BuildManifestRequest{BuildDir: filepath.Join(t.TempDir(), "nope")})
	if err == nil {
		t.Fatal("want hard error for a missing build dir (inv.4), got nil")
	}
}

func TestBuildManifest_ResolverPriority(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]string
		wantName string
		wantCmd  string
	}{
		{"pdm beats pyproject", map[string]string{"pyproject.toml": "[project]\nname=\"d\"\n", "pdm.lock": "[[package]]\n"}, "pdm", "pdm lock"},
		{"uv beats pyproject", map[string]string{"pyproject.toml": "[project]\nname=\"d\"\n", "uv.lock": "version = 1\n"}, "uv", "uv lock"},
		{"poetry", map[string]string{"poetry.lock": "[[package]]\n"}, "poetry", "poetry lock"},
		{"pipenv", map[string]string{"Pipfile.lock": "{}\n"}, "pipenv", "pipenv lock"},
		{"pyproject only", map[string]string{"pyproject.toml": "[project]\nname=\"d\"\n"}, "pip", "pip install ."},
		{"requirements only", map[string]string{"requirements.txt": "jinja2==3.1.2\n"}, "pip", "pip install -r requirements.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeFiles(t, tt.files)
			got := detectResolver(dir)
			if got.Name != tt.wantName || got.Command != tt.wantCmd {
				t.Errorf("detectResolver = {%q,%q}, want {%q,%q}", got.Name, got.Command, tt.wantName, tt.wantCmd)
			}
		})
	}
}

func hasReasonContaining(reasons []string, sub string) bool {
	for _, r := range reasons {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}
