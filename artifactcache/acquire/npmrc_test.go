package acquire

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
)

const npmrcSecret = "NPMRC_SECRET_TOKEN_v1_MUSTNOTLEAK"

func envOf(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

func writeNPMRC(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadNPMConfigRouting(t *testing.T) {
	tests := []struct {
		name    string
		project string
		user    string
		env     map[string]string
		pkg     string
		want    string
	}{
		{name: "default registry", pkg: "qs", want: DefaultNPMRegistry},
		{name: "project registry", project: "registry=https://mirror.test/npm", pkg: "qs", want: "https://mirror.test/npm/"},
		{name: "scope registry", project: "@acme:registry=https://npm.acme.test/", pkg: "@acme/lib", want: "https://npm.acme.test/"},
		{name: "scope does not capture others", project: "@acme:registry=https://npm.acme.test/", pkg: "@other/lib", want: DefaultNPMRegistry},
		{name: "project over user config", project: "registry=https://project.test/", user: "registry=https://user.test/", pkg: "qs", want: "https://project.test/"},
		{name: "user config alone", user: "@acme:registry=https://npm.pkg.github.com", pkg: "@acme/lib", want: "https://npm.pkg.github.com/"},
		{name: "env registry over files", project: "registry=https://project.test/", env: map[string]string{"NPM_CONFIG_REGISTRY": "https://env.test/"}, pkg: "qs", want: "https://env.test/"},
		{name: "env expansion", project: "registry=https://${MIRROR_HOST}/", env: map[string]string{"MIRROR_HOST": "m.test"}, pkg: "qs", want: "https://m.test/"},
		{name: "comments and quoting", project: "; c\n# c\nregistry = \"https://q.test/\"\n", pkg: "qs", want: "https://q.test/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			env := map[string]string{}
			for k, v := range tt.env {
				env[k] = v
			}
			if tt.project != "" {
				writeNPMRC(t, dir, tt.project)
			}
			if tt.user != "" {
				p := filepath.Join(t.TempDir(), "user.npmrc")
				if err := os.WriteFile(p, []byte(tt.user), 0o600); err != nil {
					t.Fatal(err)
				}
				env["NPM_CONFIG_USERCONFIG"] = p
			}
			cfg, err := LoadNPMConfig(NPMRCSources{ProjectDir: dir, LookupEnv: envOf(env)})
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.RegistryFor(tt.pkg); got != tt.want {
				t.Fatalf("RegistryFor(%q) = %q, want %q", tt.pkg, got, tt.want)
			}
		})
	}
}

// The token is bound to its own host only, and appears in no string the config or its
// errors produce.
func TestLoadNPMConfigTokenBinding(t *testing.T) {
	dir := t.TempDir()
	writeNPMRC(t, dir, strings.Join([]string{
		"@acme:registry=https://npm.acme.test/",
		"//npm.acme.test/:_authToken=${ACME_TOKEN}",
		"//elsewhere.test/:_authToken=other",
	}, "\n"))
	cfg, err := LoadNPMConfig(NPMRCSources{ProjectDir: dir, LookupEnv: envOf(map[string]string{"ACME_TOKEN": npmrcSecret})})
	if err != nil {
		t.Fatal(err)
	}
	pol := cfg.PolicyFor("@acme/lib", "")
	if pol.Credentials.For("npm.acme.test").IsEmpty() {
		t.Fatal("acme token not bound to npm.acme.test")
	}
	for _, h := range []string{"registry.npmjs.org", "elsewhere.test", "acme.test", "npm.acme.test.evil"} {
		if !pol.Credentials.For(h).IsEmpty() {
			t.Fatalf("a token is bound to %s", h)
		}
	}
	if pol.Allowlist.Allows("elsewhere.test") {
		t.Fatal("a host that only carries a token must not be allowlisted")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if s := fmt.Sprintf(verb, cfg); strings.Contains(s, npmrcSecret) {
			t.Fatalf("config leaked the token under %s", verb)
		}
		if s := fmt.Sprintf(verb, pol); strings.Contains(s, npmrcSecret) {
			t.Fatalf("policy leaked the token under %s", verb)
		}
	}
}

func TestLoadNPMConfigFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		project string
		env     map[string]string
	}{
		{name: "unset env reference", project: "//npm.acme.test/:_authToken=${MISSING_TOKEN}"},
		{name: "not key=value", project: "registry https://x.test/"},
		{name: "section header", project: "[acme]\nregistry=https://x.test/"},
		{name: "registry not a URL", project: "registry=not a url"},
		{name: "registry with userinfo", project: "registry=https://u:" + npmrcSecret + "@x.test/"},
		{name: "unterminated quote", project: "registry=\"https://x.test/"},
		{name: "bad boolean", project: "always-auth=sometimes"},
		{name: "two token paths on one host", project: "//h.test/a/:_authToken=x\n//h.test/b/:_authToken=y"},
		{name: "relative user config", env: map[string]string{"NPM_CONFIG_USERCONFIG": "rel/npmrc"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.project != "" {
				writeNPMRC(t, dir, tt.project)
			}
			_, err := LoadNPMConfig(NPMRCSources{ProjectDir: dir, LookupEnv: envOf(tt.env)})
			if !errors.Is(err, ErrMalformedNPMRC) {
				t.Fatalf("err = %v, want ErrMalformedNPMRC", err)
			}
			if strings.Contains(err.Error(), npmrcSecret) {
				t.Fatal("error leaked a value")
			}
		})
	}
}

// LoadNPMConfig reads the project .npmrc and the NPM_CONFIG_USERCONFIG file, never
// $HOME/.npmrc or a global npmrc.
func TestLoadNPMConfigReadSurface(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeNPMRC(t, home, "registry=https://home.test/\n//home.test/:_authToken="+npmrcSecret)
	project := t.TempDir()
	user := filepath.Join(t.TempDir(), "user.npmrc")
	if err := os.WriteFile(user, []byte("registry=https://user.test/"), 0o600); err != nil {
		t.Fatal(err)
	}

	var reads []string
	src := NPMRCSources{
		ProjectDir: project,
		LookupEnv:  envOf(map[string]string{"NPM_CONFIG_USERCONFIG": user, "HOME": home}),
		readFile: func(name string) ([]byte, error) {
			reads = append(reads, name)
			return os.ReadFile(name)
		},
	}
	cfg, err := LoadNPMConfig(src)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{user, filepath.Join(project, ".npmrc")}
	if fmt.Sprint(reads) != fmt.Sprint(want) {
		t.Fatalf("read %v, want exactly %v", reads, want)
	}
	if cfg.RegistryFor("qs") != "https://user.test/" {
		t.Fatalf("registry = %q", cfg.RegistryFor("qs"))
	}
	if cfg.PolicyFor("qs", "").Allowlist.Allows("home.test") {
		t.Fatal("$HOME/.npmrc was honored")
	}
}

func TestPolicyForAuthAndHints(t *testing.T) {
	dir := t.TempDir()
	writeNPMRC(t, dir, strings.Join([]string{
		"@acme:registry=https://npm.acme.test/",
		"//npm.acme.test/:always-auth=true",
		"@basic:registry=https://basic.test/",
		"//basic.test/:_auth=Zm9vOmJhcg==",
	}, "\n"))
	cfg, err := LoadNPMConfig(NPMRCSources{ProjectDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PolicyFor("@acme/x", "").Registries["npm"].RequireAuth {
		t.Fatal("always-auth host must require auth")
	}
	if !cfg.PolicyFor("@basic/x", "").Registries["npm"].RequireAuth {
		t.Fatal("an auth form this package cannot present must refuse anonymous fetches")
	}
	if cfg.PolicyFor("qs", "").Registries["npm"].RequireAuth {
		t.Fatal("public registry must not require auth")
	}

	ref := artifactcache.Ref{PURL: "pkg:npm/qs@6.5.2", Digest: "sha1:" + strings.Repeat("0", 40)}
	tests := []struct {
		hint, want string
	}{
		{"https://registry.npmjs.org/qs/-/qs-6.5.2.tgz", "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz"},
		{"https://evil.test/qs/-/qs-6.5.2.tgz", "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz"},
		{"http://registry.npmjs.org/qs/-/qs-6.5.2.tgz", "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz"},
		{"https://u:p@registry.npmjs.org/qs.tgz", "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz"},
		{"", "https://registry.npmjs.org/qs/-/qs-6.5.2.tgz"},
	}
	for _, tt := range tests {
		pol := cfg.PolicyFor("qs", tt.hint)
		got, err := pol.Backends["npm"].ResolveURL(ref, pol.Registries["npm"])
		if err != nil || got != tt.want {
			t.Errorf("hint %q: got %q, %v; want %q", tt.hint, got, err, tt.want)
		}
	}
}
