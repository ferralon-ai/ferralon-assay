package acquire

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
		allow   []string
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
		{name: "env expansion in the user config", user: "registry=https://${MIRROR_HOST}/", env: map[string]string{"MIRROR_HOST": "m.test"}, allow: []string{"MIRROR_HOST"}, pkg: "qs", want: "https://m.test/"},
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
			cfg, err := LoadNPMConfig(NPMRCSources{ProjectDir: dir, LookupEnv: envOf(env), AllowEnv: tt.allow})
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
		"//npm.acme.test/:_authToken=${NODE_AUTH_TOKEN}",
		"//elsewhere.test/:_authToken=other",
	}, "\n"))
	cfg, err := LoadNPMConfig(NPMRCSources{ProjectDir: dir, LookupEnv: envOf(map[string]string{"NODE_AUTH_TOKEN": npmrcSecret})})
	if err != nil {
		t.Fatal(err)
	}
	pol := cfg.PolicyFor("@acme/lib")
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
		{name: "env reference to a variable outside the allowlist", project: "//registry.npmjs.org/:_authToken=${GITHUB_TOKEN}", env: map[string]string{"GITHUB_TOKEN": npmrcSecret}},
		{name: "env reference in the project registry URL", project: "registry=https://r.test/x/${NPM_TOKEN}/", env: map[string]string{"NPM_TOKEN": npmrcSecret}},
		{name: "env reference in a project scope registry URL", project: "@acme:registry=https://${NPM_TOKEN}.test/", env: map[string]string{"NPM_TOKEN": "acme"}},
		{name: "env reference in a project per-host key", project: "//${NPM_TOKEN}/:_authToken=x", env: map[string]string{"NPM_TOKEN": "r.test"}},
		{name: "unset allowlisted token beside an unset reference outside the allowlist", project: "//npm.acme.test/:_authToken=${NODE_AUTH_TOKEN}${MISSING_TOKEN}"},
		{name: "unset allowlisted reference in a value that is not a credential", project: "always-auth=${NPM_TOKEN}"},
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
	realProject, err := filepath.EvalSymlinks(project)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{user, filepath.Join(realProject, ".npmrc")}
	if fmt.Sprint(reads) != fmt.Sprint(want) {
		t.Fatalf("read %v, want exactly %v", reads, want)
	}
	if cfg.RegistryFor("qs") != "https://user.test/" {
		t.Fatalf("registry = %q", cfg.RegistryFor("qs"))
	}
	if cfg.PolicyFor("qs").Allowlist.Allows("home.test") {
		t.Fatal("$HOME/.npmrc was honored")
	}
}

func TestPolicyForRequireAuth(t *testing.T) {
	tests := []struct {
		name       string
		project    string
		pkg        string
		env        map[string]string
		want       bool
		configured bool
	}{
		{name: "always-auth host", project: "@acme:registry=https://npm.acme.test/\n//npm.acme.test/:always-auth=true", pkg: "@acme/x", want: true, configured: true},
		{name: "auth form this package cannot present", project: "@basic:registry=https://basic.test/\n//basic.test/:_auth=Zm9vOmJhcg==", pkg: "@basic/x", want: true, configured: true},
		{name: "empty per-host token", project: "@acme:registry=https://npm.acme.test/\n//npm.acme.test/:_authToken=", pkg: "@acme/x", want: true, configured: true},
		{name: "optional token reference left empty fetches anonymously", project: "@acme:registry=https://npm.acme.test/\n//npm.acme.test/:_authToken=${NODE_AUTH_TOKEN?}", pkg: "@acme/x", configured: true},
		{name: "optional basic auth left empty fetches anonymously", project: "@basic:registry=https://basic.test/\n//basic.test/:_auth=${NPM_TOKEN?}", pkg: "@basic/x", configured: true},
		{name: "top-level auth on the default registry", project: "_authToken=x", pkg: "qs", want: true, configured: true},
		{name: "top-level auth on a configured default registry", project: "registry=https://mirror.test/\n_auth=Zm9vOmJhcg==", pkg: "qs", want: true, configured: true},
		{name: "top-level optional token left empty fetches anonymously", project: "_authToken=${NPM_TOKEN?}", pkg: "qs", configured: true},
		{name: "top-level always-auth on the default registry", project: "always-auth=true", pkg: "qs", want: true, configured: true},
		{name: "top-level always-auth reaches a scope registry", project: "always-auth=true\n@acme:registry=https://npm.acme.test/", pkg: "@acme/x", want: true, configured: true},
		{name: "per-host username and password", project: "@acme:registry=https://npm.acme.test/\n//npm.acme.test/:username=u\n//npm.acme.test/:_password=cA==", pkg: "@acme/x", want: true, configured: true},
		{name: "per-host client certificate", project: "@acme:registry=https://npm.acme.test/\n//npm.acme.test/:certfile=/c.pem\n//npm.acme.test/:keyfile=/k.pem", pkg: "@acme/x", want: true, configured: true},
		{name: "setup-node token on the public registry", project: "//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}", env: map[string]string{"NODE_AUTH_TOKEN": npmrcSecret}, pkg: "qs", want: true, configured: true},
		{name: "public registry", project: "@acme:registry=https://npm.acme.test/\n//npm.acme.test/:_authToken=t", pkg: "qs"},
		{name: "unset setup-node token fetches anonymously", project: "//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}", pkg: "qs", configured: true},
		{name: "unset token inside a longer value fetches anonymously", project: "@acme:registry=https://npm.acme.test/\n//npm.acme.test/:_auth=user:${NPM_TOKEN}", pkg: "@acme/x", configured: true},
		{name: "top-level unset token fetches anonymously", project: "_authToken=${NPM_TOKEN}", pkg: "qs", configured: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeNPMRC(t, dir, tt.project)
			cfg, err := LoadNPMConfig(NPMRCSources{ProjectDir: dir, LookupEnv: envOf(tt.env)})
			if err != nil {
				t.Fatal(err)
			}
			reg := cfg.PolicyFor(tt.pkg).Registries["npm"]
			if reg.RequireAuth != tt.want {
				t.Fatalf("RequireAuth = %v, want %v", reg.RequireAuth, tt.want)
			}
			if reg.AuthConfigured != tt.configured {
				t.Fatalf("AuthConfigured = %v, want %v", reg.AuthConfigured, tt.configured)
			}
			// Credentialed is that same resolution, which decides where the bytes may be kept.
			purl := "pkg:npm/" + strings.Replace(tt.pkg, "@", "%40", 1) + "@1.0.0"
			if got, err := cfg.PolicyFor(tt.pkg).Credentialed(purl); err != nil || got != tt.configured {
				t.Fatalf("Credentialed(%s) = %v, %v; want %v", purl, got, err, tt.configured)
			}
		})
	}
}

// Only DefaultNPMRCEnv and operator-named variables reach a .npmrc reference, and a token
// bound through them still goes only to its own host.
func TestLoadNPMConfigEnvAllowlist(t *testing.T) {
	env := map[string]string{"GITHUB_TOKEN": "ghs_" + npmrcSecret, "NODE_AUTH_TOKEN": npmrcSecret, "CORP_TOKEN": npmrcSecret}
	tests := []struct {
		name    string
		project string
		allow   []string
		bound   bool
	}{
		{name: "optional reference to GITHUB_TOKEN binds nothing", project: "//registry.npmjs.org/:_authToken=${GITHUB_TOKEN?}"},
		{name: "allowlisted NODE_AUTH_TOKEN", project: "//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}", bound: true},
		{name: "operator-added name", project: "//registry.npmjs.org/:_authToken=${CORP_TOKEN}", allow: []string{"CORP_TOKEN"}, bound: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeNPMRC(t, dir, tt.project)
			cfg, err := LoadNPMConfig(NPMRCSources{ProjectDir: dir, LookupEnv: envOf(env), AllowEnv: tt.allow})
			if err != nil {
				t.Fatal(err)
			}
			if got := !cfg.PolicyFor("qs").Credentials.For("registry.npmjs.org").IsEmpty(); got != tt.bound {
				t.Fatalf("token bound = %v, want %v", got, tt.bound)
			}
		})
	}
	// A project file cannot name GITHUB_TOKEN and get it, even when the operator allows
	// another name.
	dir := t.TempDir()
	writeNPMRC(t, dir, "//registry.npmjs.org/:_authToken=${GITHUB_TOKEN}")
	if _, err := LoadNPMConfig(NPMRCSources{ProjectDir: dir, LookupEnv: envOf(env), AllowEnv: []string{"CORP_TOKEN"}}); !errors.Is(err, ErrMalformedNPMRC) {
		t.Fatalf("err = %v, want ErrMalformedNPMRC", err)
	}
}

// A symlinked project .npmrc could point at the runner's own configuration, so it is refused.
func TestLoadNPMConfigRefusesSymlinkedProjectFile(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "home.npmrc")
	if err := os.WriteFile(outside, []byte("registry=https://home.test/\n//home.test/:_authToken="+npmrcSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, ".npmrc")); err != nil {
		t.Fatal(err)
	}
	_, err := LoadNPMConfig(NPMRCSources{ProjectDir: dir})
	if !errors.Is(err, ErrMalformedNPMRC) {
		t.Fatalf("err = %v, want ErrMalformedNPMRC", err)
	}
}

// A project directory reached through a directory symlink that leaves the checkout could
// make the project layer the runner's own configuration directory, so it is refused.
func TestLoadNPMConfigContainsProjectDir(t *testing.T) {
	outside := t.TempDir()
	writeNPMRC(t, outside, "registry=https://home.test/\n//home.test/:_authToken="+npmrcSecret)
	if err := os.Mkdir(filepath.Join(outside, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeNPMRC(t, filepath.Join(outside, "sub"), "registry=https://home.test/")
	checkout := t.TempDir()
	inside := filepath.Join(checkout, "pkg")
	if err := os.Mkdir(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	writeNPMRC(t, inside, "registry=https://inside.test/")
	if err := os.Symlink(outside, filepath.Join(checkout, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(inside, filepath.Join(checkout, "alias")); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		project string
		wantErr bool
		wantReg string
	}{
		{name: "project dir through a symlink leaving the checkout", project: filepath.Join(checkout, "linked"), wantErr: true},
		{name: "project dir under a symlinked ancestor leaving the checkout", project: filepath.Join(checkout, "linked", "sub"), wantErr: true},
		{name: "project dir through a symlink staying inside", project: filepath.Join(checkout, "alias"), wantReg: "https://inside.test/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := LoadNPMConfig(NPMRCSources{ProjectDir: tt.project, CheckoutRoot: checkout})
			if tt.wantErr {
				if !errors.Is(err, ErrMalformedNPMRC) {
					t.Fatalf("err = %v, want ErrMalformedNPMRC", err)
				}
				if strings.Contains(err.Error(), npmrcSecret) {
					t.Fatal("error leaked a value")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.RegistryFor("qs"); got != tt.wantReg {
				t.Fatalf("registry = %q, want %q", got, tt.wantReg)
			}
		})
	}
}

// An auth value a variable left empty names that variable, and why, for the registry it binds
// to, so the scan can say which token was missing.
func TestTokenEnvFor(t *testing.T) {
	tests := []struct {
		name    string
		project string
		env     map[string]string
		allow   []string
		pkg     string
		want    TokenEnv
	}{
		{name: "setup-node token unset", project: "//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}", pkg: "qs", want: TokenEnv{Name: "NODE_AUTH_TOKEN", State: TokenEnvUnset}},
		{name: "operator-added name unset", project: "@acme:registry=https://npm.acme.test/\n//npm.acme.test/:_authToken=${CORP_TOKEN}", allow: []string{"CORP_TOKEN"}, pkg: "@acme/x", want: TokenEnv{Name: "CORP_TOKEN", State: TokenEnvUnset}},
		{name: "optional reference unset", project: "//registry.npmjs.org/:_authToken=${NPM_TOKEN?}", pkg: "qs", want: TokenEnv{Name: "NPM_TOKEN", State: TokenEnvUnset}},
		{name: "top-level token unset", project: "_authToken=${NPM_TOKEN}", pkg: "qs", want: TokenEnv{Name: "NPM_TOKEN", State: TokenEnvUnset}},
		{name: "allowlisted token set to empty", project: "//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}", env: map[string]string{"NODE_AUTH_TOKEN": ""}, pkg: "qs", want: TokenEnv{Name: "NODE_AUTH_TOKEN", State: TokenEnvEmpty}},
		{name: "optional reference outside the allowlist, set", project: "//registry.npmjs.org/:_authToken=${CORP_TOKEN?}", env: map[string]string{"CORP_TOKEN": npmrcSecret}, pkg: "qs", want: TokenEnv{Name: "CORP_TOKEN", State: TokenEnvNotAllowed}},
		{name: "optional reference outside the allowlist, unset", project: "//registry.npmjs.org/:_authToken=${CORP_TOKEN?}", pkg: "qs", want: TokenEnv{Name: "CORP_TOKEN", State: TokenEnvNotAllowed}},
		{name: "an unset reference is named before an empty one", project: "//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}${NPM_TOKEN?}", env: map[string]string{"NODE_AUTH_TOKEN": ""}, pkg: "qs", want: TokenEnv{Name: "NPM_TOKEN", State: TokenEnvUnset}},
		{name: "token set", project: "//registry.npmjs.org/:_authToken=${NODE_AUTH_TOKEN}", env: map[string]string{"NODE_AUTH_TOKEN": npmrcSecret}, pkg: "qs"},
		{name: "another registry's unset token", project: "@acme:registry=https://npm.acme.test/\n//npm.acme.test/:_authToken=${NODE_AUTH_TOKEN}", pkg: "qs"},
		{name: "no auth entry", project: "registry=https://mirror.test/", pkg: "qs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeNPMRC(t, dir, tt.project)
			cfg, err := LoadNPMConfig(NPMRCSources{ProjectDir: dir, LookupEnv: envOf(tt.env), AllowEnv: tt.allow})
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.TokenEnvFor(tt.pkg); got != tt.want {
				t.Fatalf("TokenEnvFor(%q) = %+v, want %+v", tt.pkg, got, tt.want)
			}
			if !cfg.PolicyFor(tt.pkg).Credentials.For("registry.npmjs.org").IsEmpty() && tt.want.Name != "" {
				t.Fatal("an unset token bound a credential")
			}
		})
	}
}
