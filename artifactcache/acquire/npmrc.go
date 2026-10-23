package acquire

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/artifactcache"
	"github.com/ferralon-ai/ferralon-assay/checkout"
)

// DefaultNPMRegistry is the registry npm uses when no configuration names another.
const DefaultNPMRegistry = "https://registry.npmjs.org/"

// NPMRCSources names everything LoadNPMConfig may read. It is the whole read surface:
// the project's own .npmrc, the file NPM_CONFIG_USERCONFIG names, and NPM_CONFIG_REGISTRY.
// An implicit $HOME/.npmrc and the global npmrc are never read. A runner's home
// directory belongs to the runner, not to the build under test, and reading it would let
// credentials meant for unrelated work reach this one.
//
// NPM_CONFIG_USERCONFIG is the one file outside the project that is read. It is not
// implicit discovery: the runner sets it on purpose, and actions/setup-node writes the
// registry and its auth token there (a file under RUNNER_TEMP), so a CI build that
// installs from a private registry configures it only through this variable.
type NPMRCSources struct {
	ProjectDir string                            // the directory holding the build's package.json and lock
	LookupEnv  func(key string) (string, bool)   // environment the runner provides; nil reads nothing
	readFile   func(name string) ([]byte, error) // test seam; os.ReadFile when nil
}

// NPMConfig is the registry view of a build's npm configuration: which registry serves
// each package, which hosts may be contacted, and which token belongs to which host.
// Tokens live only inside creds, bound to their exact host.
type NPMConfig struct {
	defaultRegistry string
	scopes          map[string]string // "@scope" -> registry base URL
	requireAuth     map[string]bool   // canonical host -> an anonymous fetch must be refused
	creds           RegistryCredentials
	allow           Allowlist
}

// String names the registries and the number of bound credentials, never a token.
func (c NPMConfig) String() string {
	return fmt.Sprintf("acquire.NPMConfig(default=%s; %d scope(s); %v)", c.defaultRegistry, len(c.scopes), c.creds)
}

// GoString redacts too.
func (c NPMConfig) GoString() string { return c.String() }

// ErrMalformedNPMRC marks a configuration this package will not act on. Nothing from a
// malformed configuration is used, not even the parts that parsed.
var ErrMalformedNPMRC = errors.New("acquire: malformed npm configuration")

// npmrcError names the source and line of a malformed entry. It never carries a key's
// value, which may be a token.
type npmrcError struct {
	source string
	line   int
	reason string
}

func (e *npmrcError) Error() string {
	if e.line > 0 {
		return fmt.Sprintf("%s line %d: %s", e.source, e.line, e.reason)
	}
	return fmt.Sprintf("%s: %s", e.source, e.reason)
}

func (e *npmrcError) Unwrap() error { return ErrMalformedNPMRC }

// npmrcEntry is one key=value line after env expansion, kept with its origin.
type npmrcEntry struct {
	value  string
	source string
	line   int
}

const (
	sourceProject    = "project .npmrc"
	sourceUserConfig = "NPM_CONFIG_USERCONFIG file"
	sourceEnv        = "NPM_CONFIG_REGISTRY"
)

// LoadNPMConfig reads the sources in src and builds the registry policy. Precedence is
// npm's: NPM_CONFIG_REGISTRY over the project file over the user config file. Any
// malformed source fails the whole load with an error wrapping ErrMalformedNPMRC.
func LoadNPMConfig(src NPMRCSources) (NPMConfig, error) {
	lookup := src.LookupEnv
	if lookup == nil {
		lookup = func(string) (string, bool) { return "", false }
	}
	read := src.readFile
	if read == nil {
		read = os.ReadFile
	}

	merged := map[string]npmrcEntry{}
	layer := func(name, source string) error {
		b, err := read(name)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return &npmrcError{source: source, reason: "unreadable"}
		}
		entries, err := parseNPMRC(string(b), source, lookup)
		if err != nil {
			return err
		}
		for k, v := range entries {
			merged[k] = v
		}
		return nil
	}

	if p, ok := lookup("NPM_CONFIG_USERCONFIG"); ok && p != "" {
		if !filepath.IsAbs(p) {
			return NPMConfig{}, &npmrcError{source: sourceUserConfig, reason: "path is not absolute"}
		}
		if err := layer(p, sourceUserConfig); err != nil {
			return NPMConfig{}, err
		}
	}
	if src.ProjectDir != "" {
		if err := layer(filepath.Join(src.ProjectDir, ".npmrc"), sourceProject); err != nil {
			return NPMConfig{}, err
		}
	}
	if r, ok := lookup("NPM_CONFIG_REGISTRY"); ok && r != "" {
		merged["registry"] = npmrcEntry{value: r, source: sourceEnv}
	}
	return buildNPMConfig(merged)
}

// envRef matches npm's ${NAME} and ${NAME?} references. A plain reference to an unset
// variable is an error, as it is in npm; the "?" form expands to "".
var envRef = regexp.MustCompile(`\$\{([^${}?]+)(\?)?\}`)

func expandEnv(s, source string, line int, lookup func(string) (string, bool)) (string, error) {
	var missing string
	out := envRef.ReplaceAllStringFunc(s, func(m string) string {
		sub := envRef.FindStringSubmatch(m)
		v, ok := lookup(sub[1])
		if !ok && sub[2] == "" && missing == "" {
			missing = sub[1]
		}
		return v
	})
	if missing != "" {
		return "", &npmrcError{source: source, line: line, reason: "references unset environment variable " + strconv.Quote(missing)}
	}
	return out, nil
}

// parseNPMRC parses npm's ini dialect: key=value lines, ';' and '#' comments, optional
// quoting. A section header is refused rather than guessed at.
func parseNPMRC(text, source string, lookup func(string) (string, bool)) (map[string]npmrcEntry, error) {
	out := map[string]npmrcEntry{}
	for i, raw := range strings.Split(text, "\n") {
		line := i + 1
		s := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if s == "" || s[0] == ';' || s[0] == '#' {
			continue
		}
		if s[0] == '[' {
			return nil, &npmrcError{source: source, line: line, reason: "section headers are not supported"}
		}
		k, v, ok := strings.Cut(s, "=")
		if !ok {
			return nil, &npmrcError{source: source, line: line, reason: "line is not key=value"}
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "" {
			return nil, &npmrcError{source: source, line: line, reason: "empty key"}
		}
		var err error
		if v, err = unquoteNPMRC(v, source, line); err != nil {
			return nil, err
		}
		if k, err = expandEnv(k, source, line, lookup); err != nil {
			return nil, err
		}
		if v, err = expandEnv(v, source, line, lookup); err != nil {
			return nil, err
		}
		out[k] = npmrcEntry{value: v, source: source, line: line}
	}
	return out, nil
}

func unquoteNPMRC(v, source string, line int) (string, error) {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		u, err := strconv.Unquote(v)
		if err != nil {
			return "", &npmrcError{source: source, line: line, reason: "value has malformed quoting"}
		}
		return u, nil
	}
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		return v[1 : len(v)-1], nil
	}
	if v != "" && (v[0] == '"' || v[0] == '\'') {
		return "", &npmrcError{source: source, line: line, reason: "value has an unterminated quote"}
	}
	return v, nil
}

// buildNPMConfig turns merged entries into a policy. Keys this package has no use for are
// ignored; keys it does use must be well formed or the load fails.
func buildNPMConfig(entries map[string]npmrcEntry) (NPMConfig, error) {
	cfg := NPMConfig{
		defaultRegistry: DefaultNPMRegistry,
		scopes:          map[string]string{},
		requireAuth:     map[string]bool{},
	}
	if e, ok := entries["registry"]; ok {
		r, err := registryBase(e)
		if err != nil {
			return NPMConfig{}, err
		}
		cfg.defaultRegistry = r
	}
	alwaysAuth := false
	if e, ok := entries["always-auth"]; ok {
		b, err := npmrcBool(e)
		if err != nil {
			return NPMConfig{}, err
		}
		alwaysAuth = b
	}

	tokens := map[string]checkout.Credential{}
	tokenPath := map[string]string{} // host -> the //host/path/ prefix its token came from
	for k, e := range entries {
		switch {
		case strings.HasPrefix(k, "@") && strings.HasSuffix(k, ":registry"):
			scope := strings.TrimSuffix(k, ":registry")
			if strings.Contains(scope, "/") || len(scope) < 2 {
				return NPMConfig{}, &npmrcError{source: e.source, line: e.line, reason: "malformed scope registry key"}
			}
			r, err := registryBase(e)
			if err != nil {
				return NPMConfig{}, err
			}
			cfg.scopes[strings.ToLower(scope)] = r
		case strings.HasPrefix(k, "//"):
			cut := strings.LastIndex(k, ":")
			if cut < 0 {
				return NPMConfig{}, &npmrcError{source: e.source, line: e.line, reason: "per-registry key has no field"}
			}
			prefix, field := k[:cut], k[cut+1:]
			u, err := url.Parse("https:" + prefix)
			if err != nil || u.Hostname() == "" || u.User != nil {
				return NPMConfig{}, &npmrcError{source: e.source, line: e.line, reason: "per-registry key has a malformed host"}
			}
			host := canonicalizeHostString(u.Hostname())
			switch field {
			case "_authToken":
				if prev, dup := tokenPath[host]; dup && prev != prefix {
					return NPMConfig{}, &npmrcError{source: e.source, line: e.line, reason: "two tokens for one host under different paths"}
				}
				tokenPath[host] = prefix
				if e.value != "" {
					tokens[host] = checkout.NewCredential(e.value)
				}
			case "always-auth":
				b, err := npmrcBool(e)
				if err != nil {
					return NPMConfig{}, err
				}
				if b {
					cfg.requireAuth[host] = true
				}
			case "_auth", "_password", "username", "certfile", "keyfile":
				// An auth form this package cannot present. The registry needs auth, so
				// refuse an anonymous fetch instead of letting it fail as a false miss.
				cfg.requireAuth[host] = true
			}
		}
	}

	registries := []string{cfg.defaultRegistry}
	for _, r := range cfg.scopes {
		registries = append(registries, r)
	}
	hosts := make([]string, 0, len(registries))
	bound := map[string]checkout.Credential{}
	for _, r := range registries {
		u, _ := url.Parse(r) // registryBase already parsed it
		h := canonicalizeHostString(u.Hostname())
		hosts = append(hosts, h)
		if alwaysAuth {
			cfg.requireAuth[h] = true
		}
		if c, ok := tokens[h]; ok {
			bound[h] = c
		}
	}
	cfg.allow = NewAllowlist(hosts...)
	cfg.creds = NewRegistryCredentials(bound)
	return cfg, nil
}

func registryBase(e npmrcEntry) (string, error) {
	u, err := url.Parse(e.value)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return "", &npmrcError{source: e.source, line: e.line, reason: "registry is not an http(s) URL"}
	}
	if u.User != nil {
		return "", &npmrcError{source: e.source, line: e.line, reason: "registry URL carries userinfo"}
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", &npmrcError{source: e.source, line: e.line, reason: "registry URL carries a query or fragment"}
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return u.String(), nil
}

func npmrcBool(e npmrcEntry) (bool, error) {
	switch strings.ToLower(e.value) {
	case "true":
		return true, nil
	case "false", "":
		return false, nil
	}
	return false, &npmrcError{source: e.source, line: e.line, reason: "boolean value is not true or false"}
}

// RegistryFor returns the registry base URL that serves the npm package name.
func (c NPMConfig) RegistryFor(name string) string {
	if strings.HasPrefix(name, "@") {
		if scope, _, ok := strings.Cut(name, "/"); ok {
			if r, ok := c.scopes[strings.ToLower(scope)]; ok {
				return r
			}
		}
	}
	return c.defaultRegistry
}

// PolicyFor returns the acquisition policy for one npm package. resolvedHint is the lock's
// resolved URL. It is used as the fetch URL only when it is an HTTPS URL on a host the
// configuration allowlists; otherwise the URL is built from the package's registry. The
// lock's integrity still decides whether the bytes are accepted.
func (c NPMConfig) PolicyFor(name, resolvedHint string) Policy {
	reg := c.RegistryFor(name)
	u, _ := url.Parse(reg)
	host := canonicalizeHostString(u.Hostname())
	var backend RegistryBackend = npmBackend{}
	if hint, ok := c.allowedHint(resolvedHint); ok {
		backend = hintedBackend{url: hint}
	}
	return Policy{
		Allowlist:   c.allow,
		Registries:  map[string]RegistryConfig{"npm": {BaseURL: reg, RequireAuth: c.requireAuth[host]}},
		Backends:    map[string]RegistryBackend{"npm": backend},
		Credentials: c.creds,
	}
}

func (c NPMConfig) allowedHint(hint string) (string, bool) {
	if hint == "" {
		return "", false
	}
	u, err := url.Parse(hint)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return "", false
	}
	h, err := canonicalHost(u)
	if err != nil || !c.allow.Allows(h) {
		return "", false
	}
	return u.String(), true
}

// hintedBackend fetches from a lock's resolved URL that already passed the allowlist.
// The Acquirer still re-checks the host and binds the credential by it.
type hintedBackend struct{ url string }

func (hintedBackend) Ecosystem() string { return "npm" }

func (b hintedBackend) ResolveURL(artifactcache.Ref, RegistryConfig) (string, error) {
	return b.url, nil
}

// NPMNameOf returns the npm package name ("qs", "@scope/pkg") a "pkg:npm/…@version" PURL
// names, the key RegistryFor and PolicyFor route on.
func NPMNameOf(purl string) (string, error) {
	if eco, ok := ecosystemOf(purl); !ok || eco != "npm" {
		return "", fmt.Errorf("acquire: not an npm purl")
	}
	name, _, err := coordinate(purl)
	return name, err
}
