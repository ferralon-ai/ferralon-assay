package acquire

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

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
//
// The environment is read only through an allowlist: DefaultNPMRCEnv plus the names in
// AllowEnv. A ${VAR} reference to any other variable behaves exactly as if VAR were unset.
// A repository's .npmrc must not be able to draw an arbitrary secret from the scanner's
// environment (a CI token, a state token) and present it to a host the same file names.
type NPMRCSources struct {
	ProjectDir string // the directory holding the build's package.json and lock
	// CheckoutRoot is the checkout ProjectDir must resolve inside once every symlink is
	// followed. Empty contains ProjectDir in itself, which checks nothing about its ancestors.
	CheckoutRoot string
	LookupEnv    func(key string) (string, bool)   // environment the runner provides; nil reads nothing
	AllowEnv     []string                          // variable names readable beyond DefaultNPMRCEnv, as the operator lists them
	readFile     func(name string) ([]byte, error) // test seam; os.ReadFile when nil
}

// DefaultNPMRCEnv is the set of environment variables LoadNPMConfig reads without the
// operator naming them: npm's own configuration variables and the token variables
// actions/setup-node and npm's documentation use.
var DefaultNPMRCEnv = []string{"NPM_CONFIG_USERCONFIG", "NPM_CONFIG_REGISTRY", "NODE_AUTH_TOKEN", "NPM_TOKEN"}

// NPMConfig is the registry view of a build's npm configuration: which registry serves
// each package, which hosts may be contacted, and which token belongs to which host.
// Tokens live only inside creds, bound to their exact host.
type NPMConfig struct {
	defaultRegistry string
	scopes          map[string]string   // "@scope" -> registry base URL
	requireAuth     map[string]bool     // canonical host -> an anonymous fetch must be refused
	authConfigured  map[string]bool     // canonical host -> an auth key names it, though it may present nothing
	unsetAuthEnv    map[string]TokenEnv // canonical host -> the variable that left its auth value empty
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

// npmrcEntry is one key=value line after env expansion, kept with its origin. raw is the
// value before expansion: an optional ${VAR?} that expanded to "" is not an empty token.
type npmrcEntry struct {
	value  string
	raw    string
	token  TokenEnv // the variable that left an auth value empty, if one did
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
	env := allowedEnv(src.LookupEnv, src.AllowEnv)
	read := src.readFile
	if read == nil {
		read = os.ReadFile
	}

	merged := map[string]npmrcEntry{}
	layer := func(name, source string) error {
		var b []byte
		var err error
		if source == sourceProject && src.readFile == nil {
			b, err = readNoFollow(name)
		} else {
			b, err = read(name)
		}
		var refused *npmrcError
		if errors.As(err, &refused) {
			return err
		}
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return &npmrcError{source: source, reason: "unreadable"}
		}
		entries, err := parseNPMRC(string(b), source, env)
		if err != nil {
			return err
		}
		for k, v := range entries {
			merged[k] = v
		}
		return nil
	}

	if p, ok := env.get("NPM_CONFIG_USERCONFIG"); ok && p != "" {
		if !filepath.IsAbs(p) {
			return NPMConfig{}, &npmrcError{source: sourceUserConfig, reason: "path is not absolute"}
		}
		if err := layer(p, sourceUserConfig); err != nil {
			return NPMConfig{}, err
		}
	}
	if src.ProjectDir != "" {
		dir, err := containedDir(src.ProjectDir, src.CheckoutRoot)
		if err != nil {
			return NPMConfig{}, err
		}
		if err := layer(filepath.Join(dir, ".npmrc"), sourceProject); err != nil {
			return NPMConfig{}, err
		}
	}
	if r, ok := env.get("NPM_CONFIG_REGISTRY"); ok && r != "" {
		merged["registry"] = npmrcEntry{value: r, source: sourceEnv}
	}
	return buildNPMConfig(merged)
}

// containedDir resolves every symlink in dir and refuses a result outside root (resolved the
// same way). It matters once a workspace plan's root differs from the build dir: a committed
// directory symlink could then point the project layer outside the checkout, such as at the
// runner's home. A single-project plan passes the build dir as its own root.
func containedDir(dir, root string) (string, error) {
	if root == "" {
		root = dir
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", &npmrcError{source: sourceProject, reason: "project directory does not resolve"}
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", &npmrcError{source: sourceProject, reason: "checkout root does not resolve"}
	}
	rel, err := filepath.Rel(realRoot, realDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", &npmrcError{source: sourceProject, reason: "project directory resolves outside the checkout"}
	}
	return realDir, nil
}

// readNoFollow reads the project .npmrc, refusing a symlink or any other non-regular file. A
// committed symlink could point at a file outside the checkout, such as the runner's own
// $HOME/.npmrc. The file opened is checked to be the one Lstat saw, so swapping in a symlink
// between the two calls is refused too.
func readNoFollow(name string) ([]byte, error) {
	before, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if before.Mode()&fs.ModeSymlink != 0 {
		return nil, &npmrcError{source: sourceProject, reason: "is a symbolic link"}
	}
	if !before.Mode().IsRegular() {
		return nil, &npmrcError{source: sourceProject, reason: "is not a regular file"}
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, opened) {
		return nil, &npmrcError{source: sourceProject, reason: "changed while being read"}
	}
	return io.ReadAll(f)
}

// npmrcEnv is the environment a .npmrc reference reads: DefaultNPMRCEnv and the operator's
// extra names. Any other name reads as unset.
type npmrcEnv struct {
	lookup  func(string) (string, bool)
	allowed map[string]bool
}

func allowedEnv(lookup func(string) (string, bool), extra []string) npmrcEnv {
	allowed := map[string]bool{}
	for _, n := range DefaultNPMRCEnv {
		allowed[n] = true
	}
	for _, n := range extra {
		if n = strings.TrimSpace(n); n != "" {
			allowed[n] = true
		}
	}
	return npmrcEnv{lookup: lookup, allowed: allowed}
}

func (e npmrcEnv) get(name string) (string, bool) {
	if e.lookup == nil || !e.allowed[name] {
		return "", false
	}
	return e.lookup(name)
}

// envRef matches npm's ${NAME} and ${NAME?} references. A plain reference to an unset
// variable is an error, as it is in npm; the "?" form expands to "".
var envRef = regexp.MustCompile(`\$\{([^${}?]+)(\?)?\}`)

func expandEnv(s, source string, line int, env npmrcEnv) (string, error) {
	out, missing := expandRefs(s, env)
	if missing != "" {
		return "", &npmrcError{source: source, line: line, reason: "references unset environment variable " + strconv.Quote(missing)}
	}
	return out, nil
}

// expandRefs expands s and returns the first plain reference to an unset variable, if any.
func expandRefs(s string, env npmrcEnv) (out, missing string) {
	out = envRef.ReplaceAllStringFunc(s, func(m string) string {
		sub := envRef.FindStringSubmatch(m)
		v, ok := env.get(sub[1])
		if !ok && sub[2] == "" && missing == "" {
			missing = sub[1]
		}
		return v
	})
	return out, missing
}

// TokenEnv names the environment variable that left a registry's auth value empty, so the
// registry was fetched with no token, and why it was empty.
type TokenEnv struct {
	Name  string
	State string // TokenEnvUnset, TokenEnvEmpty or TokenEnvNotAllowed
}

const (
	// TokenEnvUnset is an allowlisted variable the runner left unset.
	TokenEnvUnset = "unset"
	// TokenEnvEmpty is an allowlisted variable the runner set to "".
	TokenEnvEmpty = "empty"
	// TokenEnvNotAllowed is an optional ${VAR?} reference to a variable outside the allowlist,
	// which the scan never reads, set or not.
	TokenEnvNotAllowed = "not_allowed"
)

// expandAuthValue expands an auth value. A plain reference to an allowlisted variable the
// runner left unset (a workflow that never exported NODE_AUTH_TOKEN) is a missing token, not a
// malformed file: the whole value reads as "", so the registry is fetched anonymously and a
// 401/403 reads as missing_credential. A partially expanded value is never kept, so no fragment
// of a token is presented. A plain reference to a variable outside the allowlist still fails the
// load: the operator has not let the scan read it. token names the variable that left the value
// empty, preferring one unset or outside the allowlist to one set to "".
func expandAuthValue(s, source string, line int, env npmrcEnv) (value string, token TokenEnv, err error) {
	var empty TokenEnv
	for _, sub := range envRef.FindAllStringSubmatch(s, -1) {
		v, ok := env.get(sub[1])
		switch {
		case ok && v == "":
			if empty.Name == "" {
				empty = TokenEnv{Name: sub[1], State: TokenEnvEmpty}
			}
		case ok:
		case sub[2] == "" && !env.allowed[sub[1]]:
			return "", TokenEnv{}, &npmrcError{source: source, line: line, reason: "references unset environment variable " + strconv.Quote(sub[1])}
		case token.Name != "":
		case !env.allowed[sub[1]]:
			token = TokenEnv{Name: sub[1], State: TokenEnvNotAllowed}
		default:
			token = TokenEnv{Name: sub[1], State: TokenEnvUnset}
		}
	}
	if token.Name == "" {
		token = empty
	}
	out, missing := expandRefs(s, env)
	if missing != "" {
		return "", TokenEnv{Name: missing, State: TokenEnvUnset}, nil
	}
	return out, token, nil
}

// authField reports whether k, a top-level or //host/ key, holds a credential.
func authField(k string) bool {
	if strings.HasPrefix(k, "//") {
		k = k[strings.LastIndex(k, ":")+1:]
	}
	switch k {
	case "_authToken", "_auth", "_password", "username":
		return true
	}
	return false
}

// parseNPMRC parses npm's ini dialect: key=value lines, ';' and '#' comments, optional
// quoting. A section header is refused rather than guessed at.
func parseNPMRC(text, source string, env npmrcEnv) (map[string]npmrcEntry, error) {
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
		// In the project file an environment reference may sit only in a value that is not
		// a URL: a key (which names the host a token binds to) or a registry URL built from
		// the environment could carry a secret to a host, or into a request path.
		if source == sourceProject && (envRef.MatchString(k) || (urlBearingKey(k) && envRef.MatchString(v))) {
			return nil, &npmrcError{source: source, line: line, reason: "environment reference in a registry host or URL"}
		}
		if k, err = expandEnv(k, source, line, env); err != nil {
			return nil, err
		}
		raw, token := v, TokenEnv{}
		if authField(k) {
			v, token, err = expandAuthValue(v, source, line, env)
		} else {
			v, err = expandEnv(v, source, line, env)
		}
		if err != nil {
			return nil, err
		}
		out[k] = npmrcEntry{value: v, raw: raw, token: token, source: source, line: line}
	}
	return out, nil
}

// urlBearingKey reports whether k's value is a registry URL.
func urlBearingKey(k string) bool {
	return k == "registry" || (strings.HasPrefix(k, "@") && strings.HasSuffix(k, ":registry"))
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
		authConfigured:  map[string]bool{},
		unsetAuthEnv:    map[string]TokenEnv{},
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
	// Top-level auth keys apply to the default registry. None is a form this package
	// presents, so they only mark that registry as needing auth: its packages are refused
	// as missing_credential rather than fetched anonymously and misread as not served. An
	// optional ${VAR?} reference that expanded to "" presents nothing, as in npm, so it
	// fetches anonymously.
	defaultAuth, defaultAuthOptional, defaultUnset := false, false, TokenEnv{}
	for _, k := range []string{"_auth", "_authToken", "username", "_password"} {
		if e, ok := entries[k]; ok {
			if emptyOptional(e) {
				defaultAuthOptional = true
				if defaultUnset.Name == "" {
					defaultUnset = e.token
				}
			} else {
				defaultAuth = true
			}
		}
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
			if authField(k) && emptyOptional(e) && e.token.Name != "" && cfg.unsetAuthEnv[host].Name == "" {
				cfg.unsetAuthEnv[host] = e.token
			}
			switch field {
			case "_authToken":
				if prev, dup := tokenPath[host]; dup && prev != prefix {
					return NPMConfig{}, &npmrcError{source: e.source, line: e.line, reason: "two tokens for one host under different paths"}
				}
				tokenPath[host] = prefix
				cfg.authConfigured[host] = true
				if emptyOptional(e) {
					break // npm fetches anonymously; a 401/403 then reads as missing_credential
				}
				cfg.requireAuth[host] = true
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
				cfg.authConfigured[host] = true
				if !emptyOptional(e) {
					cfg.requireAuth[host] = true
				}
			}
		}
	}

	if defaultAuth || defaultAuthOptional {
		u, _ := url.Parse(cfg.defaultRegistry) // registryBase already parsed it
		h := canonicalizeHostString(u.Hostname())
		cfg.authConfigured[h] = true
		if defaultAuth {
			cfg.requireAuth[h] = true
		}
		if defaultUnset.Name != "" && cfg.unsetAuthEnv[h].Name == "" {
			cfg.unsetAuthEnv[h] = defaultUnset
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

// emptyOptional reports an auth value that is empty only because an optional ${VAR?}
// reference expanded to "". A value written empty is not optional: it still requires auth.
func emptyOptional(e npmrcEntry) bool {
	return e.value == "" && e.raw != ""
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

// TokenEnvFor names the environment variable that left the auth value for name's registry
// empty, so that registry was fetched with no token; the zero TokenEnv when there is none.
func (c NPMConfig) TokenEnvFor(name string) TokenEnv {
	u, err := url.Parse(c.RegistryFor(name))
	if err != nil {
		return TokenEnv{}
	}
	return c.unsetAuthEnv[canonicalizeHostString(u.Hostname())]
}

// RegistryID identifies the registry at base URL raw for keeping per-registry state: the
// URL's scheme, lowercased host, port and path, with no trailing slash and no userinfo, query
// or fragment. A URL that does not parse identifies as "".
func RegistryID(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	host := canonicalizeHostString(u.Hostname())
	switch {
	case u.Port() != "":
		host = net.JoinHostPort(host, u.Port())
	case strings.Contains(host, ":"):
		host = "[" + host + "]"
	}
	return (&url.URL{Scheme: strings.ToLower(u.Scheme), Host: host, Path: strings.TrimRight(u.Path, "/")}).String()
}

// PolicyFor returns the acquisition policy for one npm package: its tarball URL is built
// from the registry that serves name, by name and version. The lock's integrity decides
// whether the bytes are accepted.
func (c NPMConfig) PolicyFor(name string) Policy {
	reg := c.RegistryFor(name)
	u, _ := url.Parse(reg)
	host := canonicalizeHostString(u.Hostname())
	return Policy{
		Allowlist:   c.allow,
		Registries:  map[string]RegistryConfig{"npm": {BaseURL: reg, RequireAuth: c.requireAuth[host], AuthConfigured: c.authConfigured[host] || c.requireAuth[host]}},
		Backends:    map[string]RegistryBackend{"npm": npmBackend{}},
		Credentials: c.creds,
	}
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
