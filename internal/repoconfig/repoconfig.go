// Package repoconfig reads the optional, repository-owned scan configuration file
// (.github/ferralon.yml) a repository commits to its default branch.
//
// The file is UNTRUSTED repository content, so it is handled as data and nothing else: it is
// parsed with a safe YAML loader into a node tree (no custom tags, no type registration, no
// reflection into arbitrary types), size-capped, required to be a regular file (a symlink could
// point the reader anywhere on the runner), and schema-validated. No value from it is ever
// executed or interpolated into a shell string; the one value that reaches a subprocess —
// analyze.ref — is validated here and handed to git as a single argv element by the caller.
//
// Schema v1:
//
//	version: 1
//	analyze:
//	  ref: <branch|tag|sha>   # optional; default = the ref CI checked out
//
// Forward compatibility: an unknown key at the top level or inside analyze is a WARNING and the
// read proceeds, so the schema can grow (e.g. a future analyze.path for monorepos) without
// breaking older scanners. Malformed YAML, a wrong type, an unsupported version or an invalid ref
// FAIL CLOSED with an error — a config that says something the scanner cannot honor must never be
// silently skipped, because the scan would then report on a tree the repository did not ask for.
//
// Absent file ⇒ the zero Config and no error: the default-preserving path.
package repoconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultPath is where the config file lives, relative to the scan target.
const DefaultPath = ".github/ferralon.yml"

// SchemaVersion is the only schema version this scanner understands.
const SchemaVersion = 1

// maxBytes caps how much of the file is read. The v1 schema is a handful of lines; the cap keeps a
// hostile file (or an alias-expansion bomb) from costing the runner anything.
const maxBytes = 64 << 10

// maxRefLen caps analyze.ref. Real branch/tag names and SHAs are far shorter.
const maxRefLen = 255

// Config is the parsed, validated file. The zero value means "no configuration": scan exactly what
// is on disk, as before the file existed.
type Config struct {
	// Version is the schema version the file declared (SchemaVersion when it omitted the field).
	Version int
	Analyze Analyze
}

// Analyze selects what the scan analyzes.
type Analyze struct {
	// Ref is the branch, tag or commit SHA to analyze instead of the checked-out tree. Empty means
	// the checked-out tree.
	Ref string
}

// Load reads <root>/DefaultPath. A missing file yields the zero Config, no warnings and no error.
// Warnings are human-readable notes (unknown keys, an omitted version) the caller should surface;
// they never change the result.
func Load(root string) (Config, []string, error) {
	path := filepath.Join(root, filepath.FromSlash(DefaultPath))
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Config{}, nil, nil
	}
	if err != nil {
		return Config{}, nil, fmt.Errorf("%s: %w", DefaultPath, err)
	}
	if !fi.Mode().IsRegular() {
		return Config{}, nil, fmt.Errorf("%s: must be a regular file (got %s)", DefaultPath, fi.Mode().Type())
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, nil, fmt.Errorf("%s: %w", DefaultPath, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return Config{}, nil, fmt.Errorf("%s: %w", DefaultPath, err)
	}
	if len(data) > maxBytes {
		return Config{}, nil, fmt.Errorf("%s: file exceeds %d bytes", DefaultPath, maxBytes)
	}
	return Parse(data)
}

// Parse validates the file contents. See the package doc for the fail-closed / warn rules.
func Parse(data []byte) (Config, []string, error) {
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) { // empty file / comments only
			return Config{}, []string{"file is empty; ignoring it"}, nil
		}
		return Config{}, nil, fmt.Errorf("%s: malformed YAML: %w", DefaultPath, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil {
		return Config{}, nil, fmt.Errorf("%s: malformed: expected a single YAML document", DefaultPath)
	} else if !errors.Is(err, io.EOF) {
		return Config{}, nil, fmt.Errorf("%s: malformed YAML: %w", DefaultPath, err)
	}

	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	if isNull(root) {
		return Config{}, []string{"file is empty; ignoring it"}, nil
	}
	if root.Kind != yaml.MappingNode {
		return Config{}, nil, fmt.Errorf("%s: top level must be a mapping", DefaultPath)
	}

	var (
		cfg        Config
		warnings   []string
		sawVersion bool
	)
	err := eachPair(root, "", func(key string, val *yaml.Node) error {
		switch key {
		case "version":
			sawVersion = true
			if val.Kind != yaml.ScalarNode || val.Tag != "!!int" {
				return fmt.Errorf("%s: version must be an integer", DefaultPath)
			}
			v, err := strconv.Atoi(val.Value)
			if err != nil || v != SchemaVersion {
				return fmt.Errorf("%s: unsupported version %q (this scanner understands version %d)", DefaultPath, val.Value, SchemaVersion)
			}
			cfg.Version = v
		case "analyze":
			if isNull(val) {
				return nil
			}
			if val.Kind != yaml.MappingNode {
				return fmt.Errorf("%s: analyze must be a mapping", DefaultPath)
			}
			return eachPair(val, "analyze.", func(key string, v *yaml.Node) error {
				switch key {
				case "ref":
					ref, err := scalarRef(v)
					if err != nil {
						return err
					}
					cfg.Analyze.Ref = ref
				default:
					warnings = append(warnings, fmt.Sprintf("unknown key %q ignored (not understood by this scanner version)", "analyze."+key))
				}
				return nil
			})
		default:
			warnings = append(warnings, fmt.Sprintf("unknown key %q ignored (not understood by this scanner version)", key))
		}
		return nil
	})
	if err != nil {
		return Config{}, nil, err
	}
	if !sawVersion {
		cfg.Version = SchemaVersion
		warnings = append(warnings, fmt.Sprintf("no version field; assuming version %d", SchemaVersion))
	}
	return cfg, warnings, nil
}

// eachPair walks a mapping node's key/value pairs, rejecting non-scalar and duplicate keys.
func eachPair(m *yaml.Node, prefix string, fn func(key string, val *yaml.Node) error) error {
	seen := map[string]bool{}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			return fmt.Errorf("%s: malformed: mapping keys must be plain strings", DefaultPath)
		}
		if seen[k.Value] {
			return fmt.Errorf("%s: malformed: duplicate key %q", DefaultPath, prefix+k.Value)
		}
		seen[k.Value] = true
		if v.Kind == yaml.AliasNode {
			return fmt.Errorf("%s: YAML aliases are not supported (key %q)", DefaultPath, prefix+k.Value)
		}
		if err := fn(k.Value, v); err != nil {
			return err
		}
	}
	return nil
}

func isNull(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Tag == "!!null"
}

// scalarRef extracts analyze.ref. A null value means unset. A plain integer/float scalar is kept as
// its literal source text, so an all-digit abbreviated SHA is not mangled by YAML typing.
func scalarRef(v *yaml.Node) (string, error) {
	if isNull(v) {
		return "", nil
	}
	if v.Kind != yaml.ScalarNode {
		return "", fmt.Errorf("%s: analyze.ref must be a string", DefaultPath)
	}
	switch v.Tag {
	case "!!str", "!!int", "!!float":
	default:
		return "", fmt.Errorf("%s: analyze.ref must be a string (quote it if the name looks like %s)", DefaultPath, strings.TrimPrefix(v.Tag, "!!"))
	}
	if err := ValidateRef(v.Value); err != nil {
		return "", fmt.Errorf("%s: %w", DefaultPath, err)
	}
	return v.Value, nil
}

// ValidateRef accepts a branch name, tag name or commit SHA and rejects everything else. It is
// deliberately stricter than git's own check-ref-format: the value comes from untrusted repository
// content and is passed to `git fetch` as a refspec, so it must not be able to
//
//   - look like an option ("-…", e.g. --upload-pack=…),
//   - carry a refspec destination or force marker (":" / leading "+"), which would make the fetch
//     WRITE a local ref,
//   - carry revision syntax, globs, whitespace or control bytes (^ ~ ? * [ \ @{ ..),
//
// and it never reaches a shell, so shell metacharacters are simply not in the allowed alphabet.
func ValidateRef(ref string) error {
	if ref == "" {
		return errors.New("analyze.ref is empty")
	}
	if len(ref) > maxRefLen {
		return fmt.Errorf("analyze.ref is longer than %d characters", maxRefLen)
	}
	for _, r := range ref {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == '/':
		default:
			return fmt.Errorf("analyze.ref %q contains %q: only letters, digits, '-', '_', '.' and '/' are allowed", ref, r)
		}
	}
	switch {
	case strings.HasPrefix(ref, "-"):
		return fmt.Errorf("analyze.ref %q must not start with '-'", ref)
	case strings.HasPrefix(ref, "/"), strings.HasSuffix(ref, "/"), strings.Contains(ref, "//"):
		return fmt.Errorf("analyze.ref %q has an empty path component", ref)
	case strings.Contains(ref, ".."):
		return fmt.Errorf("analyze.ref %q must not contain '..'", ref)
	case strings.HasSuffix(ref, ".lock"), strings.HasSuffix(ref, "."):
		return fmt.Errorf("analyze.ref %q is not a valid ref name", ref)
	}
	for part := range strings.SplitSeq(ref, "/") {
		if strings.HasPrefix(part, ".") {
			return fmt.Errorf("analyze.ref %q has a component starting with '.'", ref)
		}
	}
	return nil
}
