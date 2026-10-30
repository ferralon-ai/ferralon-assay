package jsanalysis

// The JavaScript install-surface classifier: which files under a build dir name or hold
// something an npm-compatible installer could read, and whether the resolver reads each fully.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
)

// ManifestCandidates returns every JavaScript install surface under root, sorted by path: each
// file whose name or content looks like a package manifest or lockfile (jsCandidate), plus every
// symlink that leaves root, symlinked directory the walk does not read through its target, and
// unreadable entry (buildtree.Candidates).
// FullyRead is true only for a regular package.json that decodes with string-valued dependency
// maps and declares no install rewrite (depManifest.rewrites), or a lockfile the resolver
// discovers (lockFiles), parses, and finds no opaque entry in.
func ManifestCandidates(root string) []buildtree.Candidate {
	locks := map[string]lockInfo{}
	for _, l := range lockFiles(root) {
		if info, ok := parseLockfile(l); ok {
			locks[l] = info
		}
	}
	return manifestCandidates(root, locks)
}

// manifestCandidates is ManifestCandidates over locks the caller already parsed (only the ones
// that parsed).
func manifestCandidates(root string, locks map[string]lockInfo) []buildtree.Candidate {
	cs := buildtree.Candidates(root, jsCandidate, func(path string) bool {
		if filepath.Base(path) == "package.json" {
			m, ok := readPackageJSON(path)
			return ok && !m.rewrites
		}
		l, ok := locks[path]
		return ok && !l.opaque
	})
	slices.SortFunc(cs, func(a, b buildtree.Candidate) int { return strings.Compare(a.Path, b.Path) })
	return cs
}

// depManifest is what the Exhaustive check reads from a package.json.
type depManifest struct {
	name     string
	hasName  bool
	declared map[string]map[string]string // dependency field → name → spec
	// rewrites is set when the manifest carries overrides, resolutions, pnpm.overrides or
	// pnpm.packageExtensions (or a "pnpm" field that is not an object), or a dependency spec in
	// the catalog: protocol: each can make an install add or swap a package the lockfile does not
	// show. A catalog: spec resolves through pnpm-workspace.yaml, so the lock's matching
	// "catalog:" specifier says nothing about what it resolves to now.
	rewrites bool
}

// rewriteKeys and pnpmRewriteKeys are the package.json fields, top-level and under "pnpm", that
// rewrite what an install resolves.
var (
	rewriteKeys     = []string{"overrides", "resolutions"}
	pnpmRewriteKeys = []string{"overrides", "packageExtensions"}
)

// readPackageJSON decodes the package.json at path. ok is false when it cannot be read, is not a
// JSON object, or has a non-string name or a dependency field that is not a map of strings.
func readPackageJSON(path string) (depManifest, bool) {
	data, err := readRegular(path)
	if err != nil {
		return depManifest{}, false
	}
	var manifest map[string]json.RawMessage
	if json.Unmarshal(data, &manifest) != nil || manifest == nil {
		return depManifest{}, false
	}
	p := depManifest{declared: map[string]map[string]string{}}
	if raw, ok := manifest["name"]; ok {
		if json.Unmarshal(raw, &p.name) != nil {
			return depManifest{}, false
		}
		p.hasName = true
	}
	for _, field := range lockedDependencyFields {
		raw, ok := manifest[field]
		if !ok {
			continue
		}
		var deps map[string]string
		if json.Unmarshal(raw, &deps) != nil {
			return depManifest{}, false
		}
		p.declared[field] = deps
		for _, spec := range deps {
			p.rewrites = p.rewrites || strings.HasPrefix(spec, "catalog:")
		}
	}
	for _, k := range rewriteKeys {
		_, has := manifest[k]
		p.rewrites = p.rewrites || has
	}
	if raw, ok := manifest["pnpm"]; ok {
		var pnpm map[string]json.RawMessage
		if json.Unmarshal(raw, &pnpm) != nil {
			p.rewrites = true
		}
		for _, k := range pnpmRewriteKeys {
			_, has := pnpm[k]
			p.rewrites = p.rewrites || has
		}
	}
	return p, true
}

// jsManifestNames are the manifests and lockfiles npm, yarn, pnpm, bun, deno and bower read.
var jsManifestNames = map[string]bool{
	"package.json": true, "package-lock.json": true, "npm-shrinkwrap.json": true,
	"yarn.lock": true, "pnpm-lock.yaml": true, "pnpm-lock.yml": true,
	"bun.lock": true, "bun.lockb": true, "deno.lock": true, "deno.json": true, "deno.jsonc": true,
	"bower.json": true, "import_map.json": true,
}

// foreignLocks are *.lock and *.lockb files other ecosystems own; every other one is a
// JavaScript candidate. Python's rye writes requirements*.lock, matched separately.
var foreignLocks = map[string]bool{
	"uv.lock": true, "poetry.lock": true, "pdm.lock": true, "Pipfile.lock": true, "pixi.lock": true,
	"Cargo.lock": true, "Gemfile.lock": true, "composer.lock": true, "flake.lock": true,
	"Podfile.lock": true, "mix.lock": true, "pubspec.lock": true, "conan.lock": true,
	"paket.lock": true, "packages.lock": true, "shard.lock": true, "renv.lock": true,
	"elm.lock": true, "esy.lock": true, "conda-lock.lock": true,
}

// docExts are formats no JavaScript installer reads its configuration from, so a manifest
// quoted in one is documentation.
var docExts = map[string]bool{
	".md": true, ".markdown": true, ".rst": true, ".adoc": true, ".html": true, ".htm": true,
	".txt": true, ".ipynb": true,
}

// jsCandidate is the JavaScript classifier: it reports whether the file at path, with up to
// buildtree.HeadSize bytes of content head (nil when binary or empty), names or holds a
// JavaScript install surface, and the rule that matched. A nil head is re-read and judged with
// its NULs removed or turned into newlines (buildtree.NULHeadMatch).
//
// Every file whose name holds "pnpmfile" is a candidate (an install hook can add any package),
// and so is a pnpm-workspace.yaml, .yarnrc* or .npmrc that mentions any of rewriteConfigWords
// (installRewriteConfig); neither is ever fully read. Other
// workspace, registry and linker configuration is not a candidate: the lockfile records its
// result, and every workspace package.json is itself a candidate.
func jsCandidate(path string, head []byte) (string, bool) {
	if why, ok := jsCandidateName(path); ok {
		return why, true
	}
	if installRewriteConfig(path, head) {
		return "install rewrite config", true
	}
	return jsCandidateContent(path, head)
}

// rewriteConfigWords are the settings through which pnpm-workspace.yaml, .yarnrc.yml and .npmrc
// add or swap packages at install time. "catalog" covers catalog: and catalogs:, which a plain
// install re-resolves without the lock naming the result; "configDependencies" covers pnpm config
// plugins, whose pnpmfile pnpm loads from node_modules; "plugins" covers yarn berry plugins, whose
// hooks can replace any descriptor. Each matches in every one of the three files.
var rewriteConfigWords = []string{"packageExtensions", "overrides", "resolutions", "pnpmfile", "catalog", "configDependencies", "plugins"}

// installRewriteConfig reports whether the file is installer configuration whose head mentions
// a setting that rewrites what an install resolves. It matches the word anywhere, comments
// included. A head that is nil (empty, or binary-looking) or fills buildtree.HeadSize (the file
// may continue past it) is not a full read, so it counts as a match.
func installRewriteConfig(path string, head []byte) bool {
	lower := strings.ToLower(filepath.Base(path))
	if !strings.HasPrefix(lower, ".yarnrc") && !strings.HasPrefix(lower, ".npmrc") && !strings.HasPrefix(lower, "pnpm-workspace.") {
		return false
	}
	if head == nil || len(head) == buildtree.HeadSize {
		return true
	}
	for _, w := range rewriteConfigWords {
		if bytes.Contains(head, []byte(w)) {
			return true
		}
	}
	return strings.HasPrefix(lower, ".npmrc") && npmrcNamesAny(head, rewriteConfigWords)
}

func jsCandidateName(path string) (string, bool) {
	if inner, ok := buildtree.TemplateInner(path); ok {
		if why, ok := jsCandidateName(inner); ok {
			return "templated " + why, true
		}
	}
	name := filepath.Base(path)
	lower := strings.ToLower(name)
	ext := filepath.Ext(lower)
	switch {
	case jsManifestNames[name]:
		return "manifest name", true
	case strings.Contains(lower, "pnpmfile") && !docExts[ext]:
		return "pnpm install hook", true
	case (ext == ".lock" || ext == ".lockb") && !foreignLocks[name] &&
		!(strings.Contains(lower, "requirement") || strings.Contains(lower, "constraint")):
		return "lockfile name", true
	}
	return "", false
}

var (
	// jsonDepsRE and jsonLockRE are the fallback for a JSON head the decoder rejects (comments,
	// trailing commas).
	jsonDepsRE = regexp.MustCompile(`"(dependencies|devDependencies|peerDependencies|optionalDependencies)"\s*:\s*\{\s*("[^"]*"\s*:\s*"|\})`)
	jsonLockRE = regexp.MustCompile(`"lockfileVersion"\s*:`)
)

func jsCandidateContent(path string, head []byte) (string, bool) {
	if docExts[strings.ToLower(filepath.Ext(path))] {
		return "", false
	}
	if head == nil {
		return buildtree.NULHeadMatch(path, jsCandidateContent)
	}
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(head, []byte("\xef\xbb\xbf")), " \t\r\n")
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return jsonManifestShape(trimmed)
	}
	src := string(head)
	if strings.Contains(src, "# yarn lockfile v1") {
		return "yarn lock content", true
	}
	topLevel := map[string]bool{}
	for _, l := range strings.Split(src, "\n") {
		if k, _, ok := strings.Cut(strings.TrimRight(l, "\r"), ":"); ok && k != "" && k == strings.TrimSpace(k) {
			topLevel[k] = true
		}
	}
	switch {
	case topLevel["__metadata"]:
		return "yarn lock content", true
	case topLevel["lockfileVersion"] && (topLevel["importers"] || topLevel["packages"] || topLevel["specifiers"] || topLevel["dependencies"]):
		return "pnpm lock content", true
	}
	return "", false
}

// jsonManifestShape reports whether a JSON object head has the top-level shape of a package
// manifest (a dependency field mapping names to string specs), a lockfile (lockfileVersion), or
// an import map that names npm packages. A head cut off at buildtree.HeadSize is judged on the
// keys it reaches; a dependency field cut off mid-value counts.
func jsonManifestShape(head []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(head))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return regexShape(head)
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return truncatedOr(err, head)
		}
		key, _ := t.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if slices.Contains(lockedDependencyFields, key) && truncated(err) {
				return "package manifest content", true
			}
			return truncatedOr(err, head)
		}
		switch {
		case key == "lockfileVersion":
			return "lockfile content", true
		case slices.Contains(lockedDependencyFields, key):
			var deps map[string]string
			if json.Unmarshal(raw, &deps) == nil {
				return "package manifest content", true
			}
		case key == "imports":
			var imports map[string]string
			if json.Unmarshal(raw, &imports) == nil {
				for _, v := range imports {
					if strings.HasPrefix(v, "npm:") {
						return "import map content", true
					}
				}
			}
		}
	}
	return "", false
}

func truncated(err error) bool {
	return errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF)
}

// truncatedOr ends a scan: a head that ran out has no more keys to judge, and one the decoder
// rejects falls back to regexShape.
func truncatedOr(err error, head []byte) (string, bool) {
	if truncated(err) {
		return "", false
	}
	return regexShape(head)
}

func regexShape(head []byte) (string, bool) {
	switch {
	case jsonLockRE.Match(head):
		return "lockfile content", true
	case jsonDepsRE.Match(head):
		return "package manifest content", true
	}
	return "", false
}
