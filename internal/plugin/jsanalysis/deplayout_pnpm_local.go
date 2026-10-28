package jsanalysis

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// A non-frozen pnpm install first asks whether the lock is up to date and re-resolves from the
// manifests when it is not, so the layout the build installs is not the lock's. A frozen install
// skips the question and refuses instead. The lane cannot see which install runs (non-CI,
// --no-frozen-lockfile and a CI opt-out are all non-frozen), so each place pnpm's decision turns
// on something outside the lock withholds unless the tree proves pnpm keeps the lock.
//
// Each gate below takes its inputs from exactly what the pnpm function it mirrors reads (pnpm
// 10.34.8 and 11.20.0, identical in both). Where the lane's data comes from elsewhere, the gate
// withholds unless that data is byte-equal to pnpm's input.
//
// getOutdatedLockfileSetting (@pnpm/lockfile.settings-checker) reads, from the lock root:
// catalogs, overrides, packageExtensionsChecksum, ignoredOptionalDependencies,
// patchedDependencies, settings.* and pnpmfileChecksum; and from the configuration the same
// names, where package.json "pnpm" keys are migrated (MIGRATED_PNPM_FIELD_KEYS) and pnpm 11 no
// longer reads them there. Gate: manifestPnpmInert, and checkConfig for the lock root.
//
// localTarballDepsAreUpToDate (@pnpm/lockfile.verification) reads, for every importer ref in
// dependencies, devDependencies and optionalDependencies: the ref itself (a "file:" ref that ends
// in .tgz, .tar.gz or .tar once the peer suffix is cut, parse5 and indexOfDepPathSuffix), the
// lock package at name@ref and its resolution.integrity, and the sha512 of
// join(lockfileDir, ref minus "file:"). It never reads resolution.tarball. Gate:
// importerLocalsHold.
//
// isLocalFileDepUpdated (@pnpm/lockfile.verification, reached from linkedPackagesAreUpToDate for
// an importer specifier that is a file: directory) reads the lock package at name@ref, its
// resolution.directory, the package.json found there, and its dependencies,
// optionalDependencies and peerDependencies against the lock package's. Gate: importerLocalsHold
// (the package must be a directory resolution) and localDirectoryHolds.
//
// linkedPackagesAreUpToDate reads, per importer dependency: the lock ref, the specifier, the
// workspace members' package.json files by directory, and the link-workspace-packages setting.
// Gate: noMemberShadow.

// maxLocalTarball caps the read of a file: tarball the lane hashes.
const maxLocalTarball = 128 << 20

// manifestPnpmInert reports whether the package.json "pnpm" field sets none of the three keys
// that change what a lock records and that pnpm 11 ignores there (MIGRATED_PNPM_FIELD_KEYS). pnpm
// 10 honours package.json pnpm.overrides, patchedDependencies and ignoredOptionalDependencies;
// pnpm 11 reads them from pnpm-workspace.yaml only, finds the lock's copy of each unmatched
// (getOutdatedLockfileSetting) and, installing without --frozen-lockfile, re-resolves without
// them. The lane cannot tell which pnpm runs (packageManager is a field a CI step can override,
// and the switch to the pinned version is off under manage-package-manager-versions=false in
// config or environment), so a set key withholds. An empty value withholds nothing.
func manifestPnpmInert(pnpm map[string]json.RawMessage) bool {
	for _, k := range []string{"overrides", "patchedDependencies", "ignoredOptionalDependencies"} {
		v, ok := pnpm[k]
		if !ok {
			continue
		}
		switch k {
		case "ignoredOptionalDependencies":
			var names []string
			if json.Unmarshal(v, &names) != nil || len(names) > 0 {
				return false
			}
		default:
			var m map[string]json.RawMessage
			if json.Unmarshal(v, &m) != nil || len(m) > 0 {
				return false
			}
		}
	}
	return true
}

// localResolution is the part of a lock package's resolution that names a local source.
type localResolution struct {
	kind      string // "tarball", "directory", or "" for any other resolution
	rel       string // path relative to the lock's directory
	integrity string
}

// localKeys are the resolution keys a local source (a file: tarball or a directory) is written
// with; any other key in such a resolution is not read.
var localKeys = map[string]bool{"tarball": true, "directory": true, "type": true, "integrity": true}

// readLocalResolution reads res, a resolution mapping written in block or flow form. ok is false
// for a local source the lane cannot read exactly: a block value that is quoted, empty or
// nested, a flow map outside the grammar flowScalar and flowKey define, a duplicate key, an
// empty tarball, type or integrity, a directory source without both "type: directory" and a
// directory (possibly the empty root), and a key outside localKeys. The empty directory is the
// lock's own directory and is read only from the flow form pnpm writes, {directory: ”, ...}.
func readLocalResolution(res *ynode) (r localResolution, ok bool) {
	if res == nil {
		return r, true
	}
	var tarball, dir, typ string
	var hasDir bool
	var keys []string
	if len(res.kids) > 0 {
		for _, k := range []string{"tarball", "directory", "type", "integrity"} {
			if c := res.child(k); c != nil && (c.quoted || c.val == "" || len(c.kids) > 0 || len(c.items) > 0) {
				return r, false
			}
		}
		keys = res.keys
		tarball, dir, typ, r.integrity = res.child("tarball").str(), res.child("directory").str(), res.child("type").str(), res.child("integrity").str()
		hasDir = res.child("directory") != nil
	} else {
		if !strings.Contains(res.val, "directory") && !strings.Contains(res.val, "file:") {
			return r, true
		}
		body, closed := strings.CutPrefix(strings.TrimSpace(res.val), "{")
		body, closed2 := strings.CutSuffix(body, "}")
		if !closed || !closed2 {
			return r, false
		}
		seen := map[string]bool{}
		for _, part := range strings.Split(body, ", ") {
			k, v, found := strings.Cut(part, ": ")
			if !found || !flowKey(k) || seen[k] {
				return r, false
			}
			seen[k] = true
			keys = append(keys, k)
			v, ok := flowScalar(v)
			if !ok {
				return r, false
			}
			switch k {
			case "tarball":
				tarball = v
			case "directory":
				dir, hasDir = v, true
			case "type":
				typ = v
			case "integrity":
				r.integrity = v
			}
		}
		if seen["tarball"] && tarball == "" || seen["type"] && typ == "" || seen["integrity"] && r.integrity == "" {
			return r, false
		}
	}
	local := hasDir || typ == "directory" || strings.HasPrefix(tarball, "file:")
	if local {
		for _, k := range keys {
			if !localKeys[k] {
				return r, false
			}
		}
	}
	switch {
	case hasDir || typ == "directory":
		if !hasDir || typ != "directory" || tarball != "" {
			return r, false
		}
		r.kind, r.rel = "directory", dir
	case strings.HasPrefix(tarball, "file:"):
		r.kind, r.rel = "tarball", strings.TrimPrefix(tarball, "file:")
	}
	return r, true
}

// flowKey reports whether k is a flow-map key the lane reads: ASCII letters, digits, "_" and "-".
func flowKey(k string) bool {
	if k == "" {
		return false
	}
	for _, c := range k {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// flowScalar reads one value of a flow mapping from a closed grammar: a single-quoted scalar
// whose only escape is a doubled quote, or a plain scalar of the characters in plainFlowChar
// (no comma, space, bracket, brace, quote or "#"), starting with a letter, digit, "." or "/" and
// not ending in ":". Anything else is not read, and neither is a quoted value a ", " split may
// have cut. An empty quoted scalar is returned as "" and the caller decides what that means.
func flowScalar(v string) (string, bool) {
	if inner, ok := strings.CutPrefix(v, "'"); ok {
		inner, ok = strings.CutSuffix(inner, "'")
		if !ok || strings.Contains(strings.ReplaceAll(inner, "''", ""), "'") {
			return "", false
		}
		return strings.ReplaceAll(inner, "''", "'"), true
	}
	if v == "" || strings.HasSuffix(v, ":") {
		return "", false
	}
	for i, c := range v {
		if !plainFlowChar(c) || i == 0 && !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '/') {
			return "", false
		}
	}
	return v, true
}

func plainFlowChar(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._/@:+=~^%-", c)
}

// localPath resolves rel (relative to the lock's directory) under the region root. A path the
// lane cannot confine to the root is not read.
func (p *pnpmLock) localPath(rel string) (string, bool) {
	if rel == "" || path.IsAbs(rel) || filepath.IsAbs(rel) || strings.ContainsAny(rel, "\\\x00") ||
		slices.Contains(strings.Split(rel, "/"), "..") {
		return "", false
	}
	return filepath.Join(p.root, filepath.FromSlash(rel)), true
}

// localSourcesHold reports whether pnpm keeps the lock for every file: dependency the lock
// pins; false when a non-frozen install would re-resolve it, or when the lane cannot tell.
//
//   - A file: tarball (localTarballDepsAreUpToDate): the lock's integrity must equal the
//     sha512 of the file the importer's ref names (importerLocalsHold), or pnpm re-resolves; the
//     loop below also hashes every other tarball resolution. The lane never read that file, so a
//     tarball swapped after locking laid out as the lock's version with the lock's dependencies.
//   - A file: directory (isLocalFileDepUpdated): the directory's package.json
//     dependencies, optionalDependencies and peerDependencies must name exactly the names the
//     lock's package records, each locked version satisfying its specifier (file:, link: and
//     workspace: specifiers are skipped). devDependencies are not compared. The lane never read the
//     directory, so a changed dependency left the lock's transitive pin in the layout.
//
// pnpm runs both checks for an importer's own dependencies only; the lane runs them for every
// local source the lock pins, which can only withhold more. A peer dependency on either side, an
// npm: alias, and any specifier the lane's range matcher does not model withhold.
func (p *pnpmLock) localSourcesHold() bool {
	if !p.importerLocalsHold() {
		return false
	}
	pkgs, src := p.doc.child("packages"), p.doc.child("packages")
	if p.version == "9.0" {
		src = p.doc.child("snapshots")
	}
	for _, k := range p.keys {
		m := pkgs.child(k)
		if p.version == "9.0" {
			m = pkgs.child(stripPeerSuffix(k))
		}
		r, ok := readLocalResolution(m.child("resolution"))
		if !ok {
			return false
		}
		switch r.kind {
		case "tarball":
			file, ok := p.localPath(r.rel)
			if !ok {
				return false
			}
			data, ok := readInRoot(p.root, file, maxLocalTarball)
			if !ok {
				return false
			}
			if r.integrity != sha512SRI(data) {
				return false
			}
		case "directory":
			if !p.localDirectoryHolds(r.rel, m, src.child(k)) {
				return false
			}
		}
	}
	return true
}

func sha512SRI(data []byte) string {
	sum := sha512.Sum512(data)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

// refWithoutSuffix cuts the peer-dependency and patch suffix off a lock ref the way pnpm's
// indexOfDepPathSuffix does: only a ref that ends in ")" has one, starting at the "(" group that
// closes the ref.
func refWithoutSuffix(ref string) string {
	if !strings.HasSuffix(ref, ")") {
		return ref
	}
	open := 1
	for i := len(ref) - 2; i >= 0; i-- {
		switch ref[i] {
		case '(':
			open--
		case ')':
			open++
		default:
			if open == 0 {
				return ref[:i+1]
			}
		}
	}
	return ref
}

// localTarballRef reports whether ref (peer suffix already cut) is a local tarball ref, as
// refIsLocalTarball.
func localTarballRef(ref string) bool {
	return strings.HasPrefix(ref, "file:") && (strings.HasSuffix(ref, ".tgz") || strings.HasSuffix(ref, ".tar.gz") || strings.HasSuffix(ref, ".tar"))
}

// importerLocalsHold walks the importers' file: refs the way localTarballDepsAreUpToDate and
// isLocalFileDepUpdated do. Each ref names the lock package name@ref (absent: pnpm re-resolves);
// a tarball ref's file is the path in the ref and its integrity the package's own, and the
// package's resolution.tarball must be that same path; a directory ref's package must be a
// directory resolution. Lock versions whose keys the lane does not map to name@ref withhold.
func (p *pnpmLock) importerLocalsHold() bool {
	pkgs := p.doc.child("packages")
	for _, rec := range p.imps {
		for _, fields := range rec.fields {
			for name, ref := range fields {
				if !strings.HasPrefix(ref, "file:") {
					continue
				}
				var key string
				switch p.version {
				case "9.0":
					key = name + "@" + ref
				case "6.0":
					key = "/" + name + "@" + ref
				default:
					return false
				}
				if p.byKey[key] == nil {
					return false
				}
				meta := pkgs.child(key)
				if p.version == "9.0" {
					meta = pkgs.child(stripPeerSuffix(key))
				}
				r, ok := readLocalResolution(meta.child("resolution"))
				if !ok {
					return false
				}
				tr := refWithoutSuffix(ref)
				if !localTarballRef(tr) {
					if r.kind != "directory" {
						return false
					}
					continue
				}
				rel := strings.TrimPrefix(tr, "file:")
				if r.kind != "tarball" || r.rel != rel || r.integrity == "" {
					return false
				}
				file, ok := p.localPath(rel)
				if !ok {
					return false
				}
				data, ok := readInRoot(p.root, file, maxLocalTarball)
				if !ok || r.integrity != sha512SRI(data) {
					return false
				}
			}
		}
	}
	return true
}

// localDirectoryHolds applies isLocalFileDepUpdated to the directory rel, whose package is
// recorded by meta (packages) and snap (the dependency edges: packages, or snapshots in 9.0).
func (p *pnpmLock) localDirectoryHolds(rel string, meta, snap *ynode) bool {
	dir, ok := p.root, true
	if rel != "" {
		dir, ok = p.localPath(rel)
	}
	if !ok {
		return false
	}
	data, ok := readInRoot(p.root, filepath.Join(dir, "package.json"), maxStyleManifest)
	if !ok {
		return false
	}
	var man map[string]json.RawMessage
	if json.Unmarshal(data, &man) != nil {
		return false
	}
	// Node reads a key exactly; the field lookups below do the same.
	field := func(k string) (map[string]string, bool) {
		out := map[string]string{}
		if v, ok := man[k]; ok && json.Unmarshal(v, &out) != nil {
			return nil, false
		}
		return out, true
	}
	if peers, ok := field("peerDependencies"); !ok || len(peers) > 0 {
		return false
	}
	if lp, ok := meta.child("peerDependencies").scalars(); !ok || len(lp) > 0 {
		return false
	}
	for _, f := range []string{"dependencies", "optionalDependencies"} {
		want, ok := field(f)
		if !ok {
			return false
		}
		have, ok := snap.child(f).scalars()
		if !ok {
			return false
		}
		for name := range have {
			if want[name] == "" {
				return false
			}
		}
		for name, spec := range want {
			locked := have[name]
			if spec == "" || locked == "" {
				return false
			}
			if strings.HasPrefix(spec, "file:") || strings.HasPrefix(spec, "link:") || strings.HasPrefix(spec, "workspace:") {
				continue
			}
			// Deliberate deviation from pnpm: its semver.satisfies reads a peer-suffixed locked
			// value as no version and re-resolves. The lane compares the bare version, so a
			// suffixed lock is read where pnpm re-resolves; a re-resolve with nothing else changed
			// should reproduce the lock (not run on a binary).
			locked, _, _ = strings.Cut(locked, "(")
			if strings.HasPrefix(spec, "npm:") || locked != spec && !rangeSatisfied(locked, spec) {
				return false
			}
		}
	}
	return true
}

// noMemberShadow mirrors linkedPackagesAreUpToDate (pnpm 10.34.8 and 11.20.0), which compares
// what the lock links with what the workspace members now offer. The link-workspace-packages
// setting is not read: pnpm 10 takes it from .npmrc, pnpm 11 from pnpm-workspace.yaml, pnpm 8
// defaults it on, and a command-line flag or environment variable sets it where the tree cannot
// show it. Both halves therefore withhold whatever the files say.
//
//   - Registry half: with the setting on, a workspace member with the dependency's name and
//     exactly its locked version makes pnpm see a link where the lock holds a registry copy
//     (isLinked false, the member satisfies the range), so it re-resolves and links the member:
//     the lane would analyse the registry bytes while pnpm installs the member's source. pnpm
//     also requires the member's version to satisfy the specifier, which holds for a lock that
//     passed the importer's version-in-range check, so it is not retested.
//   - Link half: a dependency locked as link: whose specifier is a semver range is re-resolved
//     to the registry when the member it links no longer satisfies that range (isLinked true,
//     localPackageSatisfiesRange false). pnpm skips link:, file: and workspace:. specifiers, a
//     dist-tag, and the ranges "*", "^" and "~" (after getVersionRange, so an npm: alias is
//     tested by its range). The member is looked up among the workspace manifests; one that is
//     missing cannot be read here, so it withholds.
func (p *pnpmLock) noMemberShadow(cfg *pnpmConfig) bool {
	for key, rec := range p.imps {
		dir := strings.TrimPrefix(strings.TrimPrefix(key, p.region.prefix), "/")
		if dir == "" {
			dir = "."
		}
		for _, fields := range rec.fields {
			for name, v := range fields {
				if target, linked := strings.CutPrefix(v, "link:"); linked {
					if !p.linkHolds(cfg, rec.specifiers[name], path.Join(dir, target)) {
						return false
					}
					continue
				}
				// Deliberate over-approximation: pnpm looks the member up by the whole ref, peer
				// suffix included, so a suffixed ref never matches a member; cutting the suffix
				// withholds a tree pnpm keeps.
				v, _, _ = strings.Cut(v, "(")
				for _, m := range cfg.manifests {
					ver := m.Version
					if ver == "" {
						ver = "0.0.0"
					}
					if m.Name == name && ver == v {
						return false
					}
				}
			}
		}
	}
	return true
}

// linkHolds reports whether the member at memberDir still satisfies spec, the specifier of a
// dependency the lock links. pnpm returns early for link:, file: and "workspace:." specifiers
// and for a dist-tag, then tests getVersionRange(spec) against the member's version. The lane
// skips every workspace: specifier: pnpm's test fails for an out-of-range member under
// workspace:^1.0.0, but the re-resolve under the workspace protocol keeps the member link, so
// the outcome is the same (checked on pnpm 10 and 11).
func (p *pnpmLock) linkHolds(cfg *pnpmConfig, spec, memberDir string) bool {
	switch {
	case strings.HasPrefix(spec, "link:"), strings.HasPrefix(spec, "file:"), strings.HasPrefix(spec, "workspace:"):
		return true
	case npmTagSpec.MatchString(spec):
		return true
	}
	rng := versionRange(spec)
	if rng == "*" || rng == "^" || rng == "~" {
		return true
	}
	m := cfg.manifests[memberDir]
	return m != nil && rangeSatisfied(m.Version, rng)
}

// versionRange is pnpm's getVersionRange for a specifier that is not workspace:. An npm: alias
// reads as the range after the alias name's "@", or "*" when there is none.
func versionRange(spec string) string {
	rest, ok := strings.CutPrefix(spec, "npm:")
	if !ok {
		return spec
	}
	i := strings.IndexByte(rest[min(1, len(rest)):], '@')
	if i < 0 {
		return "*"
	}
	if r := rest[1+i+1:]; r != "" {
		return r
	}
	return "*"
}

// npmTagSpec matches a dist-tag specifier. A name beginning with v or x could be a range
// (v1, x), so it is not taken for a tag.
var npmTagSpec = regexp.MustCompile(`^[A-UWYZa-uwyz][A-Za-z0-9._-]*$`)
