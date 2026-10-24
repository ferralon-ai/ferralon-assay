package jsanalysis

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// A non-frozen pnpm install first asks whether the lock is up to date and re-resolves from the
// manifests when it is not, so the layout the build installs is not the lock's. A frozen install
// skips the question and refuses instead. The lane cannot see which install runs (non-CI,
// --no-frozen-lockfile and a CI opt-out are all non-frozen), so each place pnpm's decision turns
// on something outside the lock withholds unless the tree proves pnpm keeps the lock. The
// functions below mirror, in pnpm 10.34.8 and 11.20.0 (identical in both):
//
//   - getOutdatedLockfileSetting (@pnpm/lockfile.settings-checker), with the migrated "pnpm"
//     keys of package.json that pnpm 11 no longer reads (getIgnoredPnpmFieldKeys);
//   - localTarballDepsAreUpToDate and isLocalFileDepUpdated (@pnpm/lockfile.verification);
//   - linkedPackagesAreUpToDate (@pnpm/lockfile.verification).

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

// readLocalResolution reads res, a resolution mapping written in block or flow form. ok is false
// for a local source the lane cannot read exactly: a quoted value, or a flow map it cannot split.
func readLocalResolution(res *ynode) (r localResolution, ok bool) {
	if res == nil {
		return r, true
	}
	var tarball, dir, typ string
	if len(res.kids) > 0 {
		for _, k := range []string{"tarball", "directory", "type", "integrity"} {
			if c := res.child(k); c != nil && (c.quoted || len(c.kids) > 0 || len(c.items) > 0) {
				return r, false
			}
		}
		tarball, dir, typ, r.integrity = res.child("tarball").str(), res.child("directory").str(), res.child("type").str(), res.child("integrity").str()
	} else {
		if !strings.Contains(res.val, "directory") && !strings.Contains(res.val, "file:") {
			return r, true
		}
		body, closed := strings.CutPrefix(strings.TrimSpace(res.val), "{")
		body, closed2 := strings.CutSuffix(body, "}")
		if !closed || !closed2 || strings.ContainsAny(body, "\"'{}[]") {
			return r, false
		}
		for _, part := range strings.Split(body, ",") {
			k, v, found := strings.Cut(part, ": ")
			if !found {
				return r, false
			}
			v = strings.TrimSpace(v)
			switch strings.TrimSpace(k) {
			case "tarball":
				tarball = v
			case "directory":
				dir = v
			case "type":
				typ = v
			case "integrity":
				r.integrity = v
			}
		}
	}
	switch {
	case typ == "directory" || dir != "":
		r.kind, r.rel = "directory", dir
	case strings.HasPrefix(tarball, "file:"):
		r.kind, r.rel = "tarball", strings.TrimPrefix(tarball, "file:")
	}
	return r, true
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
//     sha512 of the file now on disk, or pnpm re-resolves. The lane never read that file, so a
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
			sum := sha512.Sum512(data)
			if r.integrity != "sha512-"+base64.StdEncoding.EncodeToString(sum[:]) {
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

// localDirectoryHolds applies isLocalFileDepUpdated to the directory rel, whose package is
// recorded by meta (packages) and snap (the dependency edges: packages, or snapshots in 9.0).
func (p *pnpmLock) localDirectoryHolds(rel string, meta, snap *ynode) bool {
	dir, ok := p.localPath(rel)
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
			locked, _, _ = strings.Cut(locked, "(")
			if strings.HasPrefix(spec, "npm:") || locked != spec && !rangeSatisfied(locked, spec) {
				return false
			}
		}
	}
	return true
}

// noMemberShadow mirrors linkedPackagesAreUpToDate for a registry-locked dependency. With
// link-workspace-packages on, a workspace member with the dependency's name and exactly its
// locked version makes pnpm see a link where the lock holds a registry copy, so it re-resolves
// and links the member: the lane would analyse the registry bytes while pnpm installs the
// member's source. The setting is not read here. pnpm 10 takes it from .npmrc, pnpm 11 from
// pnpm-workspace.yaml (which the lane withholds), pnpm 8 defaults it on, and a command-line flag or
// environment variable sets it where the tree cannot show it; so a matching member withholds
// whatever the files say. pnpm also requires the member's version to satisfy the specifier, which
// holds for a lock that passed the importer's version-in-range check, so it is not retested.
func (p *pnpmLock) noMemberShadow(cfg *pnpmConfig) bool {
	for _, rec := range p.imps {
		for _, fields := range rec.fields {
			for name, v := range fields {
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
