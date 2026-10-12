package jsanalysis

import "testing"

// Exhaustive is claimed only when complete lockfiles cover every package.json and every name
// it declares; anything weaker fails open.
func TestResolveVersions_Exhaustive(t *testing.T) {
	const (
		pkgJSON        = `{"name":"app","dependencies":{"express":"^4.18.0"},"devDependencies":{"left-pad":"^1.3.0"}}`
		pkgJSONPeer    = `{"name":"app","dependencies":{"express":"^4.18.0"},"peerDependencies":{"react":">=18"}}`
		pkgJSONMissing = `{"name":"app","dependencies":{"express":"^4.18.0","lodash":"^4.17.0"}}`
		yarnLock       = "# yarn lockfile v1\n\nexpress@^4.18.0:\n  version \"4.18.2\"\n\nleft-pad@^1.3.0:\n  version \"1.3.0\"\n"
		pnpmLock       = "lockfileVersion: '6.0'\n\npackages:\n\n  /express@4.18.2:\n    resolution: {integrity: sha512-x}\n\n  /left-pad@1.3.0:\n    resolution: {integrity: sha512-y}\n"
	)
	tests := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"unlocked peer fails open", map[string]string{"package.json": pkgJSONPeer, "package-lock.json": packageLockV3}, false},
		{"package-lock covers package.json", map[string]string{"package.json": pkgJSON, "package-lock.json": packageLockV3}, true},
		{"root project is the coordinate", map[string]string{"package.json": `{"name":"Absent-Package","dependencies":{"express":"^4"}}`, "package-lock.json": packageLockV3}, false},
		{"yarn.lock", map[string]string{"package.json": pkgJSON, "yarn.lock": yarnLock}, true},
		{"pnpm-lock", map[string]string{"package.json": pkgJSON, "pnpm-lock.yaml": pnpmLock}, true},
		{"declared name missing from lock", map[string]string{"package.json": pkgJSONMissing, "package-lock.json": packageLockV3}, false},
		{"nested package.json covered by the root lock", map[string]string{"package.json": pkgJSON, "package-lock.json": packageLockV3, "tools/package.json": pkgJSON}, true},
		{"nested package.json declaring an unlocked name", map[string]string{"package.json": pkgJSON, "package-lock.json": packageLockV3, "tools/package.json": pkgJSONMissing}, false},
		{"lock only in a subproject", map[string]string{"package.json": pkgJSON, "web/package-lock.json": packageLockV3, "web/package.json": pkgJSON}, false},
		{"package.json only", map[string]string{"package.json": pkgJSON}, false},
		{"malformed lock", map[string]string{"package.json": pkgJSON, "package-lock.json": "{not json"}, false},
		{"malformed package.json", map[string]string{"package.json": "{", "package-lock.json": packageLockV3}, false},
		{"workspace package defines the coordinate", map[string]string{"package.json": pkgJSON, "package-lock.json": packageLockV3, "packages/absent-package/package.json": `{"name":"absent-package"}`}, false},
		{"node_modules package.json ignored", map[string]string{"package.json": pkgJSON, "package-lock.json": packageLockV3, "node_modules/x/package.json": pkgJSONMissing}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveJS(t, writeLockTree(t, tt.files), "absent-package")
			if r.Found {
				t.Fatalf("absent-package unexpectedly found")
			}
			if r.Exhaustive != tt.want {
				t.Fatalf("Exhaustive = %v, want %v (partiality %+v)", r.Exhaustive, tt.want, r.Partiality)
			}
		})
	}
}

// Lockfile dev/optional flags are never evidence of absence: a dev-only locked package is present.
func TestResolveVersions_DevLockedPackagePresent(t *testing.T) {
	const devLock = `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "app", "version": "1.0.0" },
    "node_modules/jest": { "version": "29.7.0", "dev": true },
    "node_modules/fsevents": { "version": "2.3.3", "optional": true }
  }
}`
	tests := []struct{ name, coord, version string }{
		{"dev flag", "jest", "29.7.0"},
		{"optional flag", "fsevents", "2.3.3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveJS(t, writeLockTree(t, map[string]string{"package.json": `{"name":"app"}`, "package-lock.json": devLock}), tt.coord)
			if !r.Found || r.Match.Version != tt.version {
				t.Fatalf("%s not reported present: found=%v match=%+v", tt.coord, r.Found, r.Match)
			}
		})
	}
}
