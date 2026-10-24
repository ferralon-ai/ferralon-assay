package jsanalysis

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"maps"
	"strings"
	"testing"
)

// nonFrozenWithheld builds the layout of a tree and reports whether the lane withholds it.
func nonFrozenWithheld(t *testing.T, files map[string]string) bool {
	t.Helper()
	return buildDepLayout(context.Background(), writeProgram(t, files)).incomplete
}

func sriOf(data string) string {
	sum := sha512.Sum512([]byte(data))
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

var fillerIntegrity = sriOf("registry bytes")

// TestPnpmNonFrozenManifestKeys: pnpm 11 ignores package.json pnpm.overrides,
// patchedDependencies and ignoredOptionalDependencies, so a non-frozen install under it
// re-resolves a tree whose lock recorded them. Each tree's lock matches its manifest, which is
// what pnpm 10 reads as up to date.
func TestPnpmNonFrozenManifestKeys(t *testing.T) {
	lock := func(extraRoot string) string {
		return "lockfileVersion: '9.0'\n\n" + extraRoot + "importers:\n\n  .:\n    dependencies:\n      o:\n        specifier: 1.0.0\n        version: 1.0.0\n\n" +
			"packages:\n\n  o@1.0.0:\n    resolution: {integrity: " + fillerIntegrity + "}\n\n  q@2.0.0:\n    resolution: {integrity: " + fillerIntegrity + "}\n\n" +
			"snapshots:\n\n  o@1.0.0:\n    dependencies:\n      q: 2.0.0\n\n  q@2.0.0: {}\n"
	}
	patch := "diff --git a/lib/x.js b/lib/x.js\nindex 1111111..2222222 100644\n--- a/lib/x.js\n+++ b/lib/x.js\n@@ -1,2 +1,2 @@\n a\n-b\n+c\n"
	patchedLock := strings.Replace(strings.Replace(lock("patchedDependencies:\n  q@2.0.0:\n    hash: abc\n    path: patches/q.patch\n\n"),
		"  q@2.0.0: {}", "  q@2.0.0(patch_hash=abc): {}", 1), "      q: 2.0.0\n", "      q: 2.0.0(patch_hash=abc)\n", 1)
	man := func(pnpm string) string {
		return `{"name":"root","version":"1.0.0","private":true,"dependencies":{"o":"1.0.0"}` + pnpm + `}`
	}
	for name, tc := range map[string]struct {
		files    map[string]string
		withheld bool
	}{
		// pnpm 10 honours these and 11 does not (probe fx/p2, pnpm 10.34.8 and 11.20.0).
		"overrides_manifest": {map[string]string{
			"package.json": man(`,"pnpm":{"overrides":{"q":"2.0.0"}}`), "pnpm-lock.yaml": lock("overrides:\n  q: 2.0.0\n\n")}, true},
		"patched_manifest": {map[string]string{
			"package.json": man(`,"pnpm":{"patchedDependencies":{"q@2.0.0":"patches/q.patch"}}`), "patches/q.patch": patch, "pnpm-lock.yaml": patchedLock}, true},
		"ignored_optional_manifest": {map[string]string{
			"package.json": man(`,"pnpm":{"ignoredOptionalDependencies":["fsevents"]}`), "pnpm-lock.yaml": lock("ignoredOptionalDependencies:\n  - fsevents\n\n")}, true},
		"ignored_optional_lock_only": {map[string]string{
			"package.json": man(""), "pnpm-lock.yaml": lock("ignoredOptionalDependencies:\n  - fsevents\n\n")}, true},
		// Controls: the workspace file is read by both versions; empty values set nothing.
		"control_patched_workspace": {map[string]string{
			"package.json": man(""), "pnpm-workspace.yaml": "patchedDependencies:\n  q@2.0.0: patches/q.patch\n", "patches/q.patch": patch, "pnpm-lock.yaml": patchedLock}, false},
		"control_empty_values": {map[string]string{
			"package.json": man(`,"pnpm":{"overrides":{},"patchedDependencies":{},"ignoredOptionalDependencies":[]}`), "pnpm-lock.yaml": lock("")}, false},
		"control_no_pnpm_field": {map[string]string{"package.json": man(""), "pnpm-lock.yaml": lock("")}, false},
		"control_unrelated_key": {map[string]string{
			"package.json": man(`,"pnpm":{"onlyBuiltDependencies":["esbuild"]}`), "pnpm-lock.yaml": lock("")}, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := nonFrozenWithheld(t, tc.files); got != tc.withheld {
				t.Errorf("withheld = %v, want %v", got, tc.withheld)
			}
		})
	}
	// The install-surface veto withholds any pnpm-workspace.yaml that sets overrides, so this
	// control is asserted where the manifest gate sits: the config read.
	t.Run("control_overrides_workspace_config", func(t *testing.T) {
		dir := writeProgram(t, map[string]string{
			"package.json": man(""), "pnpm-workspace.yaml": "overrides:\n  q: 2.0.0\n", "pnpm-lock.yaml": lock("overrides:\n  q: 2.0.0\n\n")})
		if _, ok := readPnpmConfig(dir); !ok {
			t.Error("workspace-file overrides must be read")
		}
	})
}

// localLock is a 9.0 lock whose root importer installs one local source, x, plus the registry
// package q that x's snapshot records.
func localLock(spec, resolution, snapshot string) string {
	return "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      x:\n        specifier: " + spec + "\n        version: " + spec + "\n\n" +
		"packages:\n\n  q@1.0.0:\n    resolution: {integrity: " + fillerIntegrity + "}\n\n  x@" + spec + ":\n    resolution: " + resolution + "\n    version: 1.0.0\n\n" +
		"snapshots:\n\n  q@1.0.0: {}\n\n  x@" + spec + snapshot + "\n"
}

func rootManifest(deps string) string {
	return `{"name":"root","version":"1.0.0","private":true,"dependencies":` + deps + `}`
}

// TestPnpmNonFrozenLocalTarball: localTarballDepsAreUpToDate hashes a file: tarball and
// re-resolves when its integrity differs from the lock's (probe fx/p1c-swapped: x@1.0.1 with a
// new dependency q installed by pnpm 10.34.8 and 11.20.0 outside a frozen install).
func TestPnpmNonFrozenLocalTarball(t *testing.T) {
	const spec = "file:vendor/x.tgz"
	locked := "tarball bytes at lock time"
	tree := func(tgz *string, resolution string) map[string]string {
		f := map[string]string{
			"package.json":   rootManifest(`{"x":"` + spec + `"}`),
			"pnpm-lock.yaml": localLock(spec, resolution, ": {}"),
		}
		if tgz != nil {
			f["vendor/x.tgz"] = *tgz
		}
		return f
	}
	res := func(integrity string) string {
		return "{integrity: " + integrity + ", tarball: " + spec + "}"
	}
	block := func(integrity string) string { return "\n      integrity: " + integrity + "\n      tarball: " + spec }
	swapped, same := "tarball bytes after a swap", locked
	for name, tc := range map[string]struct {
		files    map[string]string
		withheld bool
	}{
		"swapped_after_lock":   {tree(&swapped, res(sriOf(locked))), true},
		"missing":              {tree(nil, res(sriOf(locked))), true},
		"lock_integrity_sha1":  {tree(&same, res("sha1-"+base64.StdEncoding.EncodeToString([]byte("0123456789abcdefghij")))), true},
		"block_form_swapped":   {tree(&swapped, block(sriOf(locked))), true},
		"control_unchanged":    {tree(&same, res(sriOf(locked))), false},
		"control_block_form":   {tree(&same, block(sriOf(locked))), false},
		"control_http_tarball": {registryHostedTarball(), false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := nonFrozenWithheld(t, tc.files); got != tc.withheld {
				t.Errorf("withheld = %v, want %v", got, tc.withheld)
			}
		})
	}
	t.Run("outside_root", func(t *testing.T) {
		f := tree(&same, res(sriOf(locked)))
		f["pnpm-lock.yaml"] = strings.ReplaceAll(f["pnpm-lock.yaml"], "vendor/x.tgz", "../x.tgz")
		f["package.json"] = strings.ReplaceAll(f["package.json"], "vendor/x.tgz", "../x.tgz")
		if !nonFrozenWithheld(t, f) {
			t.Error("a tarball the lane cannot confine to the root must withhold")
		}
	})
}

// registryHostedTarball is a registry-hosted tarball resolution, which pnpm never hashes locally.
func registryHostedTarball() map[string]string {
	return map[string]string{
		"package.json":   rootManifest(`{"x":"1.0.0"}`),
		"pnpm-lock.yaml": localLock("1.0.0", "{integrity: "+fillerIntegrity+", tarball: https://registry.example/x/-/x-1.0.0.tgz}", ": {}"),
	}
}

// TestPnpmNonFrozenLocalDirectory: isLocalFileDepUpdated compares a file: directory's
// dependencies with the lock's snapshot, and re-resolves on any difference (probe
// fx/p1d-file-chg and p1d-file-newdep: q moved to 2.0.0, and a new r installed, outside a frozen
// install). devDependencies are not compared.
func TestPnpmNonFrozenLocalDirectory(t *testing.T) {
	const spec = "file:libs/x"
	tree := func(pkg string) map[string]string {
		f := map[string]string{
			"package.json": rootManifest(`{"x":"` + spec + `"}`),
			"pnpm-lock.yaml": localLock(spec, "{directory: libs/x, type: directory}",
				":\n    dependencies:\n      q: 1.0.0"),
		}
		if pkg != "" {
			f["libs/x/package.json"] = pkg
		}
		return f
	}
	for name, tc := range map[string]struct {
		pkg      string
		withheld bool
	}{
		"dependency_range_moved":   {`{"name":"x","version":"1.0.0","dependencies":{"q":"2.0.0"}}`, true},
		"dependency_added":         {`{"name":"x","version":"1.0.0","dependencies":{"q":"1.0.0","r":"1.0.0"}}`, true},
		"dependency_removed":       {`{"name":"x","version":"1.0.0"}`, true},
		"moved_to_optional":        {`{"name":"x","version":"1.0.0","optionalDependencies":{"q":"1.0.0"}}`, true},
		"dist_tag":                 {`{"name":"x","version":"1.0.0","dependencies":{"q":"latest"}}`, true},
		"npm_alias":                {`{"name":"x","version":"1.0.0","dependencies":{"q":"npm:q@1.0.0"}}`, true},
		"peer_dependency":          {`{"name":"x","version":"1.0.0","dependencies":{"q":"1.0.0"},"peerDependencies":{"p":"1"}}`, true},
		"empty_specifier":          {`{"name":"x","version":"1.0.0","dependencies":{"q":""}}`, true},
		"not_json":                 {`{`, true},
		"manifest_missing":         {"", true},
		"control_unchanged":        {`{"name":"x","version":"1.0.0","dependencies":{"q":"1.0.0"}}`, false},
		"control_caret":            {`{"name":"x","version":"1.0.0","dependencies":{"q":"^1.0.0"}}`, false},
		"control_dev_not_compared": {`{"name":"x","version":"1.0.0","dependencies":{"q":"1.0.0"},"devDependencies":{"z":"9"}}`, false},
		"control_version_bumped":   {`{"name":"x","version":"9.9.9","dependencies":{"q":"1.0.0"}}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := nonFrozenWithheld(t, tree(tc.pkg)); got != tc.withheld {
				t.Errorf("withheld = %v, want %v", got, tc.withheld)
			}
		})
	}
	t.Run("outside_root", func(t *testing.T) {
		f := tree(`{"name":"x","dependencies":{"q":"1.0.0"}}`)
		f["pnpm-lock.yaml"] = strings.ReplaceAll(f["pnpm-lock.yaml"], "libs/x", "../x")
		if !nonFrozenWithheld(t, f) {
			t.Error("a directory outside the root must withhold")
		}
	})
	t.Run("control_link_specifier_skipped", func(t *testing.T) {
		f := tree(`{"name":"x","version":"1.0.0","dependencies":{"q":"1.0.0","z":"link:../z"}}`)
		f["pnpm-lock.yaml"] = strings.Replace(f["pnpm-lock.yaml"], "      q: 1.0.0", "      q: 1.0.0\n      z: link:../z", 1)
		if nonFrozenWithheld(t, f) {
			t.Error("a link: specifier is skipped by isLocalFileDepUpdated")
		}
	})
}

// TestPnpmNonFrozenMemberShadow: linkedPackagesAreUpToDate re-resolves a registry-locked
// dependency when a workspace member has its name and exactly its locked version and
// link-workspace-packages is on (probe fx/p1b-10: pnpm 10.34.8 installs packages/q in place of
// the registry q@1.0.0). The setting is never read (an .npmrc that sets it is withheld by the install-surface veto
// before this gate runs, so rows here carry none).
func TestPnpmNonFrozenMemberShadow(t *testing.T) {
	lock := func(depSpec, depVersion string) string {
		return "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  packages/app:\n    dependencies:\n      q:\n        specifier: " + depSpec +
			"\n        version: " + depVersion + "\n\n  packages/q: {}\n\n" +
			"packages:\n\n  q@1.0.0:\n    resolution: {integrity: " + fillerIntegrity + "}\n\nsnapshots:\n\n  q@1.0.0: {}\n"
	}
	tree := func(memberName, memberVersion string) map[string]string {
		return map[string]string{
			"package.json":              `{"name":"root","private":true}`,
			"pnpm-workspace.yaml":       "packages:\n  - 'packages/*'\n",
			"packages/app/package.json": `{"name":"app","version":"1.0.0","dependencies":{"q":"1.0.0"}}`,
			"packages/q/package.json":   fmt.Sprintf(`{"name":%q,"version":%q}`, memberName, memberVersion),
			"pnpm-lock.yaml":            lock("1.0.0", "1.0.0"),
		}
	}
	for name, tc := range map[string]struct {
		files    map[string]string
		withheld bool
	}{
		"same_version_member":          {tree("q", "1.0.0"), true},
		"control_member_other_version": {tree("q", "2.0.0"), false},
		"control_member_other_name":    {tree("q-local", "1.0.0"), false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := nonFrozenWithheld(t, tc.files); got != tc.withheld {
				t.Errorf("withheld = %v, want %v", got, tc.withheld)
			}
		})
	}
	t.Run("control_workspace_protocol", func(t *testing.T) {
		f := tree("q", "1.0.0")
		maps.Copy(f, map[string]string{
			"packages/app/package.json": `{"name":"app","version":"1.0.0","dependencies":{"q":"workspace:^1.0.0"}}`,
			"pnpm-lock.yaml":            lock("workspace:^1.0.0", "link:../q"),
		})
		if nonFrozenWithheld(t, f) {
			t.Error("a link: dependency is not a registry copy a member can shadow")
		}
	})
}
