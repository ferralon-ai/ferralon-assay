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
		// The lock does not record the setting: pnpm 10 re-resolves to apply it.
		"overrides_manifest_unrecorded": {map[string]string{
			"package.json": man(`,"pnpm":{"overrides":{"q":"2.0.0"}}`), "pnpm-lock.yaml": lock("")}, true},
		"patched_manifest_unrecorded": {map[string]string{
			"package.json": man(`,"pnpm":{"patchedDependencies":{"q@2.0.0":"patches/q.patch"}}`), "patches/q.patch": patch, "pnpm-lock.yaml": lock("")}, true},
		"ignored_optional_manifest_unrecorded": {map[string]string{
			"package.json": man(`,"pnpm":{"ignoredOptionalDependencies":["fsevents"]}`), "pnpm-lock.yaml": lock("")}, true},
		"ignored_optional_lock_flow": {map[string]string{
			"package.json": man(""), "pnpm-lock.yaml": lock("ignoredOptionalDependencies: [fsevents]\n\n")}, true},
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
	// pnpm 10 writes a bracketed path as a single-quoted flow value.
	const bracket = "file:vendor/x[1].tgz"
	quoted := func(integrity string) string { return "{integrity: " + integrity + ", tarball: '" + bracket + "'}" }
	bracketTree := func(bytes string) map[string]string {
		return map[string]string{
			"package.json":    rootManifest(`{"x":"` + bracket + `"}`),
			"pnpm-lock.yaml":  localLock(bracket, quoted(sriOf(locked)), ": {}"),
			"vendor/x[1].tgz": bytes,
		}
	}
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
		// A quoted flow value is unquoted and hashed; a swap is seen, an unchanged file is read.
		"quoted_flow_swapped":           {bracketTree(swapped), true},
		"control_quoted_flow_unchanged": {bracketTree(locked), false},
		"double_quoted_flow_swapped": {func() map[string]string {
			f := tree(&swapped, "{integrity: "+sriOf(locked)+", tarball: \""+spec+"\"}")
			return f
		}(), true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := nonFrozenWithheld(t, tc.files); got != tc.withheld {
				t.Errorf("withheld = %v, want %v", got, tc.withheld)
			}
		})
	}
	// The tarball pnpm hashes is the one the importer's ref names, whatever the resolution says.
	integ := sriOf(locked)
	for name, resolution := range map[string]string{
		"comma_in_value":     "{integrity: " + integ + ", tarball: file:vendor/x.tgz,y}",
		"comma_in_key":       "{integrity: " + integ + ", foo,tarball: file:vendor/x.tgz}",
		"other_path":         "{integrity: " + integ + ", tarball: file:vendor/y.tgz}",
		"empty_tarball":      "{integrity: " + integ + ", tarball: ''}",
		"unknown_key":        "{integrity: " + integ + ", tarball: file:vendor/x.tgz, extra: 1}",
		"duplicate_key":      "{integrity: " + integ + ", tarball: file:vendor/x.tgz, tarball: file:vendor/x.tgz}",
		"empty_integrity":    "{integrity: '', tarball: file:vendor/x.tgz}",
		"tarball_and_type":   "{integrity: " + integ + ", tarball: file:vendor/x.tgz, type: directory}",
		"directory_in_place": "{directory: vendor/x.tgz, type: directory}",
	} {
		t.Run(name+"_swapped", func(t *testing.T) {
			f := tree(&swapped, resolution)
			f["vendor/x.tgz,y"], f["vendor/y.tgz"] = locked, locked
			if !nonFrozenWithheld(t, f) {
				t.Errorf("resolution %s names no file the importer ref does, and the ref's file was swapped", resolution)
			}
		})
	}
	// The extensions refIsLocalTarball accepts; unchanged files are read as the lock's.
	for _, ext := range []string{".tgz", ".tar.gz", ".tar"} {
		t.Run("control_extension"+ext, func(t *testing.T) {
			ref := "file:vendor/x" + ext
			f := map[string]string{
				"package.json":   rootManifest(`{"x":"` + ref + `"}`),
				"pnpm-lock.yaml": localLock(ref, "{integrity: "+sriOf(locked)+", tarball: "+ref+"}", ": {}"),
				"vendor/x" + ext: locked,
			}
			if nonFrozenWithheld(t, f) {
				t.Error("an unchanged local tarball must be read")
			}
		})
	}
	// A ref that is not a tarball ref is read as a directory; a tarball resolution behind it
	// is not what pnpm compares.
	t.Run("tarball_resolution_behind_directory_ref", func(t *testing.T) {
		const ref = "file:vendor/x"
		f := map[string]string{
			"package.json":   rootManifest(`{"x":"` + ref + `"}`),
			"pnpm-lock.yaml": localLock(ref, "{integrity: "+sriOf(locked)+", tarball: "+ref+"}", ": {}"),
			"vendor/x":       locked,
		}
		if !nonFrozenWithheld(t, f) {
			t.Error("a directory-shaped ref whose package is a tarball resolution must withhold")
		}
	})
	// The importer's ref carries a peer suffix: pnpm cuts it before testing for a tarball and
	// before hashing.
	suffixedTarball := func(bytes string) map[string]string {
		const ref = "file:vendor/x.tgz"
		return map[string]string{
			"package.json": rootManifest(`{"x":"` + ref + `","react":"18.0.0"}`),
			"pnpm-lock.yaml": "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      react:\n        specifier: 18.0.0\n        version: 18.0.0\n" +
				"      x:\n        specifier: " + ref + "\n        version: " + ref + "(react@18.0.0)\n\n" +
				"packages:\n\n  react@18.0.0:\n    resolution: {integrity: " + fillerIntegrity + "}\n\n  x@" + ref + ":\n    resolution: {integrity: " + sriOf(locked) + ", tarball: " + ref + "}\n    version: 1.0.0\n    peerDependencies:\n      react: '*'\n\n" +
				"snapshots:\n\n  react@18.0.0: {}\n\n  x@" + ref + "(react@18.0.0):\n    dependencies:\n      react: 18.0.0\n",
			"vendor/x.tgz": bytes,
		}
	}
	t.Run("peer_suffixed_ref_swapped", func(t *testing.T) {
		if !nonFrozenWithheld(t, suffixedTarball(swapped)) {
			t.Error("a swapped tarball behind a peer-suffixed ref must withhold")
		}
	})
	t.Run("control_peer_suffixed_ref", func(t *testing.T) {
		if nonFrozenWithheld(t, suffixedTarball(locked)) {
			t.Error("an unchanged tarball behind a peer-suffixed ref must be read")
		}
	})
	// A tarball the lock pins that no importer names (here, one a directory package depends
	// on) is hashed too.
	t.Run("unreferenced_tarball_swapped", func(t *testing.T) {
		f := tree(&swapped, res(sriOf(locked)))
		f["pnpm-lock.yaml"] = strings.Replace(f["pnpm-lock.yaml"], "      x:\n        specifier: "+spec+"\n        version: "+spec+"\n", " {}\n", 1)
		f["pnpm-lock.yaml"] = strings.Replace(f["pnpm-lock.yaml"], "  .:\n {}", "  .: {}", 1)
		f["package.json"] = rootManifest(`{}`)
		if !nonFrozenWithheld(t, f) {
			t.Error("a pinned tarball no importer names was swapped and must withhold")
		}
	})
	// A block-form resolution is read only when its values are plain and non-empty.
	for name, resolution := range map[string]string{
		"block_quoted_tarball": "\n      integrity: " + sriOf(locked) + "\n      tarball: 'file:vendor/x.tgz'",
		"block_empty_tarball":  "\n      integrity: " + sriOf(locked) + "\n      tarball:",
	} {
		t.Run(name, func(t *testing.T) {
			if !nonFrozenWithheld(t, tree(&same, resolution)) {
				t.Errorf("resolution %q is not read exactly and must withhold", resolution)
			}
		})
	}
	t.Run("absolute_path", func(t *testing.T) {
		const abs = "file:/vendor/x.tgz"
		f := map[string]string{
			"package.json":   rootManifest(`{"x":"` + abs + `"}`),
			"pnpm-lock.yaml": localLock(abs, "{integrity: "+sriOf(locked)+", tarball: "+abs+"}", ": {}"),
			"vendor/x.tgz":   locked,
		}
		if !nonFrozenWithheld(t, f) {
			t.Error("an absolute path names a file outside the root, whatever sits at the same path under it")
		}
	})
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
	// A resolution the lane cannot read exactly withholds, even over an unchanged directory.
	for name, resolution := range map[string]string{
		"comma_shape":     "{x,directory: libs/x, y,type: directory}",
		"unknown_key":     "{directory: libs/x, type: directory, extra: 1}",
		"no_type":         "{directory: libs/x}",
		"type_no_dir":     "{type: directory}",
		"empty_dir_plain": "{directory: , type: directory}",
		"duplicate_key":   "{directory: libs/x, directory: libs/x, type: directory}",
		"double_quoted":   "{directory: \"libs/x\", type: directory}",
		"dir_and_tarball": "{directory: libs/x, type: directory, tarball: file:libs/x}",
	} {
		t.Run("unreadable_"+name, func(t *testing.T) {
			f := tree(`{"name":"x","version":"1.0.0","dependencies":{"q":"1.0.0"}}`)
			f["pnpm-lock.yaml"] = strings.Replace(f["pnpm-lock.yaml"], "{directory: libs/x, type: directory}", resolution, 1)
			if !nonFrozenWithheld(t, f) {
				t.Errorf("resolution %s must withhold", resolution)
			}
		})
	}
	// The lock's own directory: ts-sdk's example importer installs the workspace root as file:..,
	// which pnpm writes as {directory: '', type: directory}.
	rootDir := func(rootPeers string) map[string]string {
		return map[string]string{
			"package.json":         `{"name":"root","version":"1.0.0","private":true,"dependencies":{"q":"1.0.0"}` + rootPeers + `}`,
			"pnpm-workspace.yaml":  "packages:\n  - 'example'\n",
			"example/package.json": `{"name":"example","version":"1.0.0","dependencies":{"x":"file:.."}}`,
			"pnpm-lock.yaml": "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      q:\n        specifier: 1.0.0\n        version: 1.0.0\n\n" +
				"  example:\n    dependencies:\n      x:\n        specifier: file:..\n        version: file:..\n\n" +
				"packages:\n\n  q@1.0.0:\n    resolution: {integrity: " + fillerIntegrity + "}\n\n  x@file:..:\n    resolution: {directory: '', type: directory}\n    version: 1.0.0\n\n" +
				"snapshots:\n\n  q@1.0.0: {}\n\n  x@file:..:\n    dependencies:\n      q: 1.0.0\n",
		}
	}
	t.Run("control_root_directory", func(t *testing.T) {
		if nonFrozenWithheld(t, rootDir("")) {
			t.Error("the lock's own directory is read like any other directory")
		}
	})
	t.Run("root_directory_peer_dependency", func(t *testing.T) {
		if !nonFrozenWithheld(t, rootDir(`,"peerDependencies":{"esbuild":"*"}`)) {
			t.Error("a peer dependency in the lock's own directory must withhold")
		}
	})
	t.Run("outside_root", func(t *testing.T) {
		f := tree(`{"name":"x","dependencies":{"q":"1.0.0"}}`)
		f["pnpm-lock.yaml"] = strings.ReplaceAll(f["pnpm-lock.yaml"], "libs/x", "../x")
		if !nonFrozenWithheld(t, f) {
			t.Error("a directory outside the root must withhold")
		}
	})
	t.Run("suffixed_key_dependency_moved", func(t *testing.T) {
		l := localLock(spec, "{directory: libs/x, type: directory}", ":\n    dependencies:\n      q: 1.0.0")
		l = strings.Replace(l, "        version: "+spec+"\n", "        version: "+spec+"(q@1.0.0)\n", 1)
		l = strings.Replace(l, "\n  x@"+spec+":\n    dependencies", "\n  x@"+spec+"(q@1.0.0):\n    dependencies", 1)
		f := tree(`{"name":"x","version":"1.0.0","dependencies":{"q":"2.0.0"}}`)
		f["pnpm-lock.yaml"] = l
		if !nonFrozenWithheld(t, f) {
			t.Error("a peer-suffixed directory key still names a directory whose dependency moved")
		}
	})
	t.Run("peer_dependency_in_lock_only", func(t *testing.T) {
		f := tree(`{"name":"x","version":"1.0.0","dependencies":{"q":"1.0.0"}}`)
		f["pnpm-lock.yaml"] = strings.Replace(f["pnpm-lock.yaml"], "    version: 1.0.0\n\nsnapshots", "    version: 1.0.0\n    peerDependencies:\n      p: '1'\n\nsnapshots", 1)
		if !nonFrozenWithheld(t, f) {
			t.Error("a peer dependency the lock records but the manifest lacks must withhold")
		}
	})
	// Deliberate deviation from pnpm (see localDirectoryHolds): the suffix is cut before the compare.
	t.Run("control_locked_version_with_peer_suffix", func(t *testing.T) {
		f := tree(`{"name":"x","version":"1.0.0","dependencies":{"q":"1.0.0"}}`)
		f["pnpm-lock.yaml"] = strings.Replace(f["pnpm-lock.yaml"], "      q: 1.0.0", "      q: 1.0.0(r@1.0.0)", 1)
		f["pnpm-lock.yaml"] = strings.Replace(f["pnpm-lock.yaml"], "\n  q@1.0.0: {}", "\n  q@1.0.0(r@1.0.0): {}", 1)
		if nonFrozenWithheld(t, f) {
			t.Error("a locked version's peer suffix is not part of the version compared with the specifier")
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
// the registry q@1.0.0). The setting is never read: the rows carry none, and the gate withholds
// whatever the files say.
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
	suffixed := func(f map[string]string) map[string]string {
		f["pnpm-lock.yaml"] = strings.Replace(f["pnpm-lock.yaml"], "version: 1.0.0\n", "version: 1.0.0(react@18.0.0)\n", 1)
		return f
	}
	for name, tc := range map[string]struct {
		files    map[string]string
		withheld bool
	}{
		"same_version_member":          {tree("q", "1.0.0"), true},
		"control_member_other_version": {tree("q", "2.0.0"), false},
		"control_member_other_name":    {tree("q-local", "1.0.0"), false},
		// Non-regression: the suffixed importer version has no snapshot, which withholds on
		// ab1b657 too; the row does not exercise the suffix cut in noMemberShadow.
		"non_regression_peer_suffixed_lock": {suffixed(tree("q", "1.0.0")), true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := nonFrozenWithheld(t, tc.files); got != tc.withheld {
				t.Errorf("withheld = %v, want %v", got, tc.withheld)
			}
		})
	}
	// Link half of linkedPackagesAreUpToDate: the lock links packages/t for a ^1.0.0 specifier.
	linked := func(spec, memberVersion string) map[string]string {
		return map[string]string{
			"package.json":              `{"name":"root","private":true}`,
			"pnpm-workspace.yaml":       "packages:\n  - 'packages/*'\n",
			"packages/app/package.json": `{"name":"app","version":"1.0.0","dependencies":{"t":"` + spec + `"}}`,
			"packages/t/package.json":   `{"name":"t","version":"` + memberVersion + `"}`,
			"pnpm-lock.yaml": "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\n  packages/app:\n    dependencies:\n      t:\n        specifier: '" + spec + "'" +
				"\n        version: link:../t\n\n  packages/t: {}\n",
		}
	}
	// The same tree as a nested region: members are looked up relative to the lock's directory.
	nested := func(f map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range f {
			out["sub/"+k] = v
		}
		return out
	}
	for name, tc := range map[string]struct {
		files    map[string]string
		withheld bool
	}{
		"link_member_bumped_past_range": {linked("^1.0.0", "2.0.0"), true},
		"link_member_below_range":       {linked("^1.0.0", "0.9.0"), true},
		"control_link_member_in_range":  {linked("^1.0.0", "1.4.0"), false},
		"control_link_caret_only":       {linked("^", "2.0.0"), false},
		"control_link_dist_tag":         {linked("latest", "2.0.0"), false},
		"control_link_workspace_range":  {linked("workspace:^1.0.0", "1.4.0"), false},
		"link_v_prefixed_range":         {linked("v1", "2.0.0"), true},
		"link_alias_bumped":             {linked("npm:t@^1.0.0", "2.0.0"), true},
		"control_link_alias_in_range":   {linked("npm:t@^1.0.0", "1.3.0"), false},
		"control_link_alias_no_range":   {linked("npm:t", "2.0.0"), false},
		"control_link_specifier":        {linked("link:../t", "2.0.0"), false},
		"nested_region_link_bumped":     {nested(linked("^1.0.0", "2.0.0")), true},
		"control_nested_region_link":    {nested(linked("^1.0.0", "1.4.0")), false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := nonFrozenWithheld(t, tc.files); got != tc.withheld {
				t.Errorf("withheld = %v, want %v", got, tc.withheld)
			}
		})
	}
	// Specifiers pnpm skips are not tested against the member, which need not exist.
	for name, spec := range map[string]string{
		"control_link_star_member_missing":     "*",
		"control_link_tilde_member_missing":    "~",
		"control_link_caret_member_missing":    "^",
		"control_link_file_member_missing":     "file:../t",
		"control_link_alias_empty_member_gone": "npm:t@",
	} {
		t.Run(name, func(t *testing.T) {
			f := linked(spec, "1.4.0")
			f["pnpm-lock.yaml"] = strings.Replace(f["pnpm-lock.yaml"], "link:../t", "link:../gone", 1)
			if nonFrozenWithheld(t, f) {
				t.Errorf("specifier %q is skipped by pnpm and needs no member", spec)
			}
		})
	}
	// Deliberate over-approximation: a complete peer-suffixed registry lock whose package is
	// also a workspace member of the same version. pnpm matches the member by the whole ref and
	// keeps the lock; the lane cuts the suffix and withholds.
	t.Run("peer_suffixed_lock_with_same_version_member", func(t *testing.T) {
		f := tree("q", "1.0.0")
		l := strings.Replace(f["pnpm-lock.yaml"], "version: 1.0.0\n", "version: 1.0.0(react@18.0.0)\n", 1)
		l = strings.Replace(l, "snapshots:\n\n  q@1.0.0: {}", "snapshots:\n\n  q@1.0.0(react@18.0.0): {}", 1)
		f["pnpm-lock.yaml"] = l
		if !nonFrozenWithheld(t, f) {
			t.Error("the suffix cut withholds a same-version member behind a peer-suffixed ref")
		}
	})
	t.Run("link_member_missing", func(t *testing.T) {
		f := linked("^1.0.0", "1.4.0")
		f["pnpm-lock.yaml"] = strings.Replace(f["pnpm-lock.yaml"], "link:../t", "link:../gone", 1)
		if !nonFrozenWithheld(t, f) {
			t.Error("a linked dependency whose member cannot be read must withhold")
		}
	})
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

func TestFlowScalar(t *testing.T) {
	for in, want := range map[string]struct {
		out string
		ok  bool
	}{
		"plain":           {"plain", true},
		"'quoted'":        {"quoted", true},
		"'it''s'":         {"it's", true},
		"'open":           {"", false},
		"close'":          {"", false},
		"'a'b'":           {"", false},
		`"double"`:        {"", false},
		"":                {"", false},
		"[a]":             {"", false},
		"a # c":           {"", false},
		"&anchor":         {"", false},
		"'file:vendor/x'": {"file:vendor/x", true},
		"file:a,b":        {"", false},
		"file:a b":        {"", false},
		"a:":              {"", false},
		"-a":              {"", false},
		"?a":              {"", false},
		"@scope/x":        {"", false},
		"sha512-ab+c/d==": {"sha512-ab+c/d==", true},
		"../x":            {"../x", true},
		"''":              {"", true},
	} {
		if out, ok := flowScalar(in); out != want.out || ok != want.ok {
			t.Errorf("flowScalar(%q) = %q, %v; want %q, %v", in, out, ok, want.out, want.ok)
		}
	}
}

func TestReadLocalResolutionFlow(t *testing.T) {
	for in, ok := range map[string]bool{
		"{tarball: file:vendor/x.tgz, integrity: sha512-a}":     true,
		"{tarball: 'file:vendor/x.tgz', integrity: sha512-a}":   true,
		"{'tarball': file:vendor/x.tgz, integrity: sha512-a}":   false,
		"{tarball: \"file:vendor/x.tgz\", integrity: sha512-a}": false,
		"tarball: file:vendor/x.tgz":                            false,
		"{tarball file:vendor/x.tgz}":                           false,
		"{tarball: file:vendor/x.tgz,y}":                        false,
		"{foo,tarball: file:vendor/x.tgz}":                      false,
		"{tarball: file:a.tgz, tarball: file:b.tgz}":            false,
		"{directory: '', type: directory}":                      true,
		"{directory: libs/x,y, type: directory}":                false,
		"{directory: libs/x, type: directory, extra: 1}":        false,
		"{directory: libs/x}":                                   false,
		"{type: directory}":                                     false,
		"{directory: libs/x, tarball: '', type: directory}":     false,
		"{directory: libs/x, type: directory, integrity: ''}":   false,
	} {
		if _, got := readLocalResolution(&ynode{val: in}); got != ok {
			t.Errorf("readLocalResolution(%q) ok = %v, want %v", in, got, ok)
		}
	}
	r, _ := readLocalResolution(&ynode{val: "{tarball: 'file:vendor/it''s.tgz', integrity: sha512-a}"})
	if r.kind != "tarball" || r.rel != "vendor/it's.tgz" {
		t.Errorf("single-quoted escape: got %+v", r)
	}
}

func TestVersionRange(t *testing.T) {
	for in, want := range map[string]string{
		"^1.0.0": "^1.0.0", "npm:t@^1.0.0": "^1.0.0", "npm:t": "*", "npm:t@": "*",
		"npm:@s/t@~2": "~2", "npm:@s/t": "*", "npm:": "*",
	} {
		if got := versionRange(in); got != want {
			t.Errorf("versionRange(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLocalPath(t *testing.T) {
	p := &pnpmLock{root: "/r"}
	for rel, ok := range map[string]bool{
		"vendor/x.tgz": true, "": false, "/vendor/x.tgz": false, "../x": false,
		"a/../x": false, "a\\b": false, "a/..b": true,
	} {
		if _, got := p.localPath(rel); got != ok {
			t.Errorf("localPath(%q) ok = %v, want %v", rel, got, ok)
		}
	}
}
