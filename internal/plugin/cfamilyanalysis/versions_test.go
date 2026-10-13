package cfamilyanalysis

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// conanLock is the shape `conan lock create` (Conan 2.33) writes.
const conanLock = `{
    "version": "0.5",
    "requires": [
        "zlib/1.3.1#cac0f6daea041b0ccf42934163defb20%1765284699.337",
        "fmt/10.2.1#15db2a3ea0646365bf05a6f50369ac59%1785754570.436",
        "mylib/2.0@corp/stable#0123%1700000000.0"
    ],
    "build_requires": [
        "cmake/3.27.9#e255e9c6cc3ac4856c44ad84476ec434%1701609437.645"
    ],
    "python_requires": [],
    "config_requires": []
}`

const conanfileTxt = `# comment
[requires]
zlib/1.3.1
fmt/[>=10 <11]
openssl/3.2.0#abc

[tool_requires]
cmake/3.27.9

[generators]
CMakeDeps
`

const vcpkgJSON = `{
  "name": "app",
  "builtin-baseline": "3426db05b996481ca31e95fff3734cf23e0f51bc",
  "dependencies": [
    "curl",
    { "name": "zlib", "version>=": "1.2.13" },
    { "name": "fmt", "features": ["core"] }
  ],
  "overrides": [
    { "name": "fmt", "version": "10.1.1", "port-version": 2 }
  ]
}`

// vcpkgStatus is the installed-package database shape vcpkg writes: a core paragraph per package
// and triplet, a paragraph per installed feature, and a removed package left as not-installed.
const vcpkgStatus = `Package: vcpkg-cmake
Version: 2024-04-23
Architecture: x64-linux
Multi-Arch: same
Abi: 1111
Status: install ok installed

Package: zlib
Version: 1.3.1
Depends: vcpkg-cmake:x64-linux
Architecture: x64-linux
Multi-Arch: same
Abi: 2222
Description: A compression library
Type: Port
Status: install ok installed

Package: libpng
Version: 1.6.43
Port-Version: 2
Depends: vcpkg-cmake:x64-linux, zlib
Architecture: x64-linux
Multi-Arch: same
Abi: 3333
Description: libpng is a library implementing an interface for reading and writing PNG
    (Portable Network Graphics) format files
Status: install ok installed

Package: libpng
Feature: apng
Depends: zlib:x64-linux
Architecture: x64-linux
Multi-Arch: same
Description: This is backward compatible with the regular libpng
Status: install ok installed

Package: curl
Version: 8.8.0
Architecture: x64-linux
Multi-Arch: same
Abi: 4444
Status: purge ok not-installed
`

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// pinned is a dependency a manifest pins at version. ResolveDependencyVersions reports it found and
// unresolved; the pin itself is what the inventory carries.
func pinned(name, version, source string) plugin.ResolvedDependency {
	return plugin.ResolvedDependency{Coordinate: name, Version: version, Resolved: true, Source: source}
}

var soleSourceUnproven = plugin.Partial(reasonSoleSourceUnproven)

func unpinned(name, source string) plugin.ResolvedDependency {
	return plugin.ResolvedDependency{Coordinate: name, Source: source}
}

func TestResolveDependencyVersions(t *testing.T) {
	tests := []struct {
		name       string
		files      map[string]string
		coordinate string
		wantFound  bool
		wantMatch  plugin.ResolvedDependency
		wantPart   plugin.Partiality
	}{
		{
			name:       "conan.lock pins the version",
			files:      map[string]string{conanLockFile: conanLock},
			coordinate: "zlib",
			wantFound:  true,
			wantMatch:  pinned("zlib", "1.3.1", conanLockFile),
			wantPart:   soleSourceUnproven,
		},
		{
			name:       "user/channel and revision are stripped",
			files:      map[string]string{conanLockFile: conanLock},
			coordinate: "mylib",
			wantFound:  true,
			wantMatch:  pinned("mylib", "2.0", conanLockFile),
			wantPart:   soleSourceUnproven,
		},
		{
			name:       "lock build_requires are not product dependencies",
			files:      map[string]string{conanLockFile: conanLock},
			coordinate: "cmake",
			wantPart:   plugin.Partial(plugin.PartialReasonNoManifest),
		},
		{
			name:       "conanfile.txt literal version pins",
			files:      map[string]string{conanTxtFile: conanfileTxt},
			coordinate: "openssl",
			wantFound:  true,
			wantMatch:  pinned("openssl", "3.2.0", conanTxtFile),
			wantPart:   soleSourceUnproven,
		},
		{
			name:       "conanfile.txt range is unpinned",
			files:      map[string]string{conanTxtFile: conanfileTxt},
			coordinate: "fmt",
			wantFound:  true,
			wantMatch:  unpinned("fmt", conanTxtFile),
			wantPart:   plugin.Partial(plugin.PartialReasonSourceUnpinned),
		},
		{
			name:       "lock resolves what conanfile.txt only constrains",
			files:      map[string]string{conanLockFile: conanLock, conanTxtFile: conanfileTxt},
			coordinate: "fmt",
			wantFound:  true,
			wantMatch:  pinned("fmt", "10.2.1", conanLockFile),
			wantPart:   soleSourceUnproven,
		},
		{
			name:       "vcpkg override pins and keeps its port-version",
			files:      map[string]string{vcpkgFile: vcpkgJSON},
			coordinate: "FMT",
			wantFound:  true,
			wantMatch:  pinned("fmt", "10.1.1#2", vcpkgFile),
			wantPart:   soleSourceUnproven,
		},
		{
			name:       "vcpkg override with no port-version is the upstream version",
			files:      map[string]string{vcpkgFile: `{"overrides":[{"name":"zlib","version":"1.3.1","port-version":0}]}`},
			coordinate: "zlib",
			wantFound:  true,
			wantMatch:  pinned("zlib", "1.3.1", vcpkgFile),
			wantPart:   soleSourceUnproven,
		},
		{
			name:       "vcpkg version>= is a minimum, not a pin",
			files:      map[string]string{vcpkgFile: vcpkgJSON},
			coordinate: "zlib",
			wantFound:  true,
			wantMatch:  unpinned("zlib", vcpkgFile),
			wantPart:   plugin.Partial(plugin.PartialReasonSourceUnpinned),
		},
		{
			name:       "vcpkg bare dependency is unpinned",
			files:      map[string]string{vcpkgFile: vcpkgJSON},
			coordinate: "curl",
			wantFound:  true,
			wantMatch:  unpinned("curl", vcpkgFile),
			wantPart:   plugin.Partial(plugin.PartialReasonSourceUnpinned),
		},
		{
			name:       "undeclared coordinate may be system or vendored",
			files:      map[string]string{vcpkgFile: vcpkgJSON},
			coordinate: "libpng",
			wantPart:   plugin.Partial(plugin.PartialReasonNoManifest),
		},
		{
			name:       "vcpkg status pins the installed version",
			files:      map[string]string{vcpkgStatusFile: vcpkgStatus},
			coordinate: "zlib",
			wantFound:  true,
			wantMatch:  pinned("zlib", "1.3.1", vcpkgStatusFile),
			wantPart:   soleSourceUnproven,
		},
		{
			name:       "vcpkg status keeps the port-version",
			files:      map[string]string{vcpkgStatusFile: vcpkgStatus},
			coordinate: "libpng",
			wantFound:  true,
			wantMatch:  pinned("libpng", "1.6.43#2", vcpkgStatusFile),
			wantPart:   soleSourceUnproven,
		},
		{
			name:       "vcpkg status package removed is not installed",
			files:      map[string]string{vcpkgStatusFile: vcpkgStatus},
			coordinate: "curl",
			wantPart:   plugin.Partial(plugin.PartialReasonNoManifest),
		},
		{
			name:       "vcpkg status resolves what vcpkg.json only bounds",
			files:      map[string]string{vcpkgStatusFile: vcpkgStatus, vcpkgFile: vcpkgJSON},
			coordinate: "zlib",
			wantFound:  true,
			wantMatch:  pinned("zlib", "1.3.1", vcpkgStatusFile),
			wantPart:   soleSourceUnproven,
		},
		{
			name: "vcpkg updates override status in name order",
			files: map[string]string{
				vcpkgStatusFile:                 vcpkgStatus,
				vcpkgUpdatesDir + "/0000000001": "Package: zlib\nVersion: 1.3.1\nPort-Version: 1\nArchitecture: x64-linux\nStatus: install ok installed\n",
				vcpkgUpdatesDir + "/0000000002": "Package: zlib\nVersion: 1.3.1\nPort-Version: 3\nArchitecture: x64-linux\nStatus: install ok installed\n",
			},
			coordinate: "zlib",
			wantFound:  true,
			wantMatch:  pinned("zlib", "1.3.1#3", vcpkgStatusFile),
			wantPart:   soleSourceUnproven,
		},
		{
			name:       "vcpkg status in an unknown state does not parse",
			files:      map[string]string{vcpkgStatusFile: "Package: zlib\nVersion: 1.3.1\nArchitecture: x64-linux\nStatus: install ok half-installed\n"},
			coordinate: "zlib",
			wantPart:   plugin.Partial(plugin.PartialReasonNoManifest, plugin.PartialReasonToolFailure),
		},
		{
			name:       "vcpkg status with a malformed line does not parse",
			files:      map[string]string{vcpkgStatusFile: "Package: zlib\nnot a field\nVersion: 1.3.1\nArchitecture: x64-linux\nStatus: install ok installed\n"},
			coordinate: "zlib",
			wantFound:  true,
			wantMatch:  pinned("zlib", "1.3.1", vcpkgStatusFile),
			wantPart:   plugin.Partial(reasonSoleSourceUnproven, plugin.PartialReasonToolFailure),
		},
		{
			name:       "no manifest at all",
			files:      map[string]string{"CMakeLists.txt": "project(p C)"},
			coordinate: "zlib",
			wantPart:   plugin.Partial(plugin.PartialReasonNoManifest),
		},
		{
			name:       "conanfile.py alone is not read",
			files:      map[string]string{"conanfile.py": "requires = 'zlib/1.3.1'"},
			coordinate: "zlib",
			wantPart:   plugin.Partial(plugin.PartialReasonNoManifest),
		},
		{
			name:       "two managers disagree on the pin",
			files:      map[string]string{conanLockFile: conanLock, vcpkgFile: vcpkgJSON},
			coordinate: "fmt",
			wantFound:  true,
			wantMatch:  plugin.ResolvedDependency{Coordinate: "fmt"},
			wantPart:   plugin.Partial(plugin.PartialReasonLockfileAmbiguous),
		},
		{
			name:       "unparseable vcpkg.json",
			files:      map[string]string{vcpkgFile: `{"dependencies": [`, conanTxtFile: conanfileTxt},
			coordinate: "zlib",
			wantFound:  true,
			wantMatch:  pinned("zlib", "1.3.1", conanTxtFile),
			wantPart:   plugin.Partial(reasonSoleSourceUnproven, plugin.PartialReasonToolFailure),
		},
		{
			name:       "unfamiliar conan lockfile format is not read as empty",
			files:      map[string]string{conanLockFile: `{"version":"0.4","graph_lock":{"nodes":{}}}`},
			coordinate: "zlib",
			wantPart:   plugin.Partial(plugin.PartialReasonNoManifest, plugin.PartialReasonToolFailure),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeFiles(t, tt.files)
			got, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: dir, Coordinate: tt.coordinate})
			if err != nil {
				t.Fatal(err)
			}
			if got.Found != tt.wantFound {
				t.Errorf("Found = %v, want %v", got.Found, tt.wantFound)
			}
			reported := plugin.ResolvedDependency{Coordinate: tt.wantMatch.Coordinate, Source: tt.wantMatch.Source}
			if got.Match != reported {
				t.Errorf("Match = %+v, want %+v", got.Match, reported)
			}
			if tt.wantMatch.Resolved {
				if v := pinFor(t, dir, tt.wantMatch.Coordinate, tt.wantMatch.Source); v != tt.wantMatch.Version {
					t.Errorf("pin = %q, want %q", v, tt.wantMatch.Version)
				}
			}
			if !reflect.DeepEqual(got.Partiality, tt.wantPart) {
				t.Errorf("Partiality = %+v, want %+v", got.Partiality, tt.wantPart)
			}
		})
	}
}

func TestResolveDependencyVersionsEnumerates(t *testing.T) {
	dir := writeFiles(t, map[string]string{conanTxtFile: conanfileTxt})
	got, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	want := []plugin.ResolvedDependency{
		unpinned("zlib", conanTxtFile),
		unpinned("fmt", conanTxtFile),
		unpinned("openssl", conanTxtFile),
	}
	if !reflect.DeepEqual(got.All, want) {
		t.Fatalf("All = %+v, want %+v", got.All, want)
	}
	if !reflect.DeepEqual(got.Partiality, plugin.Partial(plugin.PartialReasonSourceUnpinned, reasonSoleSourceUnproven)) {
		t.Fatalf("Partiality = %+v", got.Partiality)
	}
}

// pinFor is the version the manifest at source pins coordinate to, or "" when it pins none.
func pinFor(t *testing.T, dir, coordinate, source string) string {
	t.Helper()
	for _, d := range readManifests(dir).deps {
		if strings.EqualFold(d.name, coordinate) && d.source == source && d.resolved {
			return d.fullVersion()
		}
	}
	return ""
}

// No C/C++ dependency reaches intake resolved, from any manifest tier: a pin is not proof that the
// pinned package is the only copy of the library in the build.
func TestResolveDependencyVersionsNeverResolves(t *testing.T) {
	trees := []map[string]string{
		{conanLockFile: conanLock},
		{conanTxtFile: conanfileTxt},
		{vcpkgStatusFile: vcpkgStatus},
		{vcpkgFile: vcpkgJSON},
		{conanLockFile: conanLock, conanTxtFile: conanfileTxt, vcpkgStatusFile: vcpkgStatus, vcpkgFile: vcpkgJSON},
	}
	for _, files := range trees {
		dir := writeFiles(t, files)
		ms := readManifests(dir)
		for _, d := range ms.deps {
			got, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: dir, Coordinate: d.name})
			if err != nil {
				t.Fatal(err)
			}
			if !got.Found || got.Match.Resolved || got.Match.Version != "" || got.Partiality.Complete {
				t.Errorf("%v: %s = %+v, want found, unresolved and declared partial", files, d.name, got)
			}
		}
		all, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range all.All {
			if d.Resolved || d.Version != "" {
				t.Errorf("%v: enumerated %+v resolved", files, d)
			}
		}
	}
}

func TestResolveDependencyVersionsBadBuildDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	if _, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: missing}); err == nil {
		t.Fatal("missing build dir: want a hard error")
	}
}

// Every manifest the lane reads is read only as a regular file inside the build root. A FIFO, a
// link out of the root, or a file past the size cap is a manifest that did not read: tool_failure,
// and the manager it belongs to is unlocked. None of them blocks the read or reads as Complete.
func TestManifestReadsRefuseNonRegularFiles(t *testing.T) {
	const status = "Package: zlib\nVersion: 1.3.1\nArchitecture: x64-linux\nStatus: install ok installed\n"
	const evilStatus = "Package: evil\nVersion: 9.9\nArchitecture: x64-linux\nStatus: install ok installed\n"
	outside := writeFiles(t, map[string]string{
		"status":      evilStatus,
		"0000000001":  evilStatus,
		conanLockFile: `{"version":"0.5","requires":["evil/9.9"]}`,
		conanTxtFile:  "[requires]\nevil/9.9\n",
		vcpkgFile:     `{"overrides":[{"name":"evil","version":"9.9"}]}`,
	})
	for _, target := range []struct {
		path  string
		files map[string]string // the rest of the tree, which reads Complete on its own
	}{
		{conanLockFile, map[string]string{vcpkgStatusFile: status}},
		{conanTxtFile, map[string]string{conanLockFile: `{"version":"0.5","requires":["zlib/1.3.1"]}`}},
		{vcpkgStatusFile, map[string]string{conanLockFile: `{"version":"0.5","requires":["zlib/1.3.1"]}`}},
		{vcpkgUpdatesDir + "/0000000001", map[string]string{vcpkgStatusFile: status}},
		{vcpkgFile, map[string]string{vcpkgStatusFile: status}},
	} {
		for _, kind := range []struct {
			name string
			make func(t *testing.T, path string)
		}{
			{"FIFO", func(t *testing.T, path string) {
				if err := syscall.Mkfifo(path, 0o644); err != nil {
					t.Fatal(err)
				}
			}},
			{"link out of the build root", func(t *testing.T, path string) {
				if err := os.Symlink(filepath.Join(outside, filepath.Base(path)), path); err != nil {
					t.Fatal(err)
				}
			}},
			{"past the size cap", func(t *testing.T, path string) {
				f, err := os.Create(path)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				if err := f.Truncate(maxManifestBytes + 1); err != nil {
					t.Fatal(err)
				}
			}},
		} {
			t.Run(target.path+"/"+kind.name, func(t *testing.T) {
				dir := writeFiles(t, target.files)
				full := filepath.Join(dir, filepath.FromSlash(target.path))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				kind.make(t, full)

				type result struct {
					inv plugin.DependencyInventory
					vr  plugin.DependencyVersionResult
				}
				done := make(chan result, 1)
				go func() {
					inv, _ := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
					vr, _ := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: dir})
					done <- result{inv, vr}
				}()
				var r result
				select {
				case r = <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("the manifest read blocked")
				}
				for name, p := range map[string]plugin.Partiality{"inventory": r.inv.Partiality, "versions": r.vr.Partiality} {
					if p.Complete || !hasReason(p.Reasons, plugin.PartialReasonToolFailure) {
						t.Errorf("%s Partiality = %+v, want tool_failure", name, p)
					}
				}
				for _, n := range r.inv.Nodes {
					if strings.Contains(n.PURL, "evil") {
						t.Errorf("read a file outside the build root: %+v", n)
					}
				}
			})
		}
	}
}

func TestReadInTreeAllowsALinkInsideTheRoot(t *testing.T) {
	dir := writeFiles(t, map[string]string{"real/conan.lock": `{"version":"0.5","requires":["zlib/1.3.1"]}`})
	if err := os.Symlink(filepath.Join("real", conanLockFile), filepath.Join(dir, conanLockFile)); err != nil {
		t.Fatal(err)
	}
	if inv := inventoryAt(t, dir); !inv.Partiality.Complete {
		t.Fatalf("Partiality = %+v, want Complete", inv.Partiality)
	}
	if _, err := readInTree(dir, conanLockFile, 8); err == nil {
		t.Error("readInTree read past its limit")
	}
	if _, err := readInTree(dir, "missing", 8); !os.IsNotExist(err) {
		t.Errorf("missing file: err = %v, want not-exist", err)
	}
	if err := os.Symlink(filepath.Join(dir, "gone"), filepath.Join(dir, conanTxtFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := readInTree(dir, conanTxtFile, maxManifestBytes); err == nil || os.IsNotExist(err) {
		t.Errorf("dangling link: err = %v, want a read failure, not absence", err)
	}
}

func inventoryAt(t *testing.T, dir string) plugin.DependencyInventory {
	t.Helper()
	inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func hasReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}
