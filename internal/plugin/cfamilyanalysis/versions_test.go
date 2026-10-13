package cfamilyanalysis

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

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

func pinned(name, version, source string) plugin.ResolvedDependency {
	return plugin.ResolvedDependency{Coordinate: name, Version: version, Resolved: true, Source: source}
}

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
			wantPart:   plugin.Complete(),
		},
		{
			name:       "user/channel and revision are stripped",
			files:      map[string]string{conanLockFile: conanLock},
			coordinate: "mylib",
			wantFound:  true,
			wantMatch:  pinned("mylib", "2.0", conanLockFile),
			wantPart:   plugin.Complete(),
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
			wantPart:   plugin.Complete(),
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
			wantPart:   plugin.Complete(),
		},
		{
			name:       "vcpkg override pins and keeps its port-version",
			files:      map[string]string{vcpkgFile: vcpkgJSON},
			coordinate: "FMT",
			wantFound:  true,
			wantMatch:  pinned("fmt", "10.1.1#2", vcpkgFile),
			wantPart:   plugin.Complete(),
		},
		{
			name:       "vcpkg override with no port-version is the upstream version",
			files:      map[string]string{vcpkgFile: `{"overrides":[{"name":"zlib","version":"1.3.1","port-version":0}]}`},
			coordinate: "zlib",
			wantFound:  true,
			wantMatch:  pinned("zlib", "1.3.1", vcpkgFile),
			wantPart:   plugin.Complete(),
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
			wantPart:   plugin.Complete(),
		},
		{
			name:       "vcpkg status keeps the port-version",
			files:      map[string]string{vcpkgStatusFile: vcpkgStatus},
			coordinate: "libpng",
			wantFound:  true,
			wantMatch:  pinned("libpng", "1.6.43#2", vcpkgStatusFile),
			wantPart:   plugin.Complete(),
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
			wantPart:   plugin.Complete(),
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
			wantPart:   plugin.Complete(),
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
			wantPart:   plugin.Partial(plugin.PartialReasonToolFailure),
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
			wantPart:   plugin.Partial(plugin.PartialReasonToolFailure),
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
			if got.Match != tt.wantMatch {
				t.Errorf("Match = %+v, want %+v", got.Match, tt.wantMatch)
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
		pinned("zlib", "1.3.1", conanTxtFile),
		unpinned("fmt", conanTxtFile),
		pinned("openssl", "3.2.0", conanTxtFile),
	}
	if !reflect.DeepEqual(got.All, want) {
		t.Fatalf("All = %+v, want %+v", got.All, want)
	}
	if !reflect.DeepEqual(got.Partiality, plugin.Partial(plugin.PartialReasonSourceUnpinned)) {
		t.Fatalf("Partiality = %+v", got.Partiality)
	}
}

func TestResolveDependencyVersionsBadBuildDir(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	if _, err := ResolveDependencyVersions(context.Background(), plugin.ResolveVersionsRequest{BuildDir: missing}); err == nil {
		t.Fatal("missing build dir: want a hard error")
	}
}
