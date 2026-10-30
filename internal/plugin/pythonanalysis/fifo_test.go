//go:build unix

package pythonanalysis

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// mkfifo places a named pipe at rel under dir. Opening it for reading blocks until a writer
// appears, and none ever does.
func mkfifo(t *testing.T, dir, rel string) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(p, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	return p
}

func placeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func hasToolFailure(p plugin.Partiality) bool {
	return !p.Complete && slices.Contains(p.Reasons, plugin.PartialReasonToolFailure)
}

// TestReaders_FIFO places a named pipe where each reader looks for a file. Every reader must
// return without opening it (a reader that blocks fails the 3 s guard rather than hanging the
// run) and treat it as a file it could not read.
func TestReaders_FIFO(t *testing.T) {
	const py = "def a():\n    pass\n"
	ctx := context.Background()
	buildManifestPartial := func(t *testing.T, dir, _ string) {
		res, err := BuildManifest(ctx, plugin.BuildManifestRequest{BuildDir: dir})
		if err != nil || !hasToolFailure(res.Partiality) {
			t.Errorf("BuildManifest partiality = %+v, %v; want tool_failure", res.Partiality, err)
		}
	}
	callGraphPartial := func(t *testing.T, dir, _ string) {
		res, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: dir})
		if err != nil || !hasToolFailure(res.Partiality) {
			t.Errorf("CallGraph partiality = %+v, %v; want tool_failure", res.Partiality, err)
		}
	}
	rows := []struct {
		name  string
		files map[string]string
		fifo  string
		check func(t *testing.T, dir, pipe string)
	}{
		{name: "readPyprojectMeta pyproject.toml", fifo: "pyproject.toml", check: buildManifestPartial},
		{name: "lockfileRequiresPython uv.lock", fifo: "uv.lock", check: buildManifestPartial},
		{name: "lockfileRequiresPython pdm.lock", fifo: "pdm.lock", check: buildManifestPartial},
		{
			name:  "readPythonVersionPin .python-version",
			files: map[string]string{"pyproject.toml": "[project]\nrequires-python = \">=3.9\"\n"},
			fifo:  ".python-version", check: buildManifestPartial,
		},
		{
			name: "pyCandidateName tox.ini", fifo: "tox.ini",
			check: func(t *testing.T, _, pipe string) {
				if _, ok := pyCandidateName(pipe); !ok {
					t.Error("an unread tox.ini was not taken as an install surface")
				}
			},
		},
		{
			name: "pyCandidateName noxfile.py", fifo: "noxfile.py",
			check: func(t *testing.T, _, pipe string) {
				if _, ok := pyCandidateName(pipe); !ok {
					t.Error("an unread noxfile.py was not taken as an install surface")
				}
			},
		},
		{
			name: "manifestDecls pyproject.toml", fifo: "pyproject.toml",
			check: func(t *testing.T, _, pipe string) {
				if _, ok := manifestDecls(pipe); ok {
					t.Error("manifestDecls read a pipe")
				}
			},
		},
		{
			name: "uvSourced pyproject.toml", fifo: "pyproject.toml",
			check: func(t *testing.T, _, pipe string) {
				if uvSourced([]string{pipe}, "pyjwt") {
					t.Error("uvSourced read a pipe")
				}
			},
		},
		{
			name: "readPyLock uv.lock", fifo: "uv.lock",
			check: func(t *testing.T, _, pipe string) {
				if _, ok := readPyLock(pipe); ok {
					t.Error("readPyLock read a pipe")
				}
			},
		},
		{name: "loadProgram source file", files: map[string]string{"b.py": py}, fifo: "a.py", check: callGraphPartial},
		{
			name:  "loadProgram declared manifest",
			files: map[string]string{"a.py": "import requests\n\ndef a():\n    requests.get(1)\n"},
			fifo:  "requirements.txt", check: callGraphPartial,
		},
		{name: "loadProgram declared manifest, every import attributed", files: map[string]string{"a.py": py}, fifo: "requirements.txt", check: callGraphPartial},
		{
			name: "buildInterpreter pyproject.toml", fifo: "pyproject.toml",
			check: func(t *testing.T, dir, _ string) {
				if got := buildInterpreter(dir); !slices.Equal(got.releases, anyInterpreter.releases) || got.newer != anyInterpreter.newer {
					t.Errorf("buildInterpreter = %+v; want anyInterpreter", got)
				}
			},
		},
		{
			name: "readRequirementSpecs requirement file", fifo: "reqs.txt",
			check: func(t *testing.T, dir, _ string) {
				if _, _, ok := readRequirementSpecs(dir, "reqs.txt"); ok {
					t.Error("readRequirementSpecs read a pipe")
				}
			},
		},
		{
			name: "poetryLockConsistent poetry.lock", fifo: "poetry.lock",
			check: func(t *testing.T, _, pipe string) {
				if poetryLockConsistent(pipe, nil) {
					t.Error("poetryLockConsistent accepted a pipe")
				}
			},
		},
		{
			name: "firstPartyNames pyproject.toml", fifo: "pyproject.toml",
			check: func(t *testing.T, _, pipe string) {
				if _, ok := firstPartyNames([]string{pipe}); ok {
					t.Error("firstPartyNames ruled out first-party names from a pipe")
				}
			},
		},
		{
			name: "firstPartyNames setup.cfg", fifo: "setup.cfg",
			check: func(t *testing.T, _, pipe string) {
				if _, ok := firstPartyNames([]string{pipe}); ok {
					t.Error("firstPartyNames ruled out first-party names from a pipe")
				}
			},
		},
		{
			name: "firstPartyNames setup.py", fifo: "setup.py",
			check: func(t *testing.T, _, pipe string) {
				if _, ok := firstPartyNames([]string{pipe}); ok {
					t.Error("firstPartyNames ruled out first-party names from a pipe")
				}
			},
		},
		{
			name: "firstPartyNames uv.lock", fifo: "uv.lock",
			check: func(t *testing.T, _, pipe string) {
				if _, ok := firstPartyNames([]string{pipe}); ok {
					t.Error("firstPartyNames ruled out first-party names from a pipe")
				}
			},
		},
		{
			name: "setupCfgNamed setup.cfg", fifo: "setup.cfg",
			check: func(t *testing.T, dir, pipe string) {
				if setupCfgNamed([]string{pipe}, filepath.Join(dir, "setup.py")) {
					t.Error("setupCfgNamed found a name in a pipe")
				}
			},
		},
		{
			name: "pyprojectDynamicCovered pyproject.toml", fifo: "pyproject.toml",
			check: func(t *testing.T, _, pipe string) {
				if pyprojectDynamicCovered(pipe, []string{pipe}) {
					t.Error("pyprojectDynamicCovered accepted a pipe")
				}
			},
		},
		{
			name: "loadFiles source file", files: map[string]string{"b.py": py}, fifo: "a.py",
			check: func(t *testing.T, dir, _ string) {
				res, err := IndexSymbols(ctx, plugin.IndexSymbolsRequest{BuildDir: dir})
				if err != nil || !hasToolFailure(res.Partiality) {
					t.Errorf("IndexSymbols partiality = %+v, %v; want tool_failure", res.Partiality, err)
				}
			},
		},
		{
			name: "manifestToPyReqs requirements.txt", fifo: "requirements.txt",
			check: func(t *testing.T, dir, _ string) {
				inv, err := ResolveInventory(ctx, plugin.ResolveInventoryRequest{BuildDir: dir})
				if err != nil || !hasToolFailure(inv.Partiality) {
					t.Errorf("inventory partiality = %+v, %v; want tool_failure", inv.Partiality, err)
				}
			},
		},
		{
			name: "parseManifest requirements.txt", fifo: "requirements.txt",
			check: func(t *testing.T, dir, _ string) {
				res, err := ResolveDependencyVersions(ctx, plugin.ResolveVersionsRequest{BuildDir: dir, Coordinate: "requests"})
				if err != nil || !hasToolFailure(res.Partiality) || res.Exhaustive {
					t.Errorf("versions = %+v, %v; want tool_failure and not exhaustive", res, err)
				}
			},
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			placeFiles(t, dir, row.files)
			pipe := mkfifo(t, dir, row.fifo)
			done := make(chan struct{})
			go func() {
				defer close(done)
				row.check(t, dir, pipe)
			}()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatalf("blocked opening the pipe at %s", row.fifo)
			}
		})
	}
}

// TestResolveVersions_PipeNamedLikeASurfaceVetoes: a pipe where an install surface could be, in a
// directory the manifest discovery does not read, is an unread surface, whether its name marks
// it or only its content could. It vetoes the root pin without being opened (the 3 s guard
// fails a resolve that blocks on it).
func TestResolveVersions_PipeNamedLikeASurfaceVetoes(t *testing.T) {
	for _, pipe := range []string{"svc/pylock.toml", "svc/deps.pins"} {
		t.Run(pipe, func(t *testing.T) {
			dir := t.TempDir()
			placeFiles(t, dir, map[string]string{"requirements.txt": "pyjwt==2.8.0\n"})
			mkfifo(t, dir, pipe)
			done := make(chan plugin.DependencyVersionResult, 1)
			go func() { done <- resolveVersion(t, dir, "pyjwt") }()
			select {
			case res := <-done:
				mustUnresolvedPy(t, res)
				if res.Partiality.Complete {
					t.Fatal("result must be partial")
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("blocked opening the pipe at %s", pipe)
			}
		})
	}
}
