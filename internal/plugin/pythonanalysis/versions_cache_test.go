package pythonanalysis

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const surfacesPyproject = "[tool.poetry]\nname = \"app\"\nversion = \"1.0\"\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\nflask = \"^3.0\"\n"

func surfacesTree(t *testing.T, extra map[string]string) string {
	t.Helper()
	files := map[string]string{
		"requirements.txt": "flask==3.0.0\n",
		"pyproject.toml":   surfacesPyproject,
		"poetry.lock":      "[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\n",
		"install.sh":       "pip install -r requirements.txt --no-deps\npoetry install --only main\n",
		"lib/site-packages/jinja2-3.1.2.dist-info/METADATA": "Metadata-Version: 2.1\nName: Jinja2\nVersion: 3.1.2\n",
	}
	for k, v := range extra {
		files[k] = v
	}
	return writeTree(t, files)
}

type surfaceResults struct {
	Manifests                     []string
	Unread, Withheld, ConfigNamed bool
	Installs                      pipInstalls
	Poetry                        poetryInstalls
	Tooling                       map[string]bool
	Unrecognised                  string
	Inactive                      []string
}

func surfacesOf(ctx context.Context, dir string) surfaceResults {
	m, u, w, i, p, tl, ur, in, cn := versionSurfacesCached(ctx, dir)
	r := surfaceResults{m, u, w, cn, i, p, tl, ur, nil}
	for _, s := range in {
		r.Inactive = append(r.Inactive, s.String())
	}
	return r
}

func surfacesUncached(dir string) surfaceResults {
	m, u, w, i, p, tl, ur, in, cn := versionSurfaces(dir)
	r := surfaceResults{m, u, w, cn, i, p, tl, ur, nil}
	for _, s := range in {
		r.Inactive = append(r.Inactive, s.String())
	}
	return r
}

// TestVersionSurfacesCacheReplaysIdentically pins that a replay equals the scan it replaces, field
// for field including the unexported install records the cache must carry, and computes nothing.
func TestVersionSurfacesCacheReplaysIdentically(t *testing.T) {
	dir := surfacesTree(t, nil)
	want := surfacesUncached(dir)
	if len(want.Installs) == 0 || len(want.Poetry) == 0 || len(want.Manifests) == 0 {
		t.Fatalf("the tree records no pip or poetry installs (%+v), so the round trip is not exercised", want)
	}
	got := countComputes(t)
	ctx := cachedCtx(t)
	for i := range 3 {
		if r := surfacesOf(ctx, dir); !reflect.DeepEqual(r, want) {
			t.Fatalf("call %d:\n got %+v\nwant %+v", i, r, want)
		}
	}
	if got["versurf"] != 1 {
		t.Fatalf("versurf computed %d times for 3 calls, want 1", got["versurf"])
	}
}

// TestVersionSurfacesCacheNoDirComputesEveryTime pins that without a run cache nothing is reused.
func TestVersionSurfacesCacheNoDirComputesEveryTime(t *testing.T) {
	dir := surfacesTree(t, nil)
	got := countComputes(t)
	surfacesOf(context.Background(), dir)
	surfacesOf(context.Background(), dir)
	if got["versurf"] != 2 {
		t.Fatalf("versurf computed %d times for 2 uncached calls, want 2", got["versurf"])
	}
}

// TestVersionSurfacesCacheTreesDoNotShareEntries pins the BuildDir key: two trees with different
// results, one cache, and each tree must get its own result however the calls interleave.
func TestVersionSurfacesCacheTreesDoNotShareEntries(t *testing.T) {
	dirA := surfacesTree(t, nil)
	dirB := writeTree(t, map[string]string{"requirements.txt": "django==4.2\n", "lib/site-packages/idna-3.7.dist-info/METADATA": "Name: idna\nVersion: 3.7\n"})
	wantA, wantB := surfacesUncached(dirA), surfacesUncached(dirB)
	if reflect.DeepEqual(wantA, wantB) {
		t.Fatal("the two trees give equal surfaces, so the test cannot tell a wrong replay")
	}
	copiesA, _, _ := installedCopies(dirA)
	copiesB, _, _ := installedCopies(dirB)
	if reflect.DeepEqual(copiesA, copiesB) {
		t.Fatal("the two trees give equal installed copies, so the test cannot tell a wrong replay")
	}
	ctx := cachedCtx(t)
	for i, c := range []struct {
		dir    string
		want   surfaceResults
		copies []plugin.ResolvedDependency
	}{{dirA, wantA, copiesA}, {dirB, wantB, copiesB}, {dirA, wantA, copiesA}, {dirB, wantB, copiesB}} {
		if got := surfacesOf(ctx, c.dir); !reflect.DeepEqual(got, c.want) {
			t.Fatalf("call %d on %s replayed another tree's surfaces:\n got %+v\nwant %+v", i, c.dir, got, c.want)
		}
		if got, _, ok := installedCopiesCached(ctx, c.dir); !ok || !reflect.DeepEqual(got, c.copies) {
			t.Fatalf("call %d on %s replayed another tree's copies: %+v ok %v, want %+v", i, c.dir, got, ok, c.copies)
		}
	}
}

// TestVersionSurfacesCacheHandsOutOwnState pins that a caller that edits what it was given
// changes nothing a later call sees, on the computing call and on a replay.
func TestVersionSurfacesCacheHandsOutOwnState(t *testing.T) {
	dir := surfacesTree(t, nil)
	want := surfacesUncached(dir)
	ctx := cachedCtx(t)
	for i := range 3 {
		m, _, _, installs, poetry, tooling, _, _, _ := versionSurfacesCached(ctx, dir)
		for k := range installs {
			installs[k][0].noDeps = !installs[k][0].noDeps
			delete(installs, k)
		}
		for k := range poetry {
			poetry[k][0].only = append(poetry[k][0].only, "x")
			delete(poetry, k)
		}
		tooling["injected"] = true
		m[0] = "mutated"
		if i == 2 {
			if got := surfacesOf(ctx, dir); !reflect.DeepEqual(got, want) {
				t.Fatalf("a caller's edits reached a later call:\n got %+v\nwant %+v", got, want)
			}
		}
	}
	copies, _, _ := installedCopiesCached(ctx, dir)
	copies[0].Version = "mutated"
	if again, _, _ := installedCopiesCached(ctx, dir); again[0].Version == "mutated" {
		t.Fatal("a caller's edit of the copies reached a later call")
	}
}

// TestInstalledCopiesCacheReplays pins that a complete read is stored once and replays equal.
func TestInstalledCopiesCacheReplays(t *testing.T) {
	dir := surfacesTree(t, map[string]string{"lib/site-packages/flask-3.0.0.dist-info/METADATA": "Name: flask\nVersion: 3.0.0\n"})
	wantC, wantO, wantOK := installedCopies(dir)
	if !wantOK || len(wantC) != 2 || len(wantO) != 2 {
		t.Fatalf("installedCopies = %v %v %v, want two complete copies", wantC, wantO, wantOK)
	}
	got := countComputes(t)
	ctx := cachedCtx(t)
	for i := range 3 {
		c, o, ok := installedCopiesCached(ctx, dir)
		if !ok || !reflect.DeepEqual(c, wantC) || !reflect.DeepEqual(o, wantO) {
			t.Fatalf("call %d = %v %v %v, want %v %v %v", i, c, o, ok, wantC, wantO, wantOK)
		}
	}
	if got["instcopies"] != 1 {
		t.Fatalf("instcopies computed %d times for 3 calls, want 1", got["instcopies"])
	}
}

// TestInstalledCopiesCacheDoesNotStoreAnIncompleteRead pins that a read that did not finish is
// returned as incomplete every time and never becomes a stored success: once the tree is whole
// the next call reads it again.
func TestInstalledCopiesCacheDoesNotStoreAnIncompleteRead(t *testing.T) {
	dir := surfacesTree(t, map[string]string{"lib/site-packages/broken-1.0.dist-info/METADATA": "not metadata\n"})
	got := countComputes(t)
	ctx := cachedCtx(t)
	for i := range 2 {
		if _, _, ok := installedCopiesCached(ctx, dir); ok {
			t.Fatalf("call %d: ok = true on an unreadable copy", i)
		}
	}
	if got["instcopies"] != 2 {
		t.Fatalf("instcopies computed %d times for 2 incomplete reads, want 2 (the failure was stored)", got["instcopies"])
	}
	if err := os.Remove(filepath.Join(dir, "lib/site-packages/broken-1.0.dist-info/METADATA")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "lib/site-packages/broken-1.0.dist-info")); err != nil {
		t.Fatal(err)
	}
	c, _, ok := installedCopiesCached(ctx, dir)
	if !ok || len(c) != 1 {
		t.Fatalf("after the tree was fixed: %v ok %v, want one copy and ok", c, ok)
	}
	if got["instcopies"] != 3 {
		t.Fatalf("instcopies computed %d times, want 3", got["instcopies"])
	}
}

// TestResolveVersionsRunCacheMatchesUncached pins the op end to end: a run cache changes no
// resolve_versions result, for a coordinate on a cold cache and again on a warm one.
func TestResolveVersionsRunCacheMatchesUncached(t *testing.T) {
	dir := surfacesTree(t, nil)
	ctx := cachedCtx(t)
	for _, coord := range []string{"flask", "jinja2", "nothere", "flask"} {
		req := plugin.ResolveVersionsRequest{BuildDir: dir, Coordinate: coord}
		want, err := ResolveDependencyVersions(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ResolveDependencyVersions(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s:\n got %+v\nwant %+v", coord, got, want)
		}
	}
}
