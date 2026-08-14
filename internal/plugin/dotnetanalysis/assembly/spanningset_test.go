package assembly

// spanningset_test.go — the locate+read+ASSEMBLE contract (barrier-3b, deliverable 1).
// Every dll is bytes written into t.TempDir(): a REAL synthesized PE (standardFixture)
// where the loader must parse it, garbage where it must degrade. Nothing restores,
// fetches, execs, or loads a system assembly. Reuses resolve_test.go's writeDll /
// assetsJSON and assembly_test.go's standardFixture (same package).

import (
	"os"
	"path/filepath"
	"testing"
)

// realPE is the standard synthesized PE fixture — a genuine assembly ReadAssembly parses.
func realPE() []byte { return standardFixture(0x00).data }

// writeRealDll writes a real (parseable) PE at <root>/<parts...>, returning its dir-less
// path — the on-disk truth ResolveDependencyDll must locate for a dep to enter the set.
func writeRealDll(t *testing.T, root string, parts ...string) string {
	t.Helper()
	p := filepath.Join(append([]string{root}, parts...)...)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, realPE(), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// firstPartyAsm reads the standard fixture into a live first-party assembly.
func firstPartyAsm(t *testing.T) *Assembly {
	t.Helper()
	a, err := Read(realPE())
	if err != nil {
		t.Fatalf("read first-party PE: %v", err)
	}
	return a
}

// TestLoadSpanningSet_HappyPath: first-party + one dep whose real PE dll locates via the
// authoritative assets path ⇒ the set is [first-party, dep], first-party first, no misses.
func TestLoadSpanningSet_HappyPath(t *testing.T) {
	cache := t.TempDir()
	writeRealDll(t, cache, "foo", "1.0.0", "lib", "net8.0", "Foo.dll")
	locator, ok := ParseAssetsLocator(assetsJSON(
		[]string{cache}, "Foo/1.0.0", "foo/1.0.0", "net8.0", "lib/net8.0/Foo.dll"))
	if !ok {
		t.Fatal("ParseAssetsLocator ok=false on valid assets")
	}

	fp := firstPartyAsm(t)
	set := LoadSpanningSet(t.TempDir(), fp, locator, []DepRef{{Target: "net8.0", PkgKey: "Foo/1.0.0"}})

	if len(set.Assemblies) != 2 {
		t.Fatalf("len(Assemblies) = %d, want 2 (first-party + one located dep)", len(set.Assemblies))
	}
	if set.Assemblies[0] != fp {
		t.Fatal("first-party assembly must be first in the spanning set")
	}
	if len(set.Misses) != 0 {
		t.Fatalf("Misses = %v, want none", set.Misses)
	}
}

// TestLoadSpanningSet_DeclaredMissAbsent: a dep whose compile key points at a dll NOT on
// disk is a DECLARED MISS — absent from the set (never fabricated into an empty
// assembly), recorded in Misses. This is the completeness-hazard boundary: absent ⇒
// out-of-set ⇒ the engine abstains, never a silent leaf.
func TestLoadSpanningSet_DeclaredMissAbsent(t *testing.T) {
	cache := t.TempDir() // empty: the composed dll never exists.
	locator, ok := ParseAssetsLocator(assetsJSON(
		[]string{cache}, "Ghost/2.0.0", "ghost/2.0.0", "net8.0", "lib/net8.0/Ghost.dll"))
	if !ok {
		t.Fatal("ParseAssetsLocator ok=false")
	}

	fp := firstPartyAsm(t)
	set := LoadSpanningSet(t.TempDir(), fp, locator, []DepRef{{Target: "net8.0", PkgKey: "Ghost/2.0.0"}})

	if len(set.Assemblies) != 1 || set.Assemblies[0] != fp {
		t.Fatalf("Assemblies = %d, want exactly the first-party (a miss is NEVER fabricated into the set)", len(set.Assemblies))
	}
	if len(set.Misses) != 1 || set.Misses[0].Reason != "not located" {
		t.Fatalf("Misses = %v, want one 'not located' miss", set.Misses)
	}
}

// TestLoadSpanningSet_UnreadableDepAbsent: a dep whose dll LOCATES but holds garbage
// bytes is a declared miss too — absent from the set, recorded "unreadable", never a
// panic and never a fabricated leaf.
func TestLoadSpanningSet_UnreadableDepAbsent(t *testing.T) {
	cache := t.TempDir()
	p := filepath.Join(cache, "bar", "3.0.0", "lib", "net8.0", "Bar.dll")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte("MZ not a real PE at all"), 0o644); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	locator, ok := ParseAssetsLocator(assetsJSON(
		[]string{cache}, "Bar/3.0.0", "bar/3.0.0", "net8.0", "lib/net8.0/Bar.dll"))
	if !ok {
		t.Fatal("ParseAssetsLocator ok=false")
	}

	fp := firstPartyAsm(t)
	set := LoadSpanningSet(t.TempDir(), fp, locator, []DepRef{{Target: "net8.0", PkgKey: "Bar/3.0.0"}})

	if len(set.Assemblies) != 1 || set.Assemblies[0] != fp {
		t.Fatalf("Assemblies = %d, want exactly the first-party (unreadable dep is not fabricated)", len(set.Assemblies))
	}
	if len(set.Misses) != 1 || set.Misses[0].Reason != "unreadable" {
		t.Fatalf("Misses = %v, want one 'unreadable' miss", set.Misses)
	}
}
