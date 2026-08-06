package dotnetanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func resolve(t *testing.T, dir string, symbols ...string) plugin.SymbolResolutionResult {
	t.Helper()
	res, err := ResolveDependencySymbols(context.Background(), plugin.ResolveSymbolsRequest{
		BuildDir:        dir,
		AdvisorySymbols: symbols,
	})
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	return res
}

func resolvedDisplays(res plugin.SymbolResolutionResult) []string {
	var out []string
	for _, s := range res.Resolved {
		out = append(out, s.DisplayName)
	}
	return out
}

func containsDisplay(res plugin.SymbolResolutionResult, display string) bool {
	for _, s := range res.Resolved {
		if s.DisplayName == display {
			return true
		}
	}
	return false
}

// The two CVE advisory forms resolve: a fully namespace-qualified name
// ("Ionic.Zip.ZipEntry.Extract") and a cross-language lower-cased name ("Ecdsa.verify" for
// the C# "Ecdsa.Verify").
func TestResolve_CVEAdvisoryForms(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"ZipEntry.cs": `
namespace Ionic.Zip
{
    public class ZipEntry
    {
        public void Extract(string baseDir) { }
    }
}
`,
		"Ecdsa.cs": `
namespace EllipticCurve;
public static class Ecdsa
{
    public static bool Verify(string m, string sig, string key) { return false; }
}
`,
	})

	// Fully namespace-qualified, arity-free.
	res := resolve(t, dir, "Ionic.Zip.ZipEntry.Extract")
	if !containsDisplay(res, "ZipEntry.Extract(1)") {
		t.Errorf("Ionic.Zip.ZipEntry.Extract did not resolve; got %v", resolvedDisplays(res))
	}

	// Type-qualified only.
	res = resolve(t, dir, "ZipEntry.Extract")
	if !containsDisplay(res, "ZipEntry.Extract(1)") {
		t.Errorf("ZipEntry.Extract did not resolve; got %v", resolvedDisplays(res))
	}

	// Cross-language lower-cased method name resolves to the PascalCase C# method.
	res = resolve(t, dir, "Ecdsa.verify")
	if !containsDisplay(res, "Ecdsa.Verify(3)") {
		t.Errorf("Ecdsa.verify did not resolve case-insensitively; got %v", resolvedDisplays(res))
	}

	// Namespace-leaf-qualified form ("Zip.ZipEntry.Extract").
	res = resolve(t, dir, "Zip.ZipEntry.Extract")
	if !containsDisplay(res, "ZipEntry.Extract(1)") {
		t.Errorf("Zip.ZipEntry.Extract did not resolve; got %v", resolvedDisplays(res))
	}
}

// A no-match is an empty result, not an error, and never fabricates a resolution.
func TestResolve_NoMatch_Empty(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"A.cs": "namespace N { public class A { public void M() { } } }\n",
	})
	res := resolve(t, dir, "N.Other.Nope")
	if len(res.Resolved) != 0 {
		t.Errorf("unexpected resolution for a missing symbol: %v", resolvedDisplays(res))
	}
}

// The resolution inherits the index's declared partiality (inv.5): an unreadable subtree or
// skipped construct must not be laundered into a Complete resolution. Here a clean parse is
// Complete, proving the field is wired through.
func TestResolve_InheritsPartiality(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"A.cs": "namespace N { public class A { public void Extract() { } } }\n",
	})
	res := resolve(t, dir, "A.Extract")
	if !res.Partiality.Complete {
		t.Errorf("clean parse must be Complete; got %+v", res.Partiality)
	}
	if !containsDisplay(res, "A.Extract()") {
		t.Errorf("A.Extract() did not resolve; got %v", resolvedDisplays(res))
	}
}
