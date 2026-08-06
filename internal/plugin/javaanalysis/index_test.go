package javaanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const fixtureDir = "testdata/fixturejar"

func indexFixture(t *testing.T) plugin.SymbolIndexResult {
	t.Helper()
	res, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: fixtureDir})
	if err != nil {
		t.Fatalf("IndexSymbols: %v", err)
	}
	return res
}

// scipFor returns the SCIP id of the first symbol with the given display name, or
// "" if none.
func scipFor(syms []plugin.Symbol, display string) string {
	for _, s := range syms {
		if s.DisplayName == display {
			return s.SCIP
		}
	}
	return ""
}

func displayNames(syms []plugin.Symbol) []string {
	out := make([]string, 0, len(syms))
	for _, s := range syms {
		out = append(out, s.DisplayName)
	}
	return out
}

func TestIndexSymbols_FindsTypesMethodsFields(t *testing.T) {
	res := indexFixture(t)
	want := map[string]string{
		// type           expected package
		"Sink":              "com.example.util",
		"Sink.forward(1)":   "com.example.util",
		"Sink.PREFIX":       "com.example.util",
		"Service":           "com.example.service",
		"Service.handle()":  "com.example.service",
		"Service.handle(2)": "com.example.service",
		"Service.name":      "com.example.service",
	}
	pkgOf := map[string]string{}
	for _, s := range res.Symbols {
		pkgOf[s.DisplayName] = s.Package
	}
	for name, pkg := range want {
		got, ok := pkgOf[name]
		if !ok {
			t.Errorf("expected symbol %q in index; got display names %v", name, displayNames(res.Symbols))
			continue
		}
		if got != pkg {
			t.Errorf("symbol %q: package = %q, want %q", name, got, pkg)
		}
	}
}

func TestIndexSymbols_NestedTypesAreQualified(t *testing.T) {
	res := indexFixture(t)
	for _, want := range []string{"Service.Config", "Service.Listener", "Service.Config.retries"} {
		if scipFor(res.Symbols, want) == "" {
			t.Errorf("expected nested symbol %q; got %v", want, displayNames(res.Symbols))
		}
	}
	// The nested type's SCIP must carry both enclosing and nested type descriptors.
	got := scipFor(res.Symbols, "Service.Config.retries")
	if !strings.Contains(got, "Service#Config#retries.") {
		t.Errorf("nested field SCIP = %q, want it to contain Service#Config#retries.", got)
	}
}

func TestIndexSymbols_OverloadsDisambiguatedByArity(t *testing.T) {
	res := indexFixture(t)
	h0 := scipFor(res.Symbols, "Service.handle()")
	h2 := scipFor(res.Symbols, "Service.handle(2)")
	if h0 == "" || h2 == "" {
		t.Fatalf("expected both handle overloads; got %v", displayNames(res.Symbols))
	}
	if h0 == h2 {
		t.Errorf("overloaded methods collided on SCIP %q", h0)
	}
}

func TestIndexSymbols_EnumConstantsAndMethods(t *testing.T) {
	res := indexFixture(t)
	for _, want := range []string{"Status", "Status.OK", "Status.FAILED", "Status.isOk()"} {
		if scipFor(res.Symbols, want) == "" {
			t.Errorf("expected enum symbol %q; got %v", want, displayNames(res.Symbols))
		}
	}
}

func TestIndexSymbols_RecordTypeAndMethod(t *testing.T) {
	res := indexFixture(t)
	for _, want := range []string{"Point", "Point.sum()"} {
		if scipFor(res.Symbols, want) == "" {
			t.Errorf("expected record symbol %q; got %v", want, displayNames(res.Symbols))
		}
	}
}

func TestIndexSymbols_SCIPWellFormedAndDeterministic(t *testing.T) {
	a := indexFixture(t)
	b := indexFixture(t)
	if len(a.Symbols) != len(b.Symbols) {
		t.Fatalf("non-deterministic count: %d != %d", len(a.Symbols), len(b.Symbols))
	}
	for i := range a.Symbols {
		if a.Symbols[i].SCIP != b.Symbols[i].SCIP {
			t.Errorf("non-deterministic SCIP at %d: %q != %q", i, a.Symbols[i].SCIP, b.Symbols[i].SCIP)
		}
		if !strings.HasPrefix(a.Symbols[i].SCIP, "scip-java maven ") {
			t.Errorf("symbol %q lacks scip-java maven prefix: %q", a.Symbols[i].DisplayName, a.Symbols[i].SCIP)
		}
		if a.Symbols[i].SCIP == "" {
			t.Errorf("empty SCIP for %q", a.Symbols[i].DisplayName)
		}
	}
}

func TestIndexSymbols_SCIPUniquePerSymbol(t *testing.T) {
	res := indexFixture(t)
	seen := map[string]string{}
	for _, s := range res.Symbols {
		if prev, ok := seen[s.SCIP]; ok {
			t.Errorf("SCIP collision: %q and %q share %q", prev, s.DisplayName, s.SCIP)
		}
		seen[s.SCIP] = s.DisplayName
	}
}

func TestIndexSymbols_CleanFixtureIsComplete(t *testing.T) {
	res := indexFixture(t)
	if !res.Partiality.Complete {
		t.Errorf("expected Complete partiality for the clean fixture, got %+v", res.Partiality)
	}
}

func TestIndexSymbols_MissingBuildDirIsHardError(t *testing.T) {
	_, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: "testdata/does-not-exist"})
	if err == nil {
		t.Fatal("expected a hard error for a nonexistent build dir")
	}
}

func TestIndexSymbols_NoJavaSourcesIsHardError(t *testing.T) {
	dir := t.TempDir() // exists but has no .java files
	_, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: dir})
	if err == nil {
		t.Fatal("expected a hard error when no .java sources are present")
	}
}
