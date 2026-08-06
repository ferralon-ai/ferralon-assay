package goanalysis

import (
	"context"
	"go/types"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const fixtureDir = "testdata/fixturemod"

// findObject loads the fixture and returns the named object from the given
// fixture-relative package path (e.g. "tegron.test/fixturemod/util").
func loadFixture(t *testing.T) *LoadResult {
	t.Helper()
	res, err := LoadProgram(context.Background(), fixtureDir)
	if err != nil {
		t.Fatalf("LoadProgram: %v", err)
	}
	if len(res.Packages) == 0 {
		t.Fatalf("LoadProgram: no packages loaded")
	}
	return res
}

func lookup(t *testing.T, res *LoadResult, importPath, name string) (*types.Package, types.Object) {
	t.Helper()
	for _, p := range res.Packages {
		if p.PkgPath == importPath {
			obj := p.Types.Scope().Lookup(name)
			if obj == nil {
				t.Fatalf("object %q not found in %q", name, importPath)
			}
			return p.Types, obj
		}
	}
	t.Fatalf("package %q not loaded", importPath)
	return nil, nil
}

func TestLoadProgram_LoadsFixtureOffline(t *testing.T) {
	res := loadFixture(t)
	var got []string
	for _, p := range res.Packages {
		got = append(got, p.PkgPath)
	}
	for _, want := range []string{
		"tegron.test/fixturemod",
		"tegron.test/fixturemod/service",
		"tegron.test/fixturemod/util",
	} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected package %q among loaded packages %v", want, got)
		}
	}
}

func TestSCIPString_NonEmptyAndVersionQualified(t *testing.T) {
	res := loadFixture(t)
	pkg, obj := lookup(t, res, "tegron.test/fixturemod/util", "Sink")
	s := SCIPString(pkg, obj)
	if s == "" {
		t.Fatal("SCIPString returned empty")
	}
	if !strings.HasPrefix(s, "scip-go gomod ") {
		t.Errorf("expected scip-go gomod prefix, got %q", s)
	}
	if !strings.Contains(s, "tegron.test/fixturemod") {
		t.Errorf("expected module path in symbol, got %q", s)
	}
	// version-qualified: a non-empty version token must sit between the
	// package-name and the first descriptor.
	fields := strings.SplitN(s, " ", 5)
	if len(fields) < 5 {
		t.Fatalf("expected 5 space-separated fields, got %d: %q", len(fields), s)
	}
	if strings.TrimSpace(fields[3]) == "" {
		t.Errorf("expected non-empty version token, got %q", s)
	}
}

func TestSCIPString_Deterministic(t *testing.T) {
	res := loadFixture(t)
	pkg, obj := lookup(t, res, "tegron.test/fixturemod/util", "Sink")
	a := SCIPString(pkg, obj)
	b := SCIPString(pkg, obj)
	if a != b {
		t.Errorf("non-deterministic: %q != %q", a, b)
	}
}

func TestSCIPString_DistinctForDistinctObjects(t *testing.T) {
	res := loadFixture(t)
	upkg, sink := lookup(t, res, "tegron.test/fixturemod/util", "Sink")
	spkg, svc := lookup(t, res, "tegron.test/fixturemod/service", "Service")
	_, newFn := lookup(t, res, "tegron.test/fixturemod/service", "New")

	sinkS := SCIPString(upkg, sink)
	svcS := SCIPString(spkg, svc)
	newS := SCIPString(spkg, newFn)

	seen := map[string]string{}
	for name, s := range map[string]string{"Sink": sinkS, "Service": svcS, "New": newS} {
		if prev, ok := seen[s]; ok {
			t.Errorf("collision: %s and %s both produced %q", prev, name, s)
		}
		seen[s] = name
	}
}

func TestSCIPString_MethodDistinctFromType(t *testing.T) {
	res := loadFixture(t)
	spkg, svc := lookup(t, res, "tegron.test/fixturemod/service", "Service")
	named, ok := svc.Type().(*types.Named)
	if !ok {
		t.Fatalf("Service is not a Named type")
	}
	// the *Service method set carries Handle.
	ptr := types.NewPointer(named)
	ms := types.NewMethodSet(ptr)
	var handle types.Object
	for i := 0; i < ms.Len(); i++ {
		if ms.At(i).Obj().Name() == "Handle" {
			handle = ms.At(i).Obj()
		}
	}
	if handle == nil {
		t.Fatal("Handle method not found in *Service method set")
	}
	typeS := SCIPString(spkg, svc)
	methodS := SCIPString(spkg, handle)
	if typeS == methodS {
		t.Errorf("type and method share a symbol: %q", typeS)
	}
	if !strings.Contains(methodS, "Service") || !strings.Contains(methodS, "Handle") {
		t.Errorf("method symbol should name its receiver and method, got %q", methodS)
	}
}

func TestIndexSymbols_FindsExportedSymbols(t *testing.T) {
	res := IndexSymbolsResultMust(t)
	want := map[string]string{
		"Sink":    "tegron.test/fixturemod/util",
		"Service": "tegron.test/fixturemod/service",
		"New":     "tegron.test/fixturemod/service",
		"Handle":  "tegron.test/fixturemod/service",
	}
	have := map[string]bool{}
	for _, s := range res.Symbols {
		have[s.DisplayName] = true
	}
	for name, pkg := range want {
		if !findSymbol(res.Symbols, name, pkg) {
			t.Errorf("expected exported symbol %q in %q; got display names %v", name, pkg, displayNames(res.Symbols))
		}
	}
	if !res.Partiality.Complete {
		t.Errorf("expected Complete partiality for a clean load, got %+v", res.Partiality)
	}
}

func IndexSymbolsResultMust(t *testing.T) plugin.SymbolIndexResult {
	t.Helper()
	res, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: fixtureDir})
	if err != nil {
		t.Fatalf("IndexSymbols: %v", err)
	}
	return res
}

func findSymbol(syms []plugin.Symbol, name, pkg string) bool {
	for _, s := range syms {
		if s.Package == pkg && (s.DisplayName == name || strings.HasSuffix(s.DisplayName, "."+name) || strings.Contains(s.DisplayName, name)) {
			return true
		}
	}
	return false
}

func displayNames(syms []plugin.Symbol) []string {
	out := make([]string, 0, len(syms))
	for _, s := range syms {
		out = append(out, s.DisplayName)
	}
	return out
}

func TestIndexSymbols_SCIPDeterministicAcrossCalls(t *testing.T) {
	a := IndexSymbolsResultMust(t)
	b := IndexSymbolsResultMust(t)
	index := func(r plugin.SymbolIndexResult) map[string]string {
		m := map[string]string{}
		for _, s := range r.Symbols {
			m[s.DisplayName+"@"+s.Package] = s.SCIP
		}
		return m
	}
	ma, mb := index(a), index(b)
	for k, v := range ma {
		if mb[k] != v {
			t.Errorf("SCIP for %q changed across calls: %q != %q", k, v, mb[k])
		}
	}
}

func TestResolveDependencySymbols_MapsKnownSymbol(t *testing.T) {
	req := plugin.ResolveSymbolsRequest{
		BuildDir:        fixtureDir,
		PURL:            "pkg:golang/tegron.test/fixturemod/util",
		AdvisorySymbols: []string{"Sink"},
		VulnID:          "GO-TEST-0001",
	}
	res, err := ResolveDependencySymbols(context.Background(), req)
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	if len(res.Resolved) == 0 {
		t.Fatal("expected at least one resolved symbol for advisory symbol Sink")
	}
	for _, s := range res.Resolved {
		if !strings.Contains(s.DisplayName, "Sink") {
			t.Errorf("resolved a non-matching symbol: %q", s.DisplayName)
		}
		if s.SCIP == "" {
			t.Errorf("resolved symbol missing SCIP: %+v", s)
		}
	}
}

func TestResolveDependencySymbols_NoMatchIsEmptyNotError(t *testing.T) {
	req := plugin.ResolveSymbolsRequest{
		BuildDir:        fixtureDir,
		PURL:            "pkg:golang/tegron.test/fixturemod/util",
		AdvisorySymbols: []string{"NoSuchSymbolXYZ"},
		VulnID:          "GO-TEST-0002",
	}
	res, err := ResolveDependencySymbols(context.Background(), req)
	if err != nil {
		t.Fatalf("ResolveDependencySymbols: %v", err)
	}
	if len(res.Resolved) != 0 {
		t.Errorf("expected no matches, got %v", res.Resolved)
	}
}

func TestLoadProgram_BrokenDirIsHardError(t *testing.T) {
	_, err := LoadProgram(context.Background(), "testdata/does-not-exist")
	if err == nil {
		t.Fatal("expected a hard error loading a nonexistent build dir")
	}
}
