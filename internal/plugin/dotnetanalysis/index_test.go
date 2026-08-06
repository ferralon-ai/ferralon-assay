package dotnetanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// writeTree writes a map of relative-path → content under a fresh temp dir and returns the
// dir. Parent directories are created as needed.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func indexOf(t *testing.T, dir string) plugin.SymbolIndexResult {
	t.Helper()
	res, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("IndexSymbols: %v", err)
	}
	return res
}

func displays(res plugin.SymbolIndexResult) []string {
	var out []string
	for _, s := range res.Symbols {
		out = append(out, s.DisplayName)
	}
	return out
}

func hasDisplay(res plugin.SymbolIndexResult, display string) bool {
	for _, s := range res.Symbols {
		if s.DisplayName == display {
			return true
		}
	}
	return false
}

// symByDisplay returns the first symbol whose DisplayName matches, or a zero Symbol.
func symByDisplay(res plugin.SymbolIndexResult, display string) plugin.Symbol {
	for _, s := range res.Symbols {
		if s.DisplayName == display {
			return s
		}
	}
	return plugin.Symbol{}
}

// The two CVE sink shapes must resolve to declared symbols: DotNetZip's ZipEntry.Extract
// (a method on a class inside a BLOCK namespace, CVE-2024-48510) and starkbank-ecdsa's
// Ecdsa.Verify (a method inside a FILE-SCOPED namespace, CVE-2021-43569).
func TestIndexSymbols_CVESinkShapes(t *testing.T) {
	dir := writeTree(t, map[string]string{
		// DotNetZip — block namespace, class, overloaded Extract method + constructor.
		"Zip/ZipEntry.cs": `
using System;

namespace Ionic.Zip
{
    public partial class ZipEntry
    {
        private string _fileName;

        public ZipEntry(string fileName)
        {
            _fileName = fileName;
        }

        public string FileName { get; set; }

        public void Extract(string baseDir)
        {
            var target = System.IO.Path.Combine(baseDir, _fileName);
            WriteEntry(target);
        }

        public void Extract()
        {
            Extract(".");
        }

        private void WriteEntry(string path) { }
    }
}
`,
		// starkbank-ecdsa — file-scoped namespace, class Ecdsa with a Verify method.
		"Ecdsa.cs": `
namespace EllipticCurve;

public static class Ecdsa
{
    public static bool Verify(string message, Signature signature, PublicKey publicKey)
    {
        return signature.R.CompareTo(0) != 0;
    }
}
`,
	})

	res := indexOf(t, dir)

	// DotNetZip method sink + overload + constructor.
	if !hasDisplay(res, "ZipEntry.Extract(1)") {
		t.Errorf("missing ZipEntry.Extract(1); got %v", displays(res))
	}
	if !hasDisplay(res, "ZipEntry.Extract()") {
		t.Errorf("missing ZipEntry.Extract() overload; got %v", displays(res))
	}
	if !hasDisplay(res, "ZipEntry.ZipEntry(1)") {
		t.Errorf("missing ZipEntry constructor; got %v", displays(res))
	}
	if !hasDisplay(res, "ZipEntry") {
		t.Errorf("missing ZipEntry type; got %v", displays(res))
	}
	// The type + method must carry the dotted namespace as Package.
	if s := symByDisplay(res, "ZipEntry.Extract(1)"); s.Package != "Ionic.Zip" {
		t.Errorf("Extract package = %q, want Ionic.Zip", s.Package)
	}

	// starkbank Ecdsa.Verify under a file-scoped namespace.
	if !hasDisplay(res, "Ecdsa.Verify(3)") {
		t.Errorf("missing Ecdsa.Verify(3); got %v", displays(res))
	}
	if s := symByDisplay(res, "Ecdsa.Verify(3)"); s.Package != "EllipticCurve" {
		t.Errorf("Verify package = %q, want EllipticCurve (file-scoped namespace)", s.Package)
	}
}

// A property and a field must NOT be indexed as methods; an expression-bodied method and an
// interface method must be. Nested types resolve with the full enclosing-type chain.
func TestIndexSymbols_MemberShapes(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"Shapes.cs": `
namespace Acme.Lib
{
    public interface ICalc
    {
        int Compute(int x);
    }

    public class Calc : ICalc
    {
        private int _seed = 42;
        public int Seed { get; set; }
        public string Label => "calc";

        public int Compute(int x) => x + _seed;

        public class Inner
        {
            public void Ping() { }
        }
    }
}
`,
	})
	res := indexOf(t, dir)

	if !hasDisplay(res, "ICalc.Compute(1)") {
		t.Errorf("interface method ICalc.Compute(1) not indexed; got %v", displays(res))
	}
	if !hasDisplay(res, "Calc.Compute(1)") {
		t.Errorf("expression-bodied method Calc.Compute(1) not indexed; got %v", displays(res))
	}
	if !hasDisplay(res, "Calc.Inner") {
		t.Errorf("nested type Calc.Inner not indexed; got %v", displays(res))
	}
	if !hasDisplay(res, "Calc.Inner.Ping()") {
		t.Errorf("method on nested type Calc.Inner.Ping() not indexed; got %v", displays(res))
	}
	// Field _seed, auto-property Seed, and expression-bodied property Label must NOT be
	// mistaken for methods.
	for _, notMethod := range []string{"Calc.Seed()", "Calc.Seed(0)", "Calc._seed()", "Calc.Label()"} {
		if hasDisplay(res, notMethod) {
			t.Errorf("a field/property was mis-indexed as a method: %q", notMethod)
		}
	}
}

// Verbatim (@"..."), interpolated ($"...{expr}..."), and char literals must not perturb the
// brace balance or leak a fake declaration.
func TestIndexSymbols_LiteralsDoNotDerailBraces(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"Msg.cs": `
namespace Acme
{
    public class Msg
    {
        public string Build(string name)
        {
            var verbatim = @"class NotAType { void Fake() {} }";
            var interp = $"{name} has {name.Length} chars and a brace }} here";
            var ch = '}';
            return verbatim + interp + ch;
        }

        public void After() { }
    }
}
`,
	})
	res := indexOf(t, dir)

	if !hasDisplay(res, "Msg.Build(1)") {
		t.Errorf("Msg.Build(1) not indexed; got %v", displays(res))
	}
	// The After() method proves the brace balance survived the string literals.
	if !hasDisplay(res, "Msg.After()") {
		t.Errorf("Msg.After() not indexed — string-literal braces derailed the scanner; got %v", displays(res))
	}
	// The verbatim string's fake type/method must NOT leak into the index.
	if hasDisplay(res, "NotAType") || hasDisplay(res, "NotAType.Fake()") {
		t.Errorf("a literal's content leaked as a declaration; got %v", displays(res))
	}
}

// A build dir with no C# sources is a hard error (inv.4), never a silent empty index.
func TestIndexSymbols_NoSources_HardError(t *testing.T) {
	dir := t.TempDir()
	if _, err := IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{BuildDir: dir}); err == nil {
		t.Fatal("empty build dir must be a hard error")
	}
}

// A type with no namespace renders a well-formed "_root_" SCIP identity and an empty
// Package, never a malformed symbol.
func TestIndexSymbols_GlobalNamespace(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"Top.cs": "public class Top { public void Go() { } }\n",
	})
	res := indexOf(t, dir)
	if !hasDisplay(res, "Top.Go()") {
		t.Fatalf("Top.Go() not indexed; got %v", displays(res))
	}
	s := symByDisplay(res, "Top.Go()")
	if s.Package != "" {
		t.Errorf("global-namespace package = %q, want empty", s.Package)
	}
	if want := "scip-dotnet nuget . . _root_/Top#Go()."; s.SCIP != want {
		t.Errorf("SCIP = %q, want %q", s.SCIP, want)
	}
}
