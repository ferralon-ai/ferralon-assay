package symboltest

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/dotnetanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestDotNetReferenceProfile drives the .NET reference profile against the REAL
// first-party producer (dotnetanalysis.IndexSymbols) over the offline testdata/dotnetref
// fixture. It is the C# instance of the template TestGoReferenceProfile establishes: an
// eight-category table where every row is a declared KnownGap today (the arity-only
// producer leaves the structured identity fields zero), so the profile is GREEN under
// xfail semantics.
//
// Divergence from goref_test.go — UNGATED (BD4). goref gates on exec.LookPath("go")
// because goanalysis.IndexSymbols loads the fixture via go/packages, which needs `go` on
// PATH. dotnetanalysis.IndexSymbols is a pure-Go lexical scanner over the C# source text:
// it needs no .NET SDK, no `dotnet`, no `go` on PATH, so the drive is unconditionally
// hermetic (identical to index_test.go). Reading the C# source text is NOT executing
// target code — no restore, build, or run happens here.
func TestDotNetReferenceProfile(t *testing.T) {
	res, err := dotnetanalysis.IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{
		BuildDir: "testdata/dotnetref",
	})
	if err != nil {
		t.Fatalf("IndexSymbols on testdata/dotnetref: %v", err)
	}
	if len(res.Symbols) == 0 {
		t.Fatal("IndexSymbols emitted no symbols for the dotnetref fixture")
	}

	// GREEN under xfail: every row is a declared gap, and IndexSymbols emits
	// structured-field-empty symbols, so none match any structured Want.
	AssertProfile(t, DotNetReferenceProfile(), res.Symbols)
}

// TestDotNetReferenceProfile_MirrorsProducerShape sanity-checks the reference table
// against a hand-captured []plugin.Symbol mirroring IndexSymbols' real output shape today:
// SCIP + DisplayName + Package set, the structured identity fields left zero
// (dotnetanalysis/index.go symbolsFromParse; scip.go arity-only descriptors). The strings
// below are captured verbatim from the live producer over testdata/dotnetref. This keeps
// the mechanism verifiable structurally even without invoking the producer.
func TestDotNetReferenceProfile_MirrorsProducerShape(t *testing.T) {
	ns := dotnetRefNamespace
	mirror := []plugin.Symbol{
		{SCIP: "scip-dotnet nuget . . Symboltest/DotNetRef/Widget#", DisplayName: "Widget", Package: ns},
		{SCIP: "scip-dotnet nuget . . Symboltest/DotNetRef/Widget#Render(1).", DisplayName: "Widget.Render(1)", Package: ns},
		{SCIP: "scip-dotnet nuget . . Symboltest/DotNetRef/Widget#Widget().", DisplayName: "Widget.Widget()", Package: ns},
		{SCIP: "scip-dotnet nuget . . Symboltest/DotNetRef/Widget#Inner#", DisplayName: "Widget.Inner", Package: ns},
	}
	AssertProfile(t, DotNetReferenceProfile(), mirror)
}
