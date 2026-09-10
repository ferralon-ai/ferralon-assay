package symboltest

import (
	"context"
	"os/exec"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/goanalysis"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestGoReferenceProfile drives the Go reference profile against the REAL
// first-party producer (goanalysis.IndexSymbols) on the offline testdata/goref
// fixture. It is the concrete template the four language lanes copy for their
// PLAN-0x0: an eight-category table where every row is a declared KnownGap today
// (no Go producer populates the structured identity — packages.go:35,238-242), so
// the profile is GREEN under xfail semantics.
//
// Toolchain-gated: IndexSymbols loads the fixture via go/packages, which requires
// `go` on PATH (mirrors reach_toolchain_test.go / reachcandidate/live_test.go). It
// is otherwise hermetic — offline fixture module, GOWORK=off.
func TestGoReferenceProfile(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no `go` on PATH: cannot run goanalysis.IndexSymbols on the goref fixture")
	}

	res, err := goanalysis.IndexSymbols(context.Background(), plugin.IndexSymbolsRequest{
		BuildDir: "testdata/goref",
	})
	if err != nil {
		t.Fatalf("IndexSymbols on testdata/goref: %v", err)
	}
	if len(res.Symbols) == 0 {
		t.Fatal("IndexSymbols emitted no symbols for the goref fixture")
	}

	// GREEN under xfail: every row is a declared gap, and IndexSymbols emits
	// structured-field-empty symbols, so none match any structured Want.
	AssertProfile(t, GoReferenceProfile(), res.Symbols)
}

// TestGoReferenceProfile_MirrorsProducerShape sanity-checks — without a toolchain
// — that the reference table is well-formed against a captured []plugin.Symbol
// mirroring IndexSymbols' real output shape (sym()-style: SCIP==DisplayName,
// structured fields empty; see goanalysis/packages.go:35,238-242). This keeps the
// mechanism verifiable even where `go` is absent.
func TestGoReferenceProfile_MirrorsProducerShape(t *testing.T) {
	pkg := "symboltest.test/goref"
	mirror := []plugin.Symbol{
		// Package-scope objects: IndexSymbols sets SCIP/DisplayName/Package only.
		{SCIP: "scip-go gomod " + pkg + " . " + pkg + "/Widget#", DisplayName: "Widget", Package: pkg},
		{SCIP: "scip-go gomod " + pkg + " . " + pkg + "/Build().", DisplayName: "Build", Package: pkg},
		{SCIP: "scip-go gomod " + pkg + " . " + pkg + "/NewWidget().", DisplayName: "NewWidget", Package: pkg},
		{SCIP: "scip-go gomod " + pkg + " . " + pkg + "/Widget#Render().", DisplayName: "(*Widget).Render", Package: pkg},
	}
	AssertProfile(t, GoReferenceProfile(), mirror)
}
