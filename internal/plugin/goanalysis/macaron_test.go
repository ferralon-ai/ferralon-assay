// Hermetic goanalysis test for macaron ingress detection (ingress.go). It loads a real
// fixture (macaronmod) with the Go toolchain — no live model, no Docker, no network: the
// fixture's go.mod replaces gopkg.in/macaron.v1 with a local stub so the detector matches
// the package path without fetching the real module.
//
// It proves a handler registered on a macaron verb method (m.Post(pattern, mw, MyHandler))
// surfaces as an Ingress{Kind:"http_route", Symbol:<scip of MyHandler>} — the handler is
// boxed into the variadic ...Handler slice the detector unwraps — and that the stdlib
// net/http registrar path still produces its http_route ingress in the same module.
package goanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const macaronFixtureDir = "testdata/macaronmod"

// TestMacaron_RegisteredHandlerIsIngress proves a macaron-registered handler is detected as
// an http_route ingress, and that net/http registration in the same module is unaffected.
func TestMacaron_RegisteredHandlerIsIngress(t *testing.T) {
	res, err := FindIngresses(context.Background(), plugin.FindIngressesRequest{BuildDir: macaronFixtureDir})
	if err != nil {
		t.Fatalf("FindIngresses: %v", err)
	}

	macaronOK := false
	stdlibOK := false
	for _, in := range res.Ingresses {
		if in.Kind == "http_route" && strings.Contains(in.Symbol.SCIP, "MyHandler") {
			macaronOK = true
		}
		if in.Kind == "http_route" && strings.Contains(in.Symbol.SCIP, "stdlibHandler") {
			stdlibOK = true
		}
	}

	if !macaronOK {
		var got []string
		for _, in := range res.Ingresses {
			got = append(got, in.Kind+":"+in.Symbol.SCIP)
		}
		t.Fatalf("macaron-registered MyHandler not surfaced as an http_route ingress; got %v", got)
	}
	if !stdlibOK {
		var got []string
		for _, in := range res.Ingresses {
			got = append(got, in.Kind+":"+in.Symbol.SCIP)
		}
		t.Errorf("net/http registrar regressed: stdlibHandler not an http_route ingress; got %v", got)
	}
}
