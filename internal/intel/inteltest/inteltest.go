// Package inteltest helps tests outside package intel build the signals fixtures intel reads.
package inteltest

import (
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/intel"
)

// statedDigest is the signals_digest a hand-written fixture states.
var statedDigest = regexp.MustCompile(`"signals_digest": "sha256:[0-9a-f]{64}"`)

// Sealed is a reader of the signals document doc with the signals_digest it states replaced by the
// document's own (intel.Digest), as the producer stamps one, so intel.Parse, which verifies the
// digest, reads the fixture. doc states its digest once, as "signals_digest": "sha256:<64 hex>".
func Sealed(tb testing.TB, doc string) io.Reader {
	tb.Helper()
	if n := len(statedDigest.FindAllStringIndex(doc, -1)); n != 1 {
		tb.Fatalf("seal a signals fixture: it states %d signals_digest values; want one", n)
	}
	d, err := intel.Digest([]byte(doc))
	if err != nil {
		tb.Fatalf("seal a signals fixture: %v", err)
	}
	return strings.NewReader(statedDigest.ReplaceAllLiteralString(doc, `"signals_digest": "`+d+`"`))
}
