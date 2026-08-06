// internal/ids/ids_test.go
package ids_test

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/ids"
)

func TestNew(t *testing.T) {
	a := ids.New()
	b := ids.New()

	if len(a) != 36 {
		t.Fatalf("expected 36-char UUID, got %d chars: %q", len(a), a)
	}
	if a == "" {
		t.Fatal("New() returned empty string")
	}
	if a == b {
		t.Fatalf("two successive calls returned identical UUIDs: %q", a)
	}
	// UUIDv7 encodes a millisecond timestamp in the high bits of the first segment.
	// Two UUIDs generated in order must sort lexically in that order.
	if strings.Compare(a, b) >= 0 {
		t.Fatalf("UUIDv7 lexical order violated: %q >= %q", a, b)
	}
}
