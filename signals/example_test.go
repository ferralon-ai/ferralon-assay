package signals_test

import (
	"context"
	"fmt"

	"github.com/ferralon-ai/ferralon-assay/signals"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// Example loads a signals file and feeds it to a baseline request so the run's findings carry a
// Priority. The Report the run returns names the file that ranked them.
func Example() {
	s, err := signals.Load("testdata/signals.json")
	if err != nil {
		panic(err)
	}
	req := trigger.BaselineRequest{
		Subject: trigger.Subject{Repo: "example.com/app", Revision: "main", ResolvedCommit: "abc123"},
	}
	signals.Feed(&req, s)

	rep, err := trigger.RunBaseline(context.Background(), statestore.NewMemStore(), req)
	if err != nil {
		panic(err)
	}
	fmt.Println("ranked with", rep.Provenance.Intel.SignalsDigest)

	if e, ok := s.EPSS("CVE-2021-38561"); ok {
		fmt.Printf("EPSS %.4f as of %s\n", e.Score, e.AsOf)
	}
	if k, ok := s.KEV("CVE-2021-38561"); ok {
		fmt.Printf("KEV listed=%t in catalog %s\n", k.Listed, k.CatalogVersion)
	}
	// Output:
	// ranked with sha256:d8295c19837631c504081c43d9ef80e1f6ae5d57cd39b11a73b01c3a72b6c45b
	// EPSS 0.0123 as of 2026-10-18
	// KEV listed=false in catalog 2026.10.19
}
