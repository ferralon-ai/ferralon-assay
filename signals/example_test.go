package signals_test

import (
	"fmt"

	"github.com/ferralon-ai/ferralon-assay/signals"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// Example loads a signals file and hands it to a baseline request, so the run's findings carry a
// Priority. The request is then passed to trigger.RunBaseline as usual.
func Example() {
	s, err := signals.Load("testdata/signals.json")
	if err != nil {
		panic(err)
	}
	req := trigger.BaselineRequest{
		Subject: trigger.Subject{Repo: "example.com/app", Revision: "main", ResolvedCommit: "abc123"},
		Signals: s,
	}

	if e, ok := req.Signals.EPSS("CVE-2021-38561"); ok {
		fmt.Printf("EPSS %.4f as of %s\n", e.Score, e.AsOf)
	}
	if k, ok := req.Signals.KEV("CVE-2021-38561"); ok {
		fmt.Printf("KEV listed=%t in catalog %s\n", k.Listed, k.CatalogVersion)
	}
	// Output:
	// EPSS 0.0123 as of 2026-10-18
	// KEV listed=false in catalog 2026.10.19
}
