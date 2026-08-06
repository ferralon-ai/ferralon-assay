package trigger_test

import (
	"context"
	"fmt"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// Example_runBaseline assesses one advisory against a codebase and persists the
// Report. MemStore keeps the state in memory, so this runs with no git repository.
func Example_runBaseline() {
	store := statestore.NewMemStore()

	rep, err := trigger.RunBaseline(context.Background(), store, trigger.BaselineRequest{
		Subject:    trigger.Subject{Repo: "example.com/app", Revision: "main", ResolvedCommit: "abc123"},
		Codebase:   assessment.CodebaseRef{Repo: "example.com/app", Revision: "main"},
		Advisories: []assessment.VulnRef{{ID: "GO-2021-0113", Source: "osv"}},
	})
	if err != nil {
		panic(err)
	}
	for _, f := range rep.Advisories {
		fmt.Printf("%s: %s\n", f.Advisory.ID, f.Verdict)
	}

	state, err := store.Read(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Printf("stored %d advisories for %s\n", len(state.Report.Advisories), state.Report.Subject.Repo)
	// Output:
	// GO-2021-0113: reachable_candidate
	// stored 1 advisories for example.com/app
}
