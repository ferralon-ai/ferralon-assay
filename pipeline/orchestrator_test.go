// internal/pipeline/orchestrator_test.go
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
)

// statusExtra stands in for a status a caller declares for a stage of its own — the
// orchestrator carries whatever a Stage reports and does not enumerate the values.
const statusExtra assessment.Status = "extra"

// fakeStage records that it ran and advances the case to a fixed status.
type fakeStage struct {
	name   string
	status assessment.Status
	fail   bool
	ran    *[]string
}

func (f fakeStage) Name() string              { return f.name }
func (f fakeStage) Status() assessment.Status { return f.status }
func (f fakeStage) Run(ctx context.Context, c *assessment.Assessment, store artifact.Store) error {
	*f.ran = append(*f.ran, f.name)
	if f.fail {
		return errors.New("boom")
	}
	return nil
}

func newRunCase(t *testing.T, cases assessment.Store) *assessment.Assessment {
	t.Helper()
	c, err := cases.Create(assessment.Request{
		Vulnerability:  assessment.VulnRef{ID: "GO-2021-0001", Source: "osv"},
		Codebase:       assessment.CodebaseRef{Repo: "example.com/x", Revision: "abc"},
		Execution:      assessment.ExecutionContext{Kind: "compose"},
		OwnershipProof: assessment.OwnershipProof{Token: "tok"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return c
}

func TestOrchestratorRunAdvancesStatus(t *testing.T) {
	cases := assessment.NewMemStore()
	store := artifact.NewMemStore()
	c := newRunCase(t, cases)

	var ran []string
	stages := []Stage{
		fakeStage{name: "a", status: assessment.StatusInventory, ran: &ran},
		fakeStage{name: "b", status: assessment.StatusAnalysis, ran: &ran},
		fakeStage{name: "c", status: statusExtra, ran: &ran},
	}
	orch := NewOrchestrator(cases, store, stages)

	if err := orch.Run(context.Background(), c.ID); err != nil {
		t.Fatalf("Run: %v", err)
	}

	got, err := cases.Get(c.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != assessment.StatusComplete {
		t.Fatalf("final status = %q, want %q", got.Status, assessment.StatusComplete)
	}
	want := []string{"a", "b", "c"}
	if len(ran) != len(want) {
		t.Fatalf("ran = %v, want %v", ran, want)
	}
	for i := range want {
		if ran[i] != want[i] {
			t.Fatalf("ran[%d] = %q, want %q", i, ran[i], want[i])
		}
	}
}

func TestOrchestratorRunWithProgressLogEmitsPerStageAndCompletion(t *testing.T) {
	cases := assessment.NewMemStore()
	store := artifact.NewMemStore()
	c := newRunCase(t, cases)

	var ran []string
	stages := []Stage{
		fakeStage{name: "a", status: assessment.StatusInventory, ran: &ran},
		fakeStage{name: "b", status: assessment.StatusAnalysis, ran: &ran},
	}

	var logs []string
	orch := NewOrchestrator(cases, store, stages, WithProgressLog(func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}))

	if err := orch.Run(context.Background(), c.ID); err != nil {
		t.Fatalf("Run: %v", err)
	}

	joined := strings.Join(logs, "\n")
	for _, name := range []string{"a", "b"} {
		if !strings.Contains(joined, "stage="+name) {
			t.Errorf("progress log missing stage=%s; got:\n%s", name, joined)
		}
	}
	if !strings.Contains(joined, "complete") {
		t.Errorf("progress log missing completion line; got:\n%s", joined)
	}
	if !strings.Contains(joined, c.ID) {
		t.Errorf("progress log missing case id %q; got:\n%s", c.ID, joined)
	}
}

func TestOrchestratorRunStopsOnFailure(t *testing.T) {
	cases := assessment.NewMemStore()
	store := artifact.NewMemStore()
	c := newRunCase(t, cases)

	var ran []string
	stages := []Stage{
		fakeStage{name: "a", status: assessment.StatusInventory, ran: &ran},
		fakeStage{name: "b", status: assessment.StatusAnalysis, fail: true, ran: &ran},
		fakeStage{name: "c", status: statusExtra, ran: &ran},
	}
	orch := NewOrchestrator(cases, store, stages)

	err := orch.Run(context.Background(), c.ID)
	if err == nil {
		t.Fatalf("Run: want error, got nil")
	}

	got, err := cases.Get(c.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != assessment.StatusFailed {
		t.Fatalf("final status = %q, want %q", got.Status, assessment.StatusFailed)
	}
	want := []string{"a", "b"} // c must NOT run
	if len(ran) != len(want) {
		t.Fatalf("ran = %v, want %v", ran, want)
	}
	for i := range want {
		if ran[i] != want[i] {
			t.Fatalf("ran[%d] = %q, want %q", i, ran[i], want[i])
		}
	}
}
