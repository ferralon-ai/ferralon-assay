package github

import (
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/report"
)

func TestSummariesNameTheMode(t *testing.T) {
	tests := []struct {
		name string
		mode *report.Mode
		want string
	}{
		{name: "strict from input", mode: &report.Mode{Strictness: "strict", Source: "input"}, want: "**Strictness:** `strict` (input)"},
		{name: "practical by default", mode: &report.Mode{Strictness: "practical", Source: "default"}, want: "**Strictness:** `practical` (default)"},
		{name: "legacy report states none"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := report.NewBuilder(report.Subject{Repo: "r"}).Build()
			r.Mode = tt.mode
			for surface, body := range map[string]string{"tier0": renderSummary(r, nil), "tier1": renderTier1Body(r)} {
				if got := strings.Contains(body, "**Strictness:**"); got != (tt.want != "") {
					t.Errorf("%s: strictness line present = %v, want %v", surface, got, tt.want != "")
				}
				if tt.want != "" && !strings.Contains(body, tt.want) {
					t.Errorf("%s: missing %q", surface, tt.want)
				}
			}
		})
	}
}
