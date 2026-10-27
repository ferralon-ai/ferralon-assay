// requested_toolchain_test.go
//
// Which toolchain facts the reachability stage asks the analyzer to run under. Only an exact fact
// from a source that observed the subject is requested; build_resolved is the analyzer's own go
// command and never establishes the subject's release.
package pipeline

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
)

func TestRequestedToolchain(t *testing.T) {
	cases := []struct {
		name string
		flag bool
		fact *ToolchainFact
		want string
	}{
		{"subject declared exact", true, &ToolchainFact{Version: "go1.22.4", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared}, "go1.22.4"},
		{"ci observed exact", true, &ToolchainFact{Version: "go1.23.1", Bound: ToolchainBoundExact, Source: ToolchainSourceCIObserved}, "go1.23.1"},
		{"build resolved exact is the analyzer's go", true, &ToolchainFact{Version: "go1.24.0", Bound: ToolchainBoundExact, Source: ToolchainSourceBuildResolved}, ""},
		{"toolchain directive floor", true, &ToolchainFact{Version: "go1.22.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceToolchainDirective}, ""},
		{"go directive floor", true, &ToolchainFact{Version: "go1.21.0", Bound: ToolchainBoundMinimum, Source: ToolchainSourceGoDirective}, ""},
		{"unresolved", true, &ToolchainFact{Bound: ToolchainBoundNone, Source: ToolchainSourceUnresolved}, ""},
		{"no fact", true, nil, ""},
		{"flag off", false, &ToolchainFact{Version: "go1.22.4", Bound: ToolchainBoundExact, Source: ToolchainSourceSubjectDeclared}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			caseID := "case-requested-" + tc.name
			if tc.fact != nil {
				putJSON(t, store, caseID, artifact.TypeInventory, map[string]any{"toolchain": tc.fact})
			}
			s := reachabilityIngress{subjectToolchain: tc.flag}
			if got := s.requestedToolchain(store, caseID); got != tc.want {
				t.Fatalf("requestedToolchain = %q, want %q", got, tc.want)
			}
		})
	}
}
