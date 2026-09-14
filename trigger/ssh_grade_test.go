package trigger

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// F4 regression — an SSH server ingress on a candidate's trace grades attacker_tainted.
//
// Pins the demo-go-svc CVE-2024-45337 shape at the grading layer: handleSSHConn (an
// Ingress{Kind:"ssh"}, surfaced by the goanalysis detector — see ssh_ingress_test.go)
// reads sconn.Permissions.Extensions["role"] and reaches the x/crypto/ssh sink. Before
// the fix the sink was reachable only via main → control_flow_only; with "ssh" among the
// attacker-controllable kinds, an ssh ingress on the trace lifts it to attacker_tainted —
// parity with the same repo's net/http DoS. The main-only case is the honesty wall: no
// attacker ingress on the trace stays control_flow_only, so the fix does not blanket-upgrade.
func TestReachabilityGrade_SSHIngress(t *testing.T) {
	const (
		sshHandler  = "scip-go gomod example.com/m . example.com/m/handleSSHConn()."
		sshSink     = "scip-go gomod golang.org/x/crypto/ssh . golang.org/x/crypto/ssh/ServerConn#handleAuthErrors()."
		httpHandler = "scip-go gomod example.com/m . example.com/m/expandHandler()."
		httpSink    = "scip-go gomod example.com/m . example.com/m/expand#makeslice()."
		mainSym     = "scip-go gomod example.com/m . example.com/m/main()."
	)

	tests := []struct {
		name      string
		ingresses []plugin.Ingress
		ingress   string // reaching ingress recorded on the resolved path
		sink      string
		wantGrade report.ReachabilityGrade
		wantKind  string
	}{
		{
			name: "ssh ingress on trace -> attacker_tainted",
			ingresses: []plugin.Ingress{
				{Kind: "main", Symbol: plugin.Symbol{SCIP: mainSym}},
				{Kind: "ssh", Symbol: plugin.Symbol{SCIP: sshHandler}},
			},
			ingress:   sshHandler,
			sink:      sshSink,
			wantGrade: report.GradeAttackerTainted,
			wantKind:  "ssh",
		},
		{
			name: "http handler on trace -> attacker_tainted (unregressed)",
			ingresses: []plugin.Ingress{
				{Kind: "handler", Symbol: plugin.Symbol{SCIP: httpHandler}},
				{Kind: "http_route", Symbol: plugin.Symbol{SCIP: httpHandler}, Selector: "/expand"},
			},
			ingress:   httpHandler,
			sink:      httpSink,
			wantGrade: report.GradeAttackerTainted,
			wantKind:  "http_route",
		},
		{
			name: "main-only trace -> control_flow_only (honesty wall)",
			ingresses: []plugin.Ingress{
				{Kind: "main", Symbol: plugin.Symbol{SCIP: mainSym}},
			},
			ingress:   mainSym,
			sink:      sshSink,
			wantGrade: report.GradeControlFlowOnly,
			wantKind:  "main",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := artifact.NewMemStore()
			putJSON(t, store, "a", artifact.TypeIngressMap, plugin.IngressResult{Ingresses: tt.ingresses})
			putJSON(t, store, "a", artifact.TypeReachability, struct {
				Reachability plugin.ReachabilityResult `json:"reachability"`
			}{Reachability: plugin.ReachabilityResult{Paths: []plugin.ReachPath{
				{Sink: plugin.Symbol{SCIP: tt.sink}, Ingress: plugin.Symbol{SCIP: tt.ingress},
					Trace: []plugin.Symbol{{SCIP: tt.ingress}, {SCIP: tt.sink}}},
			}}})

			grade, entry, _ := reachabilityEvidence(store, "a")
			if grade != tt.wantGrade {
				t.Errorf("grade = %q, want %q", grade, tt.wantGrade)
			}
			if entry == nil {
				t.Fatalf("entry point = nil, want kind %q", tt.wantKind)
			}
			if entry.Kind != tt.wantKind {
				t.Errorf("entry kind = %q, want %q", entry.Kind, tt.wantKind)
			}
			wantControllable := tt.wantGrade == report.GradeAttackerTainted
			if entry.AttackerControllable != wantControllable {
				t.Errorf("AttackerControllable = %v, want %v", entry.AttackerControllable, wantControllable)
			}
		})
	}
}
