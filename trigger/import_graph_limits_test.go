package trigger

import (
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// TestFinding_NotImportedAgainstCgo: a refutation resting on the build importing none of the
// vulnerable packages holds against the bounded cgo limit, which cannot bring a package into the
// build, and against no other cgo limit or basis.
func TestFinding_NotImportedAgainstCgo(t *testing.T) {
	const net = "pkg:golang/golang.org/x/net"
	bounded := artifact.ScopedPartialityFlag{
		Reason: plugin.PartialReasonCgo, Package: "pkg:golang/github.com/mattn/go-sqlite3",
		Path: "github.com/mattn/go-sqlite3", Targets: []string{"pkg:golang/github.com/mattn/go-sqlite3", net},
	}
	cases := []struct {
		name        string
		mutate      func(*groundsFixture)
		wantVerdict report.Verdict
		wantReason  string
		wantLimits  []report.Limit
	}{
		{
			name:        "bounded cgo beside the not-imported basis clears",
			mutate:      func(fx *groundsFixture) { fx.scoped = []artifact.ScopedPartialityFlag{bounded} },
			wantVerdict: report.VerdictNotExploitable,
		},
		{
			name: "bounded cgo beside a not-reached refutation withholds",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation.Basis = plugin.RefutationAnalyzerSymbolNotReached
				fx.scoped = []artifact.ScopedPartialityFlag{bounded}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
		{
			name: "bounded cgo without a refutation withholds",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation = nil
				fx.scoped = []artifact.ScopedPartialityFlag{bounded}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
		{
			name: "a not-imported refutation of another module does not clear bounded cgo",
			mutate: func(fx *groundsFixture) {
				fx.reach.Refutation.Package = "pkg:golang/golang.org/x/text"
				fx.scoped = []artifact.ScopedPartialityFlag{bounded}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
		{
			name: "the not-imported refutation of the admitted module is not the lane's first",
			mutate: func(fx *groundsFixture) {
				first := *fx.reach.Refutation
				first.Package = "pkg:golang/golang.org/x/text"
				fx.reach.Refutations = []plugin.Refutation{*fx.reach.Refutation}
				fx.reach.Refutation = &first
				fx.scoped = []artifact.ScopedPartialityFlag{bounded}
			},
			wantVerdict: report.VerdictNotExploitable,
		},
		{
			name: "a not-reached refutation of the admitted module beside another's not-imported one withholds",
			mutate: func(fx *groundsFixture) {
				other := *fx.reach.Refutation
				other.Package = "pkg:golang/golang.org/x/text"
				fx.reach.Refutation.Basis = plugin.RefutationAnalyzerSymbolNotReached
				fx.reach.Refutations = []plugin.Refutation{other}
				fx.scoped = []artifact.ScopedPartialityFlag{bounded}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
		{
			name: "a cgo limit with no targets withholds",
			mutate: func(fx *groundsFixture) {
				unbounded := bounded
				unbounded.Targets = nil
				fx.scoped = []artifact.ScopedPartialityFlag{unbounded}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
		{
			name:        "run-wide cgo withholds",
			mutate:      func(fx *groundsFixture) { fx.footprint = []string{plugin.PartialReasonCgo} },
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
			wantLimits:  []report.Limit{{Reason: plugin.PartialReasonCgo}},
		},
		{
			name: "run-wide cgo beside bounded cgo withholds, and is the limit named",
			mutate: func(fx *groundsFixture) {
				fx.footprint = []string{plugin.PartialReasonCgo}
				fx.scoped = []artifact.ScopedPartialityFlag{bounded}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
			wantLimits:  []report.Limit{{Reason: plugin.PartialReasonCgo}},
		},
		{
			name: "another cgo limit with targets withholds",
			mutate: func(fx *groundsFixture) {
				unresolved := bounded
				unresolved.Reason = plugin.PartialReasonCgoUnresolved
				fx.scoped = []artifact.ScopedPartialityFlag{unresolved}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
		{
			name: "an unresolved cgo setting withholds",
			mutate: func(fx *groundsFixture) {
				fx.scoped = []artifact.ScopedPartialityFlag{bounded}
				fx.footprint = []string{plugin.PartialReasonCgoUnresolved}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
		{
			name: "another scoped limit on the module withholds",
			mutate: func(fx *groundsFixture) {
				other := bounded
				other.Reason = plugin.PartialReasonToolFailure
				fx.scoped = []artifact.ScopedPartialityFlag{bounded, other}
			},
			wantVerdict: report.VerdictUndetermined,
			wantReason:  report.ReasonAnalysisDidNotRun,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := netNotReached()
			fx.reach.Refutation.Basis = plugin.RefutationAnalyzerPackageNotImported
			tc.mutate(&fx)
			f := fx.finding(t)
			if f.Verdict != tc.wantVerdict || f.UndeterminedReason != tc.wantReason {
				t.Fatalf("got %s/%q, want %s/%q", f.Verdict, f.UndeterminedReason, tc.wantVerdict, tc.wantReason)
			}
			if tc.wantLimits != nil && !reflect.DeepEqual(f.WithheldBy, tc.wantLimits) {
				t.Errorf("withheld_by = %+v, want %+v", f.WithheldBy, tc.wantLimits)
			}
		})
	}
}
