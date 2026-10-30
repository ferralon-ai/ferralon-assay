//go:build live

package goanalysis

import (
	"context"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestReachability_Live_ReflectMaterializedDispatch: encoding/json calls Tag.MarshalJSON, and so
// the vulnerable language.Parse, through reflect, which leaves no call edge for govulncheck to
// follow. The program runs language.Parse, so the result must not refute it. Requirements as for
// TestReachability_Live.
func TestReachability_Live_ReflectMaterializedDispatch(t *testing.T) {
	res, err := Reachability(context.Background(), plugin.ReachabilityRequest{
		BuildDir: "testdata/reflectvulnmod",
		VulnID:   liveVulnID,
	})
	if err != nil {
		t.Fatalf("Reachability: %v", err)
	}
	if res.Refutation != nil {
		t.Fatalf("refuted %s though json.Marshal runs Tag.MarshalJSON -> language.Parse: refutation=%+v partiality=%+v",
			liveVulnID, res.Refutation, res.Partiality)
	}
	t.Logf("paths=%d partiality=%+v", len(res.Paths), res.Partiality)
}
