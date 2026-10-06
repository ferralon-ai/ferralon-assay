package main

import (
	"context"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func TestNewLane_RejectsBadConfiguration(t *testing.T) {
	for _, tc := range []struct{ key, value, want string }{
		{envTransport, "nativ", envTransport},
		{envMinConfidence, "likely", envMinConfidence},
		{envPoolSize, "0", envPoolSize},
		{envPoolSize, "many", envPoolSize},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			t.Setenv(envCacheDir, t.TempDir())
			t.Setenv(tc.key, tc.value)
			if _, err := newLane(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("newLane: err = %v, want an error naming %s", err, tc.want)
			}
		})
	}
}

// The non-graph operations never reach the lane: they are the lexical analyzer's answers.
func TestDispatch_DelegatedOperations(t *testing.T) {
	ctx := context.Background()
	resp, err := dispatch(ctx, nil, plugin.Request{Op: plugin.OpCapabilityManifest})
	if err != nil || resp.Manifest == nil || resp.Manifest.Language != "python" || resp.Manifest.Supported {
		t.Fatalf("capability_manifest = %+v, %v", resp.Manifest, err)
	}
	resp, err = dispatch(ctx, nil, plugin.Request{Op: plugin.OpGenerateHarness, GenerateHarness: &plugin.GenerateHarnessRequest{}})
	if err != nil || resp.Harness == nil || resp.Harness.Partiality.Complete {
		t.Fatalf("generate_harness = %+v, %v; want Unsupported", resp.Harness, err)
	}
	if _, err := dispatch(ctx, nil, plugin.Request{Op: plugin.OpCallGraph}); err == nil {
		t.Error("call_graph with no payload: want error")
	}
	if _, err := dispatch(ctx, nil, plugin.Request{Op: "nope"}); err == nil {
		t.Error("unknown op: want error")
	}
}
