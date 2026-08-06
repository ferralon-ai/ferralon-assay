package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// A Go scan carried zero partiality disclosure: the go.mod branch never populated
// flags. The two empty-version cases must now be told apart — an unreadable manifest
// established nothing, a readable one that lacks the module established a real fact.
func TestResolveDependencyVersion_GoModPartiality(t *testing.T) {
	const gomod = "module example.com/app\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.6\n"

	t.Run("no go.mod discloses no_manifest", func(t *testing.T) {
		v, flags, err := codebaseInventory{}.resolveDependencyVersion(
			context.Background(), t.TempDir(), "go", "golang.org/x/text", "", "", ToolchainFact{})
		if err != nil {
			t.Fatalf("resolveDependencyVersion: %v", err)
		}
		if v != "" {
			t.Errorf("version = %q, want empty", v)
		}
		if len(flags) != 1 || flags[0] != plugin.PartialReasonNoManifest {
			t.Fatalf("flags = %v, want [%s]", flags, plugin.PartialReasonNoManifest)
		}
	})

	t.Run("unparseable go.mod discloses no_manifest", func(t *testing.T) {
		dir := writeGoMod(t, "this is not a go.mod {{{\n")
		_, flags, err := codebaseInventory{}.resolveDependencyVersion(
			context.Background(), dir, "go", "golang.org/x/text", "", "", ToolchainFact{})
		if err != nil {
			t.Fatalf("resolveDependencyVersion: %v", err)
		}
		if len(flags) != 1 || flags[0] != plugin.PartialReasonNoManifest {
			t.Fatalf("flags = %v, want [%s]", flags, plugin.PartialReasonNoManifest)
		}
	})

	// The regression gate. A readable go.mod that does not require the module is an
	// HONEST ABSENCE: the codebase genuinely does not depend on it. Disclosing here
	// would qualify every true not_exploitable and make the disclosure meaningless.
	t.Run("readable go.mod without the module discloses nothing", func(t *testing.T) {
		dir := writeGoMod(t, gomod)
		v, flags, err := codebaseInventory{}.resolveDependencyVersion(
			context.Background(), dir, "go", "github.com/not/required", "", "", ToolchainFact{})
		if err != nil {
			t.Fatalf("resolveDependencyVersion: %v", err)
		}
		if v != "" {
			t.Errorf("version = %q, want empty", v)
		}
		if len(flags) != 0 {
			t.Fatalf("an honest absence must disclose nothing, got %v", flags)
		}
	})

	t.Run("resolved module discloses nothing", func(t *testing.T) {
		dir := writeGoMod(t, gomod)
		v, flags, err := codebaseInventory{}.resolveDependencyVersion(
			context.Background(), dir, "go", "golang.org/x/text", "", "", ToolchainFact{})
		if err != nil {
			t.Fatalf("resolveDependencyVersion: %v", err)
		}
		if v != "v0.3.6" {
			t.Errorf("version = %q, want v0.3.6", v)
		}
		if len(flags) != 0 {
			t.Fatalf("a resolved version must disclose nothing, got %v", flags)
		}
	})
}

// A managed-ecosystem coordinate with no language-matched analyzer (the Java/.NET
// plugin binary is absent) resolved to a bare empty version, which reads downstream as
// "not installed" and disqualifies the advisory on a comparison that never ran.
func TestResolveDependencyVersion_NoAnalyzerDisclosesAbsence(t *testing.T) {
	_, flags, err := codebaseInventory{}.resolveDependencyVersion(
		context.Background(), t.TempDir(), "java", "", "com.example:widget", "", ToolchainFact{})
	if err != nil {
		t.Fatalf("resolveDependencyVersion: %v", err)
	}
	if len(flags) != 1 || flags[0] != plugin.PartialReasonNoPlugin {
		t.Fatalf("flags = %v, want [%s]", flags, plugin.PartialReasonNoPlugin)
	}
}

// The go-toolchain scheme resolves off the bounded ToolchainFact, not a manifest or
// plugin resolver, so an unresolved fact must stay silent rather than disclose a version-resolution
// limit that was never attempted.
func TestResolveDependencyVersion_GoToolchainStaysSilent(t *testing.T) {
	_, flags, err := codebaseInventory{}.resolveDependencyVersion(
		context.Background(), t.TempDir(), "go", "", "stdlib", "go-toolchain", ToolchainFact{})
	if err != nil {
		t.Fatalf("resolveDependencyVersion: %v", err)
	}
	if len(flags) != 0 {
		t.Fatalf("go-toolchain must disclose nothing, got %v", flags)
	}
}

// The exposure footprint harvested reachability partiality only when at least one path
// was found — dropping it on exactly the zero-path case the disclosure exists for.
func TestExposureFootprint_HarvestsReachabilityPartialityWithZeroPaths(t *testing.T) {
	assessments := assessment.NewMemStore()
	store := artifact.NewMemStore()
	a, err := assessments.Create(assessment.Request{Vulnerability: assessment.VulnRef{ID: "GO-2021-0113"}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	payload, err := json.Marshal(map[string]any{
		"reachability": plugin.ReachabilityResult{
			Partiality: plugin.Partial(plugin.PartialReasonNoIngress),
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := store.Put(&artifact.Artifact{
		AssessmentID: a.ID, Type: artifact.TypeReachability, ProducedBy: "test", Payload: payload,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if err := (exposureFootprintStage{}).Run(context.Background(), a, store); err != nil {
		t.Fatalf("exposureFootprintStage.Run: %v", err)
	}

	arts, err := store.Query(a.ID, artifact.TypeExposureFootprint)
	if err != nil || len(arts) == 0 {
		t.Fatalf("Query footprint: %v (%d artifacts)", err, len(arts))
	}
	var fp artifact.ExposureFootprintPayload
	if err := json.Unmarshal(arts[0].Payload, &fp); err != nil {
		t.Fatalf("unmarshal footprint: %v", err)
	}
	var found bool
	for _, f := range fp.PartialityFlags {
		if f == plugin.PartialReasonNoIngress {
			found = true
		}
	}
	if !found {
		t.Fatalf("footprint flags = %v, want %s harvested despite zero paths",
			fp.PartialityFlags, plugin.PartialReasonNoIngress)
	}
	if fp.ReachablePathCount != 0 {
		t.Errorf("ReachablePathCount = %d, want 0", fp.ReachablePathCount)
	}
}
