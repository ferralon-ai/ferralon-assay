// internal/pipeline/manifest_seam_test.go
package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// TestInventoryFoldsBuildManifestViaPlugin exercises the plugin seam in codebase_inventory.
// StubPlugin.BuildManifest returns Unsupported with EMPTY fields, so the assertion is that the
// call path runs WITHOUT error and the TypeInventory artifact is still well-formed/decodable —
// Module/GoVersion/BuildCommand are dropped via omitempty for the stub.
func TestInventoryFoldsBuildManifestViaPlugin(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-1", Request: assessment.Request{
		Codebase: assessment.CodebaseRef{Repo: "example.com/repo", Revision: "v1"},
	}}
	fc := checkout.FakeCheckout{
		FixtureRoot: "../checkout/testdata",
		Map:         map[string]string{"example.com/repo@v1": "gomod-fixture"},
	}
	stage := codebaseInventory{checkout: fc, plugin: plugin.StubPlugin{}}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("run with plugin must not error: %v", err)
	}
	arts, _ := store.Query(c.ID, artifact.TypeInventory)
	if len(arts) == 0 {
		t.Fatal("no inventory artifact")
	}
	var inv struct {
		Repo         string `json:"repo"`
		Revision     string `json:"revision"`
		BuildDir     string `json:"build_dir"`
		Module       string `json:"module"`
		GoVersion    string `json:"go_version"`
		BuildCommand string `json:"build_command"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		t.Fatalf("inventory artifact must decode: %v", err)
	}
	if inv.BuildDir == "" {
		t.Fatal("inventory must still record the resolved BuildDir")
	}
	// StubPlugin.BuildManifest is Unsupported with empty fields → omitempty drops them.
	if inv.Module != "" || inv.GoVersion != "" || inv.BuildCommand != "" {
		t.Fatalf("stub manifest must yield empty fields, got module=%q goVersion=%q buildCommand=%q",
			inv.Module, inv.GoVersion, inv.BuildCommand)
	}
}

// TestInventoryJavaRepro_NoGoModRoutesToJavaPlugin is the pipeline-layer reproduce-first proof for
// the live-gate failure: a Java vendored_repro (NO go.mod, with .java sources) must pass
// codebase_inventory and produce an inventory tagged language="java". Before the language-aware
// checkout fix the stage aborted with "has no go.mod"; after it, the Java tree inventories and the
// recorded language routes downstream to the Java plugin path. The wired plugin is the Java
// first-party stub (Language()=="java"), so BuildManifest is invoked on the matching language and
// returns Unsupported (empty fields → omitted), exactly as Increment-1 expects.
func TestInventoryJavaRepro_NoGoModRoutesToJavaPlugin(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-java", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "TEGRON-JAVA-SSRF-0001", Source: "corpus"},
		Codebase: assessment.CodebaseRef{
			Repo:     "com.example.web/ssrf",
			Revision: "v1",
			Acquisition: assessment.Acquisition{
				Mode: "vendored_repro",
				Path: "../checkout/testdata/java-fixture",
			},
		},
	}}
	stage := codebaseInventory{plugin: javaFirstPartyStub{}}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("a no-go.mod Java repro must pass codebase_inventory, got: %v", err)
	}
	arts, _ := store.Query(c.ID, artifact.TypeInventory)
	if len(arts) == 0 {
		t.Fatal("no inventory artifact")
	}
	var inv struct {
		BuildDir     string `json:"build_dir"`
		Language     string `json:"language"`
		Module       string `json:"module"`
		GoVersion    string `json:"go_version"`
		BuildCommand string `json:"build_command"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		t.Fatalf("inventory artifact must decode: %v", err)
	}
	if inv.BuildDir == "" {
		t.Fatal("Java inventory must record the resolved BuildDir")
	}
	if inv.Language != "java" {
		t.Fatalf("Java repro inventory must route to the Java plugin (language=%q), got %q", "java", inv.Language)
	}
	// Java Increment-1 BuildManifest is Unsupported (no JDK) → empty fields dropped via omitempty.
	if inv.Module != "" || inv.GoVersion != "" || inv.BuildCommand != "" {
		t.Fatalf("Java stub manifest must yield empty fields, got module=%q goVersion=%q buildCommand=%q",
			inv.Module, inv.GoVersion, inv.BuildCommand)
	}
}

// TestInventoryGoRepro_RecordsGoLanguage is the Go-path regression: a go.mod fixture must still
// resolve, record language="go", and fold the Go plugin's BuildManifest exactly as before.
func TestInventoryGoRepro_RecordsGoLanguage(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-go-lang", Request: assessment.Request{
		Codebase: assessment.CodebaseRef{Repo: "example.com/repo", Revision: "v1"},
	}}
	fc := checkout.FakeCheckout{
		FixtureRoot: "../checkout/testdata",
		Map:         map[string]string{"example.com/repo@v1": "gomod-fixture"},
	}
	stage := codebaseInventory{checkout: fc, plugin: plugin.StubPlugin{}}
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("Go repro must inventory without error: %v", err)
	}
	arts, _ := store.Query(c.ID, artifact.TypeInventory)
	if len(arts) == 0 {
		t.Fatal("no inventory artifact")
	}
	var inv struct {
		BuildDir string `json:"build_dir"`
		Language string `json:"language"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		t.Fatalf("inventory artifact must decode: %v", err)
	}
	if inv.BuildDir == "" {
		t.Fatal("Go inventory must record the resolved BuildDir")
	}
	if inv.Language != "go" {
		t.Fatalf("a go.mod repro must record language=%q, got %q", "go", inv.Language)
	}
}

// TestInventoryNilPluginOmitsManifestFields confirms the default path stays byte-identical:
// no plugin → BuildManifest never called → manifest fields absent from the payload entirely.
func TestInventoryNilPluginOmitsManifestFields(t *testing.T) {
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-2", Request: assessment.Request{
		Codebase: assessment.CodebaseRef{Repo: "example.com/repo", Revision: "v1"},
	}}
	fc := checkout.FakeCheckout{
		FixtureRoot: "../checkout/testdata",
		Map:         map[string]string{"example.com/repo@v1": "gomod-fixture"},
	}
	stage := codebaseInventory{checkout: fc} // plugin == nil
	if err := stage.Run(context.Background(), c, store); err != nil {
		t.Fatalf("nil-plugin default must not error: %v", err)
	}
	arts, _ := store.Query(c.ID, artifact.TypeInventory)
	if len(arts) == 0 {
		t.Fatal("no inventory artifact")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(arts[0].Payload, &raw); err != nil {
		t.Fatalf("inventory artifact must decode: %v", err)
	}
	for _, k := range []string{"module", "go_version", "build_command"} {
		if _, ok := raw[k]; ok {
			t.Fatalf("nil-plugin payload must omit %q (omitempty); got it present", k)
		}
	}
}
