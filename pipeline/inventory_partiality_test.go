// inventory_partiality_test.go
//
// Hermetic pins on the dependency-version partiality carrier: codebase_inventory must
// persist WHY a resolve was incomplete, and exposure_footprint must harvest it as a
// fourth partiality axis alongside ingress / reachability / vulnerable-symbol.
//
// The failure this guards is silent: a degraded resolve leaves resolved_version empty,
// which downstream is indistinguishable from "this codebase does not use that
// dependency". Without the reason code, a repo whose dependencies could not be pinned
// produces output byte-identical to a genuinely clean scan.
//
// These tests also pin the flags as DISCLOSURE ONLY — the disqualification axis must
// still fail open exactly as it did before, never fail closed to "safe".
package pipeline

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// noManifestStub models the shipped no-lockfile degrade: a declared-partial result
// whose seeded coordinate is present but UNRESOLVED (fail open), carrying the
// no_manifest reason code.
type noManifestStub struct {
	plugin.StubPlugin
	complete bool
}

func (noManifestStub) Language() string { return "js" }

func (s noManifestStub) ResolveDependencyVersions(_ context.Context, req plugin.ResolveVersionsRequest) (plugin.DependencyVersionResult, error) {
	if s.complete {
		return plugin.DependencyVersionResult{
			Partiality: plugin.Complete(),
			Found:      true,
			Match: plugin.ResolvedDependency{
				Coordinate: req.Coordinate, Version: "1.4.0", Resolved: true, Source: "npm",
			},
		}, nil
	}
	return plugin.DependencyVersionResult{
		Partiality: plugin.Partial(plugin.PartialReasonNoManifest),
		Found:      true,
		Match: plugin.ResolvedDependency{
			Coordinate: req.Coordinate, Resolved: false, Source: "npm",
		},
	}, nil
}

type inventoryFields struct {
	Language        string   `json:"language"`
	ResolvedVersion string   `json:"resolved_version"`
	PartialityFlags []string `json:"partiality_flags"`
}

// runInventory drives advisory_intake + codebase_inventory against the JS repro tree
// (present only so the language detector sees a real JS build dir) and returns the
// store plus the decoded inventory artifact.
func runInventory(t *testing.T, complete bool) (*artifact.MemStore, string, inventoryFields) {
	t.Helper()
	store := artifact.NewMemStore()
	c := &assessment.Assessment{ID: "case-inv-partiality", Request: assessment.Request{
		Vulnerability: assessment.VulnRef{ID: "TEGRON-JS-DEP-0001", Source: "corpus"},
		Codebase: assessment.CodebaseRef{
			Repo:     "tegron/js-dep-repro",
			Revision: "v1",
			Acquisition: assessment.Acquisition{
				Mode: "vendored_repro",
				Path: "../corpus/testdata/repros/TEGRON-JS-SSRF-0001-vulnerable",
			},
		},
	}}
	if err := (advisoryIntake{}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("advisory_intake: %v", err)
	}
	if err := (codebaseInventory{plugin: noManifestStub{complete: complete}}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("codebase_inventory: %v", err)
	}

	arts, err := store.Query(c.ID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		t.Fatalf("no inventory artifact: %v", err)
	}
	var inv inventoryFields
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	return store, c.ID, inv
}

// A declared-partial resolve must record its reason code on the inventory artifact —
// and must still leave resolved_version empty (UNRESOLVED, fail open).
func TestInventory_DeclaredPartial_PersistsReasonCode(t *testing.T) {
	store, caseID, inv := runInventory(t, false)

	if got, want := inv.PartialityFlags, plugin.PartialReasonNoManifest; len(got) != 1 || got[0] != want {
		t.Fatalf("partiality_flags = %v, want [%s]", got, want)
	}
	if inv.ResolvedVersion != "" {
		t.Fatalf("a declared-partial resolve must leave resolved_version empty (UNRESOLVED), got %q", inv.ResolvedVersion)
	}

	// Disclosure only: the version axis still FAILS OPEN, exactly as before.
	if res := runDisqual(t, store, caseID); res.Disqualified {
		t.Fatalf("an unresolved version must fail open (proceed), got disqualified: %+v", res)
	}
}

// The silence-when-clean guarantee at the artifact layer: a fully-resolved scan must
// carry no partiality flags at all, so the field is absent from the serialized payload.
func TestInventory_CompleteResolve_NoPartialityFlags(t *testing.T) {
	store, caseID, inv := runInventory(t, true)

	if len(inv.PartialityFlags) != 0 {
		t.Fatalf("a complete resolve must record no partiality flags, got %v", inv.PartialityFlags)
	}
	if inv.ResolvedVersion != "1.4.0" {
		t.Fatalf("resolved_version = %q, want %q", inv.ResolvedVersion, "1.4.0")
	}

	arts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		t.Fatalf("no inventory artifact: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(arts[0].Payload, &raw); err != nil {
		t.Fatalf("decode inventory: %v", err)
	}
	if _, present := raw["partiality_flags"]; present {
		t.Errorf("clean inventory must omit partiality_flags entirely, got %v", raw)
	}
}

// exposure_footprint harvests dependency-version partiality as a fourth axis, so the
// deterministic boundary artifact is an honest account of what the pass could not do.
func TestExposureFootprint_HarvestsDependencyVersionPartiality(t *testing.T) {
	store, caseID, _ := runInventory(t, false)

	c := &assessment.Assessment{ID: caseID}
	if err := (exposureFootprintStage{}).Run(context.Background(), c, store); err != nil {
		t.Fatalf("exposure_footprint: %v", err)
	}
	arts, err := store.Query(caseID, artifact.TypeExposureFootprint)
	if err != nil || len(arts) == 0 {
		t.Fatalf("no exposure footprint artifact: %v", err)
	}
	var payload artifact.ExposureFootprintPayload
	if err := json.Unmarshal(arts[0].Payload, &payload); err != nil {
		t.Fatalf("decode footprint: %v", err)
	}

	var found bool
	for _, f := range payload.PartialityFlags {
		if f == plugin.PartialReasonNoManifest {
			found = true
		}
	}
	if !found {
		t.Fatalf("exposure footprint partiality_flags = %v, want it to carry %q",
			payload.PartialityFlags, plugin.PartialReasonNoManifest)
	}
}
