package pipeline

// Non-Go manifest membership for the intake no-manifest-entry guard.
//
// Go answers "does the codebase declare this module?" straight off go.mod (goModRequires). For
// PyPI, npm, Maven and NuGet the answer lives in the language plugin's dependency read, and
// absence is only provable when the plugin vouches that its read is exhaustive: a complete,
// edge-bearing lockfile covers every manifest it found, a JVM build graph covers the whole
// build, or every .NET project is settled on restore's own record
// (plugin.DependencyVersionResult.Exhaustive). Declared-only
// manifests, requirements files, or no lockfile at all leave Exhaustive false and the guard
// fails open. Build-isolation environments are not runtime installs, so a package only a build
// backend pulls in is outside what Exhaustive vouches for.
//
// codebase_inventory records the fact (it already holds the plugin and the advisory facts);
// disqualification_discovery reads it back, the same artifact hand-off every other intake input
// uses. A disqualification here is the existing "no_manifest_entry" intake reason, never a
// not-affected verdict.

import (
	"context"
	"encoding/json"

	"github.com/ferralon-ai/ferralon-assay/artifact"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// manifestMembership is codebase_inventory's record of whether the advisory's packages are in the
// codebase's dependency set. Known=false means absence could not be proven.
type manifestMembership struct {
	Ecosystem   string   `json:"ecosystem"`
	Coordinates []string `json:"coordinates"` // the affected-package coordinates checked, in advisory order
	Present     bool     `json:"present"`     // at least one coordinate is declared or locked
	Known       bool     `json:"known"`       // Present is a proven fact; false means absence could not be proven
}

// membershipEcosystem maps a plugin language onto the PURL type whose absence its dependency read
// can prove. It is deliberately separate from languageEcosystem, which leaves python out so the
// ecosystem-mismatch guard cannot misfire on a misdetected tree; membership only ever compares an
// advisory's own pypi/npm coordinates against that plugin's lockfile.
func membershipEcosystem(language string) string {
	switch language {
	case "python":
		return "pypi"
	case "javascript", "js":
		return "npm"
	case "java", "kotlin":
		return "maven"
	case "dotnet":
		return "nuget"
	default:
		return ""
	}
}

// resolveManifestMembership asks the language plugin whether each of the advisory's affected
// packages is in the dependency set. It returns nil (no fact, fail open) unless every affected
// package belongs to the plugin's ecosystem: an advisory that also names a package from another
// ecosystem could reach this codebase through a dependency this plugin cannot see.
func resolveManifestMembership(ctx context.Context, p plugin.LanguagePlugin, buildDir, language string, keys []PackageKey) *manifestMembership {
	eco := membershipEcosystem(language)
	if p == nil || buildDir == "" || eco == "" || p.Language() != language || len(keys) == 0 {
		return nil
	}
	m := &manifestMembership{Ecosystem: eco}
	for _, k := range keys {
		if k.Ecosystem != eco || k.Name == "" {
			return nil
		}
		m.Coordinates = append(m.Coordinates, k.Name)
	}
	exhaustive := true
	for _, coord := range m.Coordinates {
		vr, err := p.ResolveDependencyVersions(ctx, plugin.ResolveVersionsRequest{BuildDir: buildDir, Coordinate: coord})
		if err != nil {
			return nil
		}
		if vr.Found {
			m.Present, m.Known = true, true
			return m
		}
		if !vr.Exhaustive {
			exhaustive = false
		}
	}
	m.Known = exhaustive
	return m
}

// extractManifestMembership reads the membership fact codebase_inventory recorded, if any.
func extractManifestMembership(store artifact.Store, caseID string) (manifestMembership, bool) {
	arts, err := store.Query(caseID, artifact.TypeInventory)
	if err != nil || len(arts) == 0 {
		return manifestMembership{}, false
	}
	var inv struct {
		ManifestMembership *manifestMembership `json:"manifest_membership"`
	}
	if err := json.Unmarshal(arts[0].Payload, &inv); err != nil || inv.ManifestMembership == nil {
		return manifestMembership{}, false
	}
	return *inv.ManifestMembership, true
}

// intakeManifestMembership supplies intakeDisqualify's coordinate and manifest-membership inputs.
// A Go module keeps its go.mod oracle unchanged; otherwise the recorded plugin membership fact is
// used, and with none recorded the coordinate is empty so the guard cannot fire.
func intakeManifestMembership(store artifact.Store, caseID, buildDir, advModule string) (coordinate string, present, known bool) {
	if advModule != "" {
		present, known = goModRequires(buildDir, advModule)
		return advModule, present, known
	}
	m, ok := extractManifestMembership(store, caseID)
	if !ok || len(m.Coordinates) == 0 {
		return "", false, false
	}
	return m.Coordinates[0], m.Present, m.Known
}
