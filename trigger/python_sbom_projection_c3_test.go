package trigger_test

// PLAN-173 C3 — the Python inventory → SBOM projection, driven end-to-end through the REAL
// resolver. This is an EXTERNAL test package (trigger_test) so it uses only the exported
// trigger.ResolveSBOM surface and edits no package-internal (and no anvil-owned) file (C6).
//
// Honesty bar (00-prompt's sharpest review question): the fixture must exercise the actual
// pythonanalysis.ResolveInventory, not a hand-authored fakeInventoryPlugin with fabricated
// Python PURLs. So the plugin adapter's ResolveInventory calls the real resolver, and the
// codebase is a vendored_repro tree carrying a native-captured pdm.lock (jinja2 -> markupsafe).
//
// The load-bearing distribution is markupsafe: jinja2's transitive dependency, named by NO
// advisory in the corpus (verified this session against corpus/testdata/advisories, which names
// aiohttp, apache-airflow, flask, jinja2, pydantic, tegron-corpus-app — never markupsafe). It is
// exactly the "in the resolved inventory, not in the advisory work set" distribution C3 requires;
// on the pre-PLAN-100 advisory-keyed path it could never reach the SBOM.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/pythonanalysis"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// pythonInventoryPlugin is a LanguagePlugin whose every operation is StubPlugin's hermetic
// default EXCEPT Language (python) and ResolveInventory, which delegates to the REAL
// pythonanalysis.ResolveInventory. Injecting it makes trigger.ResolveSBOM resolve the actual
// Python graph and project it through PLAN-100's inventory-keyed path — no fabricated PURLs.
type pythonInventoryPlugin struct {
	plugin.StubPlugin
}

func (pythonInventoryPlugin) Language() string { return "python" }

func (pythonInventoryPlugin) ResolveInventory(ctx context.Context, req plugin.ResolveInventoryRequest) (plugin.DependencyInventory, error) {
	return pythonanalysis.ResolveInventory(ctx, req)
}

// vendoredPythonFixture materializes a vendored_repro tree: the checked-in, native-captured
// pdm.lock (jinja2 -> markupsafe) plus a trivial .py source so checkout.DetectLanguage classifies
// the tree as Python and the inventory stage routes to the python plugin. Returns the absolute
// build dir and the raw lockfile bytes (so a test can prove a projected digest was actually
// declared there, never fabricated).
func vendoredPythonFixture(t *testing.T) (dir string, lock []byte) {
	t.Helper()
	lock, err := os.ReadFile(filepath.FromSlash("../internal/plugin/pythonanalysis/testdata/pdm/pdm.lock"))
	if err != nil {
		t.Fatalf("read pdm.lock fixture: %v", err)
	}
	dir = t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pdm.lock"), lock, 0o644); err != nil {
		t.Fatalf("write pdm.lock: %v", err)
	}
	// A .py source so DetectLanguage's source-dominance walk classifies this tree as Python.
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("import jinja2\n"), 0o644); err != nil {
		t.Fatalf("write app.py: %v", err)
	}
	return dir, lock
}

// TestPythonSBOM_InventoryKeyed_NonAdvisoryDistributionAndRelationshipReachSBOM is C3 end-to-end:
// the report SBOM (via exported trigger.ResolveSBOM) carries the selected Python distributions
// with normalized PURL + exact version + direct/transitive, carries the jinja2 -> markupsafe
// parent/child relationship edge, contains markupsafe (a distribution in the inventory but in NO
// advisory work set), and — the negative control — carries strictly more Python distributions than
// the advisory work set for this codebase, which proves inventory-keying rather than advisory-keying.
func TestPythonSBOM_InventoryKeyed_NonAdvisoryDistributionAndRelationshipReachSBOM(t *testing.T) {
	dir, lock := vendoredPythonFixture(t)
	codebase := assessment.CodebaseRef{
		Repo:        "example.com/pyapp",
		Revision:    "sha",
		Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: dir},
	}

	sbom, _, err := trigger.ResolveSBOM(context.Background(), trigger.ResolveSBOMRequest{
		Codebase:      codebase,
		AssessOptions: []pipeline.AssessOption{pipeline.WithPlugin(pythonInventoryPlugin{})},
	})
	if err != nil {
		t.Fatalf("ResolveSBOM: %v", err)
	}

	// The direct distribution: normalized PURL, exact version, classified direct.
	jinja, ok := pkgByPURL(sbom, "pkg:pypi/jinja2@3.1.2")
	if !ok {
		t.Fatalf("jinja2 absent from SBOM: %+v", sbom.Packages)
	}
	if jinja.Ecosystem != "PyPI" || jinja.Name != "jinja2" || jinja.Version != "3.1.2" || !jinja.Direct {
		t.Errorf("jinja2 projected wrong: %+v (want PyPI/jinja2/3.1.2/direct)", jinja)
	}

	// markupsafe: the LOAD-BEARING distribution — transitive, and named by no advisory. Its
	// presence is exactly what an inventory-keyed projection surfaces and an advisory-keyed one drops.
	ms, ok := pkgByPURL(sbom, "pkg:pypi/markupsafe@3.0.3")
	if !ok {
		t.Fatalf("markupsafe (non-advisory transitive dep) absent from SBOM — projection is not inventory-keyed: %+v", sbom.Packages)
	}
	if ms.Ecosystem != "PyPI" || ms.Name != "markupsafe" || ms.Version != "3.0.3" || ms.Direct {
		t.Errorf("markupsafe projected wrong: %+v (want PyPI/markupsafe/3.0.3/transitive)", ms)
	}

	// The parent/child relationship edge reaches the SBOM, keyed by Package.Key() (the PURL).
	wantRel := report.Relationship{Parent: "pkg:pypi/jinja2@3.1.2", Child: "pkg:pypi/markupsafe@3.0.3"}
	if !hasRelationship(sbom, wantRel) {
		t.Errorf("jinja2 -> markupsafe relationship edge absent from SBOM: %+v", sbom.Relationships)
	}

	// Negative control. The advisory work set for THIS codebase is the subset of its SBOM
	// distributions that some corpus advisory names, derived from the REAL advisory corpus on disk
	// (not a literal). If the projection were still advisory-keyed, the SBOM would carry only that
	// subset and the two counts would be EQUAL; the strict inequality is the control's teeth.
	advNamed := advisoryNamedPyPI(t)
	if advNamed["markupsafe"] {
		t.Fatal("corpus unexpectedly names markupsafe; the non-advisory control distribution is invalid")
	}
	pyPkgs := pypiPackages(sbom)
	workSet := 0
	for _, p := range pyPkgs {
		if advNamed[p.Name] {
			workSet++
		}
	}
	if len(pyPkgs) <= workSet {
		t.Fatalf("SBOM Python distribution count %d does not exceed advisory work set %d — projection is advisory-keyed, not inventory-keyed", len(pyPkgs), workSet)
	}

	// Declared hashes reach the resolved INVENTORY node (DependencyArtifact.Digest), read from the
	// same real path. DRIFT (flagged in 04-c3-notes.md): PLAN-100's report.Package carries no digest
	// field, so the declared hash is NOT projected onto the report.SBOM node this cycle; the honest
	// maximal claim about hashes is at the inventory layer, asserted here.
	inv, _, _, err := pipeline.ResolveCodebaseInventory(context.Background(), codebase, "",
		pipeline.WithPlugin(pythonInventoryPlugin{}))
	if err != nil {
		t.Fatalf("ResolveCodebaseInventory: %v", err)
	}
	msDigest := ""
	for _, n := range inv.Nodes {
		if n.PURL == "pkg:pypi/markupsafe@3.0.3" {
			msDigest = n.Artifact.Digest
		}
	}
	if !strings.HasPrefix(msDigest, "sha256:") {
		t.Fatalf("markupsafe inventory node carries no declared sha256 digest, got %q", msDigest)
	}
	if !strings.Contains(string(lock), strings.TrimPrefix(msDigest, "sha256:")) {
		t.Errorf("markupsafe digest %q is not one declared in the lockfile — fabricated, not read", msDigest)
	}
}

func pkgByPURL(sbom report.SBOM, purl string) (report.Package, bool) {
	for _, p := range sbom.Packages {
		if p.PURL == purl {
			return p, true
		}
	}
	return report.Package{}, false
}

func hasRelationship(sbom report.SBOM, want report.Relationship) bool {
	for _, r := range sbom.Relationships {
		if r == want {
			return true
		}
	}
	return false
}

func pypiPackages(sbom report.SBOM) []report.Package {
	var out []report.Package
	for _, p := range sbom.Packages {
		if p.Ecosystem == "PyPI" {
			out = append(out, p)
		}
	}
	return out
}

// advisoryNamedPyPI reads the REAL PyPI advisory corpus and returns the set of distribution names
// some advisory targets. It is the ground truth for the "advisory work set": a projection keyed
// off advisories can only surface names in this set, so intersecting it with the SBOM yields the
// advisory-keyed baseline the negative control measures against.
func advisoryNamedPyPI(t *testing.T) map[string]bool {
	t.Helper()
	dir := filepath.FromSlash("../corpus/testdata/advisories")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read advisory corpus: %v", err)
	}
	named := map[string]bool{}
	const prefix = "pkg:pypi/"
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var adv struct {
			PURL string `json:"PURL"`
		}
		if err := json.Unmarshal(data, &adv); err != nil {
			continue
		}
		if strings.HasPrefix(adv.PURL, prefix) {
			named[strings.TrimPrefix(adv.PURL, prefix)] = true
		}
	}
	if len(named) == 0 {
		t.Fatal("advisory corpus yielded zero PyPI-named distributions; the negative control baseline is empty")
	}
	return named
}
