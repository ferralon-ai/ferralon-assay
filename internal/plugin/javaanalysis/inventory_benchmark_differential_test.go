package javaanalysis

// C1/C3/C4/C5 real-differential tests: grade ResolveInventory against captures produced OFFLINE by
// the native Maven/Gradle resolvers (`mvn dependency:tree`, `gradle dependencies`). The captures are
// COLD FIXTURES under testdata/benchmarks/<name>/ — this test ONLY READS them; it never executes
// mvn/mvnw/gradle/gradlew/java/javac/docker and never touches the network (§3.3).
//
// The oracle files are read at run time and parsed into coordinate sets; there is NO hard-coded
// expectation duplicating the oracle, so renaming or emptying a capture makes the corresponding
// differential FAIL (the resolver produces nodes the now-empty oracle does not, and vice versa).
//
// Grading scope by benchmark:
//   - FULL set-parity (either-direction set-difference fails): M1, M2, M3 (per reactor module), G1,
//     G2 (lockfile records the platform()/constraints{}-selected closure). These are the
//     fully-resolvable-on-disk benchmarks: every edge is soundly closable from the committed cache
//     slice, so the resolver's (group, artifact, version[, scope]) set must equal the native tree's
//     exactly. G2 additionally carries the Gradle selected≠declared assertion (C4).
//   - HONEST-ABSENT (C3, not full-parity): M4 (unresolvable triad), G3 (mixed multiproject: one
//     locked subproject fully resolves, one unlocked subproject is declared residue). Here the native
//     tool either aborts (M4) or resolves versions the on-disk state does not express without a
//     lockfile (G3-app-b); the resolver's contract is to emit honest-absent residue (Partial, never
//     Complete over the truncated graph), which these cases assert directly.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const benchRoot = "testdata/benchmarks"

// --- comparable tuple --------------------------------------------------------

// coord is one graded dependency instance. scope is the Maven narrowed scope / Gradle configuration;
// it is compared for Maven (where it is well-defined per node) and left "" for Gradle (where the
// native report lists a coordinate once per configuration and the resolver collapses to one node).
type coord struct {
	group, artifact, version, scope string
}

func (c coord) String() string {
	s := c.group + ":" + c.artifact + ":" + c.version
	if c.scope != "" {
		s += ":" + c.scope
	}
	return s
}

// --- resolver-side projection ------------------------------------------------

// resolveBenchmark resolves a benchmark's proj/ against its committed cache slice (m2/ for Maven,
// modules2/ for Gradle), injecting the fixture caches — never the ambient ~/.m2 or ~/.gradle.
func resolveBenchmark(name string) plugin.DependencyInventory {
	base := filepath.Join(benchRoot, name)
	buildDir := filepath.Join(base, "proj")
	m2 := newMavenCacheAt(filepath.Join(base, "m2"))
	gc := newGradleCache(filepath.Join(base, "modules2"))
	return resolveInventory(buildDir, m2, gc, nil)
}

// purlCoord recovers (group, artifact, version) from a "pkg:maven/<group>/<artifact>@<version>" PURL.
func purlCoord(t *testing.T, purl string) (group, artifact, version string) {
	t.Helper()
	s := strings.TrimPrefix(purl, "pkg:maven/")
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		version = s[i+1:]
		s = s[:i]
	}
	i := strings.LastIndexByte(s, '/')
	if i < 0 {
		t.Fatalf("PURL %q has no group/artifact separator", purl)
	}
	return s[:i], s[i+1:], version
}

// invMavenBuckets projects the resolver inventory into per-module coordinate sets (Membership.Project
// keyed), carrying the narrowed scope from Membership.Target.
func invMavenBuckets(t *testing.T, inv plugin.DependencyInventory) map[string]map[coord]bool {
	t.Helper()
	out := map[string]map[coord]bool{}
	for _, n := range inv.Nodes {
		g, a, v := purlCoord(t, n.PURL)
		proj := n.Membership.Project
		if out[proj] == nil {
			out[proj] = map[coord]bool{}
		}
		out[proj][coord{g, a, v, n.Membership.Target}] = true
	}
	return out
}

// invGradleCoords projects the resolver inventory into a flat (group, artifact, version) set
// (configuration/scope not graded — see file header).
func invGradleCoords(t *testing.T, inv plugin.DependencyInventory) map[coord]bool {
	t.Helper()
	out := map[coord]bool{}
	for _, n := range inv.Nodes {
		g, a, v := purlCoord(t, n.PURL)
		out[coord{group: g, artifact: a, version: v}] = true
	}
	return out
}

// --- Maven native.tree.txt oracle --------------------------------------------

// parseMavenTree parses an `mvn dependency:tree` capture into per-module coordinate sets, keyed by
// the module artifactId of each `@ <artifact>` section. The root coordinate of each section (no tree
// glyph) is skipped, as are "(… - omitted for conflict/duplicate …)" losers (the resolver mediates
// them away too). Scope is the last coordinate field.
func parseMavenTree(t *testing.T, data string) map[string]map[coord]bool {
	t.Helper()
	out := map[string]map[coord]bool{}
	module := ""
	for _, raw := range strings.Split(data, "\n") {
		line := strings.TrimPrefix(raw, "[INFO] ")
		line = strings.TrimPrefix(line, "[INFO]")
		if i := strings.Index(line, "dependency:"); i >= 0 && strings.Contains(line, "@ ") {
			at := strings.Index(line, "@ ")
			rest := strings.TrimSpace(line[at+2:])
			rest = strings.TrimSuffix(strings.TrimSpace(strings.TrimSuffix(rest, "---")), " ")
			module = strings.TrimSpace(rest)
			if out[module] == nil {
				out[module] = map[coord]bool{}
			}
			continue
		}
		// A dependency line carries a tree glyph (+- or \-); the root coordinate line does not.
		if !strings.Contains(line, "+- ") && !strings.Contains(line, "\\- ") {
			continue
		}
		body := strings.TrimLeft(line, "+\\|- ")
		if body == "" || strings.HasPrefix(body, "(") {
			continue // omitted-for-conflict/duplicate loser.
		}
		field := body
		if sp := strings.IndexByte(field, ' '); sp >= 0 {
			field = field[:sp]
		}
		parts := strings.Split(field, ":")
		if len(parts) < 5 {
			continue
		}
		// g:a:type:version:scope  (no classifier in these fixtures).
		c := coord{group: parts[0], artifact: parts[1], version: parts[3], scope: parts[4]}
		if out[module] == nil {
			out[module] = map[coord]bool{}
		}
		out[module][c] = true
	}
	return out
}

// --- Gradle native.deps.txt oracle -------------------------------------------

// parseGradleConfig parses one configuration block (e.g. "compileClasspath") of a `gradle
// dependencies` capture into a flat (group, artifact, version) set. It resolves "coord -> version"
// selections and "declared -> g:a:v" substitutions to the SELECTED coordinate, and skips constraint
// ("(c)") and unresolvable ("(n)") marker rows.
func parseGradleConfig(data, config string) map[coord]bool {
	out := map[coord]bool{}
	lines := strings.Split(data, "\n")
	in := false
	for _, raw := range lines {
		line := strings.TrimRight(raw, " \t")
		if !in {
			if strings.HasPrefix(line, config+" - ") || line == config {
				in = true
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			break // blank line ends the configuration block.
		}
		if !strings.Contains(line, "--- ") {
			continue
		}
		body := strings.TrimSpace(line[strings.Index(line, "--- ")+4:])
		if body == "" || strings.HasSuffix(body, "(n)") {
			continue // unresolvable declaration row.
		}
		body = strings.TrimSuffix(strings.TrimSpace(strings.TrimSuffix(body, "(*)")), " ")
		if strings.HasSuffix(body, "(c)") {
			continue // constraint-only row, not a node.
		}
		// Resolve "a -> b": b is either a bare version or a full g:a:v substitution.
		if i := strings.Index(body, " -> "); i >= 0 {
			left := strings.TrimSpace(body[:i])
			right := strings.TrimSpace(body[i+4:])
			if strings.Count(right, ":") >= 2 {
				body = right // identity substitution → selected coordinate.
			} else {
				// The left side is the declared coordinate, which for a platform()/constraints{}
				// -selected dependency is versionless (group:artifact only). Take group:artifact and
				// graft on the selected (right) version.
				lp := strings.Split(left, ":")
				if len(lp) < 2 {
					continue
				}
				body = lp[0] + ":" + lp[1] + ":" + right
			}
		}
		g, a, v := splitGradleCoord(body)
		if g == "" || a == "" || v == "" {
			continue
		}
		out[coord{group: g, artifact: a, version: v}] = true
	}
	return out
}

func splitGradleCoord(s string) (g, a, v string) {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) < 3 {
		return "", "", ""
	}
	return parts[0], parts[1], parts[2]
}

// --- differential assertion --------------------------------------------------

func assertSetsEqual(t *testing.T, label string, want, got map[coord]bool) {
	t.Helper()
	var missing, extra []string
	for c := range want {
		if !got[c] {
			missing = append(missing, c.String())
		}
	}
	for c := range got {
		if !want[c] {
			extra = append(extra, c.String())
		}
	}
	if len(missing) > 0 || len(extra) > 0 {
		sort.Strings(missing)
		sort.Strings(extra)
		t.Errorf("%s differential mismatch:\n  missing (native, not in inventory): %v\n  extra (inventory, not in native): %v",
			label, missing, extra)
	}
}

func readCapture(t *testing.T, name, file string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(benchRoot, name, file))
	if err != nil {
		t.Fatalf("read capture %s/%s: %v", name, file, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		t.Fatalf("capture %s/%s is empty — the oracle must be present for a differential", name, file)
	}
	return string(data)
}

// --- C1: benchmark parity (fully-resolvable) ---------------------------------

func TestInventory_C1_MavenParity(t *testing.T) {
	// module maps oracle section artifactId -> resolver Membership.Project.
	cases := []struct {
		name   string
		module map[string]string
	}{
		{"M1-maven-bom-conflict", map[string]string{"maven-bom-conflict": ""}},
		{"M2-maven-parent-scope-exclusions", map[string]string{"maven-parent-scope-exclusions": ""}},
		{"M3-maven-reactor-divergence", map[string]string{
			"maven-reactor-divergence": "", // reactor root (pom packaging, no deps)
			"module-a":                 "module-a",
			"module-b":                 "module-b",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			oracle := parseMavenTree(t, readCapture(t, tc.name, "native.tree.txt"))
			got := invMavenBuckets(t, resolveBenchmark(tc.name))
			for section, proj := range tc.module {
				assertSetsEqual(t, tc.name+" ["+section+"]", oracle[section], got[proj])
			}
		})
	}
}

func TestInventory_C1_GradleParity(t *testing.T) {
	// Fully-locked Gradle projects → compileClasspath (the maximal config, equal to the lockfile
	// union) is the oracle for the resolver's coordinate set.
	//   G1: lockfile + version catalog.
	//   G2: lockfile records the platform()/constraints{}-selected transitive closure.
	for _, name := range []string{"G1-gradle-lockfile-catalog", "G2-gradle-platform-constraints"} {
		t.Run(name, func(t *testing.T) {
			oracle := parseGradleConfig(readCapture(t, name, "native.deps.txt"), "compileClasspath")
			if len(oracle) == 0 {
				t.Fatalf("%s compileClasspath oracle parsed empty", name)
			}
			got := invGradleCoords(t, resolveBenchmark(name))
			assertSetsEqual(t, name+" [compileClasspath]", oracle, got)
		})
	}
}

// --- C4: selected ≠ declared -------------------------------------------------

func TestInventory_C4_SelectedNotDeclared(t *testing.T) {
	// M1: commons-codec is declared DIRECT at 1.17.1 and pulled TRANSITIVELY by httpclient at 1.11;
	// nearest-wins must select 1.17.1 (the version that drives advisory disqualification), and the
	// losing 1.11 must NOT appear in the inventory.
	inv := resolveBenchmark("M1-maven-bom-conflict")
	var codec []string
	for _, n := range inv.Nodes {
		if g, a, v := mustCoord(t, n.PURL); g == "commons-codec" && a == "commons-codec" {
			codec = append(codec, v)
		}
	}
	sort.Strings(codec)
	if len(codec) != 1 || codec[0] != "1.17.1" {
		t.Fatalf("C4: commons-codec must resolve to exactly the selected 1.17.1 (nearest-wins over transitive 1.11); got %v", codec)
	}

	// The BOM-managed jackson coordinate resolves to the version the imported jackson-bom manages
	// (2.17.2), not a version declared on the dependency (it is declared with none).
	if !hasNode(t, inv, "com.fasterxml.jackson.core", "jackson-databind", "2.17.2") {
		t.Error("C4: jackson-databind must resolve to the BOM-managed 2.17.2")
	}
}

// --- C3: honest-absent (unresolvable / no-lockfile residue) ------------------

func TestInventory_C3_MavenUnresolvedTriad(t *testing.T) {
	// M4: three distinct states. resolved is exercised cross-fixture (M1/M3); here every declared
	// coordinate is UNRESOLVABLE and must be emitted present-but-unresolved (Resolved=false, empty
	// version, declared reason), the graph must be Partial (never Complete over the truncated graph),
	// and the genuinely-absent negative control must NOT be invented.
	inv := resolveBenchmark("M4-maven-unresolved")
	if inv.Partiality.Complete {
		t.Fatal("C3: M4 inventory must be Partial, never Complete over an unresolvable graph")
	}
	for _, want := range []string{"env-gated-lib", "ghost-managed-lib"} {
		n := findByArtifact(inv, want)
		if n == nil {
			t.Errorf("C3: declared-but-unresolvable %q must be emitted (honest-absent), never dropped", want)
			continue
		}
		if n.Version != "" {
			t.Errorf("C3: %q version must stay empty, never guessed; got %q", want, n.Version)
		}
		if n.Partiality.Complete || len(n.Partiality.Reasons) == 0 {
			t.Errorf("C3: %q must carry a declared partiality reason; got %+v", want, n.Partiality)
		}
	}
	// never-declared-lib is declared in NO manifest — honest-absent ≠ absent: it must not appear.
	if findByArtifact(inv, "never-declared-lib") != nil {
		t.Error("C3: genuinely-absent never-declared-lib must NOT be invented")
	}
	// The BOM-cache-miss must be a DISTINCT declared reason from the property-unresolved one.
	if !hasReason(inv.Partiality, reasonBOMUncached) {
		t.Errorf("C3: M4 must declare the BOM-cache-miss residue %q; got %v", reasonBOMUncached, inv.Partiality.Reasons)
	}
}

func TestInventory_C4_GradleConstraintPlatformSelected(t *testing.T) {
	// G2: two direct dependencies are declared WITHOUT a version — their versions come from the build,
	// not the manifest: junit-jupiter-api via the junit-bom platform() and commons-lang3 via a
	// constraints{} block. The resolver must emit the build-SELECTED versions (the ones that drive an
	// advisory verdict), and — with a lockfile now present — the graph must be Complete with no
	// gradle_transitive residue. This is the selected≠declared story for Gradle, the analogue of M1.
	inv := resolveBenchmark("G2-gradle-platform-constraints")
	if !inv.Partiality.Complete {
		t.Errorf("C4: G2 is fully locked — inventory must be Complete; got reasons %v", inv.Partiality.Reasons)
	}
	if hasReason(inv.Partiality, reasonGradleTransitive) {
		t.Errorf("C4: G2 has a lockfile — no gradle_transitive residue expected; got %v", inv.Partiality.Reasons)
	}
	// Each declared-versionless direct dep must resolve to exactly its build-selected version.
	selected := []struct{ group, artifact, version, via string }{
		{"org.junit.jupiter", "junit-jupiter-api", "5.10.3", "junit-bom platform()"},
		{"org.apache.commons", "commons-lang3", "3.14.0", "constraints{}"},
	}
	for _, s := range selected {
		if !hasNode(t, inv, s.group, s.artifact, s.version) {
			t.Errorf("C4: %s:%s must resolve to the %s-selected %s", s.group, s.artifact, s.via, s.version)
		}
	}
}

func TestInventory_C3_GradleMixedMultiproject(t *testing.T) {
	// G3: one subproject (app-a) is LOCKED and resolves fully; another (app-b) has NO lockfile and is
	// declared residue. The whole inventory must be Partial (a single subproject's lockfile must NOT
	// make the truncated build report Complete), app-a's locked coordinates must all resolve, and
	// app-b's declared coordinates must be present as gradle_transitive residue.
	inv := resolveBenchmark("G3-gradle-multiproject-residue")
	if inv.Partiality.Complete {
		t.Fatal("C3: G3 must be Partial — a locked subproject must not mask the unlocked one as Complete")
	}
	if !hasReason(inv.Partiality, reasonGradleTransitive) {
		t.Errorf("C3: G3 must declare gradle_transitive residue for the unlocked subproject; got %v", inv.Partiality.Reasons)
	}
	// app-a locked coordinates (the 3.37.0/2.21.1/1.0.1 divergent versions) resolve cleanly.
	for _, want := range [][3]string{
		{"com.google.guava", "guava", "32.1.3-jre"},
		{"org.checkerframework", "checker-qual", "3.37.0"},
		{"com.google.errorprone", "error_prone_annotations", "2.21.1"},
		{"com.google.guava", "failureaccess", "1.0.1"},
	} {
		n := findNodeGAV(inv, want[0], want[1], want[2])
		if n == nil {
			t.Errorf("C3: G3 locked app-a coordinate %s:%s:%s must resolve", want[0], want[1], want[2])
			continue
		}
		if !n.Partiality.Complete {
			t.Errorf("C3: G3 locked coordinate %s:%s must be Complete (fully resolved from the lockfile); got %+v", want[0], want[1], n.Partiality)
		}
	}
	// app-b declared coordinates (unlocked) are present as honest-absent residue, never dropped.
	for _, want := range []string{"commons-lang3", "google-collections"} {
		n := findByArtifact(inv, want)
		if n == nil {
			t.Errorf("C3: G3 unlocked app-b coordinate %q must be emitted as declared residue, never dropped", want)
			continue
		}
		if !hasReason(n.Partiality, reasonGradleTransitive) {
			t.Errorf("C3: G3 app-b coordinate %q must carry gradle_transitive; got %+v", want, n.Partiality)
		}
	}
}

// --- C5: determinism ---------------------------------------------------------

func TestInventory_C5_Determinism(t *testing.T) {
	// Byte-identical inventory across independent resolutions (fresh caches each time — the resolver
	// holds no global state, so a fresh-cache invocation is equivalent to a separate process, while
	// Go's per-range map-iteration randomization exercises any map that leaks onto the output path),
	// plus a perturbation control: reversing the reactor POM input order must not change the output.
	for _, name := range []string{
		"M1-maven-bom-conflict", "M3-maven-reactor-divergence", "G1-gradle-lockfile-catalog",
		"M4-maven-unresolved", "G3-gradle-multiproject-residue",
	} {
		t.Run(name, func(t *testing.T) {
			var first string
			for i := 0; i < 5; i++ {
				b, err := json.Marshal(resolveBenchmark(name))
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					first = string(b)
				} else if string(b) != first {
					t.Fatalf("non-deterministic across runs:\n run0=%s\n run%d=%s", first, i, b)
				}
			}
		})
	}

	// Perturbation control: shuffle (reverse) the reactor POM discovery order for M3 and confirm the
	// emitted inventory is byte-identical — no input-order dependence, no map iteration on the output.
	base := filepath.Join(benchRoot, "M3-maven-reactor-divergence", "proj")
	m2 := filepath.Join(benchRoot, "M3-maven-reactor-divergence", "m2")
	poms := findPOMs(base)
	rev := append([]string{}, poms...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	a, _ := json.Marshal(resolveMaven(base, poms, newMavenCacheAt(m2), nil))
	b, _ := json.Marshal(resolveMaven(base, rev, newMavenCacheAt(m2), nil))
	if string(a) != string(b) {
		t.Fatalf("perturbation (reversed POM order) changed output:\n sorted=%s\n reversed=%s", a, b)
	}
}

// --- helpers -----------------------------------------------------------------

func mustCoord(t *testing.T, purl string) (g, a, v string) {
	t.Helper()
	return purlCoord(t, purl)
}

func hasNode(t *testing.T, inv plugin.DependencyInventory, g, a, v string) bool {
	t.Helper()
	return findNodeGAV(inv, g, a, v) != nil
}

func findNodeGAV(inv plugin.DependencyInventory, g, a, v string) *plugin.DependencyNode {
	want := mavenPURL(g, a, v)
	for i := range inv.Nodes {
		if inv.Nodes[i].PURL == want {
			return &inv.Nodes[i]
		}
	}
	return nil
}

func findByArtifact(inv plugin.DependencyInventory, artifact string) *plugin.DependencyNode {
	for i := range inv.Nodes {
		if inv.Nodes[i].Artifact.Identity == artifact {
			return &inv.Nodes[i]
		}
	}
	return nil
}
