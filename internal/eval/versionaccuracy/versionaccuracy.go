// Package versionaccuracy is the measurement instrument for §4.7's version-resolution
// accuracy metric (PLAN-120). It compares a lane's resolved dependency graph
// (plugin.DependencyInventory) against a recorded, human-captured native-package-manager
// oracle and reports agreement as three separate sub-scores — never a blend.
//
// # What this package is NOT
//
// It executes no target build tooling and has no scan entry point (§3.3, C5): the oracle
// is a committed, reviewed artifact produced out-of-band by a person (see the capture
// procedure deposited with this cycle), exactly as expected_sinks.json records reviewed
// ground truth rather than computing it. This package only compares two records already in
// one shape and computes a number.
//
// # Honest absence (§3.1/§3.6, C2)
//
// A fixture with no oracle, or an oracle whose fixture has changed since capture, yields
// StateUnmeasurable with a typed reason — never 0.0, never a silently omitted ledger row.
// A missing row reads downstream as "nothing to see", which is inferring safety from absent
// evidence. Sub-scores on an unmeasurable Result are the zero Rate, which renders "n/a
// (0/0)", not a measured zero.
//
// # Compared object (PLAN-100 landed; A1)
//
// The comparison is against plugin.DependencyInventory — the whole resolved graph — not
// report.SBOM, which is package-granularity (it collapses distinct same-PURL instances and
// carries no project/workspace/target membership). The oracle mirrors the five §4.1
// properties the Phase-1 gate compares: normalized PURL, exact version, direct/transitive
// relationship, parent edges, and project/workspace/target membership.
package versionaccuracy

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/corpus"
	"github.com/ferralon-ai/ferralon-assay/internal/eval/reachcandidate"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// Rate is the num/denom agreement rate. Reused from reachcandidate so the eval surface has
// one Rate type and one honest "n/a (0/0)" rendering for a zero-denominator score.
type Rate = reachcandidate.Rate

// OracleNode is one resolved package instance as the native package manager reported it.
// It mirrors plugin.DependencyNode's compared fields (§4.1). Direct is NOT omitempty: false
// (transitive) is load-bearing and a transitive node must be byte-distinguishable from a
// direct one, or the transitive-set sub-score is silently corrupted.
type OracleNode struct {
	PURL      string `json:"purl"`                // §4.1 normalized Package URL, version-embedded
	Version   string `json:"version"`             // §4.1 exact resolved version
	Direct    bool   `json:"direct"`              // §4.1 direct (true) vs transitive (false); load-bearing, not omitempty
	Project   string `json:"project,omitempty"`   // §4.1 owning project/module root
	Workspace string `json:"workspace,omitempty"` // §4.1 enclosing workspace (monorepo), when applicable
	Target    string `json:"target,omitempty"`    // §4.1 build target/configuration scope
}

// key is the node's stable, scope-qualified identity. Distinct same-PURL instances in
// different projects/workspaces/targets get distinct keys, so parent edges relate the right
// instances (mirrors plugin.DependencyNode.ID's per-instance intent, but expressed over
// review-legible coordinates rather than resolver-internal IDs).
func (n OracleNode) key() string {
	return strings.Join([]string{n.PURL, n.Project, n.Workspace, n.Target}, "\x1f")
}

// coordinate is the PURL with its @version suffix removed — the version-independent package
// identity. It lets a version MISMATCH (same coordinate, different version) be distinguished
// from an ABSENT package, which a version-embedded key cannot.
func (n OracleNode) coordinate() string { return stripVersion(n.PURL) }

// OracleEdge is one parent→child dependency edge, endpoints being OracleNode.key() values.
// Recorded explicitly because "matches native output" is a claim about the resolved graph,
// not about a version string in isolation: a version-only oracle passes a resolver whose
// transitive edges are entirely wrong.
type OracleEdge struct {
	Parent string `json:"parent"` // OracleNode.key() of the depending instance
	Child  string `json:"child"`  // OracleNode.key() of the depended-on instance
}

// Capture is the provenance of an oracle capture (C1) plus the staleness anchor (C2). Every
// field is required for the capture to be auditable; a capture with no operator or command
// is not reviewable.
type Capture struct {
	Tool          string `json:"tool"`           // native package manager ("go mod", "mvn", "npm", "dotnet", "pip")
	ToolVersion   string `json:"tool_version"`   // exact tool version the capture ran under
	Command       string `json:"command"`        // exact command executed out-of-band
	Operator      string `json:"operator"`       // who ran the capture
	CapturedAt    string `json:"captured_at"`    // RFC3339 timestamp of the capture
	FixtureDigest string `json:"fixture_digest"` // digest of the fixture inputs at capture time; the staleness anchor (C2)
	// Environment is the declared resolution environment the oracle was captured under —
	// interpreter/platform/extras for Python, target framework/RID for .NET, etc. The
	// selected dependency set is environment-parameterized, so a comparison is only valid
	// when the resolved set was produced under the SAME environment (§3.6 boundary 3): a
	// version selected under a different interpreter is not a resolver miss, it is a
	// different question. Measure gates on Observed.Environment agreement. Empty for
	// ecosystems whose selection is not environment-parameterized.
	Environment map[string]string `json:"environment,omitempty"`
}

// Oracle is the committed, versioned, digest-checkable record of one fixture's native
// resolved graph. Populating it per fixture is per-lane content work (out of scope here); an
// oracle invented in this cycle to make a test pass would be a fabricated oracle.
type Oracle struct {
	FixtureID string          `json:"fixture_id"`
	Category  corpus.Category `json:"category"`
	Nodes     []OracleNode    `json:"nodes"`
	Edges     []OracleEdge    `json:"edges"`
	Capture   Capture         `json:"capture"`
}

// AxisScore is one sub-score axis: either measured (with a Rate) or unmeasurable (with a
// reason). An axis is unmeasurable when the resolved inventory declares a Partiality that
// touches it — an honestly-unexpressed edge, or a version that could not be pinned. Scoring
// such a case as a miss would launder preserved Partiality into a measured FAILURE (§3.6):
// the resolver did not get it wrong, the fact was declared undetermined. Reason carries the
// resolved inventory's own reason code (with any lane suffix). On StateMeasured the Reason is
// empty; on StateUnmeasurable the Rate is the zero Rate, never a measured 0.0.
type AxisScore struct {
	State  State  `json:"state"`
	Reason string `json:"reason,omitempty"`
	Rate   Rate   `json:"rate"`
}

// SubScores are the three independent agreement axes (C3). They are reported separately,
// never blended: a single number cannot distinguish a resolver that gets every version right
// and every edge wrong from its opposite, and the Phase-1 gate explicitly calls out
// transitive cases. Each axis is independently measurable-or-not (§3.6): a graph whose edges
// are declared unexpressed can still have a measured version axis.
type SubScores struct {
	// ExactVersion is the fraction of oracle nodes whose coordinate the resolver reproduced
	// at the SAME version (§4.7 version-resolution accuracy, the version axis). Unmeasurable
	// when the resolved set declares source_unpinned / env_condition_unresolved: an
	// unpinnable or environment-conditional version is undetermined, not a mismatch.
	ExactVersion AxisScore `json:"exact_version"`
	// TransitiveSet is intersection-over-union agreement of the TRANSITIVE (Direct=false)
	// coordinate sets — an added or dropped transitive dependency moves it.
	TransitiveSet AxisScore `json:"transitive_set"`
	// ParentEdge is intersection-over-union agreement of the parent→child edge sets, in
	// scope-qualified key space — a rewired edge moves it while versions stay put.
	// Unmeasurable when the resolved set declares relationship_unexpressed: an edge the lock
	// does not record is absent from the graph, never inferred, and never a scored miss.
	ParentEdge AxisScore `json:"parent_edge"`
}

// State is whether a fixture's version-resolution accuracy was measured or is unmeasurable.
type State string

const (
	StateMeasured     State = "measured"
	StateUnmeasurable State = "unmeasurable"
)

// Result-level reason codes for StateUnmeasurable (C2). Empty on a measured Result. Axis-level
// unmeasurable reasons are the resolved inventory's own plugin.PartialReason* codes (§3.6),
// carried through verbatim on the AxisScore.
const (
	ReasonOracleAbsent        = "oracle_absent"        // no oracle recorded for this fixture
	ReasonOracleStale         = "oracle_stale"         // the fixture changed since the oracle was captured
	ReasonEnvironmentMismatch = "environment_mismatch" // oracle and resolved set were produced under different declared environments (§3.6 boundary 3)
)

// Result is one fixture's version-resolution-accuracy outcome. On StateUnmeasurable the
// Scores are the zero Rate (renders "n/a (0/0)"), never a measured 0.0.
type Result struct {
	FixtureID string          `json:"fixture_id"`
	Category  corpus.Category `json:"category"`
	State     State           `json:"state"`
	Reason    string          `json:"reason,omitempty"` // set iff State==StateUnmeasurable
	Scores    SubScores       `json:"scores"`
}

// Observed carries the caller's facts about the state the resolved inventory was produced
// under, for comparability gating: the fixture's current digest (staleness, C2) and the
// declared resolution environment (§3.6 boundary 3). Bundled so the comparability inputs grow
// without churning Measure's signature.
type Observed struct {
	FixtureDigest string            // the fixture's current digest; see FixtureDigest
	Environment   map[string]string // the declared environment the resolved set was produced under
}

// Measure compares a fixture's resolved inventory against its oracle and returns the honest
// Result. A nil oracle is StateUnmeasurable{ReasonOracleAbsent}; a digest disagreement is
// StateUnmeasurable{ReasonOracleStale}; an environment disagreement is
// StateUnmeasurable{ReasonEnvironmentMismatch} — comparing graphs resolved under different
// interpreters/platforms/extras is comparing different questions, not measuring a miss (§3.6).
// Only a fresh, present, same-environment oracle produces sub-scores, and even then a
// per-axis Partiality on the resolved set leaves that axis unmeasurable rather than scored.
func Measure(oracle *Oracle, resolved plugin.DependencyInventory, obs Observed) Result {
	if oracle == nil {
		return Result{State: StateUnmeasurable, Reason: ReasonOracleAbsent}
	}
	res := Result{FixtureID: oracle.FixtureID, Category: oracle.Category}
	if oracle.Capture.FixtureDigest != obs.FixtureDigest {
		res.State = StateUnmeasurable
		res.Reason = ReasonOracleStale
		return res
	}
	if !envEqual(oracle.Capture.Environment, obs.Environment) {
		res.State = StateUnmeasurable
		res.Reason = ReasonEnvironmentMismatch
		return res
	}
	res.State = StateMeasured
	res.Scores = score(*oracle, resolved)
	return res
}

// score computes the three independent sub-scores. It never executes anything — it is set
// arithmetic over two recorded graphs.
func score(oracle Oracle, resolved plugin.DependencyInventory) SubScores {
	// Resolved node lookup by coordinate → version, and node ID → scope-qualified key.
	resolvedVersionByCoord := map[string]string{}
	idToKey := map[string]string{}
	resolvedTransitive := map[string]bool{}
	for _, n := range resolved.Nodes {
		coord := stripVersion(n.PURL)
		resolvedVersionByCoord[coord] = n.Version
		on := OracleNode{
			PURL: n.PURL, Version: n.Version, Direct: n.Direct,
			Project: n.Membership.Project, Workspace: n.Membership.Workspace, Target: n.Membership.Target,
		}
		idToKey[n.ID] = on.key()
		if !n.Direct {
			resolvedTransitive[coord] = true
		}
	}

	// ExactVersion: oracle nodes reproduced at the same version.
	var exact Rate
	oracleTransitive := map[string]bool{}
	for _, n := range oracle.Nodes {
		exact.Denom++
		if v, ok := resolvedVersionByCoord[n.coordinate()]; ok && v == n.Version {
			exact.Num++
		}
		if !n.Direct {
			oracleTransitive[n.coordinate()] = true
		}
	}

	// TransitiveSet: intersection-over-union of the transitive coordinate sets.
	transitive := iou(oracleTransitive, resolvedTransitive)

	// ParentEdge: intersection-over-union of edge sets, both in scope-qualified key space.
	oracleEdges := map[string]bool{}
	for _, e := range oracle.Edges {
		oracleEdges[e.Parent+"\x1e"+e.Child] = true
	}
	resolvedEdges := map[string]bool{}
	for _, e := range resolved.Edges {
		pk, okp := idToKey[e.Parent]
		ck, okc := idToKey[e.Child]
		if okp && okc {
			resolvedEdges[pk+"\x1e"+ck] = true
		}
	}
	edges := iou(oracleEdges, resolvedEdges)

	// §3.6 boundary gating: an axis the resolved set declared partial is UNMEASURABLE, not a
	// scored miss. Collect every declared reason (graph-level + per-node), then gate each
	// axis on the reasons that touch it. TransitiveSet has no named boundary — it is measured
	// unless the whole comparison was already gated upstream.
	reasons := collectReasons(resolved)
	return SubScores{
		ExactVersion:  axis(exact, reasons, plugin.PartialReasonSourceUnpinned, plugin.PartialReasonEnvConditionUnresolved),
		TransitiveSet: AxisScore{State: StateMeasured, Rate: transitive},
		ParentEdge:    axis(edges, reasons, plugin.PartialReasonRelationshipUnexpressed),
	}
}

// axis builds a measured AxisScore from rate, unless one of the resolved set's declared
// reasons matches a base code that makes this axis undetermined — in which case the axis is
// unmeasurable and carries that reason (with any lane suffix) verbatim (§3.6).
func axis(rate Rate, reasons []string, bases ...string) AxisScore {
	for _, r := range reasons {
		for _, base := range bases {
			if hasBase(r, base) {
				return AxisScore{State: StateUnmeasurable, Reason: r}
			}
		}
	}
	return AxisScore{State: StateMeasured, Rate: rate}
}

// collectReasons gathers every declared partiality reason from the inventory — the
// graph-level Partiality and every node's Partiality — so an axis is gated whether the limit
// was declared for the whole graph or for a single node in it.
func collectReasons(inv plugin.DependencyInventory) []string {
	var out []string
	out = append(out, inv.Partiality.Reasons...)
	for _, n := range inv.Nodes {
		out = append(out, n.Partiality.Reasons...)
	}
	return out
}

// hasBase reports whether a reason string is the given base code or a lane-localised variant
// of it ("<base>:<suffix>", per the plugin vocabulary's suffix convention).
func hasBase(reason, base string) bool {
	return reason == base || strings.HasPrefix(reason, base+":")
}

// envEqual reports whether two declared environments agree. Two empty environments agree
// (an ecosystem whose selection is not environment-parameterized). A key present in one and
// absent in the other, or a differing value, is a disagreement.
func envEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		if vb, ok := b[k]; !ok || vb != va {
			return false
		}
	}
	return true
}

// iou is intersection-over-union as a Rate: Num = |a ∩ b|, Denom = |a ∪ b|. Two empty sets
// give the zero Rate ("n/a (0/0)"), which is the honest reading — there was nothing to agree
// on — not a perfect or a failing score.
func iou(a, b map[string]bool) Rate {
	union := map[string]bool{}
	for k := range a {
		union[k] = true
	}
	inter := 0
	for k := range b {
		union[k] = true
		if a[k] {
			inter++
		}
	}
	return Rate{Num: inter, Denom: len(union)}
}

// stripVersion removes the "@version" suffix from a PURL, yielding the version-independent
// coordinate. A PURL with no "@" is returned unchanged.
func stripVersion(purl string) string {
	if i := strings.LastIndex(purl, "@"); i >= 0 {
		return purl[:i]
	}
	return purl
}

// FixtureDigest is a deterministic digest of the dependency-defining inputs of a fixture,
// used as the staleness anchor. It digests the fixture's codebase identity (repo, revision,
// acquisition) — the fields that pin which dependency graph the oracle was captured against.
// The capture procedure (C7) records this value into Capture.FixtureDigest; Measure compares
// the current value against it. Deterministic and dependency-free — it executes nothing.
func FixtureDigest(f corpus.Fixture) string {
	h := sha256.New()
	// Order-stable concatenation of the codebase-identifying fields, length-prefixed so no
	// field-boundary ambiguity can make two distinct fixtures digest equal.
	for _, part := range []string{
		f.ID,
		f.Codebase.Repo,
		f.Codebase.Revision,
		f.Codebase.Acquisition.Mode,
		f.Codebase.Acquisition.Path,
		f.Codebase.Acquisition.Module,
		f.Codebase.Acquisition.Version,
	} {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0x1f})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Ledger collects per-fixture Results sliced by corpus.Category (C4), so the multi-project,
// transitive, and out-of-range dimensions §4.7 names are individually readable. PLAN-190
// reads these slices; an aggregate hides exactly the cases the Phase-1 gate names.
type Ledger struct {
	ByCategory map[corpus.Category][]Result `json:"by_category"`
}

// NewLedger returns an empty ledger.
func NewLedger() *Ledger { return &Ledger{ByCategory: map[corpus.Category][]Result{}} }

// Add slices a Result into its category. A Result whose category is empty is still recorded
// (under the empty category) rather than dropped — a silently dropped row is a silently
// unmeasured requirement.
func (l *Ledger) Add(r Result) {
	if l.ByCategory == nil {
		l.ByCategory = map[corpus.Category][]Result{}
	}
	l.ByCategory[r.Category] = append(l.ByCategory[r.Category], r)
}

// Categories returns the categories present in the ledger, sorted.
func (l *Ledger) Categories() []corpus.Category {
	out := make([]corpus.Category, 0, len(l.ByCategory))
	for c := range l.ByCategory {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
