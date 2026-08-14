package goanalysis

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/vuln/scan"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// StackFrame is one frame of a govulncheck call stack, ordered ingress->sink.
// SCIP is the symbol's id emitted by the SAME emitter the call graph uses
// (packages.go / callgraph.go), so a derived trace shares an identity space with
// CallGraph edges by construction. IsEntry marks the frame as a recognized
// program entry point (the top of a complete stack).
type StackFrame struct {
	SCIP    string
	IsEntry bool
}

// CallStack is one ordered ingress->sink path govulncheck reports for a vuln.
// Frames[0] is the entry point (when one was identified) and the final frame is
// the vulnerable sink symbol.
type CallStack struct {
	Frames []StackFrame
}

// stacksToReachPaths is the PURE derivation: each call stack -> one ReachPath.
// Sink is the bottom frame, Ingress is the top frame ONLY when it is a
// recognized entry (otherwise empty, feeding the nil-Ingress CandidatePair),
// and Trace is the ordered SCIP ids ingress->sink. Empty stacks (module/package
// level findings with no symbol trace) produce no path. No I/O — hermetically
// testable with synthetic stacks.
func stacksToReachPaths(stacks []CallStack) []plugin.ReachPath {
	var paths []plugin.ReachPath
	for _, st := range stacks {
		if len(st.Frames) == 0 {
			continue
		}
		trace := make([]plugin.Symbol, len(st.Frames))
		for i, f := range st.Frames {
			trace[i] = sym(f.SCIP)
		}
		top := st.Frames[0]
		var ingress plugin.Symbol
		if top.IsEntry {
			ingress = sym(top.SCIP)
		}
		paths = append(paths, plugin.ReachPath{
			Sink:    sym(st.Frames[len(st.Frames)-1].SCIP),
			Ingress: ingress,
			Trace:   trace,
		})
	}
	return paths
}

// reconcile is the (pure) consistency check between the derived ReachPaths and
// the x/tools call graph. It folds in the call graph's own declared partiality,
// then:
//
//   - Every adjacent pair in a Trace must be an edge in the call graph. A trace
//     the broader graph cannot corroborate is an unknown gap, declared with
//     PartialReasonReachabilityUndetermined — never silently accepted.
//   - A ReachPath with no Ingress (reachable sink, no known entry) declares
//     PartialReasonNoIngress — never "not exploitable" (inv.5).
//   - The asymmetry rule (notReachable=true): when govulncheck reported the vuln
//     present but found NO reachable symbol-level trace, we do NOT conclude
//     "safe"/"unreachable". govulncheck's miss is UNKNOWN, so we declare
//     PartialReasonReachabilityUndetermined — the static analysis could not see
//     a path, not that none exists (inv.5, §5.3/§6).
//
// INVARIANT: reconcile mints no inherent-limit reason of its own. Every reason it
// adds here names something this run could not DETERMINE, and each one is a
// did-not-run disclosure (report.ClassifyPartialityReason). The genuine limits of
// the method — reflection, dynamic dispatch, cgo — are detected structurally by
// classifyFuncPartiality (callgraph.go) and reach this function only by being
// folded in from cg.Partiality.Reasons below. Minting them here instead would file
// an undetermined result under the quiet arm, which renders it as a clean scan.
func reconcile(paths []plugin.ReachPath, cg plugin.CallGraphResult, notReachable bool) plugin.Partiality {
	reasons := map[string]bool{}
	for _, r := range cg.Partiality.Reasons {
		reasons[r] = true
	}
	if !cg.Partiality.Complete {
		// A call graph that is itself partial cannot fully corroborate any trace.
		// Carry its incompleteness even when it listed no explicit reasons — the
		// cause is unknown, which is exactly what the undetermined code says.
		if len(cg.Partiality.Reasons) == 0 {
			reasons[plugin.PartialReasonReachabilityUndetermined] = true
		}
	}

	edges := make(map[[2]plugin.Symbol]bool, len(cg.Edges))
	for _, e := range cg.Edges {
		edges[[2]plugin.Symbol{e.Caller, e.Callee}] = true
	}

	for _, p := range paths {
		if p.Ingress == (plugin.Symbol{}) {
			reasons[plugin.PartialReasonNoIngress] = true
		}
		for i := 0; i+1 < len(p.Trace); i++ {
			if !edges[[2]plugin.Symbol{p.Trace[i], p.Trace[i+1]}] {
				reasons[plugin.PartialReasonReachabilityUndetermined] = true
				break
			}
		}
	}

	if notReachable {
		reasons[plugin.PartialReasonReachabilityUndetermined] = true
	}

	if len(reasons) == 0 {
		return plugin.Complete()
	}
	return plugin.Partial(sortedKeys(reasons)...)
}

// Reachability runs govulncheck as a LIBRARY (golang.org/x/vuln/scan) over
// req.BuildDir, parses its -json finding/trace stream, derives ReachPaths, and
// reconciles them against the x/tools call graph built from the same module.
//
// govulncheck's finding/trace types live in x/vuln/internal and are not
// importable, so the stream is decoded into LOCAL structs (vulnMessage/...)
// matching govulncheck's documented -json schema. A govulncheck FAILURE (build
// broke, non-zero exit, timeout) is a HARD error (inv.4) — never a silent empty
// result. ctx governs the run via scan.Command.
//
// When req.GoToolchain names the subject's toolchain, the govulncheck
// child runs under it via GOTOOLCHAIN, so both the advisory range match and the
// stdlib package graph are the SUBJECT's rather than the analyzer's. That request is
// best-effort by design: a toolchain that cannot be fetched, or that cannot build the
// module, falls back to the analyzer's own toolchain and reports what actually ran in
// ScanToolchain. It never fails the scan and never silently claims the subject was
// scanned — the caller decides what an empty path set is evidence of.
func Reachability(ctx context.Context, req plugin.ReachabilityRequest) (plugin.ReachabilityResult, error) {
	baseEnv := reachBaseEnv()
	env, scanToolchain, switched := subjectToolchainEnv(ctx, baseEnv, req.BuildDir, req.GoToolchain)

	findings, err := runGovulncheck(ctx, req, env)
	if err != nil && switched {
		// The subject's toolchain materialized but could not complete the scan — its stdlib
		// cannot build this module, or the older go command rejects the go.mod. Fall back to
		// the analyzer's toolchain: the scan must still produce a result (an aborted scan
		// would be a worse failure than a disclosed partial one), and ScanToolchain then
		// reports the analyzer's toolchain so no caller mistakes this for a subject scan.
		env, scanToolchain, switched = baseEnv, goEnvVersion(ctx, req.BuildDir, baseEnv), false
		findings, err = runGovulncheck(ctx, req, env)
	}
	if err != nil {
		return plugin.ReachabilityResult{}, err
	}

	stacks := findingsToStacks(findings)
	paths := stacksToReachPaths(stacks)

	cg, err := CallGraph(ctx, plugin.CallGraphRequest{BuildDir: req.BuildDir})
	if err != nil {
		return plugin.ReachabilityResult{}, fmt.Errorf("call graph for reconciliation: %w", err)
	}

	// notReachable: govulncheck applied the advisory to this module but produced
	// no symbol-level trace we could turn into a path. Asymmetry rule: unknown,
	// never "safe".
	notReachable := len(findings) > 0 && len(paths) == 0

	part := reconcile(paths, cg, notReachable)
	return plugin.ReachabilityResult{Partiality: part, Paths: paths, ScanToolchain: scanToolchain}, nil
}

// reachBaseEnv is the child environment every govulncheck run starts from.
//
// govulncheck loads packages via go/packages, which spawns `go list` with THIS Env
// (x/vuln passes cfg.env straight through to packages.Config.Env). The analyzed module
// is NEVER a member of any workspace the plugin process happens to sit inside — e.g.
// Tegron's own go.work when assessing an in-repo corpus repro under ferralon-assay/. Force
// GOWORK=off LOCALLY here so the load resolves the target module standalone, mirroring
// LoadProgram (packages.go). This keeps the reachability path workspace-blind on its own
// merits rather than relying solely on the process-global GOWORK=off set far away at
// plugin entry (cmd/tegron-plugin-go/main.go) — and an unset cmd.Env would otherwise
// default to os.Environ(), reintroducing the ambient leak if any code path runs before
// that entry-point Setenv.
func reachBaseEnv() []string {
	env := os.Environ()
	out := make([]string, len(env), len(env)+1)
	copy(out, env)
	return append(out, "GOWORK=off")
}

// subjectToolchainEnv resolves the child environment for a run the caller wants executed under
// the subject's toolchain `wanted`, returning that environment, the toolchain the run will
// actually execute under, and whether a toolchain switch is in effect.
//
// Four outcomes, and the distinction between the middle two is why this is not a bare env append:
//
//   - No request (`wanted` empty — the flag is off, the subject's toolchain is only a lower bound,
//     or this is any lane other than Go): return the base environment verbatim and an EMPTY
//     scanToolchain. Empty is what makes the caller unable to read the run as a subject scan, and
//     no `go env` probe is performed, so a flag-off run is byte-identical to today's.
//   - The analyzer is ALREADY on the subject's toolchain: return the base environment untouched.
//     Pinning GOTOOLCHAIN would be a needless behavior change — it also disables the auto
//     switch-UP that a go.mod requiring a newer release depends on — and the run is already a
//     full-fidelity subject scan, so there is nothing to buy.
//   - The toolchain switch works: return the pinned environment. `go env GOVERSION` under the
//     candidate environment is both the probe and the fetch — Go downloads the toolchain on
//     demand — so a version that cannot be fetched fails here rather than mid-scan, and the
//     switch is CONFIRMED to have taken effect rather than assumed.
//   - Anything else (no network, no such release, a `go` that cannot run): return the base
//     environment and the analyzer's own toolchain. Not an error: the caller's contract is that
//     an unhonored request degrades to a disclosed partial, never to a failed scan.
func subjectToolchainEnv(ctx context.Context, baseEnv []string, buildDir, wanted string) (env []string, scanToolchain string, switched bool) {
	if wanted == "" {
		return baseEnv, "", false
	}
	local := goEnvVersion(ctx, buildDir, baseEnv)
	// Sameness is checked BEFORE loadability on purpose: an analyzer already running on the
	// subject's toolchain is a full-fidelity subject scan whatever that toolchain is, because the
	// loader is then running under itself.
	if sameGoToolchain(local, wanted) {
		return baseEnv, wanted, false
	}
	release, ok := parseGoRelease(wanted)
	if !ok || !release.loadable() {
		// Nothing to try. Below the loader floor the fetch would succeed and the scan would then
		// fail anyway, so declining here saves a ~60MB download whose only outcome is this same
		// fallback.
		return baseEnv, local, false
	}
	candidate := make([]string, len(baseEnv), len(baseEnv)+1)
	copy(candidate, baseEnv)
	candidate = append(candidate, "GOTOOLCHAIN="+release.toolchain())
	if got := goEnvVersion(ctx, buildDir, candidate); sameGoToolchain(got, wanted) {
		return candidate, wanted, true
	}
	return baseEnv, local, false
}

// goEnvVersion reports `go env GOVERSION` for buildDir under env — the release the go command
// would actually use there, which under the default GOTOOLCHAIN=auto depends on the module's own
// directives and is therefore a property of the directory, not of the installed binary. Any
// failure (no go on PATH, an unfetchable pinned toolchain, a cancelled context) yields "": an
// unknown toolchain, never a guess.
func goEnvVersion(ctx context.Context, buildDir string, env []string) string {
	cmd := exec.CommandContext(ctx, "go", "env", "GOVERSION")
	cmd.Dir = buildDir
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// sameGoToolchain reports whether two Go version strings name the same release. It compares
// NORMALIZED forms because the same release has two spellings in the wild — a pre-1.21 initial
// release reports "go1.17" where the toolchain fact carries "go1.17.0" — and a string compare
// would call those different and fetch a toolchain that is already installed.
func sameGoToolchain(a, b string) bool {
	ra, oka := parseGoRelease(a)
	rb, okb := parseGoRelease(b)
	return oka && okb && ra == rb
}

// goRelease is a plain Go release version. It exists because the same release has three different
// spellings that all matter here: the canonical three-segment form the toolchain fact carries, the
// form `go env GOVERSION` prints, and the form that names a downloadable toolchain.
type goRelease struct{ major, minor, patch int }

// parseGoRelease parses a Go release version ("go1.17", "go1.21.3"). ok is false for anything with
// no release identity — a devel or prerelease build ("devel go1.27-abc123", "go1.22rc1"), or junk —
// so such a toolchain is never declared equal to a requested release, and is never requested.
//
// This is deliberately a LOCAL parser rather than a reach into pipeline's version package: the
// analyzer subprocess owns its own comparisons (inv.8 keeps the dependency edge pointing this way),
// and what it needs — release equality and a download spelling — is not what the U7 comparator needs.
func parseGoRelease(s string) (goRelease, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "go")
	if !ok || rest == "" {
		return goRelease{}, false
	}
	segs := strings.Split(rest, ".")
	if len(segs) < 2 || len(segs) > 3 {
		return goRelease{}, false
	}
	nums := make([]int, 3)
	for i, seg := range segs {
		n, err := strconv.Atoi(seg)
		if err != nil || n < 0 {
			return goRelease{}, false
		}
		nums[i] = n
	}
	return goRelease{major: nums[0], minor: nums[1], patch: nums[2]}, true
}

// loaderMinMinor is the oldest Go 1.x minor whose `go list` the bundled go/packages loader can
// drive, and therefore the oldest subject toolchain this analysis can run under. Below it the
// toolchain fetch succeeds and the scan then fails on a flag the older go command does not have,
// which is a fallback with a large download attached rather than a different outcome.
//
// Verified empirically against the loader in this module rather than inferred from release notes:
//
//	go1.22.12, go1.21.0, go1.20.14, go1.20.9  →  scan completes
//	go1.19                                    →  "flag provided but not defined: -pgo"
//	go1.18.10, go1.17.1                       →  `invalid boolean value "Name,ImportPath,…" for -json`
//
// Raising the vendored x/tools does not lower this floor; only a loader that stops emitting those
// flags would. If that ever happens, the constant moves and nothing else does.
const loaderMinMinor = 20

// loadable reports whether the bundled package loader can drive this release's `go list`.
func (r goRelease) loadable() bool {
	if r.major != 1 {
		// Go 2 does not exist. If it ever does, assume its go command is at least as capable as
		// the floor rather than silently refusing every subject on it.
		return r.major > 1
	}
	return r.minor >= loaderMinMinor
}

// toolchain renders the release as a GOTOOLCHAIN value that names a real downloadable toolchain.
//
// The wrinkle it exists for: Go changed release naming in 1.21. The initial release of a pre-1.21
// minor is "go1.20", NOT "go1.20.0" — there is no golang.org/toolchain module version by the latter
// name, so pinning the canonical three-segment form would ask for a toolchain that cannot exist and
// degrade a perfectly scannable subject to a fallback. From 1.21 on the ".0" IS the release name.
func (r goRelease) toolchain() string {
	if r.patch == 0 && r.major == 1 && r.minor < 21 {
		return fmt.Sprintf("go%d.%d", r.major, r.minor)
	}
	return fmt.Sprintf("go%d.%d.%d", r.major, r.minor, r.patch)
}

// runGovulncheck performs one govulncheck run under env and returns the findings for req.VulnID.
// A govulncheck FAILURE (build broke, non-zero exit, timeout) is a HARD error (inv.4) — never a
// silent empty result; only the caller may decide that a failure under a switched toolchain is
// retryable.
func runGovulncheck(ctx context.Context, req plugin.ReachabilityRequest, env []string) ([]vulnFinding, error) {
	var stdout, stderr bytes.Buffer
	cmd := scan.Command(ctx, "-C", req.BuildDir, "-json", "-mode=source", "-scan=symbol", "./...")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("govulncheck start (%q): %w", req.BuildDir, err)
	}
	if err := cmd.Wait(); err != nil {
		// govulncheck signals "vulnerabilities found" via an error with
		// ExitCode()==3, and a clean scan via ExitCode()==0 — both are SUCCESS;
		// the findings are in stdout. Any other ExitCode, or a plain error
		// (build broke, ctx cancelled, DB unreachable), is a HARD failure
		// (inv.4) — never a silent empty result.
		var ec interface{ ExitCode() int }
		if !errors.As(err, &ec) || (ec.ExitCode() != 0 && ec.ExitCode() != 3) {
			return nil, fmt.Errorf("govulncheck failed (%q): %w: %s",
				req.BuildDir, err, strings.TrimSpace(stderr.String()))
		}
	}

	findings, err := parseFindings(stdout.Bytes(), req.VulnID)
	if err != nil {
		return nil, fmt.Errorf("parse govulncheck json: %w", err)
	}
	return findings, nil
}

// --- LOCAL structs for govulncheck's -json stream schema ---
// Field names/tags mirror x/vuln/internal/govulncheck (Message/Finding/Frame)
// verbatim; that package is internal and cannot be imported.

type vulnMessage struct {
	OSV     *vulnOSV     `json:"osv,omitempty"`
	Finding *vulnFinding `json:"finding,omitempty"`
}

type vulnOSV struct {
	ID string `json:"id,omitempty"`
}

type vulnFinding struct {
	OSV   string      `json:"osv,omitempty"`
	Trace []vulnFrame `json:"trace,omitempty"`
}

// vulnFrame mirrors govulncheck's Frame. Per the schema, Finding.Trace is sorted
// starting from the vulnerable symbol (sink) and ending at the entry point — the
// REVERSE of our ingress->sink CallStack order.
type vulnFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version,omitempty"`
	Package  string `json:"package,omitempty"`
	Function string `json:"function,omitempty"`
	Receiver string `json:"receiver,omitempty"`
}

// parseFindings decodes the newline-delimited JSON message stream, keeping only
// symbol-level findings (a Trace whose first/innermost frame carries a function)
// for the requested vulnID. An empty vulnID keeps all findings.
func parseFindings(out []byte, vulnID string) ([]vulnFinding, error) {
	dec := json.NewDecoder(bufio.NewReader(bytes.NewReader(out)))
	var findings []vulnFinding
	for dec.More() {
		var msg vulnMessage
		if err := dec.Decode(&msg); err != nil {
			return nil, err
		}
		f := msg.Finding
		if f == nil {
			continue
		}
		if vulnID != "" && f.OSV != vulnID {
			continue
		}
		findings = append(findings, *f)
	}
	return findings, nil
}

// findingsToStacks converts symbol-level findings to ingress->sink CallStacks.
// A finding's Trace is sink-first, so we reverse it. Module/package-level
// findings (no Function in any frame) carry no symbol trace and are dropped.
func findingsToStacks(findings []vulnFinding) []CallStack {
	var stacks []CallStack
	for _, f := range findings {
		if len(f.Trace) == 0 || f.Trace[0].Function == "" {
			continue
		}
		frames := make([]StackFrame, 0, len(f.Trace))
		// Reverse: govulncheck sink-first -> our ingress-first.
		for i := len(f.Trace) - 1; i >= 0; i-- {
			fr := f.Trace[i]
			if fr.Function == "" {
				continue
			}
			frames = append(frames, StackFrame{
				SCIP:    frameSCIP(fr),
				IsEntry: i == len(f.Trace)-1,
			})
		}
		if len(frames) == 0 {
			continue
		}
		stacks = append(stacks, CallStack{Frames: frames})
	}
	return stacks
}

// frameSCIP emits a SCIP id for a govulncheck frame using the SAME grammar as
// the SCIPString/scipFromPackage emitter (packages.go) so derived traces share
// an identity space with the call graph. Methods carry a Receiver (stripped of
// any pointer marker, matching receiverTypeName); package-level funcs do not.
func frameSCIP(fr vulnFrame) string {
	module := fr.Module
	if module == "" {
		module = "stdlib"
	}
	version := fr.Version
	if version == "" {
		version = "."
	}
	pkgPath := fr.Package
	if pkgPath == "" {
		pkgPath = "."
	}

	desc := fr.Function + "()."
	if fr.Receiver != "" {
		recv := strings.TrimPrefix(fr.Receiver, "*")
		desc = recv + "#" + fr.Function + "()."
	}
	return fmt.Sprintf("scip-go gomod %s %s %s/%s", module, version, pkgPath, desc)
}
