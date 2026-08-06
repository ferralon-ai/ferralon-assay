// Command ferralon-assay is the entrypoint for the ferralon-assay OSS CI scanner.
//
// It runs the deterministic Assess pipeline (S1–S6) over a target repository and emits a
// neutral scan Report plus its host-agnostic projections (OpenVEX, SARIF, a self-contained HTML
// report). The Prove stages (live confirmation, the tiered GitHub ResultSink, the living-verdict
// Case) are NOT reachable from this binary — depguard and the keystone linker-
// reachability gate enforce that nothing under github.com/ferralon-ai/tegron is imported here.
//
// The run modes are `baseline` (a full S1–S6 scan of every known advisory against the target),
// `pr-inherit` (diff a PR head SBOM vs the stored baseline) and `cve-watch` (scheduled OSV.dev
// watch). All three select a StateStore the same way: -git-dir / -repo seed and read the persistent
// refs/assay/state, so a baseline can seed the ref a later pr-inherit / cve-watch inherits from.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"github.com/ferralon-ai/ferralon-assay/assessment"
	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/resultsink"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/telemetry"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// version is the build identity printed by the `version` subcommand and the help
// banner. It is NOT independently stampable: it reads brand.Version, which is what
// the release cut's -ldflags -X patches, and which brand.AnalyzerVersion() also
// derives the report/SARIF provenance string from. One symbol, so `version` output
// and a report's analyzer_version can never name different builds. Do not restore a
// stampable `main.version` here.
var version = brand.Version

func main() {
	os.Exit(run())
}

// run is the real entrypoint, split from main so a deferred telemetry Shutdown flush runs on
// every exit path. The command switch returns an exit code instead of calling os.Exit
// directly — os.Exit skips deferred functions, which would drop the final metric flush on a
// short-lived CLI invocation.
func run() int {
	// Telemetry foundation. No-ops cleanly when OTEL_EXPORTER_OTLP_ENDPOINT
	// is unset — the common local-scan case — so a CLI run never blocks on a collector. Init
	// failure is non-fatal: telemetry must never break a scan.
	tel, err := telemetry.New(context.Background(), telemetry.Config{
		ServiceName:    brand.Name + "-cli",
		ServiceVersion: version,
		Component:      "assess",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, brand.Name+" telemetry init (continuing without telemetry):", err)
	} else {
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tel.Shutdown(ctx)
		}()
	}

	if len(os.Args) < 2 {
		usage()
		return 2
	}
	switch os.Args[1] {
	case "baseline":
		if err := runBaseline(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, brand.Name+" baseline:", err)
			return 1
		}
	case "pr-inherit":
		if err := runPRInherit(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, brand.Name+" pr-inherit:", err)
			return 1
		}
	case "cve-watch":
		if err := runCVEWatch(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, brand.Name+" cve-watch:", err)
			return 1
		}
	case "state":
		if err := runState(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, brand.Name+" state:", err)
			return 1
		}
	case "version", "-version", "--version":
		fmt.Fprintf(os.Stdout, "%s %s\n", brand.Name, version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown command %q\n\n", brand.Name, os.Args[1])
		usage()
		return 2
	}
	return 0
}

func usage() {
	n := brand.Name
	fmt.Fprintf(os.Stdout, `%[1]s %[2]s — %[3]s

Usage:
  %[1]s baseline   [flags]   run a full S1–S6 baseline scan, write Report + projections
  %[1]s pr-inherit [flags]   diff a PR head SBOM vs the stored baseline; inherit or re-analyze
  %[1]s cve-watch  [flags]   scheduled OSV.dev watch; heartbeat or earnest re-analysis
  %[1]s state <op> [flags]   operator views of the persisted StateStore ref (show | export)
  %[1]s version              print the build identity
  %[1]s help                 show this help

The sink set is env-driven: every run always writes the local output dir; inside GitHub
Actions it also publishes the Tier-0 job summary, and (with a write token) the Tier-1
SARIF / sticky PR comment / pinned Issue surfaces; Tier-2 Pages activates only with
%[4]s_PAGES=1. A forked PR (read-only token) publishes only Tier-0 + local.

Run "%[1]s baseline -h" for the baseline flags.
Run "%[1]s pr-inherit -h" / "%[1]s cve-watch -h" for the run-mode flags.
Run "%[1]s state help" for the state subcommands.
`, n, version, brand.Tagline, brand.EnvPrefix)
}

func runBaseline(args []string) error {
	// Baseline shares the run modes' flag surface: -subject-repo for the Report identity and the
	// StateStore-selection flags (-git-dir / -repo / -token / -api-url / -ref) for persistence, so
	// `baseline` can seed the same refs/assay/state that pr-inherit / cve-watch later read.
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	f := registerRunFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx := context.Background()

	acq, err := acquireTarget(ctx, *f.target, *f.revision, *f.repo, *f.plugin, *f.houseCanaries)
	if err != nil {
		return err
	}
	defer acq.cleanup()

	store, cleanup, err := baselineStore(f.sf)
	if err != nil {
		return err
	}
	defer cleanup()

	assessOptions := []pipeline.AssessOption{pipeline.WithPlugin(acq.plugin)}
	if opt, err := f.advisoryCorpusOption(); err != nil {
		return err
	} else if opt != nil {
		assessOptions = append(assessOptions, opt)
	}

	// Widen the compiled-in language floor with the advisories OSV.dev reports against this
	// repository's real dependencies. Resolved AFTER advisoryCorpusOption, which decides the fact
	// source the widener admits against. Never fails: an unreachable OSV degrades to the floor and
	// says so on the Report (workset.go).
	ws, err := f.scanWorkSet(ctx, acq)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "%s baseline — work set: %s\n", brand.Name, ws.describe())

	req := trigger.BaselineRequest{
		Subject: trigger.Subject{Repo: acq.repo, Revision: *f.revision, ResolvedCommit: *f.commit},
		Codebase: assessment.CodebaseRef{
			Repo:        acq.repo,
			Revision:    *f.revision,
			Acquisition: assessment.Acquisition{Mode: "vendored_repro", Path: acq.buildDir},
		},
		Advisories:    ws.advisories,
		WorkSetLimits: ws.partiality,
		AssessOptions: assessOptions,
	}

	rep, err := trigger.RunBaseline(ctx, store, req)
	if err != nil {
		return err
	}

	rescan := rescanFromEnv()
	if err := publishResult(ctx, *f.outDir, rep, f.intelProvenance(ws)); err != nil {
		return err
	}

	printSummary(*f.outDir, rep)
	printRescanContext(rescan)
	postScan(ctx, store, req.Subject, rescan)
	return nil
}

// baselineStore resolves the StateStore the baseline writes to. When an operator selects a store
// (-git-dir or -repo), the baseline persists to it — seeding refs/assay/state so a later
// pr-inherit / cve-watch can read it. When NEITHER is given, it falls back to a throwaway local
// git-ref store in a temp bare repo: baseline still needs *a* store to Read/Write against, and this
// preserves the zero-config local-scan path (no persistence, and no OSV query unless the work-set
// widening is explicitly switched on — see osvWorkSetDefault; the scan itself still contacts
// proxy.golang.org and vuln.go.dev). The returned cleanup removes the temp store (a no-op for an
// operator-selected store).
func baselineStore(sf *stateStoreFlags) (statestore.StateStore, func(), error) {
	if *sf.gitDir != "" || *sf.repo != "" {
		store, err := sf.resolve()
		if err != nil {
			return nil, func() {}, err
		}
		return store, func() {}, nil
	}

	stateDir, err := os.MkdirTemp("", brand.Name+"-state-")
	if err != nil {
		return nil, func() {}, fmt.Errorf("create state dir: %w", err)
	}
	if err := gitInitBare(stateDir); err != nil {
		os.RemoveAll(stateDir)
		return nil, func() {}, err
	}
	store := statestore.NewGitRefStore(statestore.Config{GitDir: stateDir})
	return store, func() { os.RemoveAll(stateDir) }, nil
}

func printSummary(outDir string, rep *report.Report) {
	counts := map[report.Verdict]int{}
	for _, f := range rep.Advisories {
		counts[f.Verdict]++
	}
	abs, _ := filepath.Abs(outDir)
	fmt.Fprintf(os.Stdout, "%s baseline complete\n", brand.Name)
	fmt.Fprintf(os.Stdout, "  subject:    %s@%s\n", rep.Subject.Repo, rep.Subject.Revision)
	fmt.Fprintf(os.Stdout, "  SBOM:       %d package(s)\n", len(rep.SBOM.Packages))
	for _, p := range rep.SBOM.Packages {
		fmt.Fprintf(os.Stdout, "    - %s %s %s\n", p.Ecosystem, p.Name, p.Version)
	}
	fmt.Fprintf(os.Stdout, "  findings:   %d advisory finding(s)\n", len(rep.Advisories))
	for _, v := range sortedVerdicts(counts) {
		fmt.Fprintf(os.Stdout, "    - %-20s %d\n", v, counts[v])
	}
	fmt.Fprintf(os.Stdout, "  written to: %s\n", abs)
	for _, name := range []string{resultsink.FileReportJSON, resultsink.FileReportHTML, resultsink.FileSARIF, resultsink.FileOpenVEX} {
		fmt.Fprintf(os.Stdout, "    - %s\n", filepath.Join(abs, name))
	}
}

func sortedVerdicts(counts map[report.Verdict]int) []report.Verdict {
	vs := make([]report.Verdict, 0, len(counts))
	for v := range counts {
		vs = append(vs, v)
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i] < vs[j] })
	return vs
}

// gitInitBare initializes a bare git repo at dir to hold the StateStore's state ref. It uses
// GIT_CONFIG_NOSYSTEM to stay independent of any host git config.
func gitInitBare(dir string) error {
	cmd := exec.Command("git", "-C", dir, "init", "--bare", "-q")
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git init bare state store: %v: %s", err, out)
	}
	return nil
}
