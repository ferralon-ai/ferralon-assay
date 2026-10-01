package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/internal/repoconfig"
	"github.com/ferralon-ai/ferralon-assay/report"
)

// envScanWindowSource carries the source the Action's scan-window step reported. When the
// repository config sets no window, a declared policy came from report.ScanWindowViaPolicyInput;
// absent, it counts as that too.
const envScanWindowSource = brand.EnvPrefix + "_SCAN_WINDOW_SOURCE"

// windowSource is one place a scan window can come from. ok=false passes resolution to the next
// source; an error stops it.
type windowSource func() (sw report.ScanWindow, ok bool, err error)

// resolveScanWindow returns the first window a source supplies, in the order given. The order is
// the precedence: the repository's .github/ferralon.yml overrides everything after it. ok=false
// means no source selected a window, and the scan keeps its corpus, if any, as a fact source.
func resolveScanWindow(sources ...windowSource) (sw report.ScanWindow, ok bool, err error) {
	for _, src := range sources {
		sw, ok, err := src()
		if err != nil || ok {
			return sw, ok, err
		}
	}
	return report.ScanWindow{}, false, nil
}

// newScanWindow builds the record for policy chosen via one resolution step.
func newScanWindow(policy, via string) report.ScanWindow {
	return report.ScanWindow{
		Window:      string(repoconfig.WindowForPolicy(policy)),
		Policy:      policy,
		ResolvedVia: via,
		Source:      report.ScanWindowSource{Kind: via},
	}
}

func repoConfigWindow(w repoconfig.Window) windowSource {
	return func() (report.ScanWindow, bool, error) {
		if w == "" {
			return report.ScanWindow{}, false, nil
		}
		return newScanWindow(w.Policy(), report.ScanWindowViaRepoConfig), true, nil
	}
}

func policyInputWindow(policy string) windowSource {
	return func() (report.ScanWindow, bool, error) {
		if policy == "" {
			return report.ScanWindow{}, false, nil
		}
		if !corpusPolicyPattern.MatchString(policy) {
			return report.ScanWindow{}, false, fmt.Errorf("advisory corpus policy %q is not a policy id (lowercase letters, digits, '-')", policy)
		}
		return newScanWindow(policy, report.ScanWindowViaPolicyInput), true, nil
	}
}

// describeScanWindow is the run-log line for a resolved window.
func describeScanWindow(sw report.ScanWindow) string {
	what := "policy " + sw.Policy
	if sw.Window != "" {
		what = fmt.Sprintf("%s (%s)", sw.Window, sw.Policy)
	}
	var from string
	switch sw.ResolvedVia {
	case report.ScanWindowViaRepoConfig:
		from = "from " + repoconfig.DefaultPath + " scan.window"
	case report.ScanWindowViaPolicyInput:
		from = "from the workflow's advisory-corpus-policy"
	case report.ScanWindowViaAPI:
		switch sw.Source.Kind {
		case report.ScanWindowKindCustomer:
			from = "from this repository's Ferralon customer policy"
		case report.ScanWindowKindAncestor:
			from = fmt.Sprintf("from a Ferralon customer policy %d level(s) above this repository's", *sw.Source.Distance)
		default:
			from = "from Ferralon's default policy (no customer sets one)"
		}
	default:
		from = "via " + sw.ResolvedVia
	}
	return fmt.Sprintf("scan window: %s %s", what, from)
}

// runScanWindow runs the `scan-window` command: it resolves the scan window for a checked-out
// repository and prints it as key=value lines (window, policy, source) for a CI step's outputs.
// When nothing selects a window, window and policy are empty and source is
// report.ScanWindowViaNone. When the window came from the Ferralon policy lookup, an api-source
// line carries the lookup's source record for the scan (envScanWindowAPISource).
//
// The lookup runs only for a console-linked run (linkedToConsole) whose release has a Ferralon
// endpoint, and only when .github/ferralon.yml sets no window.
// The Action runs it BEFORE fetching the advisory corpus, because the window decides which policy
// bundle is fetched; the scan itself later checks it ran against that same window
// (scanTimeWindow).
//
// Every printed value is validated first — a window is one of four names and a policy matches
// corpusPolicyPattern — so the lines carry no newline or other content from the repository.
func runScanWindow(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("scan-window", flag.ContinueOnError)
	fs.SetOutput(stderr)
	target := fs.String("target", ".", "checked-out repository whose "+repoconfig.DefaultPath+" is read")
	policy := fs.String("advisory-corpus-policy", "", "the workflow's advisory corpus policy, used when "+repoconfig.DefaultPath+" sets no scan.window")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	root, err := filepath.Abs(*target)
	if err != nil {
		return fmt.Errorf("resolve target: %w", err)
	}
	cfg, warnings, err := repoconfig.Load(root)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		fmt.Fprintf(stderr, "warning: %s: %s\n", repoconfig.DefaultPath, w)
	}
	sources := []windowSource{repoConfigWindow(cfg.Scan.Window)}
	if endpoint := scanWindowEndpoint(resolveEndpoint(linkedToConsole(), os.Getenv(envRunsURL), bakedRunsURL)); endpoint != "" {
		lookup := scanWindowLookup{endpoint: endpoint, token: resolveOIDCToken, log: stderr}
		sources = append(sources, lookup.source(context.Background()))
	}
	sources = append(sources, policyInputWindow(*policy))
	sw, ok, err := resolveScanWindow(sources...)
	if err != nil {
		return err
	}
	if ok {
		fmt.Fprintln(stderr, describeScanWindow(sw))
	} else {
		sw.ResolvedVia = report.ScanWindowViaNone
		fmt.Fprintln(stderr, "scan window: none set; the advisory corpus is a fact source only")
	}
	if _, err := fmt.Fprintf(stdout, "window=%s\npolicy=%s\nsource=%s\n", sw.Window, sw.Policy, sw.ResolvedVia); err != nil {
		return err
	}
	if sw.ResolvedVia == report.ScanWindowViaAPI {
		_, err = fmt.Fprintf(stdout, "api-source=%s\n", encodeAPISource(sw.Source))
	}
	return err
}

// scanTimeWindow records the window a scan runs against and checks it is the one the repository
// asked for. policy is the policy the run declared; repoWindow is the scanned tree's
// .github/ferralon.yml scan.window; sourceHint is envScanWindowSource.
//
// A repository window the declared policy does not match FAILS the run: the corpus on disk was
// selected for some other window, and scanning it would report a window the repository did not
// choose. That covers a workflow that resolved the window without this check (an Action and
// scanner from different releases), a workflow that passes its own corpus, and a CLI run against
// a repository that sets a window. With no declared policy and no repository window there is no
// window to record (nil).
func scanTimeWindow(repoWindow repoconfig.Window, policy, sourceHint, apiSource string) (*report.ScanWindow, error) {
	if repoWindow != "" {
		want := repoWindow.Policy()
		switch policy {
		case want:
			sw := newScanWindow(policy, report.ScanWindowViaRepoConfig)
			return &sw, nil
		case "":
			return nil, fmt.Errorf("%s sets scan.window %s, but this run declares no advisory corpus policy: the window needs the %s policy of an advisory corpus (in the Action, set advisory-corpus-repo)",
				repoconfig.DefaultPath, repoWindow, want)
		default:
			return nil, fmt.Errorf("%s sets scan.window %s (policy %s), but this run's advisory corpus was selected by policy %s: refusing to report a window the repository did not choose",
				repoconfig.DefaultPath, repoWindow, want, policy)
		}
	}
	if policy == "" {
		return nil, nil
	}
	// One arm per source the Action's scan-window step can report after the repository config. A
	// source inserted into that resolution needs an arm here too, or its runs fail closed.
	switch sourceHint {
	case "", report.ScanWindowViaPolicyInput:
		sw := newScanWindow(policy, report.ScanWindowViaPolicyInput)
		return &sw, nil
	case report.ScanWindowViaAPI:
		if repoconfig.WindowForPolicy(policy) == "" {
			return nil, fmt.Errorf("%s=%s, but the declared policy %s is not a scan window policy", envScanWindowSource, sourceHint, policy)
		}
		src, err := decodeAPISource(apiSource)
		if err != nil {
			return nil, err
		}
		sw := newScanWindow(policy, report.ScanWindowViaAPI)
		sw.Source = src
		return &sw, nil
	default:
		return nil, fmt.Errorf("%s=%q does not name a source for declared policy %s (want %s or %s)", envScanWindowSource, sourceHint, policy, report.ScanWindowViaPolicyInput, report.ScanWindowViaAPI)
	}
}

// recordScanWindow resolves the scan-time window onto f and logs it.
func (f *runFlags) recordScanWindow(policy string) error {
	sw, err := scanTimeWindow(f.repoWindow, policy, os.Getenv(envScanWindowSource), os.Getenv(envScanWindowAPISource))
	if err != nil {
		return err
	}
	f.resolvedWindow = sw
	if sw != nil {
		fmt.Fprintln(os.Stdout, describeScanWindow(*sw))
	}
	return nil
}
