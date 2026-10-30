package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/ferralon-ai/ferralon-assay/checkout"
	"github.com/ferralon-ai/ferralon-assay/internal/brand"
	"github.com/ferralon-ai/ferralon-assay/plugin"
	"github.com/ferralon-ai/ferralon-assay/report"
	"github.com/ferralon-ai/ferralon-assay/statestore"
	"github.com/ferralon-ai/ferralon-assay/trigger"
)

// languageLabels names each detected source language the way a reader knows it.
var languageLabels = map[string]string{
	checkout.LangGo:      "Go",
	checkout.LangJava:    "Java",
	checkout.LangKotlin:  "Kotlin",
	checkout.LangJS:      "JavaScript/TypeScript",
	checkout.LangPython:  "Python",
	checkout.LangDotNet:  ".NET",
	checkout.LangCFamily: "C/C++",
}

// languageLabel returns the reader's name for a detected language, or the code itself when it has
// none.
func languageLabel(language string) string {
	if l, ok := languageLabels[language]; ok {
		return l
	}
	return language
}

// analyzerMissingDetail is the one sentence the Report, the run log and the workflow annotation
// all carry for a language whose analyzer is not installed: the language, by name and code, and
// the plugin executable that was looked for.
func analyzerMissingDetail(language, binary string) string {
	return fmt.Sprintf("no analyzer for the detected %s (%s) source is installed: %s is not on PATH, so nothing was assessed",
		languageLabel(language), language, binary)
}

// analyzerMissingReport is the Report for a scan that could not analyze anything because the
// detected language's analyzer plugin is not installed. It has no SBOM and no findings, and one
// partiality note, no_language_plugin, which ClassifyPartialityReason puts in the did_not_run arm:
// every surface qualifies its headline with it, so the empty Report is never read as an all-clear.
// revision and commit are the -revision / -commit labels; an analyze.ref redirect replaces them as
// it does on a scanned Report.
func analyzerMissingReport(e *analyzerMissingError, revision, commit string) (*report.Report, error) {
	revision, commit = e.acq.provenance(revision, commit)
	rep, err := report.NewBuilder(report.Subject{Repo: e.acq.repo, Revision: revision, ResolvedCommit: commit}).
		AddPartiality(report.PartialityNote{
			Reason: plugin.PartialReasonNoPlugin,
			Detail: analyzerMissingDetail(e.acq.language, e.missing.Binary),
		}).
		WithProvenance(report.Provenance{AnalyzerVersion: trigger.AnalyzerVersion, Timestamp: time.Now().UTC()}).
		BuildValidated()
	if err != nil {
		return nil, fmt.Errorf("build report: %w", err)
	}
	return &rep, nil
}

// publishAnalyzerMissing ends a run whose detected language is outside the release and has no
// analyzer installed. It publishes analyzerMissingReport through the same sinks as a scan, so the job
// summary, the PR comment and the output directory all say the language was not analyzed, annotates
// the workflow run, and returns nil: the run exits 0. The host lacks a plugin; the scan did not fail,
// and a red check would read as a fault in the repository.
//
// Nothing reaches the work set, so the empty-work-set gate never runs, and no SBOM or baseline is
// written to the StateStore: a later run with the plugin installed starts clean. The scan-truncated
// output is set false, as on every path that published a Report, and the self-cleanup revoke check
// runs as it does after every scan (analyzerMissingRevokeCheck).
func (f *runFlags) publishAnalyzerMissing(ctx context.Context, mode string, e *analyzerMissingError) error {
	rep, err := analyzerMissingReport(e, *f.revision, *f.commit)
	if err != nil {
		return err
	}
	detail := analyzerMissingDetail(e.acq.language, e.missing.Binary)
	fmt.Fprintf(os.Stderr, "::warning title=%s::%s\n", brand.Name, escapeWorkflowData(detail))
	fmt.Fprintf(os.Stdout, "%s %s — %s\n", brand.Name, mode, detail)
	// No work set was chosen and no advisory fact was looked up: the built-in floor and table are
	// what the run starts from, and it stopped there.
	intel := report.IntelProvenance{WorkSetSource: report.WorkSetBuiltinLanguageSet, FactSource: report.FactSourceBuiltinTable}
	// Nothing was cut short: the Report is complete in what it says.
	writeScanTruncated(false, os.Stderr)
	if err := publishResult(ctx, *f.outDir, rep, intel, e.acq.analyzeRef, nil, nil); err != nil {
		return err
	}
	printSummary(*f.outDir, rep, "none: nothing was assessed")
	f.analyzerMissingRevokeCheck(ctx, mode, trigger.Subject{Repo: rep.Subject.Repo, Revision: rep.Subject.Revision, ResolvedCommit: rep.Subject.ResolvedCommit})
	return nil
}

// analyzerMissingRevokeCheck runs postScan's revoke check for a run that published an analyzer-missing
// Report. An uninstall must be detected even when nothing was assessed, or a console-linked
// repository whose language has no analyzer would never reach it. The check needs the StateStore the
// mode would have used, so it opens it only when the run is linked to a console; failing to open it
// is logged and skipped, never fatal, as postScan itself is.
func (f *runFlags) analyzerMissingRevokeCheck(ctx context.Context, mode string, subject trigger.Subject) {
	if !revokeCheckLinked() {
		return
	}
	var (
		store   statestore.StateStore
		cleanup = func() {}
		err     error
	)
	if mode == "baseline" {
		store, cleanup, err = baselineStore(f.sf)
	} else {
		store, err = f.sf.resolve()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "  self-cleanup: no state store, skipping: %v\n", err)
		return
	}
	defer cleanup()
	postScan(ctx, store, subject, rescanFromEnv())
}
