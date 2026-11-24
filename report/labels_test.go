package report

import "testing"

func TestCauseOfReason(t *testing.T) {
	for reason, want := range map[string]UndeterminedCause{
		ReasonScanCutShort:               CauseScanIncomplete,
		ReasonDependencyNotFetched:       CauseScanIncomplete,
		"tool_failure:inventory_failed":  CauseScanIncomplete,
		ReasonPackageVersionUnresolved:   CauseMissingContext,
		ReasonOwnReleaseVersionUnknown:   CauseMissingContext,
		ReasonAnalysisDidNotRun:          CauseMissingContext,
		ReasonBuildContextNotCompared:    CauseMissingContext,
		ReasonAdvisoryUnknownToAnalyzer:  CauseEngineUndecided,
		ReasonRefutationWithheld:         CauseEngineUndecided,
		ReasonAdvisorySymbolAbsent:       CauseEngineUndecided,
		ReasonVulnerableSymbolUnresolved: CauseEngineUndecided,
		ReasonAdvisorySymbolsUnvetted:    CauseEngineUndecided,
		ReasonAdvisoryRangeAbsent:        CauseEngineUndecided,
		ReasonGoToolchainUnresolved:      CauseToolchainConfig,
		ReasonGoToolchainNotScanned:      CauseToolchainConfig,
		ReasonUnspecifiedLimit:           CauseOther,
		"never_seen_before":              CauseOther,
	} {
		if got := CauseOfReason(reason); got != want {
			t.Errorf("CauseOfReason(%q) = %q, want %q", reason, got, want)
		}
	}
}
