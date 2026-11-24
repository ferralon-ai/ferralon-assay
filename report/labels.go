package report

import "strings"

// Technician-facing wording for the verdicts, for the surfaces a person reads (the job summary, the
// PR comment, the HTML report). It is presentation only: the Verdict values, the JSON, the SARIF
// levels and the exit codes keep the raw names, and every human surface shows the raw name beside the
// label so a reader can map one to the other.

// VerdictLabel is the technician-facing name of a verdict, or the raw value for one with no label.
func VerdictLabel(v Verdict) string {
	switch v {
	case VerdictReachableCandidate:
		return "Call path found"
	case VerdictNotExploitable:
		return "Exposure ruled out for this scan scope"
	case VerdictDisqualified:
		return "Outside the affected range"
	case VerdictUndetermined:
		return "Exposure assessment incomplete"
	case VerdictMaliciousPresent:
		return "Malicious package present"
	}
	return string(v)
}

// VerdictLabelWithCode is VerdictLabel followed by the raw verdict in a code span.
func VerdictLabelWithCode(v Verdict) string {
	return VerdictLabel(v) + " (`" + string(v) + "`)"
}

// VerdictNextAction is the one next step shown for a verdict, or "" for one with none.
func VerdictNextAction(v Verdict) string {
	switch v {
	case VerdictReachableCandidate:
		return "Review the evidence, and the fix PR when available."
	case VerdictNotExploitable:
		return "Defer, with the reason given. Recheck when relevant code, dependencies or configuration change."
	case VerdictDisqualified:
		return "Close this advisory for this component version."
	case VerdictUndetermined:
		return "Route by cause: repair a failed scan, provide missing build context, or keep for review."
	}
	return ""
}

// UndeterminedCause is one group of undetermined reason codes that share a next action.
type UndeterminedCause string

const (
	CauseScanIncomplete  UndeterminedCause = "scan_incomplete"
	CauseMissingContext  UndeterminedCause = "missing_build_context"
	CauseEngineUndecided UndeterminedCause = "engine_cannot_decide"
	CauseToolchainConfig UndeterminedCause = "toolchain_or_configuration"
	CauseOther           UndeterminedCause = "other"
)

// UndeterminedCauses lists the groups in the order surfaces render them.
var UndeterminedCauses = []UndeterminedCause{CauseScanIncomplete, CauseMissingContext, CauseEngineUndecided, CauseToolchainConfig, CauseOther}

// Title is the plain-words name of the group.
func (c UndeterminedCause) Title() string {
	switch c {
	case CauseScanIncomplete:
		return "Scan didn't complete"
	case CauseMissingContext:
		return "Missing build context"
	case CauseEngineUndecided:
		return "Engine can't decide yet"
	case CauseToolchainConfig:
		return "Depends on toolchain or configuration"
	}
	return "Other (needs review)"
}

// NextAction is the one plain next step for the group.
func (c UndeterminedCause) NextAction() string {
	switch c {
	case CauseScanIncomplete:
		return "Fix the scan (a tool failed, ran out of time or could not read dependencies), then run it again."
	case CauseMissingContext:
		return "Provide the missing build context (a build graph, a lockfile or pinned versions), then run the scan again."
	case CauseEngineUndecided:
		return "Keep for review: the analysis ran but cannot rule this advisory in or out yet."
	case CauseToolchainConfig:
		return "Declare the exact Go release your repository builds with (Action input subject-go-version, CLI -subject-go-version), then run the scan again."
	}
	return "Needs review: this reason code is not grouped yet."
}

// CauseOfReason groups an undetermined reason code. A code that fits no group is CauseOther, and
// surfaces show its raw code.
func CauseOfReason(reason string) UndeterminedCause {
	switch reason {
	case ReasonScanCutShort, ReasonDependencyNotFetched:
		return CauseScanIncomplete
	case ReasonPackageVersionUnresolved, ReasonAnalysisDidNotRun, ReasonBuildContextNotCompared:
		return CauseMissingContext
	case ReasonAdvisoryUnknownToAnalyzer, ReasonRefutationWithheld, ReasonAdvisorySymbolAbsent,
		ReasonVulnerableSymbolUnresolved, ReasonAdvisorySymbolsUnvetted, ReasonAdvisoryRangeAbsent:
		return CauseEngineUndecided
	case ReasonGoToolchainUnresolved, ReasonGoToolchainNotScanned:
		return CauseToolchainConfig
	}
	if reason == "tool_failure" || strings.HasPrefix(reason, "tool_failure:") {
		return CauseScanIncomplete
	}
	return CauseOther
}
