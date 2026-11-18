package plugin

// PartialReasonPartialRunUnversioned: the lane answered from a run that searched only part of the
// build, for an advisory the request named no versioned package of (ReachabilityRequest.Package is
// empty). Nothing then places the code the run left out, or the code it searched, against the
// advisory's affected range. A lane declares it on that advisory's result only, and only when its
// run left part of the build out.
const PartialReasonPartialRunUnversioned = PartialReasonToolFailure + ":partial_run_unversioned"
