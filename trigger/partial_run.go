package trigger

// ownAdvisoryPartialRunDetail is the detail of a row pipeline.OwnAdvisoryHeldForPartialRun holds.
const ownAdvisoryPartialRunDetail = "This advisory is on the scanned module itself. The module's own version could not be established, and the analysis searched only part of the build, so the advisory is not judged from that partial run. A Go module's release version is read from a full semver tag on the checked-out commit itself (prefixed with the module's directory for a nested module), so an untagged commit has none."

// ownReleaseCandidateDetail is the detail of a reachable candidate on the scanned project's own
// code whose release version was not established (ownReleaseUnversioned).
const ownReleaseCandidateDetail = "This advisory is on this repository's own code, and the release version of this checkout could not be established, so the path is reported without placing the checkout inside or outside the advisory's affected versions. A Go module's release version is read from a full semver tag on the checked-out commit itself (prefixed with the module's directory for a nested module), so an untagged commit has none."
