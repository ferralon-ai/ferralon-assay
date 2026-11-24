package trigger

// ownAdvisoryPartialRunDetail is the detail of a row pipeline.OwnAdvisoryHeldForPartialRun holds.
const ownAdvisoryPartialRunDetail = "This advisory is on the scanned module itself. The module's own version could not be established, and the analysis searched only part of the build, so the advisory is not judged from that partial run. A Go module's release version is read from a full semver tag on the checked-out commit itself (prefixed with the module's directory for a nested module), so an untagged commit has none."
