# Language support

Point Ferralon Assay at a Go, Java, JavaScript, Python or .NET repository and every one gets the same
core scan: dependency versions resolved into an SBOM, advisories disqualified when your pinned version
is provably outside their affected range, and a full `Report` in every format (`report.json`,
`report.html`, `report.sarif.json`, `openvex.json`). Reachability analysis runs deepest in Go and
reaches outward across the others over one shared protocol. Use the matrix to reason about fit.

## Fit at a glance

| Capability | Go | Java | JavaScript | Python | .NET |
|---|:-:|:-:|:-:|:-:|:-:|
| Scan → dependency SBOM | ✓ | ✓ | ✓ | ✓ | ✓ |
| Version-range disqualification | ✓ | ✓ | ✓ | ✓ | ✓ |
| Every `Report` format | ✓ | ✓ | ✓ | ✓ | ✓ |
| First-party-sink reachability | ✓ | ✓ | ✓ | ✓ | ✓ |
| Dependency-level call-graph reachability | ✓ | growing | growing | growing | growing |

Every language resolves versions, disqualifies by range, and emits every `Report` format — that is the
shared floor. Go adds the deepest reachability: it maps advisory symbols into dependency code, builds
the call graph, and computes reachability from framework entry points to the named symbols. The four
others run that same subprocess call-graph protocol for first-party sinks today; extending it into
dependency code is the direction the `LanguagePlugin` contract is built to grow.

## The three-valued verdict

Every advisory lands as one of three values: `reachable_candidate` (symbols reachable from an entry
point), `disqualified` (your version provably excludes it), or `undetermined` (reachability could not
be soundly established). For the four non-Go languages, a dependency advisory that survives version
disqualification is reported `undetermined` (`analysis_did_not_run`) — "we could not establish this" is
a deliberately different claim from "not exploitable," and Assay never makes the second when nothing
searched it. OpenVEX carries the same finding as `under_investigation`.
