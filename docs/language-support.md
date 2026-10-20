# Language support

Point Ferralon Assay at a Go, Java, Kotlin, JavaScript, Python or .NET repository and every one gets
the same core scan: dependency versions resolved into an SBOM, advisories disqualified when your
pinned version is provably outside their affected range, and a full `Report` in every format
(`report.json`, `report.html`, `report.sarif.json`, `openvex.json`). Reachability analysis runs
deepest in Go and reaches outward across the others over one shared protocol. Use the matrix to
reason about fit.

## Fit at a glance

| Capability | Go | Java | Kotlin | JavaScript | Python | .NET |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| Scan → dependency SBOM | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Version-range disqualification | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Every `Report` format | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| First-party-sink reachability | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| Reachability into dependencies | dependency source | dependency JARs | dependency JARs | call edge to the dependency boundary | call edge to the dependency boundary | NuGet assemblies |

Every language resolves versions, disqualifies by range, and emits every `Report` format — that is the
shared floor. Go adds the deepest reachability: it maps advisory symbols into dependency source,
builds the call graph, and computes reachability from framework entry points to the named symbols.
Java and Kotlin search the compiled program and its dependency JARs. .NET resolves advisory symbols
inside the restored NuGet assemblies for the build's target. Python and JavaScript bind imports to
the packages that provide them and trace first-party calls to the dependency boundary.

C/C++ is not in the scanner release asset. A scan of a C/C++ tree stops at the empty-work-set gate and
fails the run, so it never publishes a Report that reads as clean.

## Verdicts

Every advisory lands as one of five values:

| Verdict | Meaning |
|---|---|
| `reachable_candidate` | A path from an entry point reaches the advisory's symbols. A candidate, not a proof of exploitability. |
| `not_exploitable` | The package is present, and the vulnerable code is provably absent or unreachable. The row names its grounds in `evidence.basis`. |
| `disqualified` | Your resolved version is provably outside the advisory's affected range. |
| `malicious_package_present` | A known-malicious package resolved to a version the advisory lists as affected. |
| `undetermined` | The scan established nothing about the advisory. `undetermined_reason` says why. Treat it as unassessed, never as safe. |

OpenVEX carries `undetermined` and `reachable_candidate` as `under_investigation`,
`not_exploitable` and `disqualified` as `not_affected`, and `malicious_package_present` as
`affected`. [Reading the Report](operator-guide.md#reading-the-report) covers the grounds behind
`not_exploitable` and the reasons behind `undetermined`.
