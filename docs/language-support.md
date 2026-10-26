# Language support

Ferralon Assay analyzes Go, Java, Kotlin, JavaScript/TypeScript, Python and .NET repositories. What each
language supports today, feature by feature and capability group by capability group, with the caveats
that bound it, is in the [language capability matrix](capabilities/README.md). Every language resolves
into the same five verdicts below.

## Verdicts

Every advisory lands as one of five values:

| Verdict | Meaning |
|---|---|
| `reachable_candidate` | A path from an entry point reaches the advisory's symbols. A candidate, not a proof of exploitability. |
| `not_exploitable` | The vulnerable code is provably absent from what your build compiles, or provably unreachable from its entry points. The row names its grounds in `evidence.basis`. |
| `disqualified` | Your resolved version is provably outside the advisory's affected range, or the advisory's package is not in your dependency manifest or ecosystem at all. `evidence.detail` says which. |
| `malicious_package_present` | A known-malicious package resolved to a version the advisory lists as affected. |
| `undetermined` | The scan established nothing about the advisory. `undetermined_reason` says why. Treat it as unassessed, never as safe. |

OpenVEX carries `undetermined` and `reachable_candidate` as `under_investigation`,
`not_exploitable` and `disqualified` as `not_affected`, and `malicious_package_present` as
`affected`. [Reading the Report](operator-guide.md#reading-the-report) covers the grounds behind
`not_exploitable` and the reasons behind `undetermined`.
