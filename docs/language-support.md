# Language support

Ferralon Assay analyzes Go, Java, Kotlin, JavaScript/TypeScript, Python and .NET repositories. What each
language supports today, feature by feature and capability group by capability group, with the caveats
that bound it, is in the [language capability matrix](capabilities/README.md). Every language resolves
into the same five verdicts below.

C/C++ is not in the scanner release asset, which ships no C/C++ analyzer. A scan of a C/C++ tree on
the release publishes a Report with no findings and one `did_not_run` note saying C/C++ was not
analyzed and naming the missing analyzer, and the run exits 0: the host lacks an analyzer, the
repository is not at fault. The job summary and the PR comment lead with "Not analyzed", so the Report
never reads as clean. With a C/C++ analyzer you installed yourself from a source build, the scan
runs like any other language: given no corpus policy it stops at the no-work gate and fails, and
given one it publishes whatever the corpus holds for the tree's dependencies.

A missing analyzer for a language the release does ship is an install fault, not an unsupported
language: the run fails and publishes nothing, so the previous results stay in place.

## Verdicts

Every advisory lands as one of five values. The job summary, PR comment and HTML report show a plain-words label with the raw name beside it; the JSON, SARIF and exit codes keep the raw names.

| Verdict (as the report shows it) | Meaning |
|---|---|
| Call path found (`reachable_candidate`) | A path from an entry point reaches the advisory's symbols. A candidate, not a proof of exploitability. |
| Exposure ruled out for this scan scope (`not_exploitable`) | The vulnerable code is provably absent from what your build compiles, or provably unreachable from its entry points. The row names its grounds in `evidence.basis`. |
| Outside the affected range (`disqualified`) | Your resolved version is provably outside the advisory's affected range, or the advisory's package is not in your dependency manifest or ecosystem at all, or the advisory is against your own project, which carries no version tag, and the commit the advisory names as its fix is in the scanned commit's history. That last route needs the full history in the checkout (`fetch-depth: 0` in GitHub Actions); in a shallow checkout the row stays `undetermined`. `evidence.detail` says which. |
| Malicious package present (`malicious_package_present`) | A known-malicious package resolved to a version the advisory lists as affected. |
| Exposure assessment incomplete (`undetermined`) | The scan established nothing about the advisory. `undetermined_reason` says why. Treat it as unassessed, never as safe. |

OpenVEX carries `undetermined` and `reachable_candidate` as `under_investigation`,
`not_exploitable` and `disqualified` as `not_affected`, and `malicious_package_present` as
`affected`. [Reading the Report](operator-guide.md#reading-the-report) covers the grounds behind
`not_exploitable` and the reasons behind `undetermined`.
