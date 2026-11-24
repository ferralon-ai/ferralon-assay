## Ferralon Assay

**Coverage: partial — the scan did not complete.** Advisories it did not finish are shown as exposure assessment incomplete, never as clear. Fix the scan and run it again.

**Repository:** `github.com/example/widget`  
**Commit:** `abc123`  
**Analyzer:** `v0.2.0`  

**1 call path(s) found** — review below. (1 exposure ruled out for this scan scope, 1 outside the affected range, 6 exposure assessment incomplete.) This run is not a complete assessment of the codebase.

| Result | Count | Next action |
|---|---:|---|
| Call path found (`reachable_candidate`) | 1 | Review the evidence, and the fix PR when available. |
| Exposure ruled out for this scan scope (`not_exploitable`) | 1 | Defer, with the reason given. Recheck when relevant code, dependencies or configuration change. |
| Outside the affected range (`disqualified`) | 1 | Close this advisory for this component version. |
| Exposure assessment incomplete (`undetermined`) | 6 | Route by cause: repair a failed scan, provide missing build context, or keep for review. |

**Exposure assessment incomplete, by cause**

| Cause | Advisories | Next action | Reason codes |
|---|---:|---|---|
| Scan didn't complete | 2 | Fix the scan (a tool failed, ran out of time or could not read dependencies), then run it again. | `scan_cut_short` ×2 |
| Missing build context | 1 | Provide the missing build context (a build graph, a lockfile or pinned versions), then run the scan again. | `package_version_unresolved` ×1 |
| Engine can't decide yet | 1 | Keep for review: the analysis ran but cannot rule this advisory in or out yet. | `refutation_withheld` ×1 |
| Depends on toolchain or configuration | 1 | Unless it is already declared, declare the exact Go release your repository builds with (Action input subject-go-version, CLI -subject-go-version), then run the scan again. | `go_toolchain_not_scanned` ×1 |
| Other (needs review) | 1 | Needs review: this reason code is not grouped yet. | `some_new_reason` ×1 |

### Call path found

These advisories have a call path to the vulnerable code. A call path is **not** a proof of exploitability: proving it requires observing the path execute, which this scan does not do.

| Advisory | Package | Call path |
|---|---|---|
| `CVE-2023-0001` | `golang.org/x/text@v0.3.6` | net/http.Handler → text.Vuln |


--- annotations ---
::warning file=go.mod::CVE-2023-0001 (golang.org/x/text@v0.3.6): call path found (reachable_candidate) — net/http.Handler → text.Vuln. A candidate for exploitability, not a proof. Review the evidence, and the fix PR when available.
