## Ferralon Assay

**Coverage: partial — the scan did not complete.** Advisories it did not finish are shown as exposure assessment incomplete, never as clear. Fix the scan and run it again.

**Repository:** `github.com/example/widget`  
**Commit:** `abc123`  
**Analyzer:** `v0.2.0`  

**Partial coverage — no call path found in what was assessed.** 1 advisory finding(s) are closed (1 exposure ruled out for this scan scope, 0 outside the affected range, 2 exposure assessment incomplete). The scan was cut short before every advisory was assessed; see below for how to give it more time.

**Partial coverage.** This scan could not fully resolve the codebase:

- The scan was cut short before it finished (`2 of 3 advisories were not assessed: the scan reached its 30m time limit`). Every advisory it did not assess has no verdict and is counted as not assessed.

| Result | Count | Next action |
|---|---:|---|
| Call path found (`reachable_candidate`) | 0 | Review the evidence, and the fix PR when available. |
| Exposure ruled out for this scan scope (`not_exploitable`) | 1 | Defer, with the reason given. Recheck when relevant code, dependencies or configuration change. |
| Outside the affected range (`disqualified`) | 0 | Close this advisory for this component version. |
| Exposure assessment incomplete (`undetermined`) | 2 | Route by cause: repair a failed scan, provide missing build context, or keep for review. |

**Exposure assessment incomplete, by cause**

| Cause | Advisories | Next action | Reason codes |
|---|---:|---|---|
| Scan didn't complete | 2 | Fix the scan (a tool failed, ran out of time or could not read dependencies), then run it again. | `scan_cut_short` ×2 |


--- annotations ---
