# Network egress and security posture

Relocated from the README's former "Network egress" section (behavior-preserving move; see the
README's [pointer](../README.md#network-egress) for where this fits into a first read).

**Your code and your credentials never leave the runner.** No run mode is offline, though, and it is
worth being precise about what does leave.

A default `baseline` or `pr-inherit` run contacts two public hosts:

- **`proxy.golang.org`** — when it resolves the subject's module graph.
- **`vuln.go.dev`** — the Go analyzer's reachability stage runs govulncheck with no `-db` flag
  (`internal/plugin/goanalysis/reach.go`), so it resolves `golang.org/x/vuln`'s default vulnerability
  database, uncached, on every run. The module paths it looks up are visible to that host.

These are the same fetches `go build` and `govulncheck` perform.

A run configured with `advisory-corpus-repo` (recommended — see the README's
[Scope](../README.md#scope--what-this-does-not-do)) additionally clones that public corpus repository
from **`github.com`** before the scan: unauthenticated (it presents no token), shallow (`--depth 1`)
and sparse (the manifest and record partitions only). It sends the repository coordinates and nothing
about your code.

`cve-watch` adds **`api.osv.dev`**. The scan modes reach OSV only when work-set widening is switched
on explicitly (`-osv-work-set` / `ASSAY_OSV_WORK_SET`, off by default); that query sends package
coordinates — ecosystem, name, version — and nothing else. Enabling subject-toolchain reachability
(`ASSAY_SUBJECT_TOOLCHAIN_REACHABILITY`, also off by default) additionally downloads a Go toolchain
from the module proxy.

What all of these carry is dependency metadata — module paths, versions, package coordinates — never
source, and never analysis results.

Findings do travel to GitHub, by design: the StateStore ref and the publish surfaces write the
`Report` and its projections into **your own** repository, under a token you supply.

Talking to Ferralon is a separate, explicit switch. The Action's `link-to-console` input is the only
control that decides whether a scan contacts Ferralon at all; it defaults to `false`, and on that
default the scan runs fully standalone. See the README's
[self-cleanup / console-link disclosure](../README.md#self-cleanup--console-link-disclosure) for
what that switch does when it is on, including the self-cleanup side effects.
