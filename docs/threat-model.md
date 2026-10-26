# Network egress and security posture

See also the README's [Network egress](../README.md#network-egress) summary.

**Your code and your credentials never leave the runner.** No run mode is offline, though, and it is
worth being precise about what does leave.

A default `baseline` or `pr-inherit` run contacts two public hosts:

- **`proxy.golang.org`** — when it resolves the subject's module graph.
- **`vuln.go.dev`** — the Go analyzer's reachability stage runs govulncheck with no `-db` flag
  (`internal/plugin/goanalysis/reach.go`), so it resolves `golang.org/x/vuln`'s default vulnerability
  database, uncached, on every run. The module paths it looks up are visible to that host.

These are the same fetches `go build` and `govulncheck` perform.

A run configured with `advisory-corpus-repo` (recommended — see the README's
[Advisory corpus](../README.md#advisory-corpus)) additionally clones that public corpus repository
from **`github.com`** before the scan: unauthenticated (it presents no token), shallow (`--depth 1`)
and sparse (the manifest and record partitions only). It sends the repository coordinates and nothing
about your code. With `advisory-corpus-policy` set and the ref naming a corpus release, it downloads
`bundles.json` and `signals.json.gz`, plus `<policy>.jsonl.gz` when a bundle is published for that
policy, as **`github.com`** release assets (which redirect to
**`release-assets.githubusercontent.com`**). A bundle replaces the clone, and with it the route also
fetches the policy manifest from **`raw.githubusercontent.com`**. These requests are likewise
unauthenticated and carry nothing about your code. To verify the release signature first, that route
also downloads cosign from the
`sigstore/cosign` release on **`github.com`** and fetches the Sigstore trust root from the Sigstore TUF
CDN, **`tuf-repo-cdn.sigstore.dev`**; neither request carries anything about your code.

`cve-watch` adds **`api.osv.dev`**. The scan modes reach OSV only when work-set widening is switched
on explicitly (`-osv-work-set` / `ASSAY_OSV_WORK_SET`, off by default) and no advisory policy is
declared — a declared policy chooses the work set itself; that query sends package
coordinates — ecosystem, name, version — and nothing else. Enabling subject-toolchain reachability
(`ASSAY_SUBJECT_TOOLCHAIN_REACHABILITY`, also off by default) additionally downloads a Go toolchain
from the module proxy.

A JavaScript scan fetches each package tarball its lockfile pins, by name and version, from the
registry the repository's `.npmrc` (or `NPM_CONFIG_USERCONFIG`, `NPM_CONFIG_REGISTRY`) names. This
is the default; `-dependency-code=off` or `offline` (`ASSAY_DEPENDENCY_CODE`, the Action's
`dependency-code` input) turns it off. An `.npmrc` `${VAR}` reference reads only `NODE_AUTH_TOKEN`,
`NPM_TOKEN` or a variable named with `-dependency-npmrc-env`, and a token is presented only to the
host the `.npmrc` binds it to. The scanned branch's `.npmrc` chooses that host, as it does for
`npm ci`: whoever can change the `.npmrc` on a scanned branch can direct any of those tokens the job
exports to a host they control. Pull-request workflows from forks get no secrets, so the exposure is
to same-repository authors and to workflows that export a token to fork code (`pull_request_target`,
or a token placed in the job env). The control is `dependency-code: off`, or not exporting
`NODE_AUTH_TOKEN`, `NPM_TOKEN` or the named variables on jobs that scan pull requests.

Unless `dependency-code` is `off`, the Action keeps the fetched tarballs in the GitHub Actions cache,
keyed on the runner OS and the repository's lockfiles. That includes packages fetched from a private
registry with a token. Any workflow run allowed to restore that cache can read them: a run restores
caches from its own branch, its pull request's base branch and the default branch, and on a public
repository that includes pull-request workflows from forks. Use `dependency-code: off` where private
packages must not land in the cache.

What all of these carry is dependency metadata — module paths, versions, package coordinates — never
source, and never analysis results.

Findings do travel to GitHub, by design: the StateStore ref and the publish surfaces write the
`Report` and its projections into **your own** repository, under a token you supply.

Talking to Ferralon is a separate, explicit switch. The Action's `link-to-console` input is the only
control that decides whether a scan contacts Ferralon at all; it defaults to `false`, and on that
default the scan runs fully standalone. See the README's
[self-cleanup / console-link disclosure](../README.md#self-cleanup--console-link-disclosure) for
what that switch does when it is on, including the self-cleanup side effects.

The `resolve-graph` command is the only part of the CLI that executes the scanned repository's code. It
runs the repository's own Maven or Gradle, so the build's scripts and plugins run on the runner and the
tool contacts whatever repositories the build configures. A scan does not run it.
