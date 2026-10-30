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

A Java or Kotlin scan also runs the repository's own Maven or Gradle to resolve its dependency graph,
and the build tool contacts whatever repositories the build configures; the last paragraph of this
page covers what that executes.

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
exports to a host they control. Pull-request workflows from forks get no secrets by default, so the exposure is
to same-repository authors and to workflows that hand a token to fork code (`pull_request_target`,
a private repository's "send secrets to workflows from fork pull requests" setting, or a token placed
in the job env). The control is `dependency-code: off`, or not exporting
`NODE_AUTH_TOKEN`, `NPM_TOKEN` or the named variables on jobs that scan pull requests.

The fetched tarballs land in the runner's temp directory, which is emptied after the job. Which of
them also persist in the GitHub Actions cache, keyed on the runner OS and the repository's lockfiles,
is the Action's `persist-dependency-cache` input. Any workflow run allowed to restore the cache can
read it: a run restores caches from its own branch, its pull request's base branch and the default
branch, and on a public repository that includes pull-request workflows from forks. The rule is per
tarball. Under the default, `auto`, a private or internal repository (the event payload's
`github.event.repository.private`, or `visibility` of `private` or `internal`) caches every tarball.
A public repository, or an event whose payload carries no repository (`schedule`), caches every
tarball except one from a registry the effective `.npmrc` holds an auth entry for: the scanner
fetches those into a directory under the runner's temp directory that is never cached, on every
run, and never writes them to the cached directory (`-dependency-uncredentialed-cache`). It decides
which registries hold an auth entry from the same `.npmrc` resolution the fetch uses to present a
token, and fetches every tarball bound for the cached directory without presenting any credential.
When the lock pins a package from a credentialed registry and a restored cache holds a copy of it,
the scanner removes that copy. It does not sweep entries the lock no longer pins: an earlier run
wrote those, and it fetched them without presenting any credential. The cache key carries the scope (`all` or
`uncredentialed`) and a format version, so a cache saved under one never restores under the other.
`always` caches every tarball regardless and, on a public repository, exposes cached private
packages to fork pull requests; `never` caches nothing. A public-repository `offline` run reads the
uncredentialed tarballs a restored cache holds and leaves every credentialed package unread.

What all of these carry is dependency metadata — module paths, versions, package coordinates — never
source, and never analysis results.

Findings do travel to GitHub, by design: the StateStore ref and the publish surfaces write the
`Report` and its projections into **your own** repository, under a token you supply.

Talking to Ferralon is a separate, explicit switch. The Action's `link-to-console` input is the only
control that decides whether a scan contacts Ferralon at all; it defaults to `false`, and on that
default the scan runs fully standalone. See the README's
[self-cleanup / console-link disclosure](../README.md#self-cleanup--console-link-disclosure) for
what that switch does when it is on, including the self-cleanup side effects.

A Java or Kotlin scan resolves its dependency graph with the repository's own Maven or Gradle. That is
the default, `-build-graph auto`, and the `resolve-graph` command does the same ahead of a scan. Either
way the build's scripts and plugins run on the runner, and the build tool contacts whatever
repositories the build configures. This is the only point at which the CLI executes the scanned
repository's code. To keep the build tool out of the scan, resolve the graph in an earlier step and
pass it with `-build-graph <file>`, or run with `-build-graph off`; the scan then runs no build tool.
The `Report` records which of the three the scan used in `build_graph.source`.
