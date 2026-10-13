# Language support

Point Ferralon Assay at a Go, Java, Kotlin, JavaScript/TypeScript, Python or .NET repository and every
one gets the same core scan: dependency versions resolved into an SBOM, advisories ruled out when your
pinned version is provably outside their affected range, and a full `Report` in every format
(`report.json`, `report.html`, `report.sarif.json`, `openvex.json`). Reachability analysis runs deepest
in Go and reaches outward across the others over one shared protocol. The tables below say what each
language does today, row for row, so you can compare them down a column.

## The verdicts

Every advisory lands as one verdict:

- `reachable_candidate`: a call path runs from one of your entry points to the vulnerable symbol.
- `not_exploitable`: Assay found the vulnerable code in the version you ship and showed that nothing
  reaches it. It says this only on positive evidence: either the vulnerable symbols resolved inside
  that package and the analysis searched every one of them from your entry points, or the analysis
  showed the package is never loaded.
- `disqualified`: your version is outside the advisory's affected range, or the package is not in
  your build.
- `undetermined`: Assay could not establish either, and the finding names the reason in
  `undetermined_reason`. An empty search on its own is never `not_exploitable`: when the analysis
  did not run, did not find the vulnerable code, or skipped part of the build, the finding says which.

A known-malicious package is reported as `malicious_package_present`. In OpenVEX, `not_exploitable`
and `disqualified` are `not_affected`, `reachable_candidate` and `undetermined` are
`under_investigation`, and a malicious package is `affected`.

## Every table's rows

- **Dependency inventory and SBOM:** what Assay reads to list the packages you ship.
- **Advisory matching:** the advisory sources that match against that inventory. The Ferralon
  corpus is the public [`ferralon-ai/vulnerability-corpus`](https://github.com/ferralon-ai/vulnerability-corpus);
  bring-your-own is any corpus you point `-advisory-corpus` at.
- **Version rule-out:** whether an advisory's affected range rules out your pinned version, per
  source.
- **First-party reachability:** call paths from your entry points to a vulnerable symbol your own
  code defines or calls.
- **Dependency reachability:** call paths that continue into the dependency, down to the vulnerable
  function.
- **Root-project advisories:** advisories filed against your project's own package, not one of its
  dependencies.
- **What makes a result undetermined:** the conditions in this language that leave a finding
  `undetermined`, with the `undetermined_reason` or limit each one reports.

## Go

| Capability | Go |
|---|---|
| Dependency inventory and SBOM | `go.mod` and the module graph (`go mod graph`), from the module cache or your proxy |
| Advisory matching | Ferralon corpus ✓ · bring-your-own ✓ |
| Version rule-out | Ferralon corpus ✓ · bring-your-own ✓ · module versions and, for standard-library advisories, the Go toolchain version |
| First-party reachability | ✓ from `main`, `net/http` handlers, `x/crypto/ssh` servers, and `HandleFunc`/`Handle` and macaron routes |
| Dependency reachability | ✓ into every module and the standard library, down to the vulnerable function |
| Root-project advisories | ✓ |
| What makes a result undetermined | cgo in a package on the path (`cgo`, held to the packages that use it); a module the cache and proxy can't supply (`tool_failure`); a `go.work` workspace (`unsupported_phase1`); a `replace` to unpinned source (`source_unpinned`); no recognized entry point (`no_known_ingress`); an advisory that names no symbols (`advisory_symbol_absent`) |

## Java

| Capability | Java |
|---|---|
| Dependency inventory and SBOM | Maven reactor POMs and Gradle lockfiles and version catalogs, resolved from your local `.m2` and Gradle caches |
| Advisory matching | Ferralon corpus ✓ · bring-your-own ✓ |
| Version rule-out | Ferralon corpus ✓ · bring-your-own ✓ · Maven version ordering |
| First-party reachability | ✓ from Spring `@*Mapping` and JAX-RS endpoints, `@Scheduled`, `@EventListener`, `@PostConstruct`/`@PreDestroy`, Kafka, JMS and Rabbit listeners, and `HttpServlet` methods |
| Dependency reachability | in progress |
| Root-project advisories | ✓ |
| What makes a result undetermined | a parent POM or BOM missing from the cache, or an unresolved property (`source_unpinned`); profile activation (`env_condition_unresolved:profile_activation`); a Gradle transitive or uncached subtree (`relationship_unexpressed`); an injection point with several candidate beans (`dynamic_dispatch:bean_ambiguous`); AOP proxies and `@Async` (`proxy_mediated`, `async_boundary`); SpEL (`spel_present`); Spring Data repository methods (`repository_synthesized_sink`); a vulnerable function inside dependency code the analysis did not load |

## Kotlin

| Capability | Kotlin |
|---|---|
| Dependency inventory and SBOM | the same Maven and Gradle inventory as Java |
| Advisory matching | Ferralon corpus ✓ · bring-your-own ✓ |
| Version rule-out | Ferralon corpus ✓ · bring-your-own ✓ · Maven version ordering |
| First-party reachability | ✓ over your compiled classes, from `main` and the same annotations as Java |
| Dependency reachability | ⟨MEASURE⟩ |
| Root-project advisories | ✓ |
| What makes a result undetermined | no compiled build output (`tool_failure:no_build_output`); a dependency JAR missing from the cache (`tool_failure:no_dependency_artifact`); an injection point with several candidate beans (`dynamic_dispatch:bean_ambiguous`); no recognized entry point (`no_known_ingress`) |

## JavaScript/TypeScript

| Capability | JavaScript/TypeScript |
|---|---|
| Dependency inventory and SBOM | `package-lock.json` (v1–v3), `npm-shrinkwrap.json`, Yarn classic and Berry, and pnpm lockfiles |
| Advisory matching | Ferralon corpus ✓ · bring-your-own ✓ |
| Version rule-out | Ferralon corpus ✓ · bring-your-own ✓ · npm semver |
| First-party reachability | ✓ from Express and Koa routes and middleware, `http`/`https.createServer`, Next.js default exports, and Vue template events |
| Dependency reachability | in progress |
| Root-project advisories | ✓ |
| What makes a result undetermined | a computed `require` or dynamic `import()` (`relationship_unexpressed:computed_require`, `:dynamic_import`); an ambiguous lockfile (`tool_failure:lockfile_ambiguous`); platform-specific packages (`env_condition_unresolved:platform`); workspace attribution, npm aliases and peer metadata (`relationship_unexpressed`); local-path and git dependencies (`source_unpinned`); no lockfile (`no_manifest`); no recognized entry point (`no_known_ingress`) |

## Python

| Capability | Python |
|---|---|
| Dependency inventory and SBOM | `requirements*.txt`, `poetry.lock`, `Pipfile.lock`, PEP 621 `pyproject.toml`, `pdm.lock` and `uv.lock`, with environment markers evaluated for your target |
| Advisory matching | Ferralon corpus ✓ · bring-your-own ✓ |
| Version rule-out | Ferralon corpus ✓ · bring-your-own ✓ · PEP 440 |
| First-party reachability | ✓ from Flask routes and FastAPI and Starlette endpoints |
| Dependency reachability | in progress |
| Root-project advisories | ✓ |
| What makes a result undetermined | an environment marker or `requires-python` the target doesn't settle (`env_condition_unresolved`); an unpinned source (`source_unpinned`); no requirements file or lockfile (`no_manifest`); Django, Celery or bare WSGI/ASGI entry points, which are not recognized (`no_known_ingress`) |

## .NET

| Capability | .NET |
|---|---|
| Dependency inventory and SBOM | `obj/project.assets.json`, `packages.lock.json`, and `PackageReference` or `packages.config` with Central Package Management, across every project in a solution |
| Advisory matching | Ferralon corpus ✓ · bring-your-own ✓ |
| Version rule-out | Ferralon corpus ✓ · bring-your-own ✓ · NuGet version ordering |
| First-party reachability | ✓ from ASP.NET Core attribute routes and minimal-API `Map*` endpoints |
| Dependency reachability | ⟨MEASURE⟩ |
| Root-project advisories | ✓ |
| What makes a result undetermined | no restore output or lockfile (`no_resolver_output`, `no_lockfile`); a floating version range (`unresolved_version_range`); an MSBuild condition (`unevaluated_condition`); several target frameworks (`multi_target_framework`); no compiled assembly to read (`tool_failure`); no recognized entry point (`no_known_ingress`) |
