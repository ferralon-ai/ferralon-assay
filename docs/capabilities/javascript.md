# JavaScript / TypeScript capabilities

Every feature in every capability group for JavaScript / TypeScript, with its status and the caveats that bound it. The [overview](README.md) explains the groups and statuses.

| Group | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
|---|---|---|---|---|---|---|---|---|
| C / P / L | 🟩 5 / 🟨 2 / 🟥 2 | 🟩 1 / 🟨 3 / 🟥 1 | 🟩 1 / 🟨 6 / 🟥 1 | 🟩 4 / 🟨 6 / 🟥 0 | 🟩 3 / 🟨 0 / 🟥 2 | 🟩 4 / 🟨 2 / 🟥 1 | 🟩 0 / 🟨 3 / 🟥 1 | 🟩 0 / 🟨 2 / 🟥 1 |

🟩 Complete, 🟨 Partial, 🟥 Planned. Features marked N/A do not apply to the language and are not counted.

## 1. Dependency inventory

The JS lane reads the project's lockfile directly and never runs a package manager. npm (lockfile v1, v2, v3), yarn (classic and berry) and pnpm locks are turned into a per-package inventory with distinct versions, shared nodes, peer scopes, workspace members and an SBOM, so every dependency instance in a build is a named node the analysis can attach advisories to.

| Feature | Status | Caveats |
|---|---|---|
| npm lock (v1/v2/v3) inventory | Complete |  |
| yarn classic + berry lock inventory | Partial | [JS-YARN-LOCK-SPELLING](#js-yarn-lock-spelling) |
| pnpm lock inventory (v5/v6+) | Partial | [JS-PNPM-YAML-SUBSET](#js-pnpm-yaml-subset) |
| Workspaces / monorepo members | Complete |  |
| Non-registry sources (git ref, local path, alias, platform-conditional) flagged, not guessed | Complete |  |
| SBOM emission | Complete |  |
| No-lockfile fallback (declared ranges, marked unresolved) | Complete |  |
| npm lockfile v1 narrowing of scoped limits | Planned | [JS-V1-LOCK-NO-SPEC](#js-v1-lock-no-spec) |
| Lock staleness (lock no longer satisfies manifests) modelled | Planned | [JS-LOCK-STALENESS](#js-lock-staleness) |

## 2. Version clearing

A dependency is cleared on version when its resolved version falls outside an advisory's affected range. The lane resolves one version per package from the lock, matches with an npm-semver range implementation, and refuses to resolve when copies disagree, so a cleared version is a real one.

| Feature | Status | Caveats |
|---|---|---|
| npm semver range matching | Partial | [JS-ADVISORY-RANGE-U0085](#js-advisory-range-u0085) |
| Single resolved version per coordinate; straddling/disagreeing copies marked unresolved | Complete |  |
| Exhaustiveness claim (absence admission "package not in build") | Partial | [JS-EXHAUSTIVE-WITHHOLD](#js-exhaustive-withhold) |
| Install-surface vetoes (installs the lock does not govern) | Partial | [JS-INSTALL-SURFACE-GAPS](#js-install-surface-gaps) |
| Install commands held to the committed lockfile | Partial | [JS-INSTALL-HONOURS-LOCK](#js-install-honours-lock) |
| v1 lock exhaustiveness via range-satisfaction | Planned | [JS-V1-LOCK-NO-SPEC](#js-v1-lock-no-spec) |

## 3. Build-graph fidelity

The lane statically reconstructs how the build resolves packages from the lock and the repo's configuration, without installing. It produces a build manifest for the pipeline and, in dependency-code mode, a reconstructed `node_modules` layout (npm hoisting; pnpm/yarn-classic semantic regions).

| Feature | Status | Caveats |
|---|---|---|
| Lock-derived build graph (no package manager executed) | Complete |  |
| Build/install command emitted for the build | Partial | [JS-INSTALL-CMD-NPM-ONLY](#js-install-cmd-npm-only) |
| `.npmrc` / registry credential sourcing (build root + `NPM_CONFIG_USERCONFIG`) | Partial | [JS-NPMRC-PARITY](#js-npmrc-parity) |
| Private registries / scoped registries | Partial | [JS-NPMRC-PARITY](#js-npmrc-parity), [JS-LOCK-URL-UNPLUMBED](#js-lock-url-unplumbed) |
| Dependency tree reconstruction (lock-pinned, SRI-verified tarballs) | Partial | [JS-DEPCODE-UNREAD](#js-depcode-unread), [JS-SHA1-INTEGRITY](#js-sha1-integrity) |
| yarn berry dependency code | Planned | [JS-YARN-BERRY-WITHHELD](#js-yarn-berry-withheld) |
| Bundler/framework config awareness (webpack, rollup, vite, esbuild, swc) | Partial | [JS-STYLESHEET-EXEMPTION](#js-stylesheet-exemption) |
| Parse budget determinism | Partial | [JS-PARSE-TIMEOUT-WALLCLOCK](#js-parse-timeout-wallclock) |

## 4. Call graph

The call graph is a source-lexical graph over first-party TS/JS: an import-scoped resolver handles CJS and ESM, package `exports`/`imports`, tsconfig `paths`/`baseUrl` and workspaces, and calls into dependencies are package-boundary nodes (`npm:<pkg>#member`). With dependency-code reading on, dependency source is parsed and edges cross into it.

| Feature | Status | Caveats |
|---|---|---|
| First-party symbol index (TS and JS, JSX/TSX, Vue SFC) | Complete | [JS-LEXER-RESIDUE](#js-lexer-residue) |
| Import-scoped module resolution (CJS/ESM/exports/imports/tsconfig paths/workspaces) | Complete |  |
| Call edges with arity-exact linking | Partial | [JS-ARITY-EXACT-LINKING](#js-arity-exact-linking) |
| Declined-site and escaped-frame lists (`Unresolved`, `Escaped`, `unlisted_sites`) | Partial | [JS-UNLISTED-RESIDUE](#js-unlisted-residue) |
| Opaque callees (call-on-call, computed member, comma, tagged template, `new C`, `super`, decorator) declared, unbounded | Complete |  |
| Package-boundary nodes for dependency calls | Complete |  |
| Dependency-code edges (lock-pinned tarballs) | Partial | [JS-DEPCODE-UNREAD](#js-depcode-unread), [JS-UNINSPECTABLE-RUNWIDE](#js-uninspectable-runwide) |
| Out-of-tree package loads recorded | Partial | [JS-UNINSPECTABLE-RUNWIDE](#js-uninspectable-runwide) |
| TypeScript handling | Partial | [JS-TS-NO-TYPE-RESOLUTION](#js-ts-no-type-resolution) |
| Type-aware call resolution | Partial | [JS-NO-TYPES](#js-no-types) |
| Bytecode ingestion | N/A | JS is analyzed from source |

## 5. Reachability clearing

Reachability here answers "can an entry point reach the vulnerable symbol". The lane reports reachable candidates with a path. It clears on one ground: `package_not_loaded`, when no installed copy of the advisory's package is loaded by anything that runs. It never sets `Searched`, so a package that loads is `reachable_candidate` or `undetermined`.

| Feature | Status | Caveats |
|---|---|---|
| Reachable-candidate path (ingress to sink) | Complete |  |
| `not_exploitable` from a completed search with a vetted symbol set | Planned | [JS-NO-CLEAR-GROUNDS](#js-no-clear-grounds) |
| `not_exploitable` from `package_not_loaded` | Partial | [JS-LOAD-CLOSURE](#js-load-closure) |
| `not_exploitable` from `analyzer_symbol_not_reached` | Planned | [JS-NO-CLEAR-GROUNDS](#js-no-clear-grounds) |
| Unread-code programs return undetermined/analysis_did_not_run | Complete |  |
| Empty package never refutes | Complete |  |

## 6. Framework & dynamic-dispatch modeling

Entry points are recognised from Express, Koa, Node `http`, Next default handlers and Vue templates, with an Express receiver model that types `req`/`res`/`next`. Dynamic dispatch is declared, never guessed.

| Feature | Status | Caveats |
|---|---|---|
| Express ingress and receiver model | Complete |  |
| Koa router, Node http server, Next default export | Complete |  |
| Vue SFC template handlers | Complete |  |
| TS class-method ingress chains | Complete |  |
| Fastify, NestJS decorators, Hapi, Angular/React component graphs | Planned | [JS-FRAMEWORK-COVERAGE](#js-framework-coverage) |
| Escape roots (UMD, global scripts, module-less files) | Partial | [JS-ESCAPE-ROOT-UMD](#js-escape-root-umd) |
| eval / Function / dynamic require / dynamic import declared | Partial | [JS-EVAL-OVERDECLARE](#js-eval-overdeclare), [JS-LEXER-RESIDUE](#js-lexer-residue) |

## 7. Hazard bounding

Hazards are reported as partiality reasons. The question is how wide they bite. In JS, the dominant reasons are did-not-run and run-wide, so they withhold `not_exploitable` for the whole run.

| Feature | Status | Caveats |
|---|---|---|
| Scoped limits (Targets bound to packages) | Partial | [JS-SCOPE-ONLY-FOR-SOME](#js-scope-only-for-some) |
| Run-wide `uninspectable_package` without dependency code | Partial | [JS-UNINSPECTABLE-RUNWIDE](#js-uninspectable-runwide) |
| Run-wide dynamic code in dependency load paths (Express+mongoose) | Partial | [JS-LOADTIME-CODEGEN](#js-loadtime-codegen) |
| Typical project can receive a clear | Partial | [JS-LOAD-CLOSURE](#js-load-closure) |

## 8. Runtime confirmation

The lane hands the paid tier a reproducer skeleton and a path-presence taint result. Neither claims value flow.

| Feature | Status | Caveats |
|---|---|---|
| Harness generation (Node skeleton calling the sink) | Partial | [JS-HARNESS-SKELETON](#js-harness-skeleton) |
| Taint (call-path presence ingress to sink) | Partial | [JS-TAINT-PATH-ONLY](#js-taint-path-only) |
| Capability manifest | Planned | [JS-MANIFEST-UNPUBLISHED](#js-manifest-unpublished) |
| Value-flow / sanitizer modeling | N/A |  |

## Caveats

### JS-UNINSPECTABLE-RUNWIDE

**Trigger.** Any first-party import of a bare specifier while no dependency code is read: dependency code off, or a fetch that fell back (see [JS-DEPCODE-UNREAD](#js-depcode-unread)). With dependency code read, the limit stays run-wide when the reconstructed layout can't bound what a load reaches (yarn berry, an incomplete layout, a bundler alias that may replace the specifier, a load inside dependency code that can't be bounded), and for an install script (a `binding.gyp` counts as one), an unread package whose lock doesn't record install scripts, a computed load inside dependency code, or a copy bundled in a pnpm or yarn classic package's tarball.

**Effect.** Run-wide `uninspectable_package` (did_not_run) blocks `not_exploitable` for every advisory.

### JS-DEPCODE-UNREAD

**Trigger.** Running with `-dependency-code=off` (the Action's `dependency-code: off`), or a fetch that failed and fell back to reading no dependency code (`dependency_code.cause` set, with a `tool_failure:dependency_code_unavailable` note).

**Effect.** No dependency edges, and the run-wide limit under JS-UNINSPECTABLE-RUNWIDE applies.

### JS-NO-CLEAR-GROUNDS

**Trigger.** The advisory's package is loaded.

**Effect.** The reachability result never sets `Searched`, so a symbol the search did not reach in a loaded package is `undetermined`, never `not_exploitable`.

### JS-LOAD-CLOSURE

The load closure is every module the lane can show runs: each first-party source file it parses, each installed binary or module a launch text names, and everything those load, to a fixed point. The launch texts are every `package.json` script and every other `package.json` value outside the keys that hold names, versions, dependency lists, overrides, engines, workspaces, publish settings and prose (root and workspace members); every YAML and TOML file except `pnpm-lock.yaml` (compose files, Kubernetes and Helm manifests, CI workflows and actions, platform configs such as `fly.toml` and `render.yaml`); process and container files (`Procfile`, `Dockerfile*`, `Containerfile*`); process-manager and app configs (`ecosystem.*`, `pm2.*`, `nodemon.json`, `app.json`); `.npmrc`, `.yarnrc` and `.env*`; shell, batch and PowerShell scripts, `Makefile`, `justfile` and `Jenkinsfile`; files under `.husky/`, `.github/workflows/`, `.circleci/` and `.devcontainer/`; any file that opens with an interpreter line; any file that names `NODE_OPTIONS`, prose (`.md`, `.markdown`, `.txt`, `.rst`, `.adoc`) excepted; and a file with no extension that another launch text names (`node ./server`). A launch text is not interpreted: every word in it that names an installed binary or resolves as a module specifier counts. A command started from anywhere else is not seen: a preload set in a hosting platform's environment, outside the repository, is the main case, and a start command in a JSON or infrastructure file that does not name `NODE_OPTIONS` is another. A package is `package_not_loaded` when the lockfile places at least one copy of it and the closure holds no module of any copy.

**Trigger.** Any of these makes the closure incomplete, and nothing is cleared: dependency code not read; a layout the lockfile does not fully enumerate (npm v1, pnpm, Yarn classic, Yarn Plug'n'Play, bundled copies, no lockfile); a package with an install script; a first-party source file the lane does not parse (`.mts`, `.cts`, `.svelte`, `.astro`, `.mdx`, or any source under `dist`, `build`, `out`, `coverage`, `vendor` or a hidden directory); a launch text or first-party directory that could not be read, or a launch text over 16 MiB; a launch text that runs a command through a package runner (`npx`, `pnpx`, `bunx`, or `dlx` or `exec` after a package manager) that no installed package provides; a named binary that is not a source file the lane parses, or that the lockfile records and the package's `package.json` places nowhere; a `bin` field the lane cannot read; and, inside the closure, `eval` or `new Function`, a module the lane could not read or parse, a native addon, an unread or patched package, or a load of `module`, `child_process`, `worker_threads`, `vm`, `cluster`, `repl`, `inspector`, `test`, `wasi` or `sqlite`.

**Computed loads.** A `require` or `import` whose specifier is computed, in a loaded module of package P, is assumed to resolve only inside P, to P's declared dependencies (`dependencies`, `peerDependencies`, `optionalDependencies`) or to a dependency any first-party `package.json` declares (development ones included). Every module of every package in that bound joins the closure, and a computed load among them extends it by its own bound, to a fixed point. A computed load in first-party code is bound to the first-party declared dependencies. A computed load with a literal prefix (`require('idle/locale/' + l)`, `` import(`eslint-plugin-${n}`) ``) also admits what the prefix names: the installed package of that name, or every installed package whose name starts with the prefix, compared without case. A clear that rests on a closure holding a computed load carries the assumption in `evidence.assumptions`: "computed module loads in <packages> are assumed to resolve only to that code's own modules, its declared dependencies, the project's direct dependencies and any package a literal prefix names". Four things are not bounded, and make the closure incomplete: a literal prefix that can name code outside the loading package (any prefix with a `node_modules` segment, or one that ends where its runtime part can complete `..` or `node_modules`; a relative prefix that leaves the package's directory; an absolute path; a backslash, percent sign, tab or line break, or a capital letter outside ASCII; a URL or `node:` specifier, whole or begun; a `#` alias; a dot-leading name such as `.bin/`; or the start of a built-in's name listed under Trigger); a computed load in a package whose `package.json` is unreadable or lists dependencies in a form other than an object; a module loader that leaves its module's own load sites (`require` passed, exported or stored, the module wrapper's `arguments`, an escaped `createRequire` result, `Module._load`, `mainModule`); and `eval` and `new Function`, since the lane does not tell a direct `eval` from an indirect one.

**Effect.** With a complete closure, a hazard in a package nothing loads is not declared, and `uninspectable_package`, `unlisted_sites` and the computed-load limits are scoped to the loaded packages and first-party code. With an incomplete closure the run-wide limits stand and no package is cleared.

### JS-LOADTIME-CODEGEN

**Trigger.** A dependency in the load closure ([JS-LOAD-CLOSURE](#js-load-closure)) that runs `eval` or `new Function`.

**Effect.** Run-wide dynamic-code limit even with dependency code read. The same code in a package nothing loads declares nothing.

### JS-EXHAUSTIVE-WITHHOLD

**Trigger.** Overrides, pnpmfile, install scripts, certain .npmrc keys, patches, bundled deps, native addons, or a v1 lock without satisfying ranges.

**Effect.** `Exhaustive` false, so "not in build" absence admission is withheld; per-claim, not run-wide.

### JS-INSTALL-HONOURS-LOCK

**Trigger.** A build text (a `package.json` script, CI workflow, Dockerfile, shell script or git hook) runs an install that names no package and that only the lockfile holds to its pins: `npm install`, `npm ci` where the lane cannot place the copied tree, `yarn install` or bare `yarn`, `pnpm install` without `--frozen-lockfile`. The assumption is taken only when the tree supports it: the `package.json` the command installs for has a lockfile of that package manager beside it at the place the command runs (under a Dockerfile, a lock copied into the image; a lock in a directory above does not count), no other package manager's lock sits beside it, the lock covers what the manifest declares, every override or resolution names one package and gives it a version range that each locked version of it falls inside (or refers to the manifest's own range with `$name`, or names a GitHub repository, spelled as an npm v2 or v3 lock records it, that the lock installs every copy of the package from at a commit: either that same commit, or no committish where the lock records none for the package), no setting file there or above (under a Dockerfile, as copied into the image, the home directory included) can turn the lock off (an `.npmrc` key outside the ones that leave the lock in force; for yarn any `.yarnrc` or `.yarnrc.yml`; for pnpm a `pnpm-workspace.yaml` key other than `packages`), and under a workspace root every member is covered. Commands that install nothing against the lock (`npm start`, `npm test`, `npm run <script>`, `yarn run`, `nx build` and the other nx targets that run a script, a wrapper such as `wait-for-it.sh host:port -- npm start`, a read of `package.json` by `jq`, `cat` or `grep`, and `playwright install <browser>` where the project declares Playwright) need no assumption.

**Effect.** The lock's versions stand and every finding carries the annotation `assumption:install_honours_lockfile` ("install commands honour the committed lockfile"); a `package_not_loaded` clear lists it under its assumptions. The pins are withheld when a command can move the installed tree off the lock: an install that names a package (`npm install left-pad`, `yarn add`, `pnpm add`), `npm update`, `--no-package-lock`, `--no-save`, `--no-lockfile` or a flag the lane does not know, an install at a `--prefix` the lane cannot bind to a `package.json` it reads, a write to `package.json` or a lockfile before the install (a command that names one, or code passed to an interpreter such as `node -e` or `python -c` whose text names one, unless it only reads a field of a required file, as `node -p "require('./package.json').version"` does), an install where no lock of that package manager covers the manifest, a setting file that can turn the lock off, a command that names `.npmrc`, `.yarnrc`, `.yarnrc.yml` or `pnpm-workspace.yaml` (it may write one), or a wrapper whose own arguments name `package.json`, a lockfile or one of those files. An install run from a workspace member's directory withholds too: its lock sits above it.

### JS-INSTALL-SURFACE-GAPS

**Trigger.** Installs outside the lock's view (a CI workflow at the repo root, `sh -c` of a script, glob rebinds, interpreter-run installs).

**Effect.** Exhaustiveness and lock claims are either withheld or, on some of these surfaces, not gated.

### JS-INSTALL-CMD-NPM-ONLY

**Trigger.** Yarn or pnpm project.

**Effect.** BuildManifest advertises `npm ci`/`npm install`.

### JS-TS-NO-TYPE-RESOLUTION

**Trigger.** TS code whose call targets depend on types (interface dispatch, DI, generics).

**Effect.** Unresolved callee declares `dynamic_dispatch` (inherent limit).

### JS-EVAL-OVERDECLARE

**Trigger.** `setTimeout("str")`, computed member reads like `this.components[route]`, TS types `T[keyof T]`.

**Effect.** Spurious evaluated_code (blocks clearing).

### JS-LEXER-RESIDUE

**Trigger.** Regex-after-block, JSX apostrophes, `//` in regex, unicode-escaped identifiers, template interpolations.

**Effect.** Code hidden from the scan.

### JS-ARITY-EXACT-LINKING

**Trigger.** Call with optional/rest params or differing arg count.

**Effect.** No edge; the site is declared (dynamic_dispatch, inherent) and since listed in `Unresolved` with `Targets` covering every same-name declaration. Declared, not silent.

### JS-UNLISTED-RESIDUE

**Trigger.** Eval/Function body, unreadable source file, skipped construct, run-wide prototype judgment, or dependency code read into the graph.

**Effect.** `relationship_unexpressed:unlisted_sites` declared (did_not_run class by default); `Unresolved`/`Escaped` list first-party code only. Also not listed and not declared: code run with no call written at the site (JSX `<Comp />`, getters/setters, `toString`/`then`/iterator hooks, Proxy traps).

### JS-ADVISORY-RANGE-U0085

**Trigger.** Advisory range string containing U+0085.

**Effect.** Range whitespace is split on ASCII whitespace only, so U+0085 is not treated as a separator.

### JS-YARN-LOCK-SPELLING

**Trigger.** A yarn classic lock with an `@npm:` alias or spellings yarn's tokenizer rejects.

**Effect.** Wrong lock reading (berry mis-detect).

### JS-PNPM-YAML-SUBSET

**Trigger.** A pnpm lock with `\r`, tab-before-`#` or NBSP.

**Effect.** Wrong lock reading.

### JS-NPMRC-PARITY

**Trigger.** Private registries or port/path-scoped tokens.

**Effect.** Dependency acquisition fails closed or reads less.

### JS-SHA1-INTEGRITY

**Trigger.** sha1-only lock integrity.

**Effect.** Dependency acquisition fails closed or reads less.

### JS-LOCK-URL-UNPLUMBED

**Trigger.** Private registries addressed by lock URLs.

**Effect.** Dependency acquisition fails closed or reads less.

### JS-STYLESHEET-EXEMPTION

**Trigger.** React-scripts / webpack stylesheet loaders.

**Effect.** Exemption from uninspectable can be over-broad.

### JS-PARSE-TIMEOUT-WALLCLOCK

**Trigger.** Heavy files on loaded machines.

**Effect.** Same input withholds or resolves depending on load (nondeterminism).

### JS-ESCAPE-ROOT-UMD

**Trigger.** UMD files loaded as classic scripts; `window` destructuring.

**Effect.** Wrong escape treatment.

### JS-HARNESS-SKELETON

**Trigger.** Any JS harness generation.

**Effect.** The generated harness is a structural skeleton with a placeholder for input.

### JS-TAINT-PATH-ONLY

**Trigger.** Any taint query.

**Effect.** Taint is call-path presence from ingress to sink, never value flow.

### JS-FRAMEWORK-COVERAGE

**Trigger.** NestJS/Fastify/Hapi/Angular.

**Effect.** Ingress is not recognised, so no reachable paths are found for those frameworks.

### JS-V1-LOCK-NO-SPEC

**Trigger.** An npm lockfile v1.

**Effect.** A v1 lock records no specs.

### JS-LOCK-STALENESS

**Trigger.** A lock that no longer satisfies the manifests.

**Effect.** A stale lock still pins versions.

### JS-YARN-BERRY-WITHHELD

**Trigger.** A yarn berry project.

**Effect.** Yarn berry dependency code is withheld by design.

### JS-MANIFEST-UNPUBLISHED

**Trigger.** Any JS scan.

**Effect.** The JavaScript lane does not publish a capability manifest.

### JS-NO-TYPES

**Trigger.** Code whose call targets depend on types.

**Effect.** There is no type resolution.

### JS-SCOPE-ONLY-FOR-SOME

**Trigger.** Any limit other than stylesheets and some dependency-code reasons.

**Effect.** Scoped limits exist only for stylesheets and some dependency-code reasons.
