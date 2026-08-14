# JavaScript / TypeScript symbol profile

This page says exactly which source constructs the JS/TS engine turns into a symbol, what the
symbol looks like, and — just as important — which constructs it does *not* distinguish or emit. It
is meant to be read alongside the code: every claim here is traceable to
`internal/plugin/jsanalysis`.

The engine is an offline, dependency-free lexical scanner. It never runs Node, never reads a
`tsconfig`, and never looks inside `node_modules` (`scip.go:8-17`, `skipDir` at `index.go:141-147`).
That posture is deliberate — the canonical TS indexer (`scip-typescript`) needs all three, none of
which is available offline in CI. The limitations below are consequences of scanning raw source
without a resolver, not defects to be patched in place; where a construct needs type resolution to
disambiguate, the engine declares partiality rather than over-claim an identity it did not resolve.

## Two layers: read them separately

This document has two layers, and a reader must always know which is which:

- **Layer 1 — Current state.** What the engine actually emits **today**: the `scipSymbol` grammar,
  four literal example strings, and the honest limitations. The producer code (`scip.go`, `index.go`)
  is unchanged from `parity/js @ dc1b84a`; it still populates only `SCIP`, `DisplayName`, and
  `Package` on every `Symbol` (`index.go:74-84`).
- **Layer 2 — Canonical target.** How the eight §4.3 categories map onto the **frozen** canonical
  `plugin.Symbol` (the fleet's comparable 8-field struct), in JS/TS spellings, with the
  current→target population gap for each. The frozen struct **has now landed on-branch** via the
  rebase onto `parity/platform` (PLAN-000; `plugin/plugin.go:210`). So the gap is no longer that the
  fields *do not exist* — it is that the producer *does not populate* the structured fields
  (`Kind`/`Enclosing`/`Name`/`Descriptor`/`Generated`) yet. That population is the JS lane's PLAN-262
  work; the cross-producer golden table
  (`internal/plugin/jsanalysis/symbolprofile_golden_test.go`) asserts each gap as an xfail row that
  flips red the moment a producer closes it.

---

# Layer 1 — Current state (producer unchanged since `parity/js @ dc1b84a`)

## The symbol string

Every first-party symbol is built by `scipSymbol(module, enclosing, descriptor)` (`scip.go:62-77`),
which emits, space-separated:

```
scip-typescript npm <package> <version> <module>/<Class#…><descriptor>
```

- `scip-typescript npm` — the fixed manager token (`scip.go:34`), kept so IDs are recognizable to
  SCIP tooling.
- `<package>` and `<version>` — **both the literal `"."`** (`localCoordinate`, `scip.go:40`, written
  twice at `scip.go:66` and `scip.go:68`).
- `<module>/` — the source file's path relative to the build root, `/`-joined, extension stripped,
  `/`-terminated (`moduleDescriptor`, `scip.go:82-87`; `moduleOf`, `index.go:153-163`). An empty
  module renders `_root_/`.
- `<Class#…>` — one `Name#` type descriptor per enclosing class frame, outermost first.
- `<descriptor>` — the trailing per-declaration descriptor. For functions and methods this is
  arity-disambiguated: `name().` for zero params, `name(N).` otherwise (`functionDescriptor`,
  `scip.go:92-97`). For a class declaration itself it is just `Name#`.

## Every symbol's package coordinate and version are `"."` — there is no package-instance identity

`scipSymbol` writes `localCoordinate` (the literal `"."`) for **both** the package coordinate and
the version, unconditionally, on every symbol it produces (`scip.go:40,66,68`). There is no code
path that substitutes a resolved npm name or a resolved version — the scanner has no
`node_modules` and no resolver to get them from. The practical consequence: **no current JS/TS
symbol carries package-instance identity.** Two functions with the same name and arity in the same
module path are indistinguishable across package boundaries, because the coordinate and version
that would separate them are the same placeholder for everything. (Version *resolution* from
lockfiles is a separate capability — `ResolveDependencyVersions` reads `package-lock.json` /
`yarn.lock` / `pnpm-lock.yaml` — but those resolved versions never reach the symbol string.)
Changing the `"."` output is tracked as **PLAN-262** and reading `node_modules` as **PLAN-260**;
neither is in scope here. This page records the limitation; it does not advocate a fix.

## SCIP is the identity space; DisplayName is the advisory-match space

Two distinct string spaces travel on a `plugin.Symbol`, and they are not interchangeable. The SCIP
string above is the **identity** — it is what the first-party indexer, the call-graph builder, and
ingress discovery all agree on by construction (all three route through `scipSymbol`). Advisory
matching (`jsSymbolMatches`, `ingress.go:112`) is a **separate** space: it compares an advisory
identifier only against forms derived from `Symbol.DisplayName` (bare name, package-qualified,
module-leaf-qualified, arity-tolerant) and **never reads `Symbol.SCIP`**. That asymmetry is
guard-pinned (`symbolform_guard_test.go`), including a negative assertion that matching on the SCIP
string itself must return false. If you are populating an advisory corpus, you target DisplayName
forms, not SCIP strings.

## The eight symbol categories (as emitted today)

One row per category. The example strings are literal `scipSymbol` output. Only the `fetchUrl`
example corresponds to an on-disk corpus fixture
(`TEGRON-JS-SSRF-0001-vulnerable/src/fetcher.js`); the rest are grammar-derived traces of the code
path (there is no class in the current corpus fixtures), each constructed to match `scipSymbol`'s
emitted form exactly.

| # | §4.3 category | Distinguished / emitted today? | Canonical example symbol string |
|---|---|---|---|
| 1 | packages / modules | **Module: yes. npm package instance: no.** The module path is carried as the namespace descriptor prefix (`fetcher/`, `util/fetcher/`). No standalone symbol is emitted for the module itself — module identity exists only as the prefix on member symbols. The npm package coordinate and version are the literal `"."` (see the `"."` limitation above), so no package-instance identity exists. | `scip-typescript npm . . fetcher/fetchUrl(1).` (the `fetcher/` segment is the module; the two `.` tokens are the absent package + version) |
| 2 | types (interface / type alias / enum) | **No — not distinguished, and not emitted at all.** `parseDecls` (`parser.go:251-339`) recognizes only the `class` keyword and function-like shapes; it has no handling for `interface`, `type` aliases, or `enum`. No declaration of any kind is recorded for a TS type. | *not emitted* — the engine produces no symbol for a TS `interface`, `type` alias, or `enum` |
| 3 | functions | **Yes.** A module-level function (empty enclosing chain) yields a namespace-qualified, arity-disambiguated descriptor. | `scip-typescript npm . . fetcher/fetchUrl(1).` |
| 4 | methods | **Yes.** A class method carries one `Class#` type descriptor per enclosing class frame. | `scip-typescript npm . . util/fetcher/Fetcher#fetch(1).` |
| 5 | constructors | **No — not distinguished from an ordinary method.** `methodDeclAt` (`parser.go:496-516`) has no special case for the name `constructor`; it parses identically to any other method (same `kindFunc`, same `enclosing`, arity-disambiguated). Only the literal name `constructor` in the descriptor marks it. | `scip-typescript npm . . util/fetcher/Fetcher#constructor(1).` |
| 6 | overloads / generics | **No — not distinguished; arity is the only disambiguator.** Generic type params (`<…>`) are lexically skipped and never recorded (`parser.go:247,395,503-505`). A TS ambient overload *signature* (no body, ends in `;`) is not recorded as a decl at all — only the implementation (which has a body) is captured — so multiple same-arity overloads collapse to one symbol. | `scip-typescript npm . . util/box/Box#map(1).` (a generic `map<T>(fn)` — the `<T>` is absent; any same-arity overload signatures collapse into this one id) |
| 7 | nested declarations | **Partial.** A class nested inside a class **is** distinguished — `classChain()` (`parser.go:256-264`) walks every active class frame, so each becomes a `Class#` descriptor. But `enclosing` is built from class frames *only*: a function declared inside another function's body is qualified only by whatever class frames (if any) surround it, **not** by its enclosing function. Two same-name, same-arity functions at different function-nesting depths in the same (or no) class therefore produce the **identical** SCIP id — a real collision, not merely an undistinguished category. TS `namespace X {}` is not recognized at all. | Nested class, distinguished: `scip-typescript npm . . util/nest/Outer#Inner#run().` — Colliding closures: two `parse(x)` at different function-nesting depths both emit `scip-typescript npm . . util/helpers/parse(1).` |
| 8 | generated symbols (decorator / transpiler / source-mapped) | **No — not handled at all.** The scanner reads raw, un-transpiled source with no source-map awareness and no decorator parsing (`parser.go` has zero decorator-specific logic). It has no notion of "generated" vs. "authored" — it emits only what is literally written in the source. | *not emitted* — for `@Component class Widget {}` the engine emits only the authored class `scip-typescript npm . . ui/widget/Widget#` and ignores the decorator; nothing is emitted for decorator- or transpiler-generated members |

## What this means in practice (today)

The engine gives you stable, honest identities for the two things a lexical scan can resolve without
a type checker — module-level functions and class methods (including nested-class methods) — and it
records partiality everywhere resolution would be required to do better. The four categories that
degrade (types not emitted; constructors and overloads/generics not distinguished; nested closures
that can collide) all reduce to the same root cause: no resolver, no type information, arity and
enclosing-class chain as the only disambiguators. Combined with the `"."` package coordinate, the
correct mental model is: **within a single module path, this engine tells same-name symbols apart by
arity and enclosing-class chain and nothing else** — and across package boundaries it does not tell
them apart at all.

---

# Layer 2 — Canonical target (frozen field-contract PLAN-000; landed on-branch via rebase onto `parity/platform`)

The fleet froze a new canonical `plugin.Symbol`: a **comparable** struct whose every field is a
scalar, so it stays usable as a map key / `==` operand / array element everywhere the raw strings are
today (field-contract §1). Its eight fields are `Kind` (a `SymbolKind`:
`package`/`type`/`function`/`method`/`constructor`/`field`), `Package`, `Enclosing` (the enclosing
type/decl chain joined by `"."`, outermost→innermost), `Name`, `Descriptor` (overload/generic/arity
disambiguator), `Generated` (bool), plus the two rendering/bridge fields `DisplayName` and `SCIP`
(field-contract §2). Matching keys on the structured fields
`Package`/`Enclosing`/`Name`/`Descriptor` and **never on `SCIP`** — the `symbolform_guard_test.go`
contract carries forward unchanged.

**This struct has now landed on-branch** via the rebase onto `parity/platform` (PLAN-000):
`plugin.Symbol` is the comparable 8-field struct (`plugin/plugin.go:210`), and `SymbolKind`,
`OpResolveInventory`, and `DependencyInventory` all exist. What remains is *population*: the JS
producer still writes only `SCIP`/`DisplayName`/`Package` (`index.go:74-84`), so every structured
field below is an unpopulated slot the producer must start filling. This layer is the *target* those
fields reconcile to (tracked as PLAN-262), and the golden table asserts today's gap as xfail.

## JS/TS spelling decisions for the frozen fields

- **`Package`** carries the **module-path form** for first-party symbols (`"fetcher"`,
  `"util/fetcher"`), i.e. the same value the branch already populates — not an npm coordinate.
  Package-instance identity (a real `npm-name@version`) is still unavailable offline (the Layer-1
  `"."` limitation); only reading `node_modules` (**PLAN-260**) would supply it.
- **`Enclosing`** carries the class chain joined by `"."` outermost→innermost (`"Outer.Inner"`),
  per the frozen separator spec (§2). Note this differs from today's SCIP rendering, which joins
  class frames with `"#"` (`Outer#Inner#`).
- **`Descriptor`** carries the **arity** disambiguator (`"(1)"`, `"()"`). JS/TS has no by-type
  overloading, so arity is the JS spelling of the frozen `Descriptor` slot; §6 fills the same slot
  with `"(int)"` / `"<T>"` for Go. Stating this mapping explicitly: on the JS lane, arity moves out
  of the SCIP string and into the structured `Descriptor` field.
- **`Kind`** uses the frozen `SymbolKind` enum. There is no `module` kind — a module maps to
  `SymbolKindPackage`.
- **`Generated`** would be `false` for everything the JS scanner emits today (it has no
  decorator/transpiler/source-map awareness — Layer-1 category 8).

## The eight §4.3 categories → frozen `Symbol` (JS/TS spellings), with the population gap

The example literals are the *target* value. The gap column names which frozen fields the JS plugin
does **not** populate today — and today it populates only `SCIP`, `DisplayName`, and `Package`; the
structured fields `Kind`/`Enclosing`/`Name`/`Descriptor`/`Generated` now exist on the branch struct
(post-rebase) but are left unpopulated by the producer, so every structured field below is a
population gap. Populating them is the JS lane's
structured-field work (**PLAN-262** for the field values; the per-lane deterministic-population
invariant is **PLAN-2x2**), not this cycle.

| # | §4.3 category | Canonical target `Symbol{…}` (JS/TS) | Current → target population gap → owning cycle |
|---|---|---|---|
| 1 | packages / modules | `Symbol{Kind: SymbolKindPackage, Package: "util/fetcher"}` | `Package` is populated today (module-path form). `Kind` field exists (post-rebase) but is unpopulated, and no standalone package/module Symbol is emitted. npm package-instance identity still absent (Layer-1 `"."`). → `Kind`: PLAN-262 / PLAN-2x2. Package-instance identity: PLAN-260. |
| 2 | types (interface / type alias / enum) | `Symbol{Kind: SymbolKindType, Package: "util/fetcher", Name: "Fetchable"}` | **No Symbol emitted at all today** — `parseDecls` recognizes only `class` + function-like shapes, so the entire row is unpopulated (not just structured fields — the declaration itself is never recorded). → emitting type symbols + `Kind`/`Name`: PLAN-262 / PLAN-2x2. |
| 3 | functions | `Symbol{Kind: SymbolKindFunction, Package: "fetcher", Name: "fetchUrl", Descriptor: "(1)"}` | `Package` populated. `Kind`/`Name`/`Descriptor` not populated — name and arity live only inside the SCIP string and `DisplayName` today. → PLAN-262 / PLAN-2x2. |
| 4 | methods | `Symbol{Kind: SymbolKindMethod, Package: "util/fetcher", Enclosing: "Fetcher", Name: "fetch", Descriptor: "(1)"}` | `Package` populated. `Kind`/`Enclosing`/`Name`/`Descriptor` not populated — the enclosing class lives only as `Fetcher#` inside the SCIP string. → PLAN-262 / PLAN-2x2. |
| 5 | constructors | `Symbol{Kind: SymbolKindConstructor, Package: "util/fetcher", Enclosing: "Fetcher", Name: "constructor", Descriptor: "(1)"}` | Not distinguished from a method today — the only marker is the literal `Name` `constructor` embedded in the SCIP string; there is no `Kind`. Under the frozen contract `Kind: SymbolKindConstructor` is the distinguisher, and populating it requires recognizing the constructor. → PLAN-262 / PLAN-2x2. |
| 6 | overloads / generics | `Symbol{Kind: SymbolKindMethod, Package: "util/box", Enclosing: "Box", Name: "map", Descriptor: "(1)"}` | Generic params lexically skipped (never recorded); ambient overload signatures not recorded (only the implementation); `Descriptor` not a structured field. Even in the target, two same-arity overloads collapse to one value unless a richer `Descriptor` is populated. §6 fills `Descriptor` with a type descriptor (`"<T>"`/`"(int)"`); the JS lane fills it with arity `"(1)"`, since type-resolved descriptors would need a resolver the scanner does not have. → `Descriptor` (arity): PLAN-262 / PLAN-2x2; type-resolved descriptors: out of scope (no resolver). |
| 7 | nested declarations | Nested type: `Symbol{Kind: SymbolKindType, Package: "util/nest", Enclosing: "Outer", Name: "Inner"}`; nested method: `Enclosing: "Outer.Inner"` | Nested classes are captured today (as `Outer#Inner#` inside SCIP) but `Enclosing` is not a structured field. A function nested in another function's body is qualified only by class frames, so two same-name/same-arity closures still collapse to one identical `Symbol` even in the target — the frozen `Enclosing` is a *type/decl* chain (§2) and does not capture function-scope nesting. → `Enclosing` population: PLAN-262 / PLAN-2x2; closure-scope disambiguation: not specified by the frozen contract. |
| 8 | generated symbols | `Symbol{Kind: SymbolKindFunction, Package: "ui/widget", Name: "…", Generated: true}` | `Generated` is not a field today and would always be `false` — the scanner has no decorator/transpiler/source-map awareness (Layer-1 category 8), so it neither synthesizes nor flags a generated symbol. → detecting generated symbols + setting `Generated`: PLAN-262 / PLAN-2x2 (decorator/source-map awareness needs more than a lexical scan). |

## `DisplayName` and `SCIP`: the two frozen fields JS already populates

Of the eight frozen fields, `DisplayName` and `SCIP` are the two the JS plugin populates on every
first-party `Symbol` today (`index.go:69-88`). Under the frozen contract they remain
rendering/bridge fields — projected into the report at the flatten seam and read as the reachability
sink id — but they are **not** the matching identity: matchers key on
`Package`/`Enclosing`/`Name`/`Descriptor`, never `SCIP` (field-contract §2, preserving the
`symbolform_guard_test.go` contract already documented in Layer 1). So the migration for the JS lane
is: keep emitting `DisplayName`/`SCIP` as today, and additionally populate the structured fields the
branch struct does not yet carry.

## Dependency-artifact indexer → `OpResolveInventory` (Unsupported today)

The frozen contract adds the `OpResolveInventory` wire op returning a `DependencyInventory`
(field-contract §5). The JS plugin has **no dependency-artifact indexer** — `skipDir` excludes
`node_modules` from every walk (`index.go:141-147`), and no code path reads a dependency's own
source or emits a `Symbol` for a dependency's declarations. Under the frozen contract the JS plugin
must therefore return `DependencyInventory{Partiality: Partial(PartialReasonUnsupported)}` — an
explicit Unsupported partiality, **never** an empty-but-successful inventory (which reads downstream
as "this build has no dependencies", §5). Actually resolving a JS dependency inventory is
**PLAN-260** (reading `node_modules`); this cycle only records the mapping.
