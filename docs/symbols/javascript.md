# JavaScript / TypeScript symbol profile

This page says exactly which source constructs the JS/TS engine turns into a symbol, what the
symbol looks like, and — just as important — which constructs it does *not* distinguish or emit. It
is meant to be read alongside the code: every claim here is traceable to
`internal/plugin/jsanalysis`.

The symbol indexer is an offline, dependency-free lexical scanner. It never runs Node and never
type-resolves, and it does not walk `node_modules` when it indexes first-party symbols (`skipDir` in
`index.go`). That posture is deliberate — the canonical TS indexer (`scip-typescript`) needs Node, a
resolved `tsconfig` and installed `node_modules`, none of which is available offline in CI. The
limitations below are consequences of scanning raw source without a type resolver; where a construct
needs type resolution to disambiguate, the engine declares partiality rather than over-claim an
identity it did not resolve.

Other parts of the JS lane do read dependency state: dependency inventory, version exhaustiveness and
package-boundary call edges. [Dependency state the lane reads](#dependency-state-the-lane-reads)
covers them.

## Two layers: read them separately

This document has two layers, and a reader must always know which is which:

- **Layer 1 — What the engine emits.** The `scipSymbol` grammar, four literal example strings, and
  the honest limitations. The indexer populates `SCIP`, `DisplayName` and `Package` on every
  `Symbol` (`symbolsFromParse` in `index.go`).
- **Layer 2 — Canonical `plugin.Symbol` mapping.** How the eight §4.3 categories map onto the
  comparable 8-field `plugin.Symbol`, in JS/TS spellings, and which structured fields the indexer
  leaves unpopulated. The cross-producer golden table
  (`internal/plugin/jsanalysis/symbolprofile_golden_test.go`) asserts each unpopulated field as an
  xfail row that flips red the moment the producer closes it.

---

# Layer 1 — What the engine emits

## The symbol string

Every first-party symbol is built by `scipSymbol(module, enclosing, descriptor)` (`scip.go`),
which emits, space-separated:

```
scip-typescript npm <package> <version> <module>/<Class#…><descriptor>
```

- `scip-typescript npm` — the fixed manager token (`scipManager`), kept so IDs are recognizable to
  SCIP tooling.
- `<package>` and `<version>` — **both the literal `"."`** (`localCoordinate`, written twice by
  `scipSymbol`).
- `<module>/` — the source file's path relative to the build root, `/`-joined, extension stripped,
  `/`-terminated (`moduleDescriptor` in `scip.go`; `moduleOf` in `index.go`). An empty
  module renders `_root_/`.
- `<Class#…>` — one `Name#` type descriptor per enclosing class frame, outermost first.
- `<descriptor>` — the trailing per-declaration descriptor. For functions and methods this is
  arity-disambiguated: `name().` for zero params, `name(N).` otherwise (`functionDescriptor` in `scip.go`). For a class declaration itself it is just `Name#`.

## Every symbol's package coordinate and version are `"."` — there is no package-instance identity

`scipSymbol` writes `localCoordinate` (the literal `"."`) for **both** the package coordinate and
the version, unconditionally, on every symbol it produces. No code path substitutes a resolved npm
name or a resolved version into the symbol string. The practical consequence: **no JS/TS symbol
carries package-instance identity.** Two functions with the same name and arity in the same module
path are indistinguishable across package boundaries, because the coordinate and version that would
separate them are the same placeholder for everything. Version *resolution* from lockfiles and
installed copies is a separate capability (`ResolveDependencyVersions`), and those resolved versions
never reach the symbol string. This page records the limitation.

## SCIP is the identity space; DisplayName is the advisory-match space

Two distinct string spaces travel on a `plugin.Symbol`, and they are not interchangeable. The SCIP
string above is the **identity** — it is what the first-party indexer, the call-graph builder, and
ingress discovery all agree on by construction (all three route through `scipSymbol`). Advisory
matching (`jsSymbolMatches` in `ingress.go`) is a **separate** space: it compares an advisory
identifier only against forms derived from `Symbol.DisplayName` (bare name, package-qualified,
module-leaf-qualified, arity-tolerant) and **never reads `Symbol.SCIP`**. That asymmetry is
guard-pinned (`symbolform_guard_test.go`), including a negative assertion that matching on the SCIP
string itself must return false. If you are populating an advisory corpus, you target DisplayName
forms, not SCIP strings.

## The eight symbol categories (as emitted)

One row per category. The example strings are literal `scipSymbol` output. Only the `fetchUrl`
example corresponds to an on-disk corpus fixture
(`FERRALON-JS-SSRF-0001-vulnerable/src/fetcher.js`); the rest are grammar-derived traces of the code
path (there is no class in the current corpus fixtures), each constructed to match `scipSymbol`'s
emitted form exactly.

| # | §4.3 category | Distinguished / emitted? | Canonical example symbol string |
|---|---|---|---|
| 1 | packages / modules | **Module: yes. npm package instance: no.** The module path is carried as the namespace descriptor prefix (`fetcher/`, `util/fetcher/`). No standalone symbol is emitted for the module itself — module identity exists only as the prefix on member symbols. The npm package coordinate and version are the literal `"."` (see the `"."` limitation above), so no package-instance identity exists in the symbol. | `scip-typescript npm . . fetcher/fetchUrl(1).` (the `fetcher/` segment is the module; the two `.` tokens are the absent package + version) |
| 2 | types (interface / type alias / enum) | **No — not distinguished, and not emitted at all.** `parseDecls` (`parser.go`) recognizes only the `class` keyword and function-like shapes; it has no handling for `interface`, `type` aliases, or `enum`. No declaration of any kind is recorded for a TS type. | *not emitted* — the engine produces no symbol for a TS `interface`, `type` alias, or `enum` |
| 3 | functions | **Yes.** A module-level function (empty enclosing chain) yields a namespace-qualified, arity-disambiguated descriptor. | `scip-typescript npm . . fetcher/fetchUrl(1).` |
| 4 | methods | **Yes.** A class method carries one `Class#` type descriptor per enclosing class frame. | `scip-typescript npm . . util/fetcher/Fetcher#fetch(1).` |
| 5 | constructors | **No — not distinguished from an ordinary method.** `methodDeclAt` (`parser.go`) has no special case for the name `constructor`; it parses identically to any other method (same `kindFunc`, same `enclosing`, arity-disambiguated). Only the literal name `constructor` in the descriptor marks it. | `scip-typescript npm . . util/fetcher/Fetcher#constructor(1).` |
| 6 | overloads / generics | **No — not distinguished; arity is the only disambiguator.** Generic type params (`<…>`) are lexically skipped and never recorded (`parser.go`). A TS ambient overload *signature* (no body, ends in `;`) is not recorded as a decl at all — only the implementation (which has a body) is captured — so multiple same-arity overloads collapse to one symbol. | `scip-typescript npm . . util/box/Box#map(1).` (a generic `map<T>(fn)` — the `<T>` is absent; any same-arity overload signatures collapse into this one id) |
| 7 | nested declarations | **Partial.** A class nested inside a class **is** distinguished — `classChain()` (`parser.go`) walks every active class frame, so each becomes a `Class#` descriptor. But `enclosing` is built from class frames *only*: a function declared inside another function's body is qualified only by whatever class frames (if any) surround it, **not** by its enclosing function. Two same-name, same-arity functions at different function-nesting depths in the same (or no) class therefore produce the **identical** SCIP id — a real collision, not merely an undistinguished category. TS `namespace X {}` is not recognized at all. | Nested class, distinguished: `scip-typescript npm . . util/nest/Outer#Inner#run().` — Colliding closures: two `parse(x)` at different function-nesting depths both emit `scip-typescript npm . . util/helpers/parse(1).` |
| 8 | generated symbols (decorator / transpiler / source-mapped) | **No — not handled at all.** The scanner reads raw, un-transpiled source with no source-map awareness and no decorator parsing (`parser.go` has zero decorator-specific logic). It has no notion of "generated" vs. "authored" — it emits only what is literally written in the source. | *not emitted* — for `@Component class Widget {}` the engine emits only the authored class `scip-typescript npm . . ui/widget/Widget#` and ignores the decorator; nothing is emitted for decorator- or transpiler-generated members |

## What this means in practice

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

# Layer 2 — Canonical `plugin.Symbol` mapping

`plugin.Symbol` (`plugin/plugin.go`) is a **comparable** struct whose every field is a scalar, so it
stays usable as a map key, `==` operand and array element. Its eight fields are `Kind` (a
`SymbolKind`: `package`/`type`/`function`/`method`/`constructor`/`field`), `Package`, `Enclosing` (the
enclosing type/decl chain joined by `"."`, outermost→innermost), `Name`, `Descriptor`
(overload/generic/arity disambiguator), `Generated` (bool), plus the two rendering/bridge fields
`DisplayName` and `SCIP`. Matching keys on the structured fields
`Package`/`Enclosing`/`Name`/`Descriptor` and **never on `SCIP`**, as `symbolform_guard_test.go`
pins.

The JS indexer populates only `SCIP`, `DisplayName` and `Package`. Every structured field below
(`Kind`, `Enclosing`, `Name`, `Descriptor`, `Generated`) is an unpopulated slot.

## JS/TS spelling decisions for the structured fields

- **`Package`** carries the **module-path form** for first-party symbols (`"fetcher"`,
  `"util/fetcher"`) — not an npm coordinate. Package-instance identity (a real `npm-name@version`)
  is not part of the symbol (the Layer-1 `"."` limitation).
- **`Enclosing`** carries the class chain joined by `"."` outermost→innermost (`"Outer.Inner"`),
  per the `plugin.Symbol` separator spec (§2). Note this differs from the SCIP rendering, which joins
  class frames with `"#"` (`Outer#Inner#`).
- **`Descriptor`** carries the **arity** disambiguator (`"(1)"`, `"()"`). JS/TS has no by-type
  overloading, so arity is the JS spelling of the `Descriptor` slot; §6 fills the same slot
  with `"(int)"` / `"<T>"` for Go. Stating this mapping explicitly: on the JS lane, arity moves out
  of the SCIP string and into the structured `Descriptor` field.
- **`Kind`** uses the `SymbolKind` enum. There is no `module` kind — a module maps to
  `SymbolKindPackage`.
- **`Generated`** is `false` for everything the JS scanner emits (it has no
  decorator/transpiler/source-map awareness — Layer-1 category 8).

## The eight §4.3 categories → `Symbol` (JS/TS spellings), with the population gap

The example literals are the canonical value for each row. The gap column names which fields the JS
plugin does **not** populate: it populates only `SCIP`, `DisplayName` and `Package`, so every
structured field below is a gap.

| # | §4.3 category | Canonical target `Symbol{…}` (JS/TS) | Population gap |
|---|---|---|---|
| 1 | packages / modules | `Symbol{Kind: SymbolKindPackage, Package: "util/fetcher"}` | `Package` is populated (module-path form). `Kind` is unpopulated, and no standalone package/module Symbol is emitted. npm package-instance identity still absent (Layer-1 `"."`). |
| 2 | types (interface / type alias / enum) | `Symbol{Kind: SymbolKindType, Package: "util/fetcher", Name: "Fetchable"}` | **No Symbol is emitted** — `parseDecls` recognizes only `class` + function-like shapes, so the entire row is unpopulated (not just structured fields — the declaration itself is never recorded). |
| 3 | functions | `Symbol{Kind: SymbolKindFunction, Package: "fetcher", Name: "fetchUrl", Descriptor: "(1)"}` | `Package` populated. `Kind`/`Name`/`Descriptor` not populated — name and arity live only inside the SCIP string and `DisplayName`. |
| 4 | methods | `Symbol{Kind: SymbolKindMethod, Package: "util/fetcher", Enclosing: "Fetcher", Name: "fetch", Descriptor: "(1)"}` | `Package` populated. `Kind`/`Enclosing`/`Name`/`Descriptor` not populated — the enclosing class lives only as `Fetcher#` inside the SCIP string. |
| 5 | constructors | `Symbol{Kind: SymbolKindConstructor, Package: "util/fetcher", Enclosing: "Fetcher", Name: "constructor", Descriptor: "(1)"}` | Not distinguished from a method — the only marker is the literal `Name` `constructor` embedded in the SCIP string; there is no `Kind`. `Kind: SymbolKindConstructor` is the distinguisher, and populating it requires recognizing the constructor. |
| 6 | overloads / generics | `Symbol{Kind: SymbolKindMethod, Package: "util/box", Enclosing: "Box", Name: "map", Descriptor: "(1)"}` | Generic params lexically skipped (never recorded); ambient overload signatures not recorded (only the implementation); `Descriptor` not a structured field. Even in the target, two same-arity overloads collapse to one value unless a richer `Descriptor` is populated. §6 fills `Descriptor` with a type descriptor (`"<T>"`/`"(int)"`); the JS lane fills it with arity `"(1)"`, since type-resolved descriptors would need a resolver the scanner does not have. |
| 7 | nested declarations | Nested type: `Symbol{Kind: SymbolKindType, Package: "util/nest", Enclosing: "Outer", Name: "Inner"}`; nested method: `Enclosing: "Outer.Inner"` | Nested classes are captured (as `Outer#Inner#` inside SCIP) but `Enclosing` is not a structured field. A function nested in another function's body is qualified only by class frames, so two same-name/same-arity closures still collapse to one identical `Symbol` even in the target — `Enclosing` is a *type/decl* chain (§2) and does not capture function-scope nesting. |
| 8 | generated symbols | `Symbol{Kind: SymbolKindFunction, Package: "ui/widget", Name: "…", Generated: true}` | `Generated` is never set and would always be `false` — the scanner has no decorator/transpiler/source-map awareness (Layer-1 category 8), so it neither synthesizes nor flags a generated symbol. |

## `DisplayName` and `SCIP`: the two bridge fields JS populates

`DisplayName` and `SCIP` are the two fields the JS plugin populates on every first-party `Symbol`
(`symbolsFromParse` in `index.go`). They are rendering/bridge fields — projected into the report at
the flatten seam and read as the reachability sink id — but they are **not** the matching identity:
matchers key on `Package`/`Enclosing`/`Name`/`Descriptor`, never `SCIP`
(`symbolform_guard_test.go`). The mapping above is the target for the structured fields; the lane
keeps emitting `DisplayName`/`SCIP` and populating the structured fields adds to them.

## Dependency state the lane reads

The symbol indexer's `skipDir` excludes `node_modules` (and `dist`, `build`, `out`, `coverage`,
`vendor`, `.git` and dot-directories) from the first-party source walk, and no code path emits a
`Symbol` for a dependency's own declarations. Three other capabilities do read dependency state:

- **`ResolveInventory`** (`inventory.go`) is implemented from committed lockfile and manifest
  metadata. It selects one authoritative lockfile per project root among `package-lock.json`,
  `npm-shrinkwrap.json`, `yarn.lock` and `pnpm-lock.yaml`; two dialects with no signal to choose
  between them are declared `lockfile_ambiguous` and never merged. A root with neither a lockfile
  nor a `package.json` yields a declared absence rather than an empty-but-successful inventory.
- **Version exhaustiveness** (`versions_surfaces.go`, `exhaustive.go`) reads installed copies under
  `node_modules`, including scoped packages, nested `node_modules` and pnpm's `.pnpm/<id>/node_modules`.
- **Package-boundary call edges** (`boundary.go`) record `npm:` boundary edges for calls into
  dependencies, using the resolver's `tsconfig` `paths` aliases to tell a first-party import from a
  package import (`resolve.go`).

None of these put an npm coordinate or version into a symbol string; the Layer-1 `"."` limitation
stands.
