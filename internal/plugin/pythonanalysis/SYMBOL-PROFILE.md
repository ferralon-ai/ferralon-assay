# Python canonical symbol profile (PLAN-070 C1/C2)

The canonical symbol specification for the Python lane, in the format the
`plugin/symboltest` golden-equality harness fixes (PLAN-006). It names, for each of
the eight §4.3 declaration categories, the Python construct that carries it, the
fully-structured canonical `plugin.Symbol` a conformant producer must emit, and what
the current first-party scanner actually emits today.

The executable companion is `symbol_profile_test.go`: `pythonProfile()` binds the
eight categories to constructs in `testdata/symbolprofile/mod.py`, and
`TestPythonSymbolGolden` drives it against the real `IndexSymbols` producer. Every row
is a declared `KnownGap` today, so the golden is **GREEN under xfail semantics** — the
gaps are real, exactly where declared. This supersedes the pre-PLAN-006 "deliberately
red golden table": under the shipped harness a correctly-declared open gap is GREEN;
RED is reserved for a *silent closure* (a gap declared here that the producer has
started to fill — promote the row) or a *regression*. `PLAN-272` (Python first-party
structured symbol identity) is the cycle that turns these gaps green.

All identifiers below are **observations**, reproduced by:

```
go test ./internal/plugin/pythonanalysis/ -run TestPythonSymbolGolden -v -count=1
```

which logs every emitted symbol. No target code is executed; the scanner reads the
fixture source only.

## Structured identity vs. the SCIP wire id

Golden equality keys on the **structured-identity** projection
`{Kind, Package, Enclosing, Name, Descriptor, Generated}`; `SCIP` and `DisplayName`
are diagnostic-only and excluded (`symboltest/profile.go` `IdentityKey`). The Python
scanner (`symbolsFromParse`, [index.go:96-115](index.go); `sym()`,
[callgraph.go:85](callgraph.go)) populates only `SCIP`, `DisplayName`, and `Package`:
it encodes the enclosing-class chain and arity **into the SCIP string**
(`mod/Widget#render(1).`) but leaves `Kind`, `Enclosing`, `Name`, `Descriptor`, and
`Generated` zero. So no emitted symbol matches any structured `Want` — the whole
profile is one open gap set, and that is the honest current state.

## The eight categories

Each section gives the Python construct, the canonical `Want`, and the observed
first-party emission (`SCIP` — `DisplayName`).

1. **packages/modules** — the module clause of `mod.py`, import path `mod`.
   Canonical `Want`: `{Kind: package, Package: "mod"}`.
   Observed: **no standalone module symbol is emitted**; the module appears only as the
   SCIP namespace descriptor prefix `mod/` on member symbols. Gap: no `Kind:package`
   symbol (`GAP-STRUCT`, PLAN-272).

2. **types** — `class Widget`.
   Canonical `Want`: `{Kind: type, Package: "mod", Name: "Widget"}`.
   Observed: `scip-python python . . mod/Widget#` — `Widget`. Gap: `GAP-STRUCT`.

3. **functions** — module-level `def build`.
   Canonical `Want`: `{Kind: function, Package: "mod", Name: "build"}`.
   Observed: `mod/build(1).` — `build(1)`. Gap: `GAP-STRUCT`.

4. **methods** — `Widget.render`.
   Canonical `Want`: `{Kind: method, Package: "mod", Enclosing: "Widget", Name: "render"}`.
   Observed: `mod/Widget#render(1).` — `Widget.render(1)`. The enclosing class lives in
   the SCIP string; the `Enclosing` field is empty. Gap: `GAP-STRUCT`.

5. **constructors** — `Widget.__init__` (Python's constructor idiom).
   Canonical `Want`: `{Kind: constructor, Package: "mod", Enclosing: "Widget", Name: "__init__"}`.
   Observed: `mod/Widget#__init__(2).` — `Widget.__init__(2)`, emitted as an ordinary
   method with no constructor discriminator (arity 2 counts the bound `self`). Gap:
   `Kind` not marked `constructor` (`GAP-STRUCT`, PLAN-272).

6. **overloads/generics** — `typed_get` (two `@overload` arms + a `TypeVar` target).
   Canonical `Want`: `{Kind: function, Package: "mod", Name: "typed_get", Descriptor: "[T]"}`.
   Observed: **all three declarations collapse to one identical symbol** `mod/typed_get(1).`
   — `typed_get(1)`, emitted three times. The scanner disambiguates same-named
   declarations by arity alone and carries no signature or type-argument descriptor, so
   the overload arms and the implementation are indistinguishable. Gap: `GAP-COLLAPSE`
   (PLAN-272).

7. **nested declarations** — `class Config` nested under `Widget`.
   Canonical `Want`: `{Kind: type, Package: "mod", Enclosing: "Widget", Name: "Config"}`.
   Observed: `mod/Widget#Config#` — `Widget.Config`. The nesting chain is captured in the
   SCIP string; the `Enclosing` field is empty. Gap: `GAP-STRUCT`.

8. **generated symbols** — the `functools.wraps` wrapper over `traced`.
   Canonical `Want`: `{Kind: function, Package: "mod", Name: "traced", Generated: true}`.
   Observed: the synthesized wrapper is emitted as a **distinct, unmarked** symbol
   `mod/wrapper(2).` — `wrapper(2)`, and `traced` is emitted separately as `mod/traced(1).`.
   The lexical scanner sees `def wrapper` literally; it neither recognizes that
   `functools.wraps` copies `traced`'s identity onto the wrapper nor marks any symbol
   `Generated`. Gap: `GAP-GENERATED` (PLAN-272).

## Cross-producer golden table

One row per §4.3 category × §4.3 producer. **No cell is blank**: each holds either the
identifier the producer emits today or a reason code for why it does not. Reason codes:

- `GAP-STRUCT` — producer exists and emits the symbol, but leaves the structured
  identity fields unpopulated (`SCIP`/`DisplayName` only). Closed by PLAN-272.
- `GAP-COLLAPSE` — same-named declarations collapse to one identifier (arity-only
  disambiguation, no signature/type descriptor). Closed by PLAN-272.
- `GAP-GENERATED` — a synthesized symbol is not recognized or marked `Generated`.
  Closed by PLAN-272.
- `NA-PRODUCER` — the producer does not exist for Python yet: the **dependency artifact
  indexer** is PLAN-270; **advisory symbol normalization** is PLAN-272.
- `NA-CATEGORY` — the producer structurally never emits this category (the call-graph
  builder's nodes are callables, not packages/types; ingress discovery emits only
  framework entry points). An honest structural absence, not a gap to close.

| category | first-party indexer | dependency artifact indexer | advisory symbol normalization | call-graph builder | ingress discovery |
|---|---|---|---|---|---|
| packages/modules | `GAP-STRUCT` (no `Kind:package` symbol; only the `mod/` namespace prefix) | `NA-PRODUCER` (PLAN-270) | `NA-PRODUCER` (PLAN-272) | `NA-CATEGORY` | `NA-CATEGORY` |
| types | `mod/Widget#` `GAP-STRUCT` | `NA-PRODUCER` (PLAN-270) | `NA-PRODUCER` (PLAN-272) | `NA-CATEGORY` | `NA-CATEGORY` |
| functions | `mod/build(1).` `GAP-STRUCT` | `NA-PRODUCER` (PLAN-270) | `NA-PRODUCER` (PLAN-272) | `mod/build(1).` `GAP-STRUCT` | `NA-CATEGORY` (unless decorated as a route) |
| methods | `mod/Widget#render(1).` `GAP-STRUCT` | `NA-PRODUCER` (PLAN-270) | `NA-PRODUCER` (PLAN-272) | `mod/Widget#render(1).` `GAP-STRUCT` | `NA-CATEGORY` (unless a route handler) |
| constructors | `mod/Widget#__init__(2).` `GAP-STRUCT` (no constructor `Kind`) | `NA-PRODUCER` (PLAN-270) | `NA-PRODUCER` (PLAN-272) | `GAP-STRUCT` | `NA-CATEGORY` |
| overloads/generics | `mod/typed_get(1).` ×3 `GAP-COLLAPSE` | `NA-PRODUCER` (PLAN-270) | `NA-PRODUCER` (PLAN-272) | `GAP-COLLAPSE` | `NA-CATEGORY` |
| nested declarations | `mod/Widget#Config#` `GAP-STRUCT` | `NA-PRODUCER` (PLAN-270) | `NA-PRODUCER` (PLAN-272) | `NA-CATEGORY` | `NA-CATEGORY` |
| generated symbols | `mod/wrapper(2).` `GAP-GENERATED` | `NA-PRODUCER` (PLAN-270) | `NA-PRODUCER` (PLAN-272) | `GAP-GENERATED` | `NA-CATEGORY` |

## Findings surfaced by the fixture

- **Overload collapse.** The three `typed_get` declarations (two `@overload` arms + the
  implementation) emit three byte-identical `mod/typed_get(1).` symbols. A naive golden
  or a positives-only suite would not reveal that overloads are indistinguishable today;
  PLAN-272's signature/type descriptor is what separates them.
- **`functools.wraps` invisibility.** The synthesized `wrapper` is a distinct, unmarked
  symbol; the scanner does not fold it onto `traced` nor flag it `Generated`. Any
  generated-symbol handling is PLAN-272 / later reachability work.
- **No module symbol.** The first-party indexer emits no standalone `Kind:package`
  symbol; a module is only a namespace descriptor prefix on its members.
