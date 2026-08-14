# .NET canonical symbol profile

**Cycle:** `PLAN-051_dotnet-symbol-profile-goldens` (Phase 0). **Status:** specification only —
this document fixes the *target* spelling; the analyzer does not emit it yet (that is `PLAN-252`).
`internal/plugin/dotnetanalysis/` behavior is unchanged by this cycle (C5).

This is the .NET row of §4.3's "publish and test a canonical symbol profile per language." It is a
**`plugin.Symbol` struct-field population contract**, not a SCIP string grammar. Five producers —
first-party indexer, dependency-artifact indexer (`PLAN-250`), advisory symbol normalization
(`PLAN-220`), call-graph builder (`PLAN-350`), ingress discovery (`PLAN-352`) — must emit the **same
struct-field values** for the same declaration. Matching keys on the structured fields
`Package` / `Enclosing` / `Name` / `Descriptor` / `Kind`; **never** on `SCIP` or `DisplayName`
(those are rendering/bridge fields — PLAN-000 `field-contract.md` §2, `symbolform_guard_test`
contract).

The frozen `plugin.Symbol` (PLAN-000 `field-contract.md` §2 — quoted field names/tags, not
re-derived):

```go
type Symbol struct {
    Kind        SymbolKind // package|type|function|method|constructor|field
    Package     string     // module coordinate
    Enclosing   string     // enclosing chain, segments joined by "." (U+002E), outermost→innermost
    Name        string     // member name; empty for a package Symbol
    Descriptor  string     // overloads/generics signature / type-arg descriptor
    Generated   bool       // true for compiler-synthesized symbols
    DisplayName string     // human rendering (bridge — NOT matched)
    SCIP        string     // self-emitted SCIP id (bridge — NOT matched)
}
```

The machine-checkable half of this profile — one hand-written value per §4.3 category, all
pairwise-distinct under the match key, plus the C3 overload mutation control — lives in
[`symbols_profile_fixtures_test.go`](./symbols_profile_fixtures_test.go) and runs green today.

---

## Field population rules (.NET)

### `Package` — Decision A (nickel, `barrier-decisions-A-B.md`): versionless NuGet coordinate

`Package = "pkg:nuget/<coordinate>"` — the **bare NuGet coordinate, NO `@version`**.

- **First-party** code fills `<coordinate>` from the build's own identity: the `.csproj` `PackageId`,
  falling back to `AssemblyName` when application code declares no `PackageId`. Source: `.csproj` /
  MSBuild props (**S**) or assembly metadata (**M**) — never Roslyn.
- **Dependency-artifact** code (`PLAN-250`) fills `<coordinate>` from the resolved package's NuGet id.
- **Advisory** records (`PLAN-220`, from `PLAN-050`'s landed shape) already carry
  `Coordinate: "Newtonsoft.Json"` / `PURL: "pkg:nuget/Newtonsoft.Json"`, versionless.

**Why versionless.** Version is *not* symbol identity here — it is the disqualification axis, resolved
separately in `versions.go` (`.csproj` pin vs. advisory `UpperExclusive`/`AffectedRanges`). If identity
carried `@version`, the version-independent advisory producer could never equal a resolved dependency's
`Symbol`, and §8.5 ("first-party and dependency share one symbol space") would fail on the very producer
that drives reachability. This also matches the Go convention in the frozen contract (`Package` =
`golang.org/x/text`, no version).

**Worked example (C2 forward + advisory match).** Declaration
`Newtonsoft.Json.JsonConvert.SerializeObject(object)`:

| Producer | `Package` | `Enclosing` | `Name` | `Descriptor` | `Kind` |
|---|---|---|---|---|---|
| first-party build of Newtonsoft | `pkg:nuget/Newtonsoft.Json` | `Newtonsoft.Json.JsonConvert` | `SerializeObject` | `(object)` | method |
| dependency-artifact indexer | `pkg:nuget/Newtonsoft.Json` | `Newtonsoft.Json.JsonConvert` | `SerializeObject` | `(object)` | method |
| advisory normalization | `pkg:nuget/Newtonsoft.Json` | `Newtonsoft.Json.JsonConvert` | `SerializeObject` | `(object)` | method |

All three are **equal** under the match key. ✓

**Worked example (C2 reverse — over-normalization guard).** A **vendored** copy of
`Newtonsoft.Json.JsonConvert` compiled directly into application `MyApp` emits
`Package = "pkg:nuget/MyApp"` — **distinct** from the dependency copy's `pkg:nuget/Newtonsoft.Json`.
The coordinate carries the physical-assembly distinction; dropping the version does not weaken it
(the distinction is the *id*, not the version). A rule that normalized the coordinate away (rejected
option A1) would collapse these two and fail C2 in reverse.

**Two more worked micro-cases.**
- **Multi-targeted project** (`net8.0` + `netstandard2.0` in one `.csproj`): the TFM is **not** part of
  the coordinate (`PackageId`/`AssemblyName` carry no TFM), so both targets emit the **same** `Package`
  and correctly **collapse to one** symbol — a type is one identity regardless of how many frameworks it
  is built for.
- **`PackageId` ≠ `AssemblyName`:** `PackageId` **wins**; `AssemblyName` is the fallback **only** for
  unpublished application code that declares no `PackageId` (which is never consumed as a dependency, so
  the fallback cannot desync from a dependency indexer's nupkg id).

**Rejected:** A1 (normalize the coordinate away) over-normalizes — makes a vendored copy equal to the
dependency — and needs a separate compare-key field; A3 (split display/compare key) needs a new
`Symbol` field, and `plugin/plugin.go` is reserved to `PLAN-000` (spine §3.4).

### `Enclosing` — namespace + enclosing-type chain, `.`-joined, outermost→innermost

.NET namespaces are **not** independent `Symbol`s — a namespace has no `Kind` of its own; it is the
**leading segments of a type's `Enclosing`**. For `Newtonsoft.Json.JsonConvert`: `Enclosing =
"Newtonsoft.Json"`, `Name = "JsonConvert"`. For a member, `Enclosing` is namespace + containing
type(s): `SerializeObject` on that type has `Enclosing = "Newtonsoft.Json.JsonConvert"`. Nested types
append the outer type: `MyApp.Outer.Inner` → `Enclosing = "MyApp.Outer"`, `Name = "Inner"`.

The `.` separator does not mark the namespace/type boundary, but identity holds regardless: both
producers reconstruct the **same joined string** (source knows `namespace`/`class` syntactically;
metadata knows the namespace prefix and the nested-class relation). Determinism is what matters, and
it holds.

### `Descriptor` — Decision B (nickel): canonical short-name parameter list

`Descriptor = [generic-segment] "(" + comma-joined canonical param-type names + ")"`. A zero-parameter
method has `Descriptor = "()"`. A non-generic, non-overloaded type has `Descriptor = ""`.

**Canonical type-name form (the one load-bearing rule).** A parameter type is spelled as the
**C# keyword for the built-in types** (`string`, `int`, `object`, `bool`, …) **and the
namespace-stripped short name for all others** (`Type`, `List`, `JsonSerializerSettings`). This is
derivable from C# **source text syntactically** — the source scanner does not resolve `using` imports
to full namespaces (which would need a Roslyn semantic model and silently answer Open Question 2). The
metadata producer strips its namespaces to match: `System.String` → `string`, `System.Type` → `Type`.

**Lexical `using`-alias expansion (stated rule, not a boundary).** A file-scope `using X = A.B.C;`
alias is **expanded lexically** — by reading the file's own `using` directives (a local, file-local
directive lookup, **not** a semantic model) — before the short name is taken, so a parameter written
`X` and one written `C` both canonicalize to `C`. This makes the source producer emit the same short
name the metadata producer does (metadata never sees the alias, only the aliased type), closing an
otherwise-silent source/metadata mismatch. Because aliases are resolvable file-locally, this is a
**stated rule** (C6-safe, no Roslyn) — unlike the cross-namespace short-name collision below, which is
*not* resolvable file-locally and therefore remains a declared boundary.

**Modifier spellings (exact tokens):**

| Construct | Spelling | Example param | Token in `Descriptor` |
|---|---|---|---|
| generic **method** arity segment | backtick-arity `` `N `` (`N` = type-param count), prefixed; **no names** | `T Cast<T>(object)` | `` `1(object) `` |
| **parameter typed as a type-parameter** | positional index: method type-param *i* → `!!i`, containing-type type-param *i* → `!i` (0-based, declaration order) | `T Cast<T>(T x)` | `` `1(!!0) `` |
| constructed generic **type** as a param | short-name-parameterized, recursively canonical; a type-param arg goes positional (`List<!!0>`) | `List<string> xs` | `(List<string>)` |
| `ref` / `out` / `in` | leading token on the param type, space-separated | `ref int x` | `(ref int)` |
| array rank | `[]`, `[,]`, `[,,]`, … (rank = commas + 1) | `int[,] grid` | `(int[,])` |
| value-type nullable (`Nullable<T>`) | `?` suffix | `int? n` | `(int?)` |
| reference-type nullable annotation | **erased** to the non-nullable short name | `string? s` | `(string)` |

**Generic identity is positional/arity, NOT type-parameter names (nickel, barrier Decision B
correction 2026-08-06).** The generic segment is the **backtick-arity `` `N ``** (ECMA-335 convention):
`Foo<T>(…)` → `` `1 ``, `Foo<T,U>(…)` → `` `2 ``, a non-generic method has no segment. Ordering holds:
`Foo<T,U>(…)` ≠ `Foo<T>(…)` ≠ non-generic `Foo(…)`. A generic **type declaration** (open) carries
**arity only, no names**: `class Cache<TKey,TValue>` → `Name = "Cache"`, `Descriptor = "`2"`. A
**parameter whose type IS a type-parameter** is spelled by positional index — method type-parameter *i*
(0-based, declaration order) → `!!i`, containing-type type-parameter *i* → `!i` — recursively canonical
inside a constructed generic (`List<TSource>` where `TSource` is method type-param 0 → `List<!!0>`).
Example: `TResult Map<TSource,TResult>(TSource src)` → `Name = "Map"`, `Descriptor = "`2(!!0)"` (arity
2; the parameter is method type-param 0). Concrete generic arguments that are ordinary types keep their
short name (`List<string>`); only type-*parameters* go positional.

**Why positional, not the names.** Type-parameter *names* are **not** part of identity: C# forbids
overloading on type-param name, an override or interface-implementation may **rename** them
(`ICache.Get<T>` implemented as `Get<U>` is the same method), and the ECMA-335 metadata signature blob
is itself **positional** (`!!0`) — so a name-based spelling would diverge from the metadata producer on
any parameter typed as a type-parameter. Positional is source-derivable by **local declaration-position
lookup** (the type-param list is right there in the method/type declaration — no Roslyn), so C6 holds.

**Reference-type nullability is erased on purpose:** C# forbids overloading on reference-type
nullability, so `string?` never *distinguishes* two overloads, and requiring the `[Nullable]`
attribute would split the source (`?` syntactic) and metadata producers. Value-type `int?` is
`Nullable<int>` — a genuinely distinct overload target (`Foo(int)` ≠ `Foo(int?)`), and **both**
producers see it (source `?`, metadata `Nullable<Int32>`), so it is kept.

**Declared collision boundary (C6-honest).** The short-name form has one bounded collision mode: two
overloads whose parameters are *different types sharing a short name across namespaces* —
`Bar(A.Foo)` vs `Bar(B.Foo)` — both render `Bar(Foo)`. **Determinism always holds; non-collision
holds for the overwhelming common case** (distinct type names). This residual collision is a
**declared limitation**, not resolved via fully-resolved FQNs (rejected option B3 — imports Roslyn,
fails C6). `PLAN-252` may emit a partiality note when it detects a short-name collision.

**Rejected:** B2 (ECMA-335 signature blob) is canonical but needs the **compiled assembly**, which the
zero-toolchain source scanner lacks — it splits the two producers; B3 (resolved FQN) needs a **Roslyn
semantic model** and silently answers Open Question 2.

### `Kind` — .NET has no namespace-scope free functions

Every .NET callable is a member of a type, so `Kind = method` covers instance and static methods
alike (static-ness is not part of identity). `Kind = function` is the **module-scope** case only — a
C# top-level-statement program's callable, which has **no declaring type** (`Enclosing = ""`); this
empty `Enclosing` is exactly what separates a function from a static method.

### `Generated` — the §4.3 generated-symbol discriminator

`true` for compiler-synthesized symbols: async/iterator state-machine types, auto-property backing
fields (`<Prop>k__BackingField`), closure classes, and auto-property accessor bodies. See ⚑SM below.

---

## Coverage table — fifteen entries (C1)

**Info source (C6):** **S** = C# source text · **M** = ECMA-335 metadata · **R** = Roslyn semantic
model. No entry is silently **R**-only. `⚑` flags the three hardest / the metadata-only entry.

### §4.3 — eight categories

| # | Category | `Kind` | Field spelling | Worked example (`Package` / `Enclosing` / `Name` / `Descriptor`) | Src |
|---|---|---|---|---|---|
| 1 | packages/modules | package | `Package="pkg:nuget/<coord>"` (Decision A); `Name`/`Enclosing` empty | `pkg:nuget/Newtonsoft.Json` / — / — / — | S or M |
| 2 | types | type | namespace→`Enclosing`, bare→`Name` | `pkg:nuget/Newtonsoft.Json` / `Newtonsoft.Json` / `JsonConvert` / `` | S or M |
| 3 | functions | function | module-scope; `Enclosing=""` | `pkg:nuget/MyApp` / — / `Run` / `()` | S or M |
| 4 | methods | method | Decision B param list | `pkg:nuget/Newtonsoft.Json` / `Newtonsoft.Json.JsonConvert` / `SerializeObject` / `(object)` | S or M |
| 5 | constructors | constructor | `Name=".ctor"` (instance) / `".cctor"` (static); Decision B params | `pkg:nuget/Newtonsoft.Json` / `Newtonsoft.Json.JsonSerializerSettings` / `.ctor` / `()` | S or M |
| 6 | overloads/generics ⚑ | method | `Descriptor` = `` [`N] `` arity segment + param list | `pkg:nuget/Newtonsoft.Json` / `Newtonsoft.Json.JsonConvert` / `DeserializeObject` / `` `1(string) `` | S or M |
| 7 | nested declarations | type | outer type is innermost `Enclosing` segment | `pkg:nuget/MyApp` / `MyApp.Outer` / `Inner` / `` | S or M |
| 8 | generated symbols ⚑SM | type | `Generated=true`; mangled `Name` | `pkg:nuget/MyApp` / `MyApp.Widget` / `<FetchAsync>d__0` / `` | **M** |

### §5.2 deliverable 5 — seven items

| Item | `Kind` | Field spelling | Worked example (`Package` / `Enclosing` / `Name` / `Descriptor`) | Src |
|---|---|---|---|---|
| assembly/type/method identity | (per row 1/2/4) | `Package`=Decision A; `Enclosing`=ns+type chain; `Name`=member | as rows 1, 2, 4 | S or M |
| constructor & accessor names | constructor / method | ctor `.ctor`/`.cctor`; property `get_<P>`/`set_<P>`; event `add_<E>`/`remove_<E>` — a naming convention (not Roslyn) | `pkg:nuget/MyApp` / `MyApp.Widget` / `get_Name` / `()` | S or M |
| generic arity | method / type | backtick-arity count (`` `1 ``=1, `` `2 ``=2); **no type-param names** | `pkg:nuget/MyApp` / `MyApp.Cache` / `Cache` / `` `2 `` | S or M |
| overload signatures ⚑B | method | Decision B canonical param list; `(string)` ≠ `(Type)` | `pkg:nuget/Newtonsoft.Json` / `Newtonsoft.Json.JsonConvert` / `Deserialize` / `(Type)` | S or M |
| explicit interface impls ⚑EII | method | short-name qualifier `.`-joined into `Name` | `pkg:nuget/MyApp` / `MyApp.Widget` / `IDisposable.Dispose` / `()` | S or M |
| nested types | type | as row 7 | as row 7 | S or M |
| generated-state-machine → source ⚑SM | (map) | decode `<Name>d__N` → source method `Name` | maps `<FetchAsync>d__0` → `pkg:nuget/MyApp` / `MyApp.Widget` / `FetchAsync` / `()` | **M** |

### The three hardest, made airtight (C1 counterexample-surfacer)

A second reader must reproduce these byte-for-byte from the rules above:

- **Explicit interface implementation (⚑EII).** C# `void IDisposable.Dispose()` declared in
  `MyApp.Widget`. The interface qualifier uses the **short-name canonical form** (`IDisposable`, not
  `System.IDisposable`) and is `.`-joined onto the member name — matching how metadata names an
  explicit impl. Result: `Kind=method`, `Package="pkg:nuget/MyApp"`, `Enclosing="MyApp.Widget"`,
  `Name="IDisposable.Dispose"`, `Descriptor="()"`. Distinct from an implicit `Dispose`
  (`Name="Dispose"`). **Boundary:** two interfaces named `IDisposable` in different namespaces both
  render `IDisposable.Dispose` — the same declared cross-namespace short-name collision as ⚑B.
- **Generic method arity.** C# `T DeserializeObject<T>(string value)` on
  `Newtonsoft.Json.JsonConvert`. The generic segment is the **backtick-arity `` `1 ``** (arity = 1, no
  type-param name) prefixing the canonical param list. Result: `Name="DeserializeObject"`,
  `Descriptor="`1(string)"`. This is distinct from a non-generic `DeserializeObject(string)`
  (`Descriptor="(string)"`) and from `DeserializeObject<T,U>(string)` (`Descriptor="`2(string)"`).
  Renaming the type parameter (`DeserializeObject<U>(string)`) does **not** change the identity — the
  segment is arity-only. A parameter *typed* as the type-parameter goes positional:
  `T Cast<T>(T value)` → `Descriptor="`1(!!0)"`.
- **Async state machine (⚑SM).** C# `async Task<int> FetchAsync()` on `MyApp.Widget` compiles to a
  state-machine **type** `<FetchAsync>d__0` (nested in `Widget`, `Generated=true`). Its symbol:
  `Kind=type`, `Enclosing="MyApp.Widget"`, `Name="<FetchAsync>d__0"`. The **mapping** rule decodes the
  mangle `<Name>d__N` → source method `Name`, yielding the source `FetchAsync` symbol
  (`Kind=method`, `Enclosing="MyApp.Widget"`, `Name="FetchAsync"`, `Descriptor="()"`,
  `Generated=false`).

---

## ⚑SM — generated-state-machine → source mapping is metadata-only (declared partiality)

`<FetchAsync>d__0` and its `MoveNext` exist **only in compiled IL**; C# source text never contains
them. The decode `<Name>d__N` → `Name` is a **name-mangling pattern, not a semantic query** (no Roslyn
needed) — but the **first-party source scanner cannot emit these symbols at all**, because it never
sees them. This entry is therefore **metadata-dependent** (`PLAN-250` / Prove-tier): only a producer
reading ECMA-335 metadata (or a compiled assembly) can emit the state-machine type and the mapping
edge.

**Stated source-side partiality reason.** When only C# source is available, a producer that encounters
an `async`/iterator method emits the ordinary source-method symbol (e.g. `FetchAsync`) and declares
partiality for the generated state machine and any call edges routed through `MoveNext` — it must
**not** invent a `<…>d__N` symbol it cannot observe. Declared, not silent → C6 holds.

`Generated bool` is the discriminator: the state-machine type carries `Generated=true`; the source
method it maps back to carries `Generated=false`.

---

## C6 — producer independence (summary)

Every one of the fifteen entries is spellable from **S or M**; none requires a Roslyn semantic model.
The two hazards resolve to metadata, not the semantic model, and are declared:

- **⚑SM** (state-machine mapping) is **M-only**, with a stated source-side partiality reason above.
- **⚑B** (overload signatures) and **⚑EII** (explicit-interface qualifier) use the **syntactic
  short-name canonical form** — S-derivable, with the M-side reader normalizing to match — and carry
  a declared cross-namespace short-name collision boundary rather than importing Roslyn to resolve it.

The profile survives either answer to Open Question 2 (Roslyn vs. metadata-reader toolchain): no
entry is satisfiable *only* by Roslyn.
