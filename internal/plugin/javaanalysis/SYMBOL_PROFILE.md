# Java canonical symbol profile

Cycle PLAN-040, Phase 0. Lane: java. Package `internal/plugin/javaanalysis/`.

This is the published, quotable profile of the Java symbol identifier: for each symbol
category, the **exact identifier string the emitter renders today** (verbatim, greppable), the
**canonical (target) identifier** it is measured against, and a **separability verdict**. It is the
prose companion to the descriptor-vs-arity decision
(`execution/descriptor-vs-arity-decision.md`) and grep-matches that decision per identifier string
(convergence C3). Every id string below is reproducible by reading
`scip.go` —
nothing here is invented, nothing executed.

## How the identifier is built (the one axiom)

Every `SCIP` string this package mints comes from **one** builder, `scipSymbol`
(scip.go:58-73),
fed one trailing descriptor from `typeDescriptor` / `methodDescriptor` / `fieldDescriptor`
(scip.go:86-99). Its output is, byte for byte:

```
scip-java maven <coord> <version> <pkgDescriptor><Enclosing#…><descriptor>
```

where the manager token is the constant `scip-java maven` (scip.go:31), and **both** `<coord>` and
`<version>` are the constant `localCoordinate` = `.` (scip.go:37, written at scip.go:62-64). The
engine never type-resolves (scip.go:7-14) — it is a declaration-shape parser. Every collapse below
follows from that single fact.

## Identity model (reconciled to the frozen PLAN-000 field contract)

Reconciled against the frozen contract at
`cycles/2026-08-06_1740_plugin-contract-rework/execution/field-contract.md` (PLAN-000 landed green at
`400bc75`; released for this design reconciliation by L0 ANS `cobalt-q4`). The earlier draft
of this profile assumed `SCIP`/`DisplayName`/`Package` would be *renamed* on the rebase — **that was
wrong and is corrected here**: the frozen contract **keeps all three unchanged** and **adds** five
structured identity fields.

Frozen `plugin.Symbol` is a **comparable scalar struct** with, in order: `Kind SymbolKind`
(`package|type|function|method|constructor|field`), `Package`, `Enclosing` (enclosing type/decl
chain, segments joined by `.` outermost→innermost — the *structured* form of the `#`-chain the SCIP
string renders), `Name`, `Descriptor` (the overload/generic disambiguator — **the frozen home of the
JVM-descriptor gap** below), `Generated bool`, `DisplayName`, `SCIP`.

- **Matching identity = `Kind`/`Package`/`Enclosing`/`Name`/`Descriptor`.** `SCIP` and `DisplayName`
  are rendering/bridge fields, **never** the match key — the `symbolform_guard_test` contract pins
  "matching never keys on `.SCIP`," preserved verbatim by the freeze.
- **Population lag (load-bearing for this profile).** On `400bc75` the Java plugin still populates
  only `SCIP`/`DisplayName`/`Package`; the five structured fields exist on the struct but are **zero**
  for Java until **PLAN-242** (the Java PLAN-2x2 that normalises them). So every separability verdict
  below has *two* horizons: the **rendered `SCIP` string today** (what the emitter mints, greppable,
  unchanged) and the **structured field** that will carry the same distinction once PLAN-242 populates
  it. Where a construct collapses in today's SCIP string but the frozen contract already provides a
  field to separate it (constructors→`Kind`, overloads→`Descriptor`, generated→`Generated`), the
  collapse is a **population gap PLAN-242 closes**, not a contract gap — called out per entry.

Field-name note: any `SCIP`/`DisplayName`/`Package` mention below names both the frozen Go field
(unchanged) and the wire string it renders; the assembly point is
index.go:105-109.

## Reading the entries

- **Emitted today** — the literal string on disk, minted by the named function. Greppable.
- **Canonical (target)** — what the identifier is *required* to be. For the descriptor gap this is the
  illustrative TARGET form, marked `[TARGET — not yet emitted]` exactly as the decision marks it.
- **Verdict** — SEPARATED (two distinct source constructs get two distinct ids), COLLAPSED (two
  distinct constructs render the same id, or distinguishing information is discarded — shown with a
  concrete collision), or ABSENT (never minted at all — an honest omission, not a mislabel).

All worked examples use package `com.example.web` unless noted, so path faithfulness is visible.

---

## §4.3 general categories (eight entries)

### 1. Packages / modules — SPLIT: package *path* SEPARATED, module/artifact COLLAPSED

Java declaration:

```java
package com.example.web;
public class UrlServiceImpl { }
```

No symbol is ever minted *for* a package — the package is a prefix only, produced by
`packageDescriptor` (scip.go:78-83): `com.example.web` → `com/example/web/`, and the unnamed package
→ `_root_/`. The type carrying that prefix renders:

- **Emitted today** (via `scipSymbol` + `typeDescriptor`):
  `scip-java maven . . com/example/web/UrlServiceImpl#`
- **Canonical (target):** package *path* is already canonical — faithful and SEPARATED. The
  **module/artifact coordinate is not**: the target carries the resolving Maven coordinate + version
  in the two slots that today both render `.`.

Verdict: **SPLIT.** Package *path* is **SEPARATED** (rendered faithfully, dots → `/`). Module /
artifact is **COLLAPSED**: the coordinate slot and the version slot are both the `localCoordinate`
placeholder `.` (scip.go:62-64). Collision: `class UrlServiceImpl` in package `com.example.web`
shipped from artifact `org.acme:web-a:1.0` and from `org.acme:web-b:2.0` both render
`scip-java maven . . com/example/web/UrlServiceImpl#` — every module collapses to the same `. .`.

### 2. Types — SEPARATED

```java
package com.example.web;
public class UrlServiceImpl { }
```

- **Emitted today** (`scipSymbol` + `typeDescriptor`, scip.go:86):
  `scip-java maven . . com/example/web/UrlServiceImpl#`
- **Canonical (target):** same shape once the coordinate/version slots resolve; the type descriptor
  itself is already canonical.

Verdict: **SEPARATED.** `typeDescriptor` renders `Name#`; the package prefix distinguishes
same-named types in different packages.

### 3. Functions (free) — ABSENT

Java has no free functions; every method is a type member. There is no declaration to write and no
id is minted. Verdict: **ABSENT** — never minted, not mislabelled. (N/A to the language, listed for
completeness of §4.3.)

### 4. Methods — SEPARATED by name + arity only

```java
package com.example.web;
public class UrlServiceImpl {
    String fetch(String u) { ... }
}
```

- **Emitted today** (`scipSymbol` + `methodDescriptor("fetch", 1)`, scip.go:91-96):
  `scip-java maven . . com/example/web/UrlServiceImpl#fetch(1).`
- **Canonical (target):** the descriptor form — see entry §-JVM-descriptors below. The `1` is a
  parameter *count*, not a signature.

Verdict: **SEPARATED by name + arity only.** Distinct by name and by parameter *count*; the residual
collapse (same-arity/different-type overloads) is entry 6.

### 5. Constructors — COLLAPSED into methods

```java
package com.example.web;
public class UrlServiceImpl {
    UrlServiceImpl(int retries) { ... }
}
```

A constructor is parsed as an ordinary `kindMethod` whose name equals the class name; it takes the
`methodDescriptor` arm at index.go:96-98.

- **Emitted today** (`scipSymbol` + `methodDescriptor("UrlServiceImpl", 1)`):
  `scip-java maven . . com/example/web/UrlServiceImpl#UrlServiceImpl(1).`
- **Canonical (target):** a constructor-marked identifier — scip-java spells it with the `` `<init>` ``
  descriptor. The emitter mints **no `<init>` marker** at all.

Verdict: **COLLAPSED into methods — as a population gap, not a contract gap.** The rendered id does
not *say* "constructor," so constructor-vs-method is not machine-distinguishable *today*. Collision:
the constructor `UrlServiceImpl(int)` and any hypothetical member method literally named
`UrlServiceImpl` taking one parameter both render `…UrlServiceImpl#UrlServiceImpl(1).`. **The frozen
contract already provides the separator:** `SymbolKindConstructor` is a first-class `SymbolKind`, so
once PLAN-242 populates `Kind`, a constructor is `Kind: constructor` and the method is `Kind: method`
— distinct under `==` even while the SCIP string still collides. The collapse is therefore PLAN-242's
to close by population; the contract does not need to change.

### 6. Overloads / generics — COLLAPSED (both)

**Overloads:**

```java
package com.example.web;
public class Calc {
    int f(int x)    { ... }
    int f(String s) { ... }
}
```

- **Emitted today:** *both* overloads render `scip-java maven . . com/example/web/Calc#f(1).`
- **Canonical (target):** distinct descriptors — `f(int)` → `…Calc#f(I).` and
  `f(String)` → `…Calc#f(Ljava/lang/String;).` `[TARGET — not yet emitted]`

Verdict: **COLLAPSED.** Concrete collision: `f(int)` and `f(String)` both → `f(1).`. The collapse
lives in the id space; the edge layer surfaces it honestly as `Partial(dynamic_dispatch)` when a
call site cannot resolve to exactly one decl — it is never a silent mis-link, only a coincident id.
The frozen contract's `Descriptor` field is the structured home for the disambiguator (its
illustrative value is `"(int)"`; the Java lane fills it with the full JVM parameter descriptor — see
entry C), so PLAN-242 separates these two overloads by `Descriptor` without touching `SCIP`.

**Generics:**

```java
package com.example.web;
public class Box<T> { }
```

- **Emitted today:** `scip-java maven . . com/example/web/Box#` — type parameters lexically stripped
  (the parser skips `<…>` groups; type params never reach `scipSymbol`).
- **Canonical (target):** raw-bound erasure, matching how the JVM erases generics.

Verdict: **COLLAPSED.** `class Box<T>` and a raw `class Box` render the identical `Box#`; the
type-parameter arity is unrepresented.

### 7. Nested declarations — SEPARATED

```java
package com.example.web;
public class Service {
    static class Config {
        int retries;
    }
}
```

- **Emitted today** (`scipSymbol` with `enclosing = ["Service","Config"]` + `fieldDescriptor("retries")`):
  `scip-java maven . . com/example/web/Service#Config#retries.`
- **Canonical (target):** same `#`-chained shape; already canonical.

Verdict: **SEPARATED.** One `T#` per enclosing type, outer→inner (scip.go:67-70). The `#`-chain tail
`Service#Config#retries.` is pinned by `TestIndexSymbols_NestedTypesAreQualified` (index_test.go).

### 8. Generated symbols — ABSENT

```java
// bytecode-synthesized, no source declaration:
//   lambda$fetch$0, enum values()/valueOf(String),
//   bridge methods, access$000 accessors
```

The source-declaration parser never sees bytecode-synthesized members. Lambdas become nameless block
frames; enum `values()`/`valueOf`, bridge methods, and `access$` accessors are simply never
constructed. There is **no id string to show** — none is minted.

Verdict: **ABSENT** — never minted, not mislabelled. The frozen contract *does* now carry a
`Generated bool` on `Symbol` (the field a `Kind: function, Generated: true` synthetic would set), but
the Java `decl` the source parser produces has no such member to flag: bytecode-synthesized symbols
never enter the parser's view, so they are missing from the index, never present-but-wrong. ABSENT is
a **source-visibility** limit (a bytecode indexer at Prove tier would populate `Generated`), not a
missing-field limit — the earlier "no flag exists" phrasing is corrected by the freeze.

---

## §5.1-deliverable-6 Java specifics (seven entries)

### A. Fully-qualified methods — SEPARATED

```java
package com.example.web;
public class UrlServiceImpl {
    Response handle(HttpRequest req, int flags) { ... }
}
```

- **Emitted today** (`scipSymbol` + `methodDescriptor("handle", 2)`):
  `scip-java maven . . com/example/web/UrlServiceImpl#handle(2).`
- **Canonical (target):** same fully-qualified shape with a descriptor tail in place of arity.

Verdict: **SEPARATED.** Package prefix + enclosing chain + name + arity fully qualify the method
across packages and types.

### B. Constructors — COLLAPSED

As §4.3 entry 5: `UrlServiceImpl(int)` →
`scip-java maven . . com/example/web/UrlServiceImpl#UrlServiceImpl(1).`, **no `<init>` marker**.
Verdict: **COLLAPSED** — constructor identity is not recoverable from the id.

### C. JVM descriptors — COLLAPSED / ABSENT — **the core gap**

```java
package com.example.web;
public class UrlServiceImpl {
    String fetch(String u) { ... }
}
```

- **Emitted today** (`methodDescriptor`, scip.go:91-96 — an integer parameter **count**):
  `scip-java maven . . com/example/web/UrlServiceImpl#fetch(1).`
- **Canonical (target)** — the PLAN-242 north star, copied verbatim from the decision:
  `scip-java maven . . com/example/web/UrlServiceImpl#fetch(Ljava/lang/String;).   [TARGET — not yet emitted]`

Verdict: **COLLAPSED / ABSENT — this is *the* fidelity gap.** No JVM type descriptor
(`(Ljava/lang/String;)V`) is ever emitted: return type, parameter types, and array/generic shape are
all discarded, leaving only an arity integer. The canonical identifier carries the erased JVM
parameter *descriptor* (parameter types in internal form — `Lcom/example/web/Url;`, `I`, `[B`, …),
so `fetch(String)` and `fetch(int)` become **distinct** identifiers; today they collide on `fetch(1).`
(entry 6). Arity is the honest approximation, recorded via `Partiality`, and this gap is exactly what
the Phase-0 golden table reports RED. `PLAN-242` closes it (and, in the same pass, the `+N`
overloaded-erasure hole below).

**Frozen home + lane convention.** The structured field this descriptor lands in is `Symbol.Descriptor`
(frozen). It is a free `string`: the contract's illustrative value is the readable `"(int)"`, but the
Java lane convention this profile fixes for PLAN-242 is the **full JVM parameter descriptor** in
internal form — `fetch(String)` → `Descriptor: "(Ljava/lang/String;)"`, `f(int)` → `"(I)"` — so the
lane's `Descriptor` and the target SCIP tail agree. The contract permits this (the example is not
binding on the lane), so it is a lane decision, not a freeze contradiction.

### D. Nested classes — SEPARATED

```java
package com.example.web;
public class Outer {
    class Inner { }
}
```

- **Emitted today** (`scipSymbol` with `enclosing = ["Outer"]` + `typeDescriptor("Inner")`):
  `scip-java maven . . com/example/web/Outer#Inner#`
- **Canonical (target):** same `#`-chained shape; already canonical.

Verdict: **SEPARATED.** `#`-chained, one segment per enclosing type (scip.go:67-70).

### E. Bridge / synthetic methods — ABSENT

Bridge and synthetic methods (covariant-return bridges, `access$` accessors, lambda desugars) exist
only in bytecode; the source parser cannot see them. **No id is minted.** Verdict: **ABSENT** — never
minted, not mislabelled. Same source-visibility story as §4.3 entry 8: the freeze's `Generated` flag
exists, but the source `decl` has no synthetic member to carry it — a bytecode (Prove-tier) indexer
would populate it, an Assess-tier source parser cannot.

### F. Shading / relocation — COLLAPSED

```java
// a relocated (shaded) dependency, e.g. gson relocated under a vendor prefix:
package shaded.com.google.gson;
public class Gson { }
```

- **Emitted today** (`scipSymbol` + `typeDescriptor`):
  `scip-java maven . . shaded/com/google/gson/Gson#`

The relocated package *path* is faithful (so a shaded `shaded.com.google.gson.Gson` is path-distinct
from an un-shaded `com.google.gson.Gson`), but the **artifact coordinate is erased to `.`**
(scip.go:62-64), and the Prove-path reader `canonicalizeSCIP` erases even a real library symbol's
scip-java coordinate down into this same space. Verdict: **COLLAPSED.** Provenance — *which jar,
which shade* — is not recoverable from the id; only the textual path survives.

### G. Cross-release aliases — COLLAPSED

```java
// the same type in two releases of the same artifact (v1.0 and v2.0):
package com.example.web;
public class UrlServiceImpl { }
```

- **Emitted today** (both releases):
  `scip-java maven . . com/example/web/UrlServiceImpl#`

The version slot (the second `.`) is the `localCoordinate` placeholder (scip.go:64), so two releases
of the same symbol are **byte-identical** ids. Verdict: **COLLAPSED.** Cross-release aliasing cannot
be expressed — the version constraint collapses identically to the module/artifact collapse in §4.3
entry 1.

---

## Design intent for the (held) characterization test

The table-driven test is deliberately **held** this cycle. When it is written, it is a mechanical
transcription of the entries above — this section fixes its shape so no judgment is re-litigated:

1. **SEPARATED entries assert pairwise-distinct rendered ids.** The five SEPARATED entries below must
   have pairwise-distinct `SCIP` strings; the test builds each via the same minter named in its entry
   and asserts all-distinct:

   - types → `scip-java maven . . com/example/web/UrlServiceImpl#`
   - methods → `scip-java maven . . com/example/web/UrlServiceImpl#fetch(1).`
   - fully-qualified methods → `scip-java maven . . com/example/web/UrlServiceImpl#handle(2).`
   - nested declarations → `scip-java maven . . com/example/web/Service#Config#retries.`
   - nested classes → `scip-java maven . . com/example/web/Outer#Inner#`

   Package-path separability (§4.3 entry 1) is witnessed *by* these five, whose distinct prefixes come
   from `packageDescriptor` — no separate id is needed.

2. **COLLAPSED entries are the documented gaps — assert the collision, not distinctness.** The test
   pins the same-arity/different-type overload collapse as a *characterization* (currently unpinned by
   any test): `f(int)` and `f(String)` in one enclosing type both render
   `scip-java maven . . com/example/web/Calc#f(1).`. Likewise it may pin constructor-as-method
   (`UrlServiceImpl(1).`, no `<init>`), generics-stripping (`Box#`), and the coordinate/version
   collapse (`. .`). These assert *equality* of two distinct constructs' ids — the measured RED.

3. **ABSENT entries assert nothing is minted.** Generated / bridge / synthetic symbols: the test
   asserts the index contains no id for a lambda/bridge/`access$`/`values()` member — omission, not a
   mislabel.

**Two horizons (reconciled to the freeze).** The `SCIP`/`DisplayName`/`Package` fields are **not**
renamed by PLAN-000 (the earlier draft's assumption was wrong) — they are kept, and the structured
identity fields are added alongside. So the test has two horizons:

- **Today (on `400bc75`, pre-PLAN-242):** the Java plugin populates only `SCIP`/`DisplayName`/`Package`;
  the structured fields are zero for Java. The held test therefore asserts against the rendered `SCIP`
  **strings** above — the SEPARATED five distinct, the COLLAPSED pairs equal, the ABSENT set empty.
  This is the version that unblocks first (compile needs only the landed contract, not PLAN-242).
- **After PLAN-242 populates the structured fields:** the SEPARATED assertions become distinctness of
  the **structured identity tuple** (`Kind`/`Package`/`Enclosing`/`Name`/`Descriptor`) under `==` — the
  match key the `symbolform_guard` contract mandates — and the constructor and same-arity-overload
  collapses **flip from equal to distinct** (via `Kind: constructor` and the JVM `Descriptor`
  respectively), so those rows migrate from the COLLAPSED assertion to the SEPARATED one. The test
  should be structured so that migration is a row-verdict change, not a rewrite.
