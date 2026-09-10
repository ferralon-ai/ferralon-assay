// Package symboltest is the canonical symbol-profile golden-equality harness
// (PLAN-006). A language's producer conformance is expressed as a Profile: a set
// of ProfileRows, each binding one of the eight frozen declaration categories to
// a concrete source construct and to the canonical plugin.Symbol a conformant
// producer must emit for it.
//
// The harness applies GOLDEN-EQUALITY semantics (profile-format.md §2/§3):
//
//   - Equality key is the STRUCTURED-IDENTITY projection
//     {Kind, Package, Enclosing, Name, Descriptor, Generated}. SCIP and
//     DisplayName are diagnostic-only and EXCLUDED from equality. Because
//     plugin.Symbol is a comparable struct, equality is a plain == over a copy
//     with SCIP/DisplayName zeroed (IdentityKey) — no go-cmp, no reflect.
//   - A row with Gap == nil is MUST-MATCH: a structurally-equal emitted symbol
//     must exist, else the harness reports a regression.
//   - A row with Gap != nil is an EXPECTED-FAILURE (xfail): the producer must NOT
//     yet match Want. No match is GREEN (the gap is real, exactly where
//     declared); an unexpected match is a "gap silently closed" finding —
//     promote the row by deleting its KnownGap.
//   - A coverage guard fails a Profile that drops any of the eight required
//     categories (RequiredCategories): a missing category is itself a defect.
//   - When a matched emitted symbol carries SCIP == DisplayName (the sym(s)
//     collapse in goanalysis/packages.go:35 — no distinct wire id yet), the
//     harness records a diagnostic note. It NEVER fails equality on it.
//
// GoReferenceProfile is the Go reference instance the four language lanes
// (java/dotnet/js/python) copy for their PLAN-0x0. Its rows target the fully
// structured canonical identity the field-contract froze; since no Go producer
// populates the structured fields today, every row carries a KnownGap and the
// profile is GREEN under xfail semantics.
package symboltest
