# Attribution-review state model (§4.4.8)

The **attribution-review workflow** governs one question per advisory: *is the symbol the advisory names
as vulnerable actually the vulnerable one, and how sure are we?* Advisories name symbols in prose or in
loosely-scoped identifiers; a named symbol can resolve to more than one candidate (overloads, renames,
relocations across versions), or turn out to be wrong. This model gives that judgment a small closed set
of named states and evidence-driven transitions, so per-symbol certainty is an auditable review outcome —
never a synthesized confidence number stamped onto the evidence record (see §4.4.4 in `Provenance`).

PLAN-024 establishes the **type** (`AttributionStatus`, the `attributionStatusRecognized` validator) and
this **model**. It is NOT wired onto the advisory record's symbol axis this cycle: per-symbol population
rides on typed symbols (`plugin.Symbol`, anvil-q15) and is executed at scale by PLAN-220. The type is
fail-open like `TrustTier`: an unrecognized wire value decodes to the zero (`unreviewed`), never rejecting
the document (inv.5).

## States

| State | Meaning |
|---|---|
| `unreviewed` (zero) | As-ingested. No review has examined this attribution yet. The default for every advisory symbol until a review moves it, and the fail-open landing for an unrecognized value. |
| `confirmed` | Review established this symbol **is** the vulnerable one for this advisory — the identity resolves to a single candidate and evidence supports it. |
| `ambiguous` | The symbol identity is **underdetermined**: the advisory's symbol could resolve to more than one candidate (overload / rename / relocation) and evidence does not yet single one out. No counter-claim — just insufficient resolution. |
| `disputed` | Review surfaced positive **counter-evidence** that this symbol is NOT the vulnerable one (e.g. the named symbol provably never reaches the sink). A standing contradiction, not mere under-resolution. |

`ambiguous` and `disputed` are deliberately distinct: ambiguous is "we cannot tell which," disputed is "we
have reason to believe not." They carry different downstream weight and different remediation (ambiguous
wants more resolution evidence; disputed wants the attribution re-sourced or dropped).

## Transitions

```
                 resolve to a single supported candidate
   unreviewed ───────────────────────────────────────────────▶ confirmed
       │                                                            ▲
       │ multiple candidates, none singled out                     │ new evidence resolves the ambiguity
       ├──────────────────────────────────────────▶ ambiguous ─────┘
       │                                                │
       │                                                │ counter-evidence: named symbol never reaches sink
       │ counter-evidence found directly                ▼
       └──────────────────────────────────────────▶ disputed
```

- **unreviewed → confirmed**: a review resolves the named symbol to exactly one candidate and finds
  supporting evidence (the candidate reaches the advisory's sink / matches the fix commit).
- **unreviewed → ambiguous**: a review finds the named symbol resolves to multiple candidates with no
  disambiguating evidence.
- **unreviewed → disputed** or **ambiguous → disputed**: a review finds positive counter-evidence for the
  attribution (the named symbol, or every candidate for it, provably does not reach the sink).
- **ambiguous → confirmed**: later evidence (a version pin, a call-graph, a maintainer note) singles out
  one candidate and supports it.
- No transition **out of** `confirmed` or `disputed` is defined within a single corpus revision — a
  terminal judgment is re-opened only by re-ingesting the advisory at a new `InputDigest` (a new review
  cycle over fresh source bytes), never by mutating a decided record in place.

## Who / what decides

A transition is driven by **evidence**, recorded against the advisory's provenance, not by fiat:
- **Automated** signals move `unreviewed → ambiguous` (a resolver that finds >1 candidate) and can propose
  `→ disputed` (a call-graph showing no path to the sink). Automation never asserts `confirmed` alone —
  confirmation is a positive claim that requires corroboration.
- **Human review** (PLAN-220's workflow at scale) adjudicates `confirmed` and `disputed`, and is the
  authority that closes an `ambiguous` attribution. The reviewer's authority to refute is separately gated
  by `TrustTier` (a `byo`/`third_party` source cannot unilaterally `dispute` a `first_party` attribution);
  the two axes compose — `AttributionStatus` is the per-symbol judgment, `TrustTier` is the standing to
  make it.

Every state is context, never a verdict: an attribution's status weights how a warrant reads the symbol
evidence downstream, but it never by itself decides exploitability (inv.5).
