# leave-behind

`leave-behind` generates a bundle of pre-computed, addressable answers to the
structural questions a coding agent would otherwise derive by grep → read →
infer. It drives the [`cgx`](https://github.com/ferralon-ai) CLI over a
repository's already-built call-graph index and writes one bundle of JSON
artifacts an agent reads instead of rebuilding the graph in its head.

**Audience:** engineers running the POC, and agent authors consuming the bundle.

This is a proof-of-concept and a **walled garden**: it imports nothing from the
assay pipeline (`pipeline/`, `artifact/`, `trigger/`, `plugin/`) and shells only
to the `cgx` binary. Everything it produces is deterministic — there is no LLM in
the answer path.

## The idea

An agent asking "who calls this?" greps a name, opens the call sites, and mentally
reconstructs the call graph. Every inference costs tokens and misses dynamic
dispatch, interface satisfaction, and name collisions. A **leave-behind** replaces
that loop with one addressable file carrying `file:line` evidence and a
deterministic confidence label. Same question, same answer, every time.

## The honesty model (read this before trusting a number)

On this repo's index, **95.2% of call edges are labeled `possible`** (162,279 of
170,473) — high coverage, `trust: high`, zero unresolved refs, but low per-edge
precision without a SCIP index. That is the point, not a defect: an agent grepping
has the same uncertainty with *zero* labels. These artifacts hand it that
uncertainty **quantified, labeled, and reproducible**.

Three rules the generator enforces in code, and every consumer must respect:

1. **Never read a `possible` edge as fact.** Every artifact carries confidence
   either as cgx's verbatim `approximation` envelope (a machine-readable
   over/under-approximation disclosure with quantified reasons) or, where cgx
   emits no envelope, as a per-row `confidence` label.
2. **Empty ≠ proven absent.** A zero-result artifact says so explicitly (see
   `data-flow.json`), never "safe" or "no callers".
3. **Structural, not semantic.** Data-flow provenance is SSA derives-from, *not*
   security-typed taint; the artifact labels itself accordingly.

## Build

```
go build -o leave-behind ./cmd/leave-behind
```

## Run

```
leave-behind \
  -repo /path/to/repo-with-.cgx \
  -cgx-bin /path/to/cgx \
  -out ./leave-behind-bundle
```

The index must already exist (`<repo>/.cgx/`). `leave-behind` never rebuilds it.

### `cgx` on PATH

In this environment `cgx` is a shell alias (`cargo run …`), which `os/exec`
cannot expand — so `-cgx-bin` is effectively required here. Without it, the tool
looks up `cgx` on PATH and, if absent, exits with a message naming the real binary
(`~/workspace/cgx/main/target/release/cgx`).

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `-repo` | `.` | Indexed repository (must contain `.cgx/`). |
| `-out` | `./leave-behind-bundle` | Output bundle directory. |
| `-cgx-bin` | (PATH lookup) | Path to the `cgx` binary. |
| `-pkg` | `hostmatch` | First-party package to card (Symbol + Blast-Radius). |
| `-depth` | `3` | Traversal depth for blast-radius callers. |
| `-base` | `HEAD~1` | Base git ref for the PR diff. |
| `-head` | `HEAD` | Head git ref for the PR diff. |

## Bundle layout

```
leave-behind-bundle/
├── manifest.json                     # index of all ten leave-behinds + graph-honesty header
├── atlas.json                        # 1. Repo Atlas & Hotspot Map
├── symbols/<pkg>/<sym>.json          # 2. Symbol Cards (one per symbol)
├── blast-radius/<pkg>/<sym>.json     # 3. Blast-Radius Cards (one per symbol)
├── dead-code.json                    # 6. Dead-Code Inventory
├── data-flow.json                    # 9. Data-Flow Provenance
└── pr-diff.json                      # 10. PR Call-Graph Diff
```

Filenames are stable — an agent addresses an artifact by path. Card filenames drop
the `<pkg>::` prefix and collapse Go receiver punctuation (`hostmatch::(*Matcher)::Allows`
→ `Matcher.Allows.json`).

## The ten leave-behinds

`manifest.json` records all ten on two shelves: **structural** (addressable by code
address — symbol FQN or file) and **semantic** (addressable by question). Six are
built live in this POC; four are schema stubs whose manifest entry records the
address scheme, intended file(s), a token-cost estimate, a "reach for this when…"
line, and the `cgx` command that would produce them.

| # | Leave-behind | Shelf | cgx command | POC |
|---|---|---|---|---|
| 1 | Repo Atlas & Hotspot Map | structural | `symbols --rank …` + `search --all` | **live** |
| 2 | Symbol Card | structural | `explain <FQN>` | **live** |
| 3 | Blast-Radius Card | structural | `callers <FQN> --depth N` | **live** |
| 4 | Dependency Footprint | structural | `callees <FQN> --depth N` | stub |
| 5 | Reachability & Paths | structural | `reaches` / `paths` | stub |
| 6 | Dead-Code Inventory | semantic | `unused --kind function` | **live** |
| 7 | Entrypoint & Attack-Surface | semantic | `symbols` + `unused --kind entrypoint` | stub |
| 8 | Interface / Implementer Map | semantic | `query 'MATCH (t)-[:IMPLEMENTS]->(i)…'` | stub |
| 9 | Data-Flow Provenance | semantic | `query 'MATCH (a)-[:DATA_FLOW]->(b)…'` | **live** |
| 10 | PR Call-Graph Diff | semantic | `diff <base> <head>` | **live** |

## How an agent consumes the bundle

1. **Read `manifest.json` first.** Its `graph_honesty` header (verbatim
   `cgx doctor`) states the precision floor up front; `honesty_spine` states the
   framing; each entry says when to reach for it and what it costs in tokens.
2. **Random-access the structural shelf by address.** Editing `X`? Read
   `symbols/<pkg>/X.json` (what it is + every incident edge) and
   `blast-radius/<pkg>/X.json` (who breaks) — two file reads instead of N greps.
3. **Read the semantic shelf by question.** "What's safe to delete?" →
   `dead-code.json`. "What changed in this PR?" → `pr-diff.json`.
4. **Respect the labels.** Filter or weight by `confidence`; treat the
   `approximation` envelope as the ceiling on what the artifact proves.

## Per-artifact notes (grounded in the real output)

- **`atlas.json`** — first-party hub ranking (inbound/outbound/total) plus a
  per-package symbol inventory. `vendor/` and `corpus/testdata/` are filtered out,
  because the raw top hub on this repo is a vendored protobuf type. `cgx symbols`
  emits no envelope; each hub row's `inbound.by_confidence` breakdown is the
  honesty carrier.
- **Symbol Cards** — `cgx explain` carries **no** top-level envelope; confidence
  and condition are per-edge. On the sample `Matcher.Allows.json`, the outgoing
  `language::Region::Contains` edges are name-collision over-approximations across
  the vendored corpus, every one labeled `possible`; the two real in-package calls
  are `probable`. The card hands the agent that distinction rather than hiding it.
- **Blast-Radius Cards** — reverse-reachability closure with the verbatim
  `over_under` envelope (over: dynamic-dispatch candidate edges; under: depth cap +
  unresolved external calls). Cards split direct vs transitive callers and count
  test callers. **Cost scales with `-depth`**: depth 3 on a `possible`-heavy graph
  fans the over-approximated candidate set out fast — the sample bundle's eight
  cards total ~380 KB. Lower `-depth` for a tighter, cheaper set.
- **`dead-code.json`** — first-party unused functions split into
  `exported_but_unused` (public-API candidates, *not* dead) and
  `unexported_no_ref` (stronger delete candidates). The envelope's
  `unresolved-external-calls` count is carried verbatim: some listed functions may
  be reached only via unindexed/dynamic sites and are **not** safe to delete on
  this evidence.
- **`data-flow.json`** — structural provenance only. On the current index this
  returns **zero** edges; the artifact carries the envelope, `count: 0`, and an
  `empty_semantics` note explaining that the index appears built without the
  dataflow layer — empty is not proof that no value flows exist. Rebuild with
  `cgx index` (dataflow on by default) to populate.
- **`pr-diff.json`** — `cgx diff` carries no per-edge confidence (it is set math
  over two snapshots). Re-query an added edge with `callers`/`paths` to judge its
  certainty. When the requested range cannot be resolved (single-commit history,
  or a rev syntax cgx's git layer rejects such as `HEAD~1`), the generator falls
  back to a degenerate self-diff and discloses the degradation in `note`.

## Tests

```
go test ./cmd/leave-behind/...
```

Tests drive a **fake `cgx`** (a stub shell script via `-cgx-bin`) so they need
neither the real binary nor an index. They cover the subprocess decoders, verbatim
envelope preservation, the empty-result honesty note, the first-party/exported
classifiers, card-name sanitization, and the manifest shape (ten entries, six live
+ four stub, graph-honesty header present).
