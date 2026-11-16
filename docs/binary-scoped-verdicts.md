# Binary-scoped verdicts (Go)

A Go repository that ships programs, such as traefik's `cmd/traefik`, has two answers to "can this
advisory's vulnerable code run?":

- **Library view.** Any importable package is an entry point, because almost any repository can be
  imported, and a false negative is the failure the scanner cannot ship. This is the analysis the
  row's verdict reports, and the `library-entrypoints` setting shapes it
  ([GO-LIBRARY-ESCAPE](capabilities/go.md#go-library-escape)).
- **Program view.** The entry points are only the `main` and `init` functions of the shipped `main`
  packages. A caller that imports the module does not count.

When the program view rules the advisory out and the library view cannot, the row says so, scoped to
the binaries, and **the library view's verdict is never changed**.

## What the program view runs

The lane runs govulncheck a second time, over the shipped `main` packages alone, so govulncheck's own
entry-point rule (a main package's `main` and `init`) is the program view. It runs once per scan and is
cached; it runs only when a row needs it, that is when the library view holds no refutation and has
something to rule out (a refutation withheld, or a path that does not begin in a shipped `main`).

A shipped `main` package is a `main` package with compiled files, in a main module of the build, with
no `example`, `examples`, `test`, `tests` or `testdata` element below the module path. A `main` under
`cmd/` counts, and so does a generator or release tool the build compiles (traefik has four besides
`cmd/traefik`): the scan cannot tell which mains are shipped, and including one only makes the claim
harder to earn. The scope is **all** the shipped mains together: govulncheck reports one path per
symbol, so which of several binaries reach an advisory cannot be told from one run, and the claim is
made only when none of them does.

The program view rules an advisory out only when:

- govulncheck, run over the mains, matches the advisory to the same module the library view matched and
  finds no call to its vulnerable functions;
- the load is complete and its cgo state is known;
- no file the build left out (another platform, a build tag) may call into the module
  (`excluded_files`), and no call reflection makes may reach it (`reflection:call`);
- the run declares no limit that says a step did not run: no run-wide reason other than `reflection`
  and `dynamic_dispatch`, which are limits of the method, and no scoped limit that is unbounded or can
  reach the module.

It leaves out the two checks that ask who imports the build: `library_escape` and `unsearched_methods`.
A step that cannot be completed leaves the view empty. It never concludes from what it did not run.

## The row

One row, with an added field. Nothing is renamed, and a consumer that ignores `scoped_verdicts` reads
the report as before. The row's own `verdict`, `undetermined_reason` and `evidence` are the library
view's. Counts of verdicts count the row once.

```json
{
  "advisory": {"id": "GO-2024-0000"},
  "verdict": "undetermined",
  "undetermined_reason": "refutation_withheld",
  "evidence": {"detail": "..."},
  "scoped_verdicts": [
    {
      "verdict": "not_exploitable",
      "scope": {"kind": "binaries", "targets": ["cmd/traefik"], "module": "github.com/traefik/traefik/v3"},
      "evidence": {
        "basis": "vulnerable_symbol_unreachable",
        "detail": "golang.org/x/net@v0.33.0: started from the main and init of cmd/traefik only: govulncheck matched the advisory to ... and found no call path to its vulnerable functions ... (analyzer_symbol_not_reached)"
      }
    }
  ]
}
```

- `scoped_verdicts` is present only on a `reachable_candidate` row or an `undetermined` row, and the
  library view must not have ruled the advisory out (a row that is already `not_exploitable` holds for
  every caller). `Report.Validate` rejects it elsewhere.
- `verdict` is always `not_exploitable`. `scope.kind` is `binaries`; `scope.targets` are the main
  packages' directories relative to the module root, sorted (`.` for a main at the root);
  `scope.module` is the scanned module's path, and `Report.Validate` rejects a scope without it.
- `evidence` has the same fields as any `not_exploitable`. Its basis is `vulnerable_symbol_unreachable`.
  It carries no `assumptions`: the scope is the whole of its claim.
- The grounds are those of any refutation: the admitted package's version resolved, the advisory names
  no other package, and the refutation is of the admitted package. The row also passes the gate every
  `not_exploitable` passes: no toolchain axis left undetermined and no did-not-run limit counting for
  the package, other than the library-entry withholds the program view answers. A `reachable_candidate`
  row is held to it too, though its own verdict never reaches that gate.

## Wording

Surfaces a person reads say it in one sentence:

> Not reachable from the shipped binary `cmd/traefik`; still possible when this module is imported as a
> library.

With several binaries: "Not reachable from the shipped binaries `cmd/a`, `cmd/b`; ...". The HTML report
shows it beside the row's own label, and the SARIF message ends with it.

## OpenVEX

The finding keeps its own statement, for the module's package, with the library view's status. For
each scoped verdict, a second statement follows it:

- `products`: one per binary, `@id` the **binary**: `pkg:golang/<module>@<scanned commit>?binary=<target>`,
  the target percent-encoded as a purl qualifier value is, for example
  `pkg:golang/github.com/traefik/traefik/v3@020ab5f3…?binary=cmd%2Ftraefik`. The vulnerable
  dependency's purl is the product's `subcomponents[].@id`.
- `status`: `not_affected`, `justification`: `vulnerable_code_not_in_execute_path`, and an
  `impact_statement` with the sentence above.

**Why this identifier.** The product has to be the binary, and a purl names a package, so the binary is
the module's purl plus a `binary` qualifier carrying the directory its `main` package is built from,
the one name a Go build gives it. The qualifier is on every binary, a `main` at the module root
included (`?binary=.`), so no binary's identifier is the module's own purl: that one names the library
view, and a scoped statement must never be read as a claim about it. The version is the scanned commit,
because the scan knows no release of the repository. An OpenVEX consumer matches a statement on the
product it ships, so it finds `not_affected` for the binary it runs and the library view's status for the
module.

## SARIF

The result keeps its own level, kind and rule. `properties.scoped_verdicts` holds the same objects as the
JSON, and the message ends with the sentence above.

## What it does not say

The scope says nothing about code that imports the module as a library, and nothing about binaries the
repository does not build from its own `main` packages. If one shipped binary does reach the advisory,
no scoped verdict is made, even for the others.
