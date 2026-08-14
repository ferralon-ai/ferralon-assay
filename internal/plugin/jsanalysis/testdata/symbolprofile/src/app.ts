// Offline JS/TS fixture for the symbol-profile golden harness (PLAN-060 C2).
//
// It exercises the emittable §4.3 constructs so the golden table can be driven
// against the REAL first-party producer (jsanalysis.IndexSymbols), hermetically:
// the scanner is a pure-Go lexical scan that runs no toolchain (no Node, no tsc,
// no scip-typescript), so no test skip is needed. Every construct below is emitted
// with SCIP / DisplayName / Package only — no structured identity is populated
// today (index.go:74-84) — which is exactly what the golden table's KnownGaps
// assert. This file is authored by hand; it never comes from the analyzer's own
// output (cold-fixture rule).

export function fetchUrl(u: string): string {
  return u;
}

export class Fetcher {
  base: string;

  constructor(base: string) {
    this.base = base;
  }

  fetch(path: string): string {
    return fetchUrl(this.base + path);
  }

  map<T>(fn: (x: T) => T, x: T): T {
    return fn(x);
  }
}

export class Outer {
  wrap() {
    class Inner {}
    return Inner;
  }
}
