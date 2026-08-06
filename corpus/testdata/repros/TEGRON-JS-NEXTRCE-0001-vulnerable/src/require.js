'use strict';

// require.js is the first-party Next.js module-resolution helper named by advisory
// TEGRON-JS-NEXTRCE-0001 (GHSA-5vj8-3v2h-h38v). requireModule(page) is THE RCE SINK:
// it resolves a caller-supplied page path with NO bundles-directory containment and
// require()s it, so an attacker-controlled path yields arbitrary module execution.
//
// This mirrors server/require.js at Next.js tag 5.0.0 (X, last-vulnerable):
//   import resolve from './resolve'
//   export default async function requireModule (path) {
//     const f = await resolve(path)   // unrestricted user-path resolver
//     return require(f)               // arbitrary require = RCE
//   }
// collapsed to a single file (the deleted server/resolve.js helper is folded into
// resolvePath here) so the removal at Y is a same-file symbol deletion.

// resolvePath is the reduced stand-in for the deleted server/resolve.js resolver: it
// returns the caller-supplied path verbatim, with no containment check.
function resolvePath(page) {
    return page;
}

// requireModule is THE RCE SINK — removed at Next.js 5.1.0 (renamed to the guarded
// requirePage; see the -fixed variant). At X it require()s an unrestricted path.
function requireModule(page) {
    const f = resolvePath(page);
    return require(f);
}

module.exports = { requireModule };
