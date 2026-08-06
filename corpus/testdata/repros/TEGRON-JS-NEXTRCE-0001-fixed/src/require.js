'use strict';

const { join, normalize } = require('path');

// require.js at Next.js 5.1.0 (Y, fixed). The advisory-named RCE sink requireModule
// is REMOVED (grep -c requireModule === 0), mirroring the real server/require.js at
// tag 5.1.0. PR #3776 replaced the unrestricted requireModule/resolve resolver with
// requirePage + a getPagePath bundles-directory containment guard (throws on paths
// that escape the bundles root); PR #3787 deleted server/resolve.js. Because the
// symbol requireModule no longer exists in the tree, ResolveDependencySymbols(
// Symbols:["requireModule"]) returns len==0 — the Assess-tier symbol-removal flip.
//
// FAITHFULNESS NOTE: the successor requirePage still reaches a require(), now behind
// getPagePath's containment check. The flip is keyed on the genuinely-deleted
// symbol requireModule (absent at Y), not on the guard: this is a real symbol
// removal, though a skeptic could frame 5.1.0 as a guarded refactor of the same
// require() path.

// getPagePath is the bundles-directory containment guard added by the fix: it
// rejects any page path that would escape the bundles root.
function getPagePath(page, opts) {
    const bundles = join(opts.dir, 'bundles', 'pages');
    const p = join(bundles, normalize('/' + page));
    if (p.indexOf(bundles) !== 0) {
        throw new Error('page path outside bundles directory');
    }
    return p;
}

// requirePage is the guarded successor to the removed requireModule sink. It
// require()s only a contained path.
function requirePage(page, opts) {
    return require(getPagePath(page, opts));
}

module.exports = { requirePage };
