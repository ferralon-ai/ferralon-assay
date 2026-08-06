'use strict';

// Minimal JS checkout fixture (NO go.mod, NO .java) used by the language-aware
// checkout + inventory tests. It only needs to be a recognizable JS source tree.
function handler(req, res) {
    res.end('ok');
}

module.exports = { handler };
