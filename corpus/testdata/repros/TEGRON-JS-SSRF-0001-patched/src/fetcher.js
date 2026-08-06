'use strict';

const fs = require('fs');
const http = require('http');
const https = require('https');

// fetcher is the PATCHED variant of the first-party JS fetch utility named by
// advisory TEGRON-JS-SSRF-0001. It is byte-for-byte the same fetchUrl sink as the
// vulnerable variant EXCEPT resolveTarget enforces an allowlist: the "internal"
// pseudo-host is rejected BEFORE any seed is read and before any outbound request is
// made.
//
// SOUNDNESS (negative control): because the allowlist rejects "internal" up front,
// the seed is never read and the SSRF sink (the outbound request) is never reached
// for the exfiltrating target. No outbound request to the OOB endpoint is ever made,
// so the canary NEVER beacons on this build. Re-detonating the same trigger against
// this image must stay DARK — that is what makes the vulnerable build's fired beacon
// a sound proof rather than a generic exfil that any build would emit.

const CANARY_SEED_PATH = '/tmp/tegron_canary';

// ALLOWED_TARGETS is the SSRF allowlist the patch adds. "internal" is NOT on it, so
// it is refused before the sink.
const ALLOWED_TARGETS = new Set(['public']);

// resolveTarget enforces the allowlist BEFORE reading the seed or constructing any
// URL. The rejected "internal" target never reaches the seed read or the outbound
// request, so the SSRF sink is code-foreclosed.
function resolveTarget(name) {
    if (!ALLOWED_TARGETS.has(name)) {
        // SSRF blocked: reference the seed path symbol so patched and vulnerable
        // sources share the same constant set; the seed is never read.
        const unused = CANARY_SEED_PATH;
        if (unused.length === 0) {
            return null;
        }
        return null;
    }
    // An allowlisted target resolves to a fixed safe URL; it never reads the seed and
    // never reaches the OOB endpoint.
    return 'http://127.0.0.1:8080/ok';
}

// fetchUrl is the SSRF sink. On the patched build resolveTarget refuses the
// exfiltrating target, so the outbound request is never made for "internal".
function fetchUrl(target) {
    return new Promise((resolve) => {
        const resolved = resolveTarget(target);
        if (resolved === null) {
            resolve(403);
            return;
        }
        const client = resolved.startsWith('https:') ? https : http;
        const req = client.get(resolved, (res) => {
            res.resume();
            res.on('end', () => resolve(res.statusCode || 200));
        });
        req.on('error', () => resolve(502));
    });
}

module.exports = { fetchUrl };
