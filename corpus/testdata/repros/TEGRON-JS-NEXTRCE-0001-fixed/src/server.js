'use strict';

const http = require('http');
const { requirePage } = require('./require');

// server.js is the PATCHED variant of the TEGRON-JS-NEXTRCE-0001 ingress (Next.js
// 5.1.0, Y = fixed). It is the same catch-all http_route ingress as the vulnerable
// variant EXCEPT the render hop now calls requirePage — the guarded successor — and
// the advisory-named sink requireModule is GONE from require.js. This mirrors the
// real 5.1.0 diff (PR #3776 renamed requireModule -> requirePage and added a
// bundles-dir containment guard; PR #3787 deleted server/resolve.js). The advisory
// sink symbol requireModule no longer resolves anywhere in the tree, so the Assess
// verdict flips reachable_candidate -> not_exploitable by SYMBOL REMOVAL.

function makeApp() {
    const routes = {};
    const app = {
        get(path, handler) {
            routes['GET'] = handler;
        },
        listen(port) {
            const server = http.createServer((req, res) => {
                const u = new URL(req.url, 'http://127.0.0.1');
                const handler = routes['GET'];
                const fakeReq = { params: { path: u.pathname.slice(1) } };
                const fakeRes = {
                    json(body) {
                        res.writeHead(200);
                        res.end(JSON.stringify(body));
                    },
                };
                if (handler) {
                    Promise.resolve(handler(fakeReq, fakeRes)).catch(() => {
                        res.writeHead(500);
                        res.end('err');
                    });
                } else {
                    res.writeHead(404);
                    res.end('not found');
                }
            });
            server.listen(port, '127.0.0.1');
        },
    };
    return app;
}

// handleRender is the catch-all route handler (the ingress). It now forwards the
// page path through render to the guarded requirePage successor.
async function handleRender(req, res) {
    const mod = await render(req.params.path);
    res.json(Object.keys(mod));
}

// render is the utility hop. At Y it calls requirePage, not the removed
// requireModule.
function render(pagePath) {
    return requirePage(pagePath, { dir: __dirname });
}

const app = makeApp();
app.get('/:path*', handleRender);
app.listen(8080);
