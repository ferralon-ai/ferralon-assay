'use strict';

const http = require('http');
const { requireModule } = require('./require');

// server.js is the Express-shaped INGRESS for TEGRON-JS-NEXTRCE-0001 (Next.js
// < 5.1.0 module-resolution RCE, GHSA-5vj8-3v2h-h38v). app.get('/:path*',
// handleRender) registers handleRender as the catch-all route handler — the same
// lexically-detectable Express route-registration shape (named handler reference)
// the analyzer recognizes as an http_route ingress. handleRender reads the
// attacker-controlled page path from the URL and passes it through render() to
// requireModule() (the RCE sink), so the source call graph is
// ingress(handleRender) -> render -> requireModule. This mirrors the real Next.js
// v5.0.0 chain server/index.js '/:path*' -> this.render -> render.js doRender ->
// requireModule(pagePath), collapsed to a direct named-call chain (method hop and
// cross-file import removed) so the pure-Go call graph connects it hermetically.
//
// To stay dependency-free (no node_modules install) this file uses a tiny
// hand-rolled router shaped exactly like Express's app.get(path, handler); the
// runtime is the Node http module. A GET /pages/index resolves and requires the
// caller-controlled path.

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

// handleRender is the catch-all route handler (the ingress). It forwards the
// attacker-controlled page path through the render hop to the RCE sink.
async function handleRender(req, res) {
    const mod = await render(req.params.path);
    res.json(Object.keys(mod));
}

// render is the utility hop between the ingress and the sink (the reduced stand-in
// for render.js doRender), exercising the analyzer's multi-edge call-graph
// resolution: handleRender -> render -> requireModule.
function render(pagePath) {
    return requireModule(pagePath);
}

const app = makeApp();
app.get('/:path*', handleRender);
app.listen(8080);
