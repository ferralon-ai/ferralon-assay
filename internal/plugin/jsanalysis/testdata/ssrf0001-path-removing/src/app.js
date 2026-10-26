'use strict';

const http = require('http');

// app.js is the Express-shaped INGRESS for FERRALON-JS-SSRF-0001. app.get('/fetch',
// handleFetch) registers handleFetch as the route handler — the lexically-detectable
// Express route-registration shape with a NAMED handler reference. handleFetch reads
// the attacker-controlled `target` query parameter and passes it through a utility
// (handle) to fetchUrl (the SSRF sink), so the source call graph is
// ingress(handleFetch) -> handle -> fetchUrl.
//
// To stay dependency-free (no node_modules install in the Docker build) this file
// uses a tiny hand-rolled router shaped exactly like Express's app.get(path,
// handler) so the pure-Go analyzer recognizes the route idiom, while the runtime is
// the Node http module. The trigger argv drives GET /fetch?target=internal.

function makeApp() {
    const routes = {};
    const app = {
        get(path, handler) {
            routes['GET ' + path] = handler;
        },
        listen(port) {
            const server = http.createServer((req, res) => {
                const u = new URL(req.url, 'http://127.0.0.1');
                const handler = routes['GET ' + u.pathname];
                const fakeReq = { query: Object.fromEntries(u.searchParams) };
                const fakeRes = {
                    send(body) {
                        res.writeHead(200);
                        res.end(String(body));
                    },
                };
                if (handler) {
                    Promise.resolve(handler(fakeReq, fakeRes)).catch(() => {
                        res.writeHead(502);
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

// handleFetch is the route handler (the ingress). The path-removing patch drops the
// outbound fetch from the route: it refuses every target and no longer calls into
// fetcher.js, so no ingress reaches fetchUrl (which stays defined in fetcher.js).
async function handleFetch(req, res) {
    res.send('403');
}

const app = makeApp();
app.get('/fetch', handleFetch);
app.listen(8080);
