'use strict';

const http = require('http');
const { fetchUrl } = require('./fetcher');

// app.js is the Express-shaped INGRESS for TEGRON-JS-SSRF-0001. app.get('/fetch',
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

// handleFetch is the route handler (the ingress). It forwards the attacker-controlled
// `target` through the utility hop to the SSRF sink.
async function handleFetch(req, res) {
    const status = await handle(req.query.target);
    res.send(String(status));
}

// handle is the utility hop between the ingress and the sink, exercising the
// analyzer's multi-edge call-graph resolution (handleFetch -> handle -> fetchUrl).
function handle(target) {
    return fetchUrl(target);
}

const app = makeApp();
app.get('/fetch', handleFetch);
app.listen(8080);
