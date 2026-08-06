package com.example.web;

import com.sun.net.httpserver.HttpExchange;

/**
 * FetchServlet is the servlet INGRESS for TEGRON-JAVA-SSRF-0001. It extends
 * HttpServlet and overrides doGet — the lexically-detectable servlet entry-point
 * shape. doGet reads the attacker-controlled `target` query parameter and passes
 * it through a utility method (handle) to UrlFetcher.fetch (the SSRF sink), so the
 * source call graph is ingress(doGet) -> handle -> UrlFetcher.fetch.
 */
public class FetchServlet extends HttpServlet {

    @Override
    public void doGet(HttpExchange req, StringBuilder resp) throws Exception {
        String target = queryParam(req, "target");
        int status = handle(target);
        resp.append(status);
    }

    // handle is the utility hop between the ingress and the sink, exercising the
    // analyzer's multi-edge call-graph resolution (doGet -> handle -> fetch).
    int handle(String target) throws Exception {
        return UrlFetcher.fetch(target);
    }

    private static String queryParam(HttpExchange req, String key) {
        String raw = req.getRequestURI().getRawQuery();
        if (raw == null) {
            return "";
        }
        for (String kv : raw.split("&")) {
            int eq = kv.indexOf('=');
            if (eq > 0 && kv.substring(0, eq).equals(key)) {
                return kv.substring(eq + 1);
            }
        }
        return "";
    }
}
