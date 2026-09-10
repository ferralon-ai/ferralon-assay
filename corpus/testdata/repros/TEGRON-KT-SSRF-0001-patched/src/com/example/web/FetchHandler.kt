package com.example.web

import com.sun.net.httpserver.HttpExchange

/**
 * FetchHandler is the HTTP INGRESS for TEGRON-KT-SSRF-0001. handle(HttpExchange)
 * reads the attacker-controlled `target` query parameter and passes it through a
 * utility hop (dispatch) to UrlFetcher.fetch (the SSRF sink), so the compiled-
 * bytecode call graph is ingress(handle) -> dispatch -> UrlFetcher.fetch. Main
 * registers this handler on GET /fetch, exactly as the Java repro's Main dispatches
 * to the servlet doGet.
 */
class FetchHandler {

    fun handle(exchange: HttpExchange): Int {
        val target = queryParam(exchange, "target")
        return dispatch(target)
    }

    // dispatch is the utility hop between the ingress and the sink, exercising the
    // analyzer's multi-edge call-graph resolution (handle -> dispatch -> fetch).
    private fun dispatch(target: String): Int {
        return UrlFetcher.fetch(target)
    }

    private fun queryParam(exchange: HttpExchange, key: String): String {
        val raw = exchange.requestURI.rawQuery ?: return ""
        for (kv in raw.split("&")) {
            val eq = kv.indexOf('=')
            if (eq > 0 && kv.substring(0, eq) == key) {
                return kv.substring(eq + 1)
            }
        }
        return ""
    }
}
