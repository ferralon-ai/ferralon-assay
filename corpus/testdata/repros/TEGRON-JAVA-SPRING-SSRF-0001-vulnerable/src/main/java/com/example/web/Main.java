package com.example.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.OutputStream;
import java.net.InetSocketAddress;

/**
 * Main starts the repro HTTP server on 127.0.0.1:8080 and routes GET /fetch to the
 * @RestController's fetch method, performing the same field injection a Spring
 * container would: it constructs UrlServiceImpl and assigns it to the @Autowired
 * UrlService field. (The first-party annotation stubs are inert at runtime, so the
 * wiring is done explicitly here — the analysis path is what the @Autowired/
 * interface shape exercises; the runtime path is a real HTTP server that performs
 * the real SSRF so the canary engine detonates.)
 *
 * The proof engine's trigger argv ("/server & sleep 1; wget .../fetch?
 * target=internal") drives this ingress; in the VULNERABLE build the SSRF sink
 * beacons the seed to the Tegron-controlled OOB endpoint.
 */
public final class Main {
    public static void main(String[] args) throws Exception {
        FetchController controller = new FetchController();
        controller.svc = new UrlServiceImpl(); // the @Autowired interface injection

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 8080), 0);
        server.createContext("/fetch", (HttpExchange exchange) -> {
            String target = queryParam(exchange, "target");
            int code = 200;
            String body;
            try {
                body = String.valueOf(controller.fetch(target));
            } catch (Exception e) {
                code = 502;
                body = "err";
            }
            byte[] out = body.getBytes();
            exchange.sendResponseHeaders(code, out.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(out);
            }
        });
        server.setExecutor(null);
        server.start();
        Thread.currentThread().join();
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
