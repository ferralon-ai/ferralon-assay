package com.example.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.OutputStream;
import java.net.InetSocketAddress;

/**
 * Main starts the repro HTTP server on 127.0.0.1:8080 and routes GET /fetch to the
 * FetchServlet servlet ingress, exactly as a servlet container would dispatch to
 * doGet. The proof engine's trigger argv ("/server & sleep 1; wget .../fetch?
 * target=internal") drives this ingress; in the VULNERABLE build the SSRF sink
 * beacons the seed to the Tegron-controlled OOB endpoint.
 */
public final class Main {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 8080), 0);
        FetchServlet servlet = new FetchServlet();
        server.createContext("/fetch", (HttpExchange exchange) -> {
            StringBuilder resp = new StringBuilder();
            int code = 200;
            try {
                servlet.doGet(exchange, resp);
            } catch (Exception e) {
                code = 502;
                resp.setLength(0);
                resp.append("err");
            }
            byte[] body = resp.toString().getBytes();
            exchange.sendResponseHeaders(code, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        server.setExecutor(null);
        server.start();
        // Keep the process alive; the container's trigger drives a single request.
        Thread.currentThread().join();
    }
}
