package com.example.web

import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress

/**
 * Main starts the repro HTTP server on 127.0.0.1:8080 and routes GET /fetch to the
 * FetchHandler ingress. The proof engine's trigger argv ("/server & sleep 1; wget
 * .../fetch?target=internal") drives this ingress; in the VULNERABLE build the SSRF
 * sink beacons the seed to the Tegron-controlled OOB endpoint. With
 * `kotlinc -include-runtime -d app.jar`, the JVM entry point is
 * com.example.web.MainKt.
 */
fun main() {
    val server = HttpServer.create(InetSocketAddress("127.0.0.1", 8080), 0)
    val handler = FetchHandler()
    server.createContext("/fetch") { exchange ->
        var code = 200
        var body: String
        try {
            body = handler.handle(exchange).toString()
        } catch (e: Exception) {
            code = 502
            body = "err"
        }
        val bytes = body.toByteArray()
        exchange.sendResponseHeaders(code, bytes.size.toLong())
        exchange.responseBody.use { it.write(bytes) }
    }
    server.executor = null
    server.start()
    // Keep the process alive; the container's trigger drives a single request.
    Thread.currentThread().join()
}
