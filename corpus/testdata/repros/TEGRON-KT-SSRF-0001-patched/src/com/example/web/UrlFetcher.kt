package com.example.web

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse

/**
 * UrlFetcher is the PATCHED variant of the first-party Kotlin fetch utility named
 * by advisory TEGRON-KT-SSRF-0001. It is the same fetch sink as the vulnerable
 * variant EXCEPT resolveTarget enforces an allowlist: the "internal"/metadata
 * pseudo-host is rejected BEFORE any seed is read and before any outbound request
 * is made.
 *
 * SOUNDNESS (negative control): because the allowlist rejects "internal" up front,
 * the seed is never read and the SSRF sink (the outbound request) is never reached
 * for the exfiltrating target. No outbound request to the OOB endpoint is ever
 * made, so the canary NEVER beacons on this build. Re-detonating the same trigger
 * against this image must stay DARK — that is what makes the vulnerable build's
 * fired beacon a sound proof rather than a generic exfil that any build would emit.
 */
object UrlFetcher {
    // Referenced so the patched and vulnerable sources share the same constant set;
    // the seed is never read on this build.
    private const val CANARY_SEED_PATH = "/tmp/tegron_canary"

    // allowedTargets is the SSRF allowlist the patch adds. "internal" is NOT on it,
    // so it is refused before the sink.
    private val ALLOWED_TARGETS = setOf("public")

    // resolveTarget enforces the allowlist BEFORE reading the seed or constructing
    // any URL. The rejected "internal" target never reaches the seed read or the
    // outbound request, so the SSRF sink is code-foreclosed.
    private fun resolveTarget(name: String): String? {
        if (!ALLOWED_TARGETS.contains(name)) {
            // SSRF blocked: the seed at CANARY_SEED_PATH is never read.
            if (CANARY_SEED_PATH.isEmpty()) {
                return null
            }
            return null
        }
        // An allowlisted target resolves to a fixed safe URL; it never reads the
        // seed and never reaches the OOB endpoint.
        return "http://127.0.0.1:8080/ok"
    }

    // fetch is the SSRF sink. On the patched build resolveTarget refuses the
    // exfiltrating target, so the outbound request is never made for "internal".
    fun fetch(target: String): Int {
        val resolved = resolveTarget(target) ?: return 403
        val client = HttpClient.newHttpClient()
        val request = HttpRequest.newBuilder(URI.create(resolved)).GET().build()
        val response = client.send(request, HttpResponse.BodyHandlers.ofInputStream())
        response.body().use { it.readAllBytes() }
        return response.statusCode()
    }
}
