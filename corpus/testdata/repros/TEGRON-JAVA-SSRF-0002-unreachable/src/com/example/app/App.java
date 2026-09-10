package com.example.app;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * TEGRON-JAVA-SSRF-0002 UNREACHABLE variant. Intended verdict: not_exploitable.
 *
 * WHY not_exploitable: the vulnerable dependency com.example.net:urlkit is installed at 2.0.3,
 * INSIDE the advisory's affected range (see pom.xml), so the version axis does NOT disqualify and
 * the case reaches reachability analysis. fetch(String) below IS the SSRF sink — an unguarded
 * outbound GET to a caller-supplied URL, shaped exactly like TEGRON-JAVA-SSRF-0001's
 * UrlFetcher.fetch. It is PHYSICALLY PRESENT in source but DEAD CODE: there is no servlet ingress,
 * no route annotation, no interface-dispatch hop, and main() never calls it (main only prints a
 * banner). The sink is therefore present yet unreachable, so the reachable candidate set is empty —
 * and that emptiness is EVIDENCE ("the sink is defined but never called"), not a "sink not found".
 * The call graph is complete and clean (no unresolved edge, no dynamic dispatch); the dead sink is
 * simply never reached, which decides not_exploitable statically at the reach axis. Nothing here is
 * meant to be built or run.
 */
public final class App {

    private App() {
    }

    public static void main(String[] args) {
        // Benign entry point. Deliberately does NOT call fetch(...): the SSRF sink below is dead
        // code, which is the entire point of this fixture.
        System.out.println("urlkit-repro: ready");
    }

    // fetch is THE SSRF SINK: an unguarded outbound GET to a caller-supplied URL, the same shape as
    // TEGRON-JAVA-SSRF-0001's UrlFetcher.fetch. Nothing in this program invokes it, so it is
    // unreachable dead code.
    public static int fetch(String target) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder(URI.create(target)).GET().build();
        HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream body = response.body()) {
            body.readAllBytes();
        }
        return response.statusCode();
    }
}
