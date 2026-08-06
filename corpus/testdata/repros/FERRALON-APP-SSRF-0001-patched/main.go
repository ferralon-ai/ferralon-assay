// Package main is the PATCHED variant of the FERRALON-APP-SSRF-0001 corpus repro (server-side
// request forgery, CWE-918). It is byte-for-byte the same handler as the vulnerable variant
// EXCEPT resolveTarget enforces an allowlist: the internal/metadata pseudo-host is rejected
// before any seed is read and before any outbound request is made.
//
// SOUNDNESS (negative control): because the allowlist rejects "internal" up front, the seed
// is never read and the SSRF sink (http.Get of the resolved URL) is never reached for the
// exfiltrating target. No outbound request to the OOB endpoint is ever made, so the canary
// NEVER beacons on this build. Detonating the same trigger against this image must stay DARK
// — that is what makes the vulnerable build's fired beacon a sound proof rather than a
// generic exfil that any build would emit.
package main

import (
	"io"
	"net/http"
	"os"
)

const canarySeedPath = "/tmp/tegron_canary"

// allowedTargets is the SSRF allowlist the patch adds. "internal" (and any
// internal/metadata pseudo-host) is NOT on it, so it is refused before the sink.
var allowedTargets = map[string]bool{
	"public": true,
}

// resolveTarget enforces the allowlist BEFORE reading the seed or constructing any URL. The
// rejected "internal" target never reaches the seed read or the outbound request, so the
// SSRF sink is code-foreclosed.
func resolveTarget(name string) (string, bool) {
	if !allowedTargets[name] {
		return "", false
	}
	// An allowlisted target resolves to a fixed safe URL; it never reads the seed and never
	// reaches the OOB endpoint.
	return "http://127.0.0.1:8080/ok", true
}

func fetchHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	resolved, ok := resolveTarget(target)
	if !ok {
		// SSRF blocked: the allowlist rejected the target. Reference the seed path symbol so
		// the patched and vulnerable sources share the same constant set; the seed is never read.
		_ = canarySeedPath
		_ = os.Getenv
		w.WriteHeader(http.StatusForbidden)
		return
	}
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
