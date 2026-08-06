// Package main is a vendored corpus repro for advisory GO-2021-0113 (out-of-bounds
// read / panic in golang.org/x/text/language.Parse on a malformed tag, fixed in
// v0.3.7). It pins the VULNERABLE x/text v0.3.6.
//
// SOUNDNESS: the canary beacon is intrinsic to the vulnerable symbol's faulting
// behavior. The handler passes the untrusted Accept-Language header straight to
// language.Parse inside a defer/recover. The recover block — reached ONLY when
// language.Parse PANICS (i.e. only when the GO-2021-0113 out-of-bounds read fired) —
// is the ONLY place that reads the planted seed (/tmp/tegron_canary) and beacons it
// to $TEGRON_OOB_URL?data=<seed>. A request that does not trip the panic returns
// normally and never reads the seed, so it never beacons. On a patched x/text
// (v0.3.7) Parse returns an error instead of panicking, the recover block is never
// entered, and nothing is exfiltrated. This is what makes a fired beacon attributable
// to the vulnerable fault rather than to a generic "cat the seed" exfil.
package main

import (
	"io"
	"net/http"
	"os"

	"golang.org/x/text/language"
)

const canarySeedPath = "/tmp/tegron_canary"

// beaconCanary is the intrinsic exfil. It is invoked ONLY from the panic-recovery
// path, so reaching it is proof that language.Parse faulted. It reads the planted
// per-case seed and surfaces it to the out-of-band endpoint the sandbox controls.
func beaconCanary() {
	oob := os.Getenv("TEGRON_OOB_URL")
	if oob == "" {
		return
	}
	seed, err := os.ReadFile(canarySeedPath)
	if err != nil {
		return
	}
	resp, err := http.Get(oob + "?data=" + string(seed))
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

func parseHandler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			// Reached ONLY when language.Parse panicked (the GO-2021-0113 fault).
			beaconCanary()
			w.WriteHeader(http.StatusInternalServerError)
		}
	}()
	tag := r.Header.Get("Accept-Language")
	// language.Parse is the GO-2021-0113 vulnerable symbol; on x/text v0.3.6 a
	// malformed tag triggers an out-of-bounds read that PANICS (not a returned error).
	parsed, _ := language.Parse(tag)
	_, _ = io.WriteString(w, parsed.String())
}

func main() {
	http.HandleFunc("/", parseHandler)
	_ = http.ListenAndServe("127.0.0.1:8080", nil)
}
