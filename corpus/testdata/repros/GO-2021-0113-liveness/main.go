// Package main is the LIVENESS-AUGMENTED counterpart of the GO-2021-0113 trivial
// repro (out-of-bounds read / panic in golang.org/x/text/language.Parse on a
// malformed tag, fixed in v0.3.7). It pins the same VULNERABLE x/text v0.3.6 and
// keeps the SAME parseHandler/route/port (GET / on 127.0.0.1:8080), so the PoNE flip
// can clone it as the source, LLM-patch it, and detonate the exploit two-trace on the
// predecessor (this build, unpatched) vs the patched build.
//
// EXPLOIT SOUNDNESS (unchanged from -trivial): the exploit canary beacon is intrinsic
// to the vulnerable symbol's faulting behavior. The handler passes the untrusted
// Accept-Language header straight to language.Parse inside a defer/recover. The recover
// block — reached ONLY when language.Parse PANICS (i.e. only when the GO-2021-0113
// out-of-bounds read fired) — is the ONLY place that reads the planted seed
// (/tmp/tegron_canary) and beacons it to $TEGRON_OOB_URL?data=<seed>. A request that does
// not trip the panic returns normally and never enters the recover block. On a patched
// x/text (v0.3.7) Parse returns an error instead of panicking, the recover block is never
// entered, and nothing is exfiltrated via this path. beaconCanary is left BYTE-FOR-BYTE
// as in -trivial (no kind param ⇒ the observer attributes it as the canary fired-signal).
//
// LIVENESS SOUNDNESS (the §4a F2 addition): the benign liveness beacon proves THIS
// handler/route is ALIVE without carrying the exploit payload. It is GATED on a
// distinct benign marker header — X-Tegron-Liveness — that the exploit trace NEVER
// sends. It fires ONLY on the SUCCESS path (no panic) AND only when the marker is
// present. This gating is load-bearing for soundness:
//
//   - The exploit detonate run sends a MALFORMED tag and NO marker. On the predecessor
//     it panics → exploit beacon; on the PATCHED build it does NOT panic, falls through
//     to the success path, but has NO marker → it does NOT beacon liveness. So the
//     patched exploit trace stays DARK and cannot false-fire the negative trace.
//   - The liveness probe run sends a WELL-FORMED tag AND the marker. It never panics, so
//     it always reaches the success path, sees the marker, and beacons (kind=liveness) on
//     BOTH the predecessor and the patched build — proving the route is up either way.
//
// Were the success-path beacon NOT marker-gated, the patched exploit detonate (malformed
// tag, no panic → success path) would surface the injected secret and FALSELY fire the
// negative trace, destroying the two-trace. The marker is what makes the liveness beacon
// reachable ONLY by the liveness probe and NEVER by the exploit trace.
package main

import (
	"io"
	"net/http"
	"os"

	"golang.org/x/text/language"
)

const canarySeedPath = "/tmp/tegron_canary"

// livenessCanarySeedPath / livenessOOBURLEnv are the DISTINCT co-located liveness channel. When
// the orchestrator runs the liveness probe IN THE SAME container as the exploit detonation (the
// D.6b cross-run-transport close), the exploit channel owns the canonical /tmp/tegron_canary +
// TEGRON_OOB_URL, and the benign liveness beacon reads ITS secret from this distinct seed path
// and beacons to this distinct URL — so the two secret-gated channels reach two independent
// observers and never cross-fire. For the legacy SEPARATE-run liveness probe (which sets only
// TEGRON_OOB_URL and seeds only /tmp/tegron_canary), beaconLiveness falls back to those, so both
// the co-located and the separate-run liveness paths work from the one repro.
const (
	livenessCanarySeedPath = "/tmp/tegron_canary_liveness"
	livenessOOBURLEnv      = "TEGRON_LIVENESS_OOB_URL"
)

// livenessMarkerHeader is the distinct benign marker the liveness probe sends and the
// exploit trace NEVER sends. Its presence (on the non-panic success path) is the sole
// gate on the liveness beacon — see the LIVENESS SOUNDNESS note above.
const livenessMarkerHeader = "X-Tegron-Liveness"

// beaconCanary is the intrinsic EXPLOIT exfil. It is invoked ONLY from the panic-recovery
// path, so reaching it is proof that language.Parse faulted. It reads the planted
// per-case seed and surfaces it to the out-of-band endpoint the sandbox controls. Left
// byte-for-byte identical to the -trivial repro (TestLivePoNETwoTrace depends on that
// fixture; this is the same intrinsic-fault exfil, just in the augmented variant).
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

// beaconLiveness is the benign LIVENESS exfil. It surfaces the SAME per-run injected
// seed but with kind=liveness, so the observer records it as a distinct fired liveness
// signal. It is invoked ONLY from the success path AND only when the benign marker header
// is present — the exploit trace never sets the marker, so it can never reach this beacon.
// The seed it reads is the per-run secret the sandbox plants; distinctness of the liveness
// vs exploit secret is enforced per-run by the orchestrator's two CanarySets (the liveness
// probe and the exploit detonate inject different secrets), not by a second seed file.
func beaconLiveness() {
	// Prefer the DISTINCT co-located liveness channel (its own URL + seed). Fall back to the
	// canonical OOB url + canary seed for the legacy SEPARATE-run liveness probe, which sets only
	// TEGRON_OOB_URL and plants only /tmp/tegron_canary.
	oob := os.Getenv(livenessOOBURLEnv)
	seedPath := livenessCanarySeedPath
	if oob == "" {
		oob = os.Getenv("TEGRON_OOB_URL")
		seedPath = canarySeedPath
	}
	if oob == "" {
		return
	}
	seed, err := os.ReadFile(seedPath)
	if err != nil {
		return
	}
	resp, err := http.Get(oob + "?data=" + string(seed) + "&kind=liveness")
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
	// SUCCESS PATH (no panic). Marker-gated benign liveness beacon: fires ONLY when the
	// distinct X-Tegron-Liveness marker is present — which the exploit trace never sends.
	// This is what keeps the patched exploit detonate (malformed tag, no panic, no marker)
	// DARK on the liveness signal. See the LIVENESS SOUNDNESS note at the top of the file.
	if r.Header.Get(livenessMarkerHeader) != "" {
		beaconLiveness()
	}
	_, _ = io.WriteString(w, parsed.String())
}

func main() {
	http.HandleFunc("/", parseHandler)
	_ = http.ListenAndServe("127.0.0.1:8080", nil)
}
