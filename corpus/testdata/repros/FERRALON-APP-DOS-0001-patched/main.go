// Package main is the PATCHED variant of the FERRALON-APP-DOS-0001 corpus repro (uncontrolled
// resource consumption, CWE-400). It is the same handler as the vulnerable variant EXCEPT
// expandHandler bounds `count` to maxCount BEFORE the allocation, so an oversized count is
// rejected with an error instead of faulting the process.
//
// SOUNDNESS (negative control): because the count is bounded before make([]byte, n), the
// allocation never faults, the defer/recover block is never entered, and beaconFault is never
// called. The canary NEVER beacons on this build. Detonating the same trigger against this
// image must stay DARK — that is what makes the vulnerable build's fired beacon a sound proof
// of the resource-exhaustion fault rather than a generic exfil any build would emit.
package main

import (
	"io"
	"net/http"
	"os"
	"strconv"
)

const canarySeedPath = "/tmp/tegron_canary"

// maxCount is the bound the patch adds: any larger count is rejected before allocation.
const maxCount = 1 << 20 // 1 MiB

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
			// Unreachable on the patched build: the bound below prevents the fault. Kept so the
			// patched and vulnerable sources share the same recovery structure.
			beaconFault()
			w.WriteHeader(http.StatusInternalServerError)
		}
	}()
	n, err := strconv.Atoi(r.URL.Query().Get("count"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// THE PATCH: bound the attacker-controlled count BEFORE allocating. An oversized count is
	// refused, so the allocation never faults and the recover path is never entered.
	if n < 0 || n > maxCount {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	buf := make([]byte, n)
	_, _ = w.Write([]byte(strconv.Itoa(len(buf))))
}

func main() {
	http.HandleFunc("/expand", expandHandler)
	_ = http.ListenAndServe("127.0.0.1:8080", nil)
}
