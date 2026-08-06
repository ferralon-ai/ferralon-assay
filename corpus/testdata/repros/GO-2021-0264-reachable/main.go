// Package main is a vendored corpus repro for advisory GO-2021-0264 (panic in the
// stdlib archive/zip (*Reader).Open on an archive whose entry names are only slashes
// or ".." elements; affects Go 1.16.0-1.16.9 and 1.17.0-1.17.2). The vulnerable symbol
// lives in the Go toolchain, not a versioned module, so it is modeled as a service
// compiled on a vulnerable toolchain (its Dockerfile pins go1.17.1).
//
// The HTTP handler accepts a ZIP upload and reaches (*zip.Reader).Open on a
// user-controlled entry name, so govulncheck finds a reachable ingress->sink pair and
// a candidate pair is built (direction=exploitable). There is DELIBERATELY no
// panic-recovery exfil here: confirming the panic requires a vulnerable toolchain plus
// a crafted pathological archive, which the Phase-1 canary engine cannot deliver. The
// case therefore stops honestly at stopped_capability (no registered engine), not at a
// false proven. Pre-wiring a beacon for this sink would be cheating, so we do not.
package main

import (
	"archive/zip"
	"io"
	"net/http"
)

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	zr, err := zip.NewReader(newReaderAt(body), int64(len(body)))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	for _, f := range zr.File {
		// (*zip.Reader).Open is the GO-2021-0264 vulnerable symbol, reached on the
		// attacker-supplied entry name. On a vulnerable toolchain a pathological name
		// (all slashes or "..") panics.
		rc, err := zr.Open(f.Name)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, rc)
		_ = rc.Close()
	}
	w.WriteHeader(http.StatusOK)
}

func newReaderAt(b []byte) io.ReaderAt { return &byteReaderAt{b} }

type byteReaderAt struct{ b []byte }

func (r *byteReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.b)) {
		return 0, io.EOF
	}
	n := copy(p, r.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func main() {
	http.HandleFunc("/upload", uploadHandler)
	_ = http.ListenAndServe("127.0.0.1:8080", nil)
}
