package pythoncgx

import (
	"fmt"
	"strings"
	"time"
)

// Transport selects how the SDK runs cgx.
type Transport string

const (
	// TransportWasm runs cgx in-process as a WebAssembly module (the SDK default).
	TransportWasm Transport = "wasm"
	// TransportNative drives a native cgx binary as a long-lived subprocess.
	TransportNative Transport = "native"
)

// The cgx edge-confidence tiers, lowest to highest. They are cgx's own tokens and are passed
// to cgx verbatim as a minimum: a floor of "probable" keeps probable and certain edges.
const (
	ConfidencePossible = "possible"
	ConfidenceProbable = "probable"
	ConfidenceCertain  = "certain"
)

// DefaultMinConfidence drops cgx's `possible` tier: over-approximated, name-based candidate
// sets whose edge counts run to millions on large Python trees and which the host decodes and
// stores once per advisory. probable+certain is the tier the incumbent's
// single-resolution rule corresponds to.
const DefaultMinConfidence = ConfidenceProbable

// Config is the lane's configuration. cmd/assay-plugin-python-cgx fills it from the
// environment; this package never reads the environment itself.
type Config struct {
	Transport     Transport
	CgxBin        string // native transport: absolute path of the cgx binary
	WasmModule    string // wasm transport: module file overriding the SDK's embedded module
	CacheDir      string // root for index snapshots and the SDK's compile cache
	PoolSize      int    // extractor instances; 0 leaves the SDK default
	MinConfidence string // ConfidencePossible | ConfidenceProbable | ConfidenceCertain
	StatsFile     string // when set, one JSON line per operation is appended here
	// CgxBinSHA256 and WasmModuleSHA256 pin CgxBin and WasmModule (hex SHA-256). A file the
	// configuration names is run only when its digest matches; with no pin it is not run.
	CgxBinSHA256     string
	WasmModuleSHA256 string
	// Fallback, when set, is the transport an operation retries once on after the wasm engine
	// traps (the linear-memory limit included) while indexing. Only TransportNative is
	// accepted (ParseFallback); empty disables the retry.
	Fallback Transport
	// FailureTTL is how long an index failure that may not recur (EngineExit, EngineContext)
	// is replayed before the index is attempted again; 0 never replays one. Deterministic
	// failures (EngineMemoryLimit, EngineTrap) are replayed for as long as the tree, engine
	// build and options are unchanged. ParseFailureTTL gives the default.
	FailureTTL time.Duration
}

// ParseTransport reads a transport name. Empty selects TransportWasm; anything unrecognised
// is an error rather than a silent fallback to the other transport.
func ParseTransport(s string) (Transport, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(TransportWasm):
		return TransportWasm, nil
	case string(TransportNative):
		return TransportNative, nil
	default:
		return "", fmt.Errorf("pythoncgx: unknown transport %q (want %q or %q)", s, TransportWasm, TransportNative)
	}
}

// ParseMinConfidence reads a confidence floor. Empty selects DefaultMinConfidence.
func ParseMinConfidence(s string) (string, error) {
	switch v := strings.ToLower(strings.TrimSpace(s)); v {
	case "":
		return DefaultMinConfidence, nil
	case ConfidencePossible, ConfidenceProbable, ConfidenceCertain:
		return v, nil
	default:
		return "", fmt.Errorf("pythoncgx: unknown confidence %q (want %s, %s or %s)", s, ConfidenceCertain, ConfidenceProbable, ConfidencePossible)
	}
}

// ParseFallback reads the fallback transport. Empty disables it; native is the only fallback,
// since it is the remedy for the wasm engine's memory ceiling.
func ParseFallback(s string) (Transport, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return "", nil
	case string(TransportNative):
		return TransportNative, nil
	default:
		return "", fmt.Errorf("pythoncgx: unknown fallback %q (want %q or empty)", s, TransportNative)
	}
}

// ParseFailureTTL reads FailureTTL as a Go duration ("30m", "0s"). Empty selects
// DefaultFailureTTL; a negative duration is an error.
func ParseFailureTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return DefaultFailureTTL, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("pythoncgx: failure TTL %q: %w", s, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("pythoncgx: failure TTL %q is negative", s)
	}
	return d, nil
}
