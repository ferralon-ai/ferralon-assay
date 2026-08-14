package artifactcache

import (
	"encoding/base64"
	"encoding/hex"
	"path/filepath"
	"strings"
)

// algoRawLen is the CLOSED allowlist of digest algorithms and their fixed raw byte
// lengths. Any algorithm outside this set fails the gate as ErrMalformedRef. The label is
// a fixed key from this map, never attacker-derived, so it is always a safe path segment.
var algoRawLen = map[string]int{
	"sha1":   20,
	"sha256": 32,
	"sha512": 64,
}

// DecodeDigest is the decode-validate GATE (OQ1). It runs before any path derivation, so a
// crafted ref.Digest is rejected as ErrMalformedRef before a path is ever built:
//
//   - split on the FIRST ':' into (algo, payload); a missing ':' is malformed;
//   - require algo in the closed {sha1,sha256,sha512} allowlist;
//   - decode payload deterministically by charset+length (hex if len==2*rawLen, else
//     base64 std/url if len==base64Len) — never "try one then the other";
//   - reject unless the decoded length equals the algorithm's fixed raw length.
//
// The returned raw bytes are the integrity anchor the Acquirer verifies against and the
// input to the lowercase-hex canonical path. ref.Digest itself keeps the lane's wire form.
func DecodeDigest(digest string) (algo string, raw []byte, err error) {
	i := strings.IndexByte(digest, ':')
	if i < 0 {
		return "", nil, &MalformedReason{Detail: "missing ':' separator between algorithm and payload"}
	}
	algo = digest[:i]
	payload := digest[i+1:]

	rawLen, ok := algoRawLen[algo]
	if !ok {
		return "", nil, &MalformedReason{Algo: algo, Detail: "unknown digest algorithm (not sha1/sha256/sha512)"}
	}

	hexLen := rawLen * 2
	b64Len := base64.StdEncoding.EncodedLen(rawLen) // std and url produce the same length

	switch len(payload) {
	case hexLen:
		raw, err = hex.DecodeString(payload)
		if err != nil {
			return "", nil, &MalformedReason{Algo: algo, Detail: "payload is not valid hex"}
		}
	case b64Len:
		enc := base64.StdEncoding
		if strings.ContainsAny(payload, "-_") { // base64url alphabet markers
			enc = base64.URLEncoding
		}
		raw, err = enc.DecodeString(payload)
		if err != nil {
			return "", nil, &MalformedReason{Algo: algo, Detail: "payload is not valid base64"}
		}
	default:
		return "", nil, &MalformedReason{Algo: algo, Detail: "payload length matches neither hex nor base64 for this algorithm"}
	}

	if len(raw) != rawLen {
		return "", nil, &MalformedReason{Algo: algo, Detail: "decoded digest has the wrong length for its algorithm"}
	}
	return algo, raw, nil
}

// CanonicalPathFromBytes builds the content-addressed path from validated raw digest
// bytes: <root>/<algo>/<hex[:2]>/<hex>, where hex is the LOWERCASE-hex re-encoding of the
// raw bytes. Lowercase hex (drawn only from [0-9a-f]) is the canonical form specifically so
// a case-insensitive filesystem (macOS APFS/HFS+ default) cannot collide two distinct
// digests onto one path, and so no wire character ('/', '+', '=') can survive into a
// segment. algo is a fixed label from the closed allowlist. Callers must pass bytes that
// already cleared DecodeDigest.
func CanonicalPathFromBytes(root, algo string, raw []byte) string {
	seg := hex.EncodeToString(raw)
	return filepath.Join(root, algo, seg[:2], seg)
}

// CanonicalPath runs the gate and derives the content-addressed path for digest, or returns
// ErrMalformedRef. It is the single derivation both Store.Lookup (read) and the Acquirer
// (publish) share, so the two can never disagree about where an artifact lives.
func CanonicalPath(root, digest string) (string, error) {
	algo, raw, err := DecodeDigest(digest)
	if err != nil {
		return "", err
	}
	return CanonicalPathFromBytes(root, algo, raw), nil
}
