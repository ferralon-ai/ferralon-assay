package artifactcache

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"io"
)

// Verify re-hashes the bytes behind h against ref.Digest. Store.Lookup trusts the canonical
// path it derives, so a reader that must know the bytes are the pinned ones (a pre-seeded
// offline cache, a cache another process can write) calls Verify before using them. A
// mismatch is an *IntegrityReason; a digest that fails DecodeDigest is ErrMalformedRef.
func Verify(h Handle, ref Ref) error {
	algo, raw, err := DecodeDigest(ref.Digest)
	if err != nil {
		return err
	}
	var hh hash.Hash
	switch algo {
	case "sha1":
		hh = sha1.New()
	case "sha256":
		hh = sha256.New()
	default:
		hh = sha512.New()
	}
	if _, err := io.Copy(hh, io.NewSectionReader(h, 0, h.Size())); err != nil {
		return err
	}
	got := hh.Sum(nil)
	if hex.EncodeToString(got) != hex.EncodeToString(raw) {
		return &IntegrityReason{
			PURL:              ref.PURL,
			Algo:              algo,
			ExpectedCanonical: algo + ":" + hex.EncodeToString(raw),
			GotCanonical:      algo + ":" + hex.EncodeToString(got),
		}
	}
	return nil
}
