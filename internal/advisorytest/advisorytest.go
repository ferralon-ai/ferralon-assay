// Package advisorytest is test support for code that needs advisory facts.
//
// The scanner carries no advisories of its own. Tests that exercise a stage against a known advisory
// read it from the fixture corpus under corpus/testdata/advisories: one JSON document per advisory
// (pipeline.AdvisoryFacts, field for field), pinned by sha256 in manifest.json. This package locates
// that directory from its own source file, so a test in any package reads the same fixtures, and it
// verifies every pin before decoding.
//
// It is generic over the fact type so it does not import pipeline: pipeline's own tests use it.
package advisorytest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ManifestFile is the fixture corpus index.
const ManifestFile = "manifest.json"

// Manifest is the fixture corpus index: the schema handle, the per-advisory pins, and the
// whole-corpus digest over the sorted pins.
type Manifest struct {
	SchemaVersion string           `json:"schema_version"`
	Advisories    map[string]Entry `json:"advisories"`
	CorpusDigest  string           `json:"corpus_digest"`
}

// Entry pins one advisory file by the "sha256:<hex>" digest of its exact bytes.
type Entry struct {
	File   string `json:"file"`
	Digest string `json:"digest"`
}

// Dir returns the absolute path of the fixture corpus directory.
func Dir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		panic("advisorytest: cannot locate the package source")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "corpus", "testdata", "advisories")
}

// Digest returns the "sha256:<hex>" digest of b.
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ReadManifest reads and decodes the fixture corpus manifest.
func ReadManifest() (Manifest, error) {
	var man Manifest
	b, err := os.ReadFile(filepath.Join(Dir(), ManifestFile))
	if err != nil {
		return man, err
	}
	if err := json.Unmarshal(b, &man); err != nil {
		return man, fmt.Errorf("decode %s: %w", ManifestFile, err)
	}
	return man, nil
}

// Load reads every advisory the manifest pins, verifies each file against its digest, and decodes
// it into T, rejecting a field T does not declare.
func Load[T any]() (map[string]T, error) {
	man, err := ReadManifest()
	if err != nil {
		return nil, err
	}
	out := make(map[string]T, len(man.Advisories))
	for id, e := range man.Advisories {
		b, err := os.ReadFile(filepath.Join(Dir(), e.File))
		if err != nil {
			return nil, err
		}
		if got := Digest(b); got != e.Digest {
			return nil, fmt.Errorf("%s: digest %s, manifest pins %s", e.File, got, e.Digest)
		}
		var v T
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("%s: %w", e.File, err)
		}
		out[id] = v
	}
	return out, nil
}

// MustLoad is Load for a package-level test variable; it panics on any error.
func MustLoad[T any]() map[string]T {
	m, err := Load[T]()
	if err != nil {
		panic("advisorytest: " + err.Error())
	}
	return m
}

// Source serves loaded fixtures by id. With T = pipeline.AdvisoryFacts it is a
// pipeline.AdvisorySource.
type Source[T any] map[string]T

// Lookup returns the fixture for id.
func (s Source[T]) Lookup(id string) (T, bool) {
	v, ok := s[id]
	return v, ok
}
