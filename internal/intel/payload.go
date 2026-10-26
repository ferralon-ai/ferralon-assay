package intel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
)

// fieldSet names the fields a struct decode reads from a JSON object, each with the fields of its
// own value (nil when the value is not an object the decode reads fields from).
type fieldSet map[string]fieldSet

// envelopeFields are the top-level fields of a signals document parse reads.
var envelopeFields = fieldSet{"signals_version": nil, "generated_at": nil, "record_count": nil, "signals_digest": nil, "records": nil}

// recordFields are the fields of a record wireRecord reads.
var recordFields = fieldSet{
	"identifier": nil,
	"epss":       {"score": nil, "percentile": nil, "as_of": nil},
	"kev":        {"listed": nil, "date_added": nil, "catalog_version": nil, "date_released": nil},
}

// checkKey refuses key as the next key of an object whose keys so far are keys, when the digest and
// the struct decode would read the object differently. The digest sees an object as a map of exact
// keys; encoding/json's struct decode matches a key to a field under Unicode case folding
// (strings.EqualFold) and keeps the last of repeated keys. So a key that repeats one before it, a
// key equal to one before it under case folding, and a key that folds to a field of fields but is
// not spelled as it are each refused: {"Score": 0.9, "score": 0.1} and {"score": 0.1, "Score": 0.9}
// hash alike but would load different scores. A key spelled differently from every other key and
// field under case folding is accepted: the producer may add fields within 1.x.
func checkKey(keys []string, key string, fields fieldSet) error {
	for _, k := range keys {
		if k == key {
			return fmt.Errorf("key %q appears more than once", key)
		}
	}
	for f := range fields {
		if f != key && strings.EqualFold(f, key) {
			return fmt.Errorf("key %q is not the field %q: it differs only in case", key, f)
		}
	}
	for _, k := range keys {
		if strings.EqualFold(k, key) {
			return fmt.Errorf("keys %q and %q differ only in case", k, key)
		}
	}
	return nil
}

// decodeChecked decodes the JSON value raw as encoding/json decodes one into an any with UseNumber
// — the value the digest hashes — and refuses, at any depth, an object key checkKey refuses.
// fields are the fields the struct decode reads from raw.
func decodeChecked(raw []byte, fields fieldSet) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return decodeValue(dec, fields, "")
}

// decodeValue decodes the next value from dec for decodeChecked; path names it in an error.
func decodeValue(dec *json.Decoder, fields fieldSet, path string) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch tok {
	case json.Delim('{'):
		obj := map[string]any{}
		var keys []string
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, _ := tok.(string)
			if err := checkKey(keys, key, fields); err != nil {
				if path != "" {
					err = fmt.Errorf("%s: %w", path, err)
				}
				return nil, err
			}
			keys = append(keys, key)
			sub := key
			if path != "" {
				sub = path + "." + key
			}
			if obj[key], err = decodeValue(dec, fields[key], sub); err != nil {
				return nil, err
			}
		}
		_, err := dec.Token()
		return obj, err
	case json.Delim('['):
		arr := []any{}
		for dec.More() {
			v, err := decodeValue(dec, nil, path+"[]")
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		_, err := dec.Token()
		return arr, err
	}
	return tok, nil
}

// recordName names a record in an error message: its identifier, normalised, or "no identifier".
func recordName(raw []byte) string {
	var rec map[string]json.RawMessage
	var id string
	if json.Unmarshal(raw, &rec) == nil && json.Unmarshal(rec["identifier"], &id) == nil && normalise(id) != "" {
		return normalise(id)
	}
	return "no identifier"
}

// Which records value a document holds.
const (
	recordsMissing  = iota // absent, or null
	recordsNotArray        // some other value
	recordsArray
)

// envelope is a signals document as readEnvelope reads it: the top-level fields raw, and each
// record raw.
type envelope struct {
	signalsVersion, generatedAt, recordCount, signalsDigest json.RawMessage

	records      int // recordsMissing, recordsNotArray or recordsArray
	recordValues []json.RawMessage

	// keyErr is the first top-level key checkKey refuses. parse reports it after an unsupported
	// signals_version, which is refused first.
	keyErr error
}

// readEnvelope reads one JSON object from dec, to the end of the stream, keeping each field parse
// reads raw and each record raw, one record at a time: the records array is never held as one value
// alongside the records cut from it.
func readEnvelope(dec *json.Decoder) (*envelope, error) {
	if tok, err := dec.Token(); err != nil {
		return nil, err
	} else if tok != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	env := &envelope{}
	var keys []string
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		if err := checkKey(keys, key, envelopeFields); err != nil && env.keyErr == nil {
			env.keyErr = err
		}
		keys = append(keys, key)
		var dst *json.RawMessage
		switch key {
		case "records":
			if err := env.readRecords(dec); err != nil {
				return nil, err
			}
			continue
		case "signals_version":
			dst = &env.signalsVersion
		case "generated_at":
			dst = &env.generatedAt
		case "record_count":
			dst = &env.recordCount
		case "signals_digest":
			dst = &env.signalsDigest
		default:
			dst = new(json.RawMessage)
		}
		if err := dec.Decode(dst); err != nil {
			return nil, err
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			err = errors.New("data after the document")
		}
		return nil, err
	}
	return env, nil
}

// readRecords reads the records value from dec into env.
func (env *envelope) readRecords(dec *json.Decoder) error {
	env.records, env.recordValues = recordsNotArray, nil
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case nil:
		env.records = recordsMissing
	case json.Delim('['):
		env.records = recordsArray
		for dec.More() {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return err
			}
			env.recordValues = append(env.recordValues, raw)
		}
		_, err := dec.Token()
		return err
	case json.Delim('{'):
		// Skip the object, token by token, to its end.
		for depth := 1; depth > 0; {
			tok, err := dec.Token()
			if err != nil {
				return err
			}
			switch tok {
			case json.Delim('{'), json.Delim('['):
				depth++
			case json.Delim('}'), json.Delim(']'):
				depth--
			}
		}
	}
	return nil
}

// payloadHash is the producer's signals_digest (ferralon-ai/intel, internal/signals/public Build),
// taken one record at a time: "sha256:" and the lowercase hex SHA-256 of the canonical form of the
// object {signals_version, record_count, records}. Neither generated_at nor signals_digest is
// covered. Each record is the value decodeChecked gives, so each number is hashed as the token the
// file carries, as the producer hashes the corpus's own tokens; record_count is hashed as the
// integer, as the producer hashes len(records). Key order and whitespace in the file do not matter;
// array order does.
//
// The canonical form is the producer's corpus.CanonicalJSON (ferralon-ai/intel internal/corpus):
// encoding/json's Encoder, which writes map keys sorted, with HTML escaping off, a two-space indent
// and the one trailing newline Encode adds. payloadHash writes the same bytes straight into the
// hash, never holding the canonical form of the payload: the object's keys, sorted, are
// record_count, records and signals_version, and each record is encoded with the indent prefix of
// its depth, the four spaces that open its line in the whole encoding.
type payloadHash struct {
	sha hash.Hash
	out *heldNewline
	enc *json.Encoder
	n   int // records hashed
}

func newPayloadHash(count int) *payloadHash {
	h := &payloadHash{sha: sha256.New()}
	h.out = &heldNewline{w: h.sha}
	h.enc = json.NewEncoder(h.out)
	h.enc.SetEscapeHTML(false)
	h.enc.SetIndent("    ", "  ")
	fmt.Fprintf(h.sha, "{\n  \"record_count\": %d,\n  \"records\": [", count)
	return h
}

// record hashes the next record.
func (h *payloadHash) record(v any) error {
	if h.n == 0 {
		io.WriteString(h.sha, "\n    ")
	} else {
		io.WriteString(h.sha, ",\n    ")
	}
	h.n++
	return h.encode(v)
}

// sum ends the payload with version and returns its digest.
func (h *payloadHash) sum(version string) (string, error) {
	if h.n == 0 {
		io.WriteString(h.sha, "],\n  \"signals_version\": ")
	} else {
		io.WriteString(h.sha, "\n  ],\n  \"signals_version\": ")
	}
	if err := h.encode(version); err != nil {
		return "", err
	}
	io.WriteString(h.sha, "\n}\n")
	return "sha256:" + hex.EncodeToString(h.sha.Sum(nil)), nil
}

// encode writes v's canonical encoding into the hash, without the newline Encode ends it with.
func (h *payloadHash) encode(v any) error {
	err := h.enc.Encode(v)
	h.out.held = false
	return err
}

// heldNewline writes through to w, holding back a trailing newline until more bytes follow, so the
// newline Encode ends a value with can be dropped.
type heldNewline struct {
	w    io.Writer
	held bool
}

func (h *heldNewline) Write(p []byte) (int, error) {
	n := len(p)
	if n == 0 {
		return 0, nil
	}
	if h.held {
		if _, err := h.w.Write([]byte{'\n'}); err != nil {
			return 0, err
		}
		h.held = false
	}
	if p[n-1] == '\n' {
		p, h.held = p[:n-1], true
	}
	_, err := h.w.Write(p)
	return n, err
}

// Digest recomputes the signals_digest of the signals document doc (plain JSON): the value Load and
// Parse check the document's own signals_digest against. A tool or test that writes a signals file
// stamps it with this. It does not validate the document; Parse does.
func Digest(doc []byte) (string, error) {
	var env struct {
		SignalsVersion string          `json:"signals_version"`
		RecordCount    int             `json:"record_count"`
		Records        json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal(doc, &env); err != nil {
		return "", fmt.Errorf("not a signals document: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(env.Records))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return "", fmt.Errorf("records is not an array")
	}
	h := newPayloadHash(env.RecordCount)
	for dec.More() {
		var rec any
		if err := dec.Decode(&rec); err != nil {
			return "", fmt.Errorf("records: %w", err)
		}
		if err := h.record(rec); err != nil {
			return "", fmt.Errorf("canonicalize the signals payload: %w", err)
		}
	}
	return h.sum(env.SignalsVersion)
}
