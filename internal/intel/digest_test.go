package intel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

// producerFile is a signals file the producer wrote: ferralon-ai/intel's
// fixtures/e2e-mini/fixtures/public/signals.json at 902d67ab8f1d (last changed in 75e45c9102f),
// copied byte for byte. Its signals_digest is producerDigest, computed by the producer's Build, not
// by anything in this package.
const (
	producerFile   = "testdata/producer-signals.json"
	producerDigest = "sha256:f9dacce837232668428b8e76487e0a478ecb7556e2910abb63cc33ab7560313f"
)

func producerDoc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(producerFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// reserialize writes the JSON document doc compactly with every object's keys in reverse order, and
// every number as the token doc carries: the same document, none of the same bytes.
func reserialize(t *testing.T, doc string) string {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	var write func(v any)
	write = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Sort(sort.Reverse(sort.StringSlice(keys)))
			b.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					b.WriteByte(',')
				}
				write(k)
				b.WriteByte(':')
				write(x[k])
			}
			b.WriteByte('}')
		case []any:
			b.WriteByte('[')
			for i, e := range x {
				if i > 0 {
					b.WriteByte(',')
				}
				write(e)
			}
			b.WriteByte(']')
		default:
			enc, err := json.Marshal(x)
			if err != nil {
				t.Fatal(err)
			}
			b.Write(enc)
		}
	}
	write(v)
	return b.String()
}

// swapFirstRecords is doc with its first two records in each other's place.
func swapFirstRecords(t *testing.T, doc string) []byte {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	recs := v["records"].([]any)
	recs[0], recs[1] = recs[1], recs[0]
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestLoadVerifiesSignalsDigest: Load and Parse recompute signals_digest over the payload in the
// producer's canonical form. The producer's own file loads, and so does the same document in other
// bytes; a changed value, digest, count or record order is refused, naming both digests, and
// nothing loads.
func TestLoadVerifiesSignalsDigest(t *testing.T) {
	doc := producerDoc(t)
	var indented bytes.Buffer
	if err := json.Indent(&indented, []byte(strings.ReplaceAll(doc, "\n", "")), "\t", "\t"); err != nil {
		t.Fatal(err)
	}
	const otherDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const firstScore, secondScore = `"score": 0.00679`, `"score": 0.00485`
	for _, c := range []struct {
		name string
		body []byte
		// refused is empty when the file loads, else a fragment the error must carry.
		refused string
	}{
		{"as the producer wrote it", []byte(doc), ""},
		{"gzip", gzipped(t, doc), ""},
		{"keys reordered, no whitespace", []byte(reserialize(t, doc)), ""},
		{"tabs and other line breaks", indented.Bytes(), ""},
		{"generated_at moved", []byte(strings.Replace(doc, `"2026-10-20T15:18:57Z"`, `"2027-01-01T00:00:00Z"`, 1)), ""},
		{"one record's value changed", []byte(strings.Replace(doc, firstScore, `"score": 0.00678`, 1)), "signals_digest mismatch"},
		{"one record's value changed, reserialized", []byte(reserialize(t, strings.Replace(doc, firstScore, `"score": 0.5`, 1))), "signals_digest mismatch"},
		{"stated digest changed", []byte(strings.Replace(doc, producerDigest, otherDigest, 1)), "the file states sha256:111111111111… but its payload hashes to sha256:f9dacce83723…"},
		{"record_count changed", []byte(strings.Replace(doc, `"record_count": 107`, `"record_count": 106`, 1)), "record_count is 106 but the file holds 107 records"},
		{"two records' scores swapped", []byte(strings.Replace(strings.Replace(strings.Replace(doc, firstScore, "@", 1), secondScore, firstScore, 1), "@", secondScore, 1)), "signals_digest mismatch"},
		{"first two records swapped", swapFirstRecords(t, doc), "signals_digest mismatch"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := writeFixture(t, "signals.json", c.body)
			for _, l := range []struct {
				name string
				load func() (*Signals, error)
			}{
				{"Load", func() (*Signals, error) { return Load(path) }},
				{"Parse", func() (*Signals, error) { return Parse(bytes.NewReader(c.body)) }},
			} {
				s, err := l.load()
				if c.refused == "" {
					if err != nil {
						t.Fatalf("%s: %v", l.name, err)
					}
					if s.Digest != producerDigest || s.Records() != 107 {
						t.Errorf("%s loaded %s with %d records; want %s with 107", l.name, s.Digest, s.Records(), producerDigest)
					}
					continue
				}
				if err == nil || s != nil {
					t.Fatalf("%s = %v, %v; want the file refused", l.name, s, err)
				}
				if !strings.Contains(err.Error(), c.refused) {
					t.Errorf("%s error %q lacks %q", l.name, err, c.refused)
				}
			}
		})
	}
}

// TestDigest: Digest is the producer's signals_digest of a document — the producer's own file's,
// and validDoc's (testDigest, computed by the producer's corpus.CanonicalJSON) — whatever the bytes.
func TestDigest(t *testing.T) {
	doc := producerDoc(t)
	for _, c := range []struct{ name, doc, want string }{
		{"producer's file", doc, producerDigest},
		{"producer's file, reserialized", reserialize(t, doc), producerDigest},
		{"validDoc", validDoc, testDigest},
		{"validDoc, reserialized", reserialize(t, validDoc), testDigest},
		{"number tokens kept", tokenDoc, tokenDigest},
	} {
		if got, err := Digest([]byte(c.doc)); err != nil || got != c.want {
			t.Errorf("%s: Digest = %q, %v; want %s", c.name, got, err, c.want)
		}
	}
	if _, err := Digest([]byte("signals")); err == nil {
		t.Error("Digest of a non-document must error")
	}
}

// tokenDoc carries numbers float64 would rewrite (0.10 as 0.1, 1e-05 as 0.00001). Its digest was
// computed by the producer's corpus.CanonicalJSON, which hashes each number as the token the corpus
// carries.
const (
	tokenDigest = "sha256:b1f3478919bca4b9332551a70ea0b4c4606494f171d558bb7808a00c08be1fff"
	tokenDoc    = `{"signals_version": "1.0.0", "record_count": 1, "signals_digest": "` + tokenDigest + `",
	  "records": [{"identifier": "CVE-2026-0001", "epss": {"score": 0.10, "percentile": 1e-05, "as_of": "2026-10-01"}}]}`
)

// TestLoadRefusesValidDocTampered: hand-written documents whose digests the producer's rule gave
// load, and the same document with a value edited does not.
func TestLoadRefusesValidDocTampered(t *testing.T) {
	for name, doc := range map[string]string{"validDoc": validDoc, "tokenDoc": tokenDoc} {
		if _, err := Load(writeFixture(t, "signals.json", []byte(doc))); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	tampered := strings.Replace(validDoc, `"listed": true`, `"listed": false`, 1)
	if _, err := Load(writeFixture(t, "signals.json", []byte(tampered))); err == nil || !strings.Contains(err.Error(), "signals_digest mismatch") {
		t.Errorf("validDoc with a KEV value flipped: err = %v; want a digest mismatch", err)
	}
}

// wholeDigest is the producer's signals_digest taken the way the producer takes it, and the way
// this package took it before it streamed the hash: the whole payload decoded generically, then
// encoded at once by corpus.CanonicalJSON's Encoder settings. It is the reference payloadHash must
// equal.
func wholeDigest(t *testing.T, doc string) string {
	t.Helper()
	var env struct {
		SignalsVersion string          `json:"signals_version"`
		RecordCount    int             `json:"record_count"`
		Records        json.RawMessage `json:"records"`
	}
	if err := json.Unmarshal([]byte(doc), &env); err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(env.Records))
	dec.UseNumber()
	var recs any
	if err := dec.Decode(&recs); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{"signals_version": env.SignalsVersion, "record_count": env.RecordCount, "records": recs}); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TestPayloadHashMatchesWholeEncoding: the digest hashed one record at a time is the digest of the
// whole payload encoded at once, for documents that exercise every shape the canonical form has:
// no records, one, several; nested and empty objects and arrays an unknown field carries; strings
// HTML escaping would change, escapes, and non-ASCII; and number tokens float64 would rewrite.
func TestPayloadHashMatchesWholeEncoding(t *testing.T) {
	head := `{"signals_version": "1.2.3", "signals_digest": "` + testDigest + `", `
	for name, doc := range map[string]string{
		"producer's file": producerDoc(t),
		"validDoc":        validDoc,
		"tokenDoc":        tokenDoc,
		"no records":      head + `"record_count": 0, "records": []}`,
		"one record":      head + `"record_count": 1, "records": [{"identifier": "CVE-1", "epss": {"score": 1E-7, "as_of": "2026-10-01"}}]}`,
		"unknown fields": head + `"record_count": 2, "records": [
		  {"identifier": "CVE-1", "epss": {"score": 0.50, "as_of": "2026-10-01"}, "note": "<a & b> \u00e9 \"q\" \\ \t", "tags": [], "meta": {}, "deep": {"x": [1, {"y": [[]], "z": null}], "w": true}},
		  {"identifier": "CVE-2", "kev": {"listed": false, "catalog_version": "v", "date_released": "d", "extra": [{"b": 2, "a": 1}]}, "ünï": "Ω"}]}`,
	} {
		want := wholeDigest(t, doc)
		if got, err := Digest([]byte(doc)); err != nil || got != want {
			t.Errorf("%s: Digest = %q, %v; want %s", name, got, err, want)
		}
		sealed := strings.Replace(doc, testDigest, want, 1)
		if !strings.Contains(sealed, want) {
			continue // the producer's file states its own digest
		}
		if s, err := Parse(strings.NewReader(sealed)); err != nil || s.Digest != want {
			t.Errorf("%s: Parse of the sealed document = %v; want it verified as %s", name, err, want)
		}
	}
}
