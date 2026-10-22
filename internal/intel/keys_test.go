package intel

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCheckKey: a key is refused when it repeats a key before it, when it is equal to one before it
// under case folding, or when it folds to a known field without being spelled as it; any other
// key, a field the producer may add in 1.x, is accepted.
func TestCheckKey(t *testing.T) {
	epss := recordFields["epss"]
	for _, c := range []struct {
		name   string
		keys   []string
		key    string
		fields fieldSet
		// refused is empty when the key is accepted, else a fragment the error must carry.
		refused string
	}{
		{"a field, spelled as it", nil, "score", epss, ""},
		{"a field after other fields", []string{"as_of", "percentile"}, "score", epss, ""},
		{"an unknown key", []string{"score"}, "scores", epss, ""},
		{"an unknown key, no fields", []string{"a"}, "b", nil, ""},
		{"a repeated field", []string{"score"}, "score", epss, `key "score" appears more than once`},
		{"a repeated unknown key", []string{"note"}, "note", epss, `key "note" appears more than once`},
		{"a field's case variant, alone", nil, "Score", epss, `key "Score" is not the field "score"`},
		{"a field's case variant after the field", []string{"score"}, "Score", epss, `key "Score" is not the field "score"`},
		{"a field's case variant, upper", nil, "AS_OF", epss, `key "AS_OF" is not the field "as_of"`},
		{"a field folded through long s", nil, "ſcore", epss, "key \"ſcore\" is not the field \"score\""},
		{"a field folded through the Kelvin sign", nil, "Kev", recordFields, "key \"Kev\" is not the field \"kev\""},
		{"unknown keys equal under case folding", []string{"Note"}, "note", epss, `keys "Note" and "note" differ only in case`},
		{"unknown keys equal under case folding, no fields", []string{"a"}, "A", nil, `keys "a" and "A" differ only in case`},
	} {
		err := checkKey(c.keys, c.key, c.fields)
		switch {
		case c.refused == "" && err != nil:
			t.Errorf("%s: %v; want the key accepted", c.name, err)
		case c.refused != "" && (err == nil || !strings.Contains(err.Error(), c.refused)):
			t.Errorf("%s: err = %v; want it to carry %q", c.name, err, c.refused)
		}
	}
}

// digestOf is the signals_digest of doc.
func digestOf(t *testing.T, doc string) string {
	t.Helper()
	d, err := Digest([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// sealed is the signals document doc with the testDigest it states replaced by its own digest, so
// that Parse refuses it, if it does, for something other than a digest mismatch.
func sealed(t *testing.T, doc string) string {
	t.Helper()
	return strings.Replace(doc, testDigest, digestOf(t, doc), 1)
}

// TestParseRefusesKeysTheDigestCannotSee (Eric's r1 on #188): the digest hashes each object as a
// map of exact keys, while the loader matches keys to fields under case folding and keeps the last
// of a repeated key, so {"Score": 0.9, "score": 0.1} and {"score": 0.1, "Score": 0.9} hash alike
// and would load different scores. Every such document is refused, at any depth, naming the record
// and the key, though its digest is its own; a document whose unknown keys are spelled differently
// from every field still loads.
func TestParseRefusesKeysTheDigestCannotSee(t *testing.T) {
	const asOf = `"as_of": "2026-10-01"`
	doc := func(fields, record string) string {
		return sealed(t, `{"signals_version": "1.0.0", "record_count": 1, "signals_digest": "`+testDigest+`", `+fields+`"records": [`+record+`]}`)
	}
	rec := func(fields string) string { return doc("", `{"identifier": "CVE-1", `+fields+`}`) }
	scoreFirst, scoreLast := rec(`"epss": {"Score": 0.9, "score": 0.1, `+asOf+`}`), rec(`"epss": {"score": 0.1, "Score": 0.9, `+asOf+`}`)
	if a, b := digestOf(t, scoreFirst), digestOf(t, scoreLast); a != b {
		// Not reached: the two orders hash alike, which is why their keys must be refused.
		t.Fatalf("Eric's two orders hash apart (%s, %s); the case this test pins is gone", a, b)
	}
	for _, c := range []struct{ name, doc, refused string }{
		{"Score before score", scoreFirst, `records[0] (CVE-1): epss: key "Score" is not the field "score"`},
		{"score before Score", scoreLast, `records[0] (CVE-1): epss: key "Score" is not the field "score"`},
		{"a lone Score", rec(`"epss": {"Score": 0.9, ` + asOf + `}`), `records[0] (CVE-1): epss: key "Score" is not the field "score"`},
		{"an exact duplicate", rec(`"epss": {"score": 0.1, "score": 0.9, ` + asOf + `}`), `records[0] (CVE-1): epss: key "score" appears more than once`},
		{"an escaped duplicate", rec(`"epss": {"score": 0.1, "score": 0.9, ` + asOf + `}`), `records[0] (CVE-1): epss: key "score" appears more than once`},
		{"a long-s variant", rec(`"epss": {"ſcore": 0.9, ` + asOf + `}`), "records[0] (CVE-1): epss: key \"ſcore\" is not the field \"score\""},
		{"a variant inside kev", rec(`"kev": {"Listed": true, "listed": false, "catalog_version": "c", "date_released": "d"}`), `records[0] (CVE-1): kev: key "Listed" is not the field "listed"`},
		{"a duplicate inside kev", rec(`"kev": {"listed": true, "catalog_version": "c", "date_released": "d", "listed": false}`), `records[0] (CVE-1): kev: key "listed" appears more than once`},
		{"a duplicate epss", rec(`"epss": {"score": 0.1, ` + asOf + `}, "epss": {"score": 0.9, ` + asOf + `}`), `records[0] (CVE-1): key "epss" appears more than once`},
		{"an identifier variant", doc("", `{"Identifier": "CVE-2", "identifier": "CVE-1", "epss": {"score": 0.1, `+asOf+`}}`), `records[0] (CVE-1): key "Identifier" is not the field "identifier"`},
		{"case-equal unknown keys", rec(`"epss": {"score": 0.1, ` + asOf + `}, "source": {"url": "a", "URL": "b"}`), `records[0] (CVE-1): source: keys "url" and "URL" differ only in case`},
		{"a duplicate deep in an unknown value", rec(`"epss": {"score": 0.1, ` + asOf + `, "model": {"runs": [{"v": 1, "v": 2}]}}`), `records[0] (CVE-1): epss.model.runs[]: key "v" appears more than once`},
		{"a top-level variant", doc(`"Record_Count": 2, `, `{"identifier": "CVE-1", "epss": {"score": 0.1, `+asOf+`}}`), `key "Record_Count" is not the field "record_count"`},
		{"a top-level duplicate", doc(`"signals_version": "1.0.0", `, `{"identifier": "CVE-1", "epss": {"score": 0.1, `+asOf+`}}`), `key "signals_version" appears more than once`},
	} {
		s, err := Parse(strings.NewReader(c.doc))
		if err == nil || s != nil || !strings.Contains(err.Error(), c.refused) {
			t.Errorf("%s: Parse = %v, %v; want it refused with %q", c.name, s, err, c.refused)
		}
	}

	s, err := Parse(strings.NewReader(doc(`"producer": {"name": "intel", "Version": "1"}, `,
		`{"identifier": "CVE-1", "epss": {"score": 0.1, "scores": [0.2], "model": "v4", `+asOf+`}, "source": {"url": "a", "urls": ["b"]}}`)))
	if err != nil {
		t.Fatalf("unknown keys spelled apart from every field: %v; want the document loaded", err)
	}
	if e, ok := s.EPSS("CVE-1"); !ok || e.Score != 0.1 {
		t.Errorf("EPSS(CVE-1) = %+v, %v; want score 0.1", e, ok)
	}
}

// TestCheckKeyAgreesWithTheStructDecode pins what checkKey assumes of encoding/json on the
// toolchain the tests run on: the struct decode reads a key into a field exactly when the key is
// the field's name or one checkKey calls its case variant, never a key checkKey accepts as unknown
// (delimiters count: "asof" and "as-of" are not "as_of").
func TestCheckKeyAgreesWithTheStructDecode(t *testing.T) {
	epss := recordFields["epss"]
	for _, c := range []struct{ key, value string }{
		{"score", "0.5"}, {"Score", "0.5"}, {"SCORE", "0.5"}, {"ſcore", "0.5"}, {"scores", "0.5"}, {"s_core", "0.5"}, {"scor", "0.5"},
		{"as_of", `"x"`}, {"AS_OF", `"x"`}, {"As_Of", `"x"`}, {"asof", `"x"`}, {"as-of", `"x"`}, {"AsOf", `"x"`}, {"as__of", `"x"`},
	} {
		var rec wireRecord
		if err := json.Unmarshal([]byte(`{"epss": {"`+c.key+`": `+c.value+`}}`), &rec); err != nil {
			t.Fatalf("%s: %v", c.key, err)
		}
		read := rec.EPSS != nil && (rec.EPSS.Score != nil || rec.EPSS.AsOf != "")
		_, field := epss[c.key]
		variant := checkKey(nil, c.key, epss) != nil
		if read != (field || variant) {
			t.Errorf("key %q: the struct decode reads it = %v, but checkKey calls it a field %v, a variant %v", c.key, read, field, variant)
		}
	}
}
