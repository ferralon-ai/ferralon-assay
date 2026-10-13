package dotnetanalysis

// floor_newtonsoft_test.go — the built-in CVE-2024-21907 (Newtonsoft.Json MaxDepth) floor
// symbols, resolved against a synthesized Newtonsoft.Json and searched by Reachability. A
// route into the unbounded JsonReader.Push that none of the public entries names must still
// keep the advisory out of not_exploitable.

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/pipeline"
	"github.com/ferralon-ai/ferralon-assay/plugin"
)

const floorNewtonsoftCVE = "CVE-2024-21907"

var (
	sigInstIntVoid   = []byte{0x20, 0x01, 0x01, 0x08} // instance void M(int)
	sigInstBool      = []byte{0x20, 0x00, 0x02}       // instance bool M()
	sigInstGetString = []byte{0x20, 0x00, 0x0E}       // instance string M()
)

// TestFloorNewtonsoft_SymbolSet pins the floor entry. Dropping JsonReader.Push reopens the
// BsonReader, ReadAs* and custom-reader routes; dropping a public entry hides the common
// routes from the path.
func TestFloorNewtonsoft_SymbolSet(t *testing.T) {
	want := []string{
		"Newtonsoft.Json.JsonReader.Push",
		"Newtonsoft.Json.JsonConvert.DeserializeObject",
		"Newtonsoft.Json.JsonConvert.DeserializeAnonymousType",
		"Newtonsoft.Json.JsonConvert.PopulateObject",
		"Newtonsoft.Json.JsonConvert.DeserializeXmlNode",
		"Newtonsoft.Json.JsonConvert.DeserializeXNode",
		"Newtonsoft.Json.JsonSerializer.Deserialize",
		"Newtonsoft.Json.JsonSerializer.Populate",
		"Newtonsoft.Json.JsonTextReader.Read",
		"Newtonsoft.Json.JsonTextReader.ReadAsync",
		"Newtonsoft.Json.Linq.JToken.Parse",
		"Newtonsoft.Json.Linq.JToken.ReadFrom",
		"Newtonsoft.Json.Linq.JToken.ReadFromAsync",
		"Newtonsoft.Json.Linq.JToken.Load",
		"Newtonsoft.Json.Linq.JToken.LoadAsync",
		"Newtonsoft.Json.Linq.JObject.Parse",
		"Newtonsoft.Json.Linq.JObject.Load",
		"Newtonsoft.Json.Linq.JObject.LoadAsync",
		"Newtonsoft.Json.Linq.JArray.Parse",
		"Newtonsoft.Json.Linq.JArray.Load",
		"Newtonsoft.Json.Linq.JArray.LoadAsync",
		"Newtonsoft.Json.Linq.JConstructor.Load",
		"Newtonsoft.Json.Linq.JConstructor.LoadAsync",
		"Newtonsoft.Json.Linq.JProperty.Load",
		"Newtonsoft.Json.Linq.JProperty.LoadAsync",
	}
	got := slices.Clone(pipeline.AdvisoryTable[floorNewtonsoftCVE].Symbols)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("%s floor symbols = %v\nwant %v", floorNewtonsoftCVE, got, want)
	}
}

// Hand-built reader hierarchy. MethodDef RIDs are assigned in this order, from 1.
const (
	ridReaderPush         = 1 // JsonReader.Push: private, the depth check the fix bounds
	ridReaderSetToken     = 2 // JsonReader.SetToken: protected, calls Push
	ridReaderRead         = 3 // JsonReader.Read: abstract
	ridReaderSkip         = 4 // JsonReader.Skip: callvirt Read
	ridTextRead           = 5 // JsonTextReader.Read: SetToken
	ridTextReadAsString   = 6 // JsonTextReader.ReadAsString: SetToken, never Read
	ridTextReadAsync      = 7
	ridBsonCtor           = 8
	ridBsonRead           = 9 // BsonReader.Read: SetToken
	floorReaderNamespace  = "Newtonsoft.Json"
	floorBsonNamespace    = "Newtonsoft.Json.Bson"
	floorNewtonsoftAsmRef = "Newtonsoft.Json"
)

// floorNewtonsoft synthesizes Newtonsoft.Json with the reader shapes the advisory turns on
// (JsonReader -> SetToken -> private Push, JsonTextReader, Bson.BsonReader) and an empty
// static stub for every other symbol the floor names, so every floor symbol resolves and an
// app that reaches none of them is fully searched.
func floorNewtonsoft(t *testing.T, symbols []string) []byte {
	t.Helper()
	b := scaffold()
	obj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	b.addType(0, "<Module>", "", 0, nil)
	call := func(rid uint32) []byte { return ilCall(mtok(xMethodDef, rid)) }

	reader, _ := b.addType(0x81, "JsonReader", floorReaderNamespace, obj, []mspec{
		{name: "Push", flags: 0x0081, sig: sigInstIntVoid, il: body()},
		{name: "SetToken", flags: 0x0084, sig: sigInstIntVoid, il: body(call(ridReaderPush))},
		{name: "Read", flags: 0x05C6, sig: sigInstBool},
		{name: "Skip", flags: 0x0086, sig: sigInstVoid, il: body(ilCallvirt(mtok(xMethodDef, ridReaderRead)))},
	})
	readerBase := cTypeDefOrRef(xTypeDef, reader)
	b.addType(0x1, "JsonTextReader", floorReaderNamespace, readerBase, []mspec{
		{name: "Read", flags: 0x00C6, sig: sigInstBool, il: body(call(ridReaderSetToken))},
		{name: "ReadAsString", flags: 0x01C6, sig: sigInstGetString, il: body(call(ridReaderSetToken))},
		{name: "ReadAsync", flags: 0x00C6, sig: sigInstGetObject, il: body()},
	})
	b.addType(0x1, "BsonReader", floorBsonNamespace, readerBase, []mspec{
		{name: ".ctor", flags: 0x1886, sig: sigInstVoid, il: body()},
		{name: "Read", flags: 0x00C6, sig: sigInstBool, il: body(call(ridReaderSetToken))},
	})
	handBuilt := map[string]bool{
		floorReaderNamespace + ".JsonReader":     true,
		floorReaderNamespace + ".JsonTextReader": true,
		floorBsonNamespace + ".BsonReader":       true,
	}

	stubs := map[string][]string{} // qualified type -> method names
	for _, s := range symbols {
		dot := strings.LastIndex(s, ".")
		if dot < 0 {
			t.Fatalf("floor symbol %q is not Type.Method", s)
		}
		if typ := s[:dot]; !handBuilt[typ] && !slices.Contains(stubs[typ], s[dot+1:]) {
			stubs[typ] = append(stubs[typ], s[dot+1:])
		}
	}
	types := make([]string, 0, len(stubs))
	for typ := range stubs {
		types = append(types, typ)
	}
	slices.Sort(types)
	for _, typ := range types {
		dot := strings.LastIndex(typ, ".")
		var methods []mspec
		for _, m := range stubs[typ] {
			methods = append(methods, mspec{name: m, flags: 0x16, sig: sigStaticStringToObject, il: body()})
		}
		b.addType(0x1, typ[dot+1:], typ[:dot], obj, methods)
	}
	return b.bytesNamed("Newtonsoft.Json")
}

// floorApp builds App.dll whose Main runs calls(b), plus any first-party types extra adds.
func floorApp(calls func(b *peb) [][]byte) []byte {
	b := scaffold()
	obj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
	b.addType(0, "<Module>", "", 0, nil)
	var il [][]byte
	if calls != nil {
		il = calls(b)
	}
	_, mainRID := b.addType(0, "Program", "App", obj, []mspec{{name: "Main", flags: 0x16, sig: sigStaticVoid, il: body(il...)}})
	b.entry = mtok(xMethodDef, mainRID[0])
	return b.bytesNamed("App")
}

// TestFloorNewtonsoft_UnnamedReaderRoutesAreNotCleared resolves the live floor symbols against
// floorNewtonsoft and runs Reachability over every matched SCIP. With an empty Main every one
// is searched, which is what licenses not_exploitable. Each other row reaches the unbounded
// depth only through a route no public floor entry names, so some matched SCIP must stay out
// of Searched behind a path.
func TestFloorNewtonsoft_UnnamedReaderRoutesAreNotCleared(t *testing.T) {
	ref := func(b *peb, ns, name string) uint32 {
		return b.extTypeRefScoped(b.asmRef(floorNewtonsoftAsmRef), ns, name)
	}
	tests := []struct {
		name      string
		app       func(t *testing.T) []byte
		wantClear bool // every matched SCIP searched, no path
	}{
		{"empty Main is fully searched", func(*testing.T) []byte { return floorApp(nil) }, true},
		{"ReadAsString without Read", func(*testing.T) []byte {
			return floorApp(func(b *peb) [][]byte {
				text := ref(b, floorReaderNamespace, "JsonTextReader")
				return [][]byte{
					ilNewobjOp(b.memberRef(text, ".ctor", sigInstVoid)),
					ilCallvirt(b.memberRef(text, "ReadAsString", sigInstGetString)),
				}
			})
		}, false},
		{"new BsonReader then Read", func(*testing.T) []byte {
			return floorApp(func(b *peb) [][]byte {
				bson := ref(b, floorBsonNamespace, "BsonReader")
				return [][]byte{
					ilNewobjOp(b.memberRef(bson, ".ctor", sigInstVoid)),
					ilCallvirt(b.memberRef(bson, "Read", sigInstBool)),
				}
			})
		}, false},
		{"BsonReader through base-typed JsonReader.Read", func(*testing.T) []byte {
			return floorApp(func(b *peb) [][]byte {
				bson := ref(b, floorBsonNamespace, "BsonReader")
				reader := ref(b, floorReaderNamespace, "JsonReader")
				return [][]byte{
					ilNewobjOp(b.memberRef(bson, ".ctor", sigInstVoid)),
					ilCallvirt(b.memberRef(reader, "Read", sigInstBool)),
				}
			})
		}, false},
		{"BsonReader through base-typed JsonReader.Skip", func(*testing.T) []byte {
			return floorApp(func(b *peb) [][]byte {
				bson := ref(b, floorBsonNamespace, "BsonReader")
				reader := ref(b, floorReaderNamespace, "JsonReader")
				return [][]byte{
					ilNewobjOp(b.memberRef(bson, ".ctor", sigInstVoid)),
					ilCallvirt(b.memberRef(reader, "Skip", sigInstVoid)),
				}
			})
		}, false},
		{"first-party JsonReader subclass", func(*testing.T) []byte {
			b := scaffold()
			obj := cTypeDefOrRef(xTypeRef, b.extTypeRef("System", "Object"))
			reader := ref(b, floorReaderNamespace, "JsonReader")
			setToken := b.memberRef(reader, "SetToken", sigInstIntVoid)
			b.addType(0, "<Module>", "", 0, nil)
			// MyReader methods are MethodDef RIDs 1 (.ctor) and 2 (Read); Main is 3.
			b.addType(0x1, "MyReader", "App", cTypeDefOrRef(xTypeRef, reader), []mspec{
				{name: ".ctor", flags: 0x1886, sig: sigInstVoid, il: body()},
				{name: "Read", flags: 0x00C6, sig: sigInstBool, il: body(ilCall(setToken))},
			})
			_, mainRID := b.addType(0, "Program", "App", obj, []mspec{{name: "Main", flags: 0x16, sig: sigStaticVoid, il: body(
				ilNewobjOp(mtok(xMethodDef, 1)),
				ilCallvirt(mtok(xMethodDef, 2)),
			)}})
			b.entry = mtok(xMethodDef, mainRID[0])
			return b.bytesNamed("App")
		}, false},
	}
	symbols := pipeline.AdvisoryTable[floorNewtonsoftCVE].Symbols
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newDepFixture(t,
				`"Newtonsoft.Json/12.0.3":{"type":"package","runtime":{"lib/net8.0/Newtonsoft.Json.dll":{}}}`,
				newtonsoftLib)
			f.writePkgFile(t, "newtonsoft.json/12.0.3/lib/net8.0/Newtonsoft.Json.dll", floorNewtonsoft(t, symbols))
			if err := os.MkdirAll(filepath.Join(f.buildDir, "bin"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(f.buildDir, "bin", "App.dll"), tt.app(t), 0o644); err != nil {
				t.Fatal(err)
			}

			res := resolveNewtonsoft(t, f, symbols...)
			if len(res.Matched) != len(symbols) || !res.Partiality.Complete {
				t.Fatalf("resolved %d of %d floor symbols, partiality %+v; the fixture must declare every one",
					len(res.Matched), len(symbols), res.Partiality)
			}
			var sinks []string
			for _, s := range symbols {
				sinks = append(sinks, res.Matched[s]...)
			}
			reach, err := Reachability(nil, plugin.ReachabilityRequest{BuildDir: f.buildDir, Symbols: sinks})
			if err != nil {
				t.Fatal(err)
			}
			var unsearched []string
			for _, s := range sinks {
				if !slices.Contains(reach.Searched, s) {
					unsearched = append(unsearched, s)
				}
			}
			if tt.wantClear {
				if len(unsearched) != 0 || len(reach.Paths) != 0 {
					t.Fatalf("empty Main: unsearched %v, %d paths, partiality %+v; want every floor SCIP searched",
						unsearched, len(reach.Paths), reach.Partiality)
				}
				return
			}
			if len(unsearched) == 0 || len(reach.Paths) == 0 {
				t.Fatalf("every floor SCIP searched (%d paths): the route clears as not_exploitable", len(reach.Paths))
			}
		})
	}
}
