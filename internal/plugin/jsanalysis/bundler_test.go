package jsanalysis

import (
	"path/filepath"
	"reflect"
	"testing"
)

// bundlerFixtureDir is the per-tool fixture root.
func bundlerFixtureDir(tool, variant string) string {
	return filepath.Join("testdata", "bundler", tool, variant)
}

func aliasMap(cfg bundlerConfig) map[string]string {
	m := map[string]string{}
	for _, a := range cfg.Aliases {
		m[a.From] = a.To
	}
	return m
}

func defineMap(cfg bundlerConfig) map[string]string {
	m := map[string]string{}
	for _, d := range cfg.Defines {
		m[d.Key] = d.Value
	}
	return m
}

func namesKey(cfg bundlerConfig, key string) bool {
	for _, u := range cfg.Unreadable {
		if u.Key == key {
			return true
		}
	}
	return false
}

// TestReadBundlerConfigsLiteral asserts that a purely-literal configuration for each
// of the six tools yields exactly the expected alias/define/platform/entry maps and a
// Complete partiality (C3, literal half).
func TestReadBundlerConfigsLiteral(t *testing.T) {
	cases := []struct {
		tool     string
		kind     bundlerKind
		aliases  map[string]string
		defines  map[string]string
		platform bundlerPlatform
		entries  []string
	}{
		{
			tool: "webpack", kind: bundlerWebpack,
			aliases:  map[string]string{"@components": "./src/components", "utils": "./src/utils"},
			defines:  map[string]string{"__DEV__": "false", "VERSION": `"1.2.3"`},
			platform: platformNode,
			entries:  []string{"./src/app.js", "./src/admin.js"},
		},
		{
			tool: "rollup", kind: bundlerRollup,
			aliases:  map[string]string{"@lib": "./src/lib", "@utils": "./src/utils"},
			defines:  map[string]string{"__VERSION__": `"2.0.0"`},
			platform: platformUnknown,
			entries:  []string{"./src/main.js"},
		},
		{
			tool: "esbuild", kind: bundlerEsbuild,
			aliases:  map[string]string{"@app": "./src/app"},
			defines:  map[string]string{"process.env.NODE_ENV": `"production"`, "DEBUG": "false"},
			platform: platformNode,
			entries:  []string{"./src/index.ts", "./src/worker.ts"},
		},
		{
			tool: "vite", kind: bundlerVite,
			aliases:  map[string]string{"@": "./src", "@components": "./src/components"},
			defines:  map[string]string{"__APP_VERSION__": `"1.0.0"`, "__FEATURE__": "true"},
			platform: platformBrowser,
			entries:  []string{"./index.html"},
		},
		{
			tool: "swc", kind: bundlerSWC,
			aliases:  map[string]string{"@app/*": "./src/app/*", "@lib/*": "./src/lib/*"},
			defines:  map[string]string{"__DEBUG__": "false", "VERSION": `"3.1.4"`},
			platform: platformUnknown,
			entries:  nil,
		},
		{
			tool: "babel", kind: bundlerBabel,
			aliases:  map[string]string{"@root": "./src", "@test": "./test"},
			defines:  map[string]string{"__ENV__": "production", "__DEBUG__": "false"},
			platform: platformNode,
			entries:  nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			configs, part := readBundlerConfigs(bundlerFixtureDir(tc.tool, "literal"))
			if len(configs) != 1 {
				t.Fatalf("want 1 config, got %d", len(configs))
			}
			cfg := configs[0]
			if cfg.Tool != tc.kind {
				t.Errorf("tool: want %q, got %q", tc.kind, cfg.Tool)
			}
			if cfg.ConfigFile == "" {
				t.Error("ConfigFile provenance empty")
			}
			if !cfg.Partiality.Complete {
				t.Errorf("literal config must be Complete; got reasons %v, unreadable %v", cfg.Partiality.Reasons, cfg.Unreadable)
			}
			if !part.Complete {
				t.Errorf("aggregate partiality must be Complete; got %v", part.Reasons)
			}
			if got := aliasMap(cfg); !reflect.DeepEqual(got, tc.aliases) {
				t.Errorf("aliases: want %v, got %v", tc.aliases, got)
			}
			if got := defineMap(cfg); !reflect.DeepEqual(got, tc.defines) {
				t.Errorf("defines: want %v, got %v", tc.defines, got)
			}
			if cfg.Platform != tc.platform {
				t.Errorf("platform: want %q, got %q", tc.platform, cfg.Platform)
			}
			if cfg.ServerSide != (tc.platform == platformNode) {
				t.Errorf("serverSide: want %v for platform %q, got %v", tc.platform == platformNode, tc.platform, cfg.ServerSide)
			}
			if !reflect.DeepEqual(cfg.Entries, tc.entries) {
				t.Errorf("entries: want %v, got %v", tc.entries, cfg.Entries)
			}
		})
	}
}

// TestReadBundlerConfigsComputed asserts that a configuration computing a value at
// load time yields a declared-partial result that NAMES the unreadable key, for each
// of the six tools — never a default, empty, or silently truncated map (C3, computed
// half; §3.6).
func TestReadBundlerConfigsComputed(t *testing.T) {
	cases := []struct {
		tool          string
		unreadableKey string
		reason        string
		// swallowedFrom is the alias key that MUST NOT appear in the extracted alias
		// map — proving the computed value was not silently defaulted.
		swallowedFrom string
	}{
		{"webpack", "resolve.alias.@components", reasonComputedBundlerAlias, "@components"},
		{"rollup", "alias.entries.@lib", reasonComputedBundlerAlias, "@lib"},
		{"esbuild", "alias.@app", reasonComputedBundlerAlias, "@app"},
		{"vite", "resolve.alias.@", reasonComputedBundlerAlias, "@"},
		{"swc", "jsc.transform.optimizer.globals.vars.VERSION", reasonComputedBundlerDefine, ""},
		{"babel", "module-resolver.alias.@root", reasonComputedBundlerAlias, "@root"},
	}

	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			configs, part := readBundlerConfigs(bundlerFixtureDir(tc.tool, "computed"))
			if len(configs) != 1 {
				t.Fatalf("want 1 config, got %d", len(configs))
			}
			cfg := configs[0]
			if cfg.Partiality.Complete {
				t.Fatalf("computed config must be declared partial; got Complete")
			}
			if part.Complete {
				t.Errorf("aggregate partiality must be partial for a computed config")
			}
			if !namesKey(cfg, tc.unreadableKey) {
				t.Errorf("computed config must NAME the unreadable key %q; got %+v", tc.unreadableKey, cfg.Unreadable)
			}
			if !hasReason(cfg.Partiality, tc.reason) {
				t.Errorf("partiality must carry reason %q; got %v", tc.reason, cfg.Partiality.Reasons)
			}
			// §3.6: the computed value must not have been silently defaulted into the map.
			if tc.swallowedFrom != "" {
				if _, ok := aliasMap(cfg)[tc.swallowedFrom]; ok {
					t.Errorf("computed alias %q must not appear in the extracted map (silent default)", tc.swallowedFrom)
				}
			}
		})
	}
}

// TestComputedMutationControl is the C3 mutation control: it proves the "names the
// key" assertion is load-bearing. A reader that SWALLOWS the computed key (drops the
// unreadableRef instead of recording it) must make the second assertion of
// TestReadBundlerConfigsComputed go red.
func TestComputedMutationControl(t *testing.T) {
	const key = "resolve.alias.@components"
	configs, _ := readBundlerConfigs(bundlerFixtureDir("webpack", "computed"))
	if len(configs) != 1 {
		t.Fatalf("want 1 config, got %d", len(configs))
	}
	cfg := configs[0]

	// Real reader: the assertion passes.
	if !namesKey(cfg, key) {
		t.Fatalf("real reader must name %q", key)
	}

	// Mutant reader: swallow the computed key (drop its unreadableRef). The same
	// assertion must now FAIL — confirming it actually tests the naming, not a
	// coincidental partiality from elsewhere.
	mutant := cfg
	mutant.Unreadable = nil
	for _, u := range cfg.Unreadable {
		if u.Key == key {
			continue // swallow it
		}
		mutant.Unreadable = append(mutant.Unreadable, u)
	}
	if namesKey(mutant, key) {
		t.Fatalf("mutation control failed: swallowing key %q still reports it named", key)
	}
}
