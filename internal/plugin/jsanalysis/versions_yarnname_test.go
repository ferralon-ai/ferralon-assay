package jsanalysis

import "testing"

// yarn <name> that no yarn command takes runs "yarn run <name>": a script, or a declared
// dependency's bin, installs nothing; every yarn command and every token withholds.
func TestResolveVersions_YarnRunsName(t *testing.T) {
	const lock = `{"name":"app","lockfileVersion":3,"packages":{` +
		`"":{"name":"app","version":"1.0.0","dependencies":{"express":"4.19.2"},"devDependencies":{"prettier":"2.8.4","npm-run-all":"4.1.5"}},` +
		`"node_modules/express":{"version":"4.19.2"},"node_modules/prettier":{"version":"2.8.4","dev":true},` +
		`"node_modules/npm-run-all":{"version":"4.1.5","dev":true}}}`
	pkg := func(scripts string) map[string]string {
		return map[string]string{"package-lock.json": lock, "package.json": `{"name":"app","version":"1.0.0",` +
			`"dependencies":{"express":"4.19.2"},"devDependencies":{"prettier":"2.8.4","npm-run-all":"4.1.5"},` +
			`"scripts":{"lint":"eslint .",` + scripts + `}}`}
	}
	tests := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"dependency bin with args", pkg(`"format":"yarn prettier --write ."`), true},
		{"script with nothing after it", pkg(`"check":"yarn lint"`), true},
		{"script with args appended", pkg(`"check":"yarn lint --fix"`), false},
		{"neither a script nor a dependency", pkg(`"format":"yarn left-pad"`), false},
		{"dependency naming a token", pkg(`"all":"yarn npm-run-all lint"`), false},
		{"argument naming a token", pkg(`"format":"yarn prettier npx"`), false},
		{"flag before the name", pkg(`"format":"yarn --silent prettier --write ."`), false},
		{"bare yarn", pkg(`"setup":"yarn"`), false},
		{"yarn install", pkg(`"setup":"yarn install"`), false},
		{"yarn add", pkg(`"setup":"yarn add prettier"`), false},
		{"yarn up", pkg(`"setup":"yarn up prettier"`), false},
		{"yarn upgrade-interactive", pkg(`"setup":"yarn upgrade-interactive"`), false},
		{"yarn dlx", pkg(`"setup":"yarn dlx prettier"`), false},
		{"yarn workspaces foreach", pkg(`"setup":"yarn workspaces foreach run build"`), false},
		{"yarn global add", pkg(`"setup":"yarn global add prettier"`), false},
		{"yarn import", pkg(`"setup":"yarn import"`), false},
		{"yarn link", pkg(`"setup":"yarn link prettier"`), false},
		{"yarn unplug", pkg(`"setup":"yarn unplug prettier"`), false},
		{"yarn set version", pkg(`"setup":"yarn set version berry"`), false},
		{"builtin shadowing a script name", pkg(`"add":"echo hi","x":"yarn add"`), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveJS(t, writeLockTree(t, tt.files), "express")
			if !r.Found {
				t.Fatalf("express not found: %+v", r.All)
			}
			if r.Match.Resolved != tt.want {
				t.Fatalf("Resolved = %v, want %v (match %+v)", r.Match.Resolved, tt.want, r.Match)
			}
		})
	}
}
