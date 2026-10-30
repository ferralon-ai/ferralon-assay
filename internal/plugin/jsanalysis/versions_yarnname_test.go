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
		{"flag spelled as a script name", pkg(`"--silent":"echo hi","x":"yarn --silent"`), false},
		{"script name with a slash", pkg(`"lint/js":"echo hi","x":"yarn lint/js"`), false},
		{"script name with a backslash", pkg(`"lint\\js":"echo hi","x":"yarn lint\\js"`), false},
		{"double dash among the args", pkg(`"format":"yarn prettier --cwd ../b -- --write ."`), false},
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

// npx <name> with a declared dependency runs its local bin or fetches into the npx cache,
// never the project's node_modules; every other npx form withholds.
func TestResolveVersions_NpxRunsDependency(t *testing.T) {
	const lock = `{"name":"app","lockfileVersion":3,"packages":{` +
		`"":{"name":"app","version":"1.0.0","dependencies":{"express":"4.19.2"},"devDependencies":{"openapi-typescript":"5.4.1","@scope/gen":"1.0.0","npm-run-all":"4.1.5"}},` +
		`"node_modules/express":{"version":"4.19.2"},"node_modules/openapi-typescript":{"version":"5.4.1","dev":true},` +
		`"node_modules/@scope/gen":{"version":"1.0.0","dev":true},"node_modules/npm-run-all":{"version":"4.1.5","dev":true}}}`
	pkg := func(script string) map[string]string {
		return map[string]string{"package-lock.json": lock, "package.json": `{"name":"app","version":"1.0.0",` +
			`"dependencies":{"express":"4.19.2"},"devDependencies":{"openapi-typescript":"5.4.1","@scope/gen":"1.0.0","npm-run-all":"4.1.5"},` +
			`"scripts":{"gen":` + script + `}}`}
	}
	tests := []struct {
		name   string
		script string
		want   bool
	}{
		{"declared dependency with args", `"npx openapi-typescript api.yaml --output types.ts"`, true},
		{"scoped declared dependency", `"npx @scope/gen"`, true},
		{"undeclared name", `"npx left-pad"`, false},
		{"version on the name", `"npx openapi-typescript@6 api.yaml"`, false},
		{"version on a scoped name", `"npx @scope/gen@2"`, false},
		{"--yes before the name", `"npx --yes openapi-typescript api.yaml"`, false},
		{"-p before the name", `"npx -p left-pad openapi-typescript"`, false},
		{"-c", `"npx -c 'openapi-typescript api.yaml'"`, false},
		{"dependency naming a token", `"npx npm-run-all gen"`, false},
		{"argument naming a token", `"npx openapi-typescript yarn"`, false},
		{"bare npx", `"npx"`, false},
		{"npm exec stays vetoed", `"npm exec openapi-typescript api.yaml"`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveJS(t, writeLockTree(t, pkg(tt.script)), "express")
			if !r.Found {
				t.Fatalf("express not found: %+v", r.All)
			}
			if r.Match.Resolved != tt.want {
				t.Fatalf("Resolved = %v, want %v (match %+v)", r.Match.Resolved, tt.want, r.Match)
			}
		})
	}
}
