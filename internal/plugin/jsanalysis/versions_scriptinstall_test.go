package jsanalysis

import (
	"path/filepath"
	"testing"
)

// A script surface that runs a JavaScript package manager in any form other than the allowed
// ones, or whose allowed form does not bind to files read here, withholds every pin: the build
// may install a version no lock read here records.
func TestResolveVersions_ScriptInstallVeto(t *testing.T) {
	const (
		lock = `{"name":"app","lockfileVersion":3,"packages":{` +
			`"":{"name":"app","version":"1.0.0","dependencies":{"express":"4.19.2"}},` +
			`"node_modules/express":{"version":"4.19.2"}}}`
		docker   = "FROM node:20\nWORKDIR /app\nCOPY package.json package-lock.json ./\nRUN "
		yarnLock = "# yarn lockfile v1\n\n\nexpress@^4.18.0:\n  version \"4.18.2\"\n"
		yarnPkg  = `{"name":"app","version":"1.0.0","dependencies":{"express":"^4.18.0"}}`
	)
	pkg := func(scripts string) string {
		if scripts == "" {
			return `{"name":"app","version":"1.0.0","dependencies":{"express":"4.19.2"}}`
		}
		return `{"name":"app","version":"1.0.0","dependencies":{"express":"4.19.2"},"scripts":{` + scripts + `}}`
	}
	npm := func(extra map[string]string) map[string]string {
		files := map[string]string{"package.json": pkg(""), "package-lock.json": lock}
		for k, v := range extra {
			files[k] = v
		}
		return files
	}
	tests := []struct {
		name  string
		files map[string]string
		want  bool
		root  string // the build root, under the tree written
	}{
		// The repros: a version installed only by a script command.
		{"repro: Dockerfile pins express", npm(map[string]string{"Dockerfile": docker + "npm ci && npm install express@4.18.2\n"}), false, ""},
		{"repro: postinstall pins express", npm(map[string]string{"package.json": pkg(`"postinstall":"npm install --no-save express@4.18.2"`)}), false, ""},

		// Named installs, runners and package managers outside the allowed forms.
		{"transitive: npm install left-pad", npm(map[string]string{"install.sh": "npm install left-pad\n"}), false, ""},
		{"bare npm install", npm(map[string]string{"install.sh": "npm install\n"}), false, ""},
		{"bare npm i", npm(map[string]string{"Makefile": "deps:\n\tnpm i\n"}), false, ""},
		{"plain yarn", npm(map[string]string{"install.sh": "yarn\n"}), false, ""},
		{"yarn install", npm(map[string]string{"install.sh": "yarn install\n"}), false, ""},
		{"yarn install --immutable", npm(map[string]string{"install.sh": "yarn install --immutable\n"}), false, ""},
		{"bare pnpm install", npm(map[string]string{"install.sh": "pnpm install\n"}), false, ""},
		{"yarn add", npm(map[string]string{"install.sh": "yarn add left-pad\n"}), false, ""},
		{"npx", npm(map[string]string{"install.sh": "npx create-thing\n"}), false, ""},
		{"npm exec", npm(map[string]string{"install.sh": "npm exec -- create-thing\n"}), false, ""},
		{"yarn dlx", npm(map[string]string{"install.sh": "yarn dlx create-thing\n"}), false, ""},
		{"pnpx", npm(map[string]string{"install.sh": "pnpx create-thing\n"}), false, ""},
		{"bunx", npm(map[string]string{"install.sh": "bunx create-thing\n"}), false, ""},
		{"npm ci -g", npm(map[string]string{"install.sh": "npm ci -g\n"}), false, ""},
		{"pnpm run installs first", npm(map[string]string{"install.sh": "pnpm run build\n"}), false, ""},
		{"yarn shorthand script", npm(map[string]string{"install.sh": "yarn build\n"}), false, ""},
		{"npm run with trailing argv", npm(map[string]string{"install.sh": "npm run build -- --prod\n"}), false, ""},
		{"unknown: bun install", npm(map[string]string{"install.sh": "bun install\n"}), false, ""},
		{"unknown: bun add", npm(map[string]string{"install.sh": "bun add left-pad\n"}), false, ""},
		{"unknown: deno install", npm(map[string]string{"install.sh": "deno install npm:left-pad\n"}), false, ""},
		{"unknown: corepack", npm(map[string]string{"install.sh": "corepack enable\n"}), false, ""},

		// package.json scripts, every value whatever its key.
		{"script body npm install", npm(map[string]string{"package.json": pkg(`"setup":"npm install"`)}), false, ""},
		{"prebuild hook runs yarn", npm(map[string]string{"package.json": pkg(`"prebuild":"yarn","build":"tsc"`)}), false, ""},
		{"nested a to b to npm i", npm(map[string]string{"package.json": pkg(`"a":"npm run b","b":"npm i"`)}), false, ""},
		{"npm test with an installing pretest", npm(map[string]string{"package.json": pkg(`"pretest":"npm install mocha","test":"mocha"`), "install.sh": "npm test\n"}), false, ""},
		{"postinstall", npm(map[string]string{"package.json": pkg(`"postinstall":"yarn add left-pad"`)}), false, ""},

		// Expansions and variables.
		{"npm_config_registry set by Dockerfile ENV", npm(map[string]string{"Dockerfile": "FROM node:20\nENV npm_config_registry=https://registry.example.com\nWORKDIR /app\nCOPY package.json package-lock.json ./\nRUN npm ci\n"}), false, ""},
		{"YARN_ variable in CI", npm(map[string]string{".github/workflows/ci.yml": "on: push\nenv:\n  YARN_REGISTRY: https://registry.example.com\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci\n"}), false, ""},

		// What an allowed form reads.
		{"unreadable package.json", map[string]string{"package.json": "{not json", "package-lock.json": lock, "install.sh": "npm run build\n"}, false, ""},
		{"yarn --frozen-lockfile with no yarn.lock", npm(map[string]string{"install.sh": "yarn install --frozen-lockfile\n"}), false, ""},
		{"npm ci with no package-lock.json", map[string]string{"package.json": yarnPkg, "yarn.lock": yarnLock, "install.sh": "npm ci\n"}, false, ""},

		// Binding: the directory a command runs in and the file it reads there.
		{"npm pkg set then run", npm(map[string]string{"Dockerfile": docker + "npm pkg set scripts.x=\"npm i lodash\"\nRUN npm run x\n"}), false, ""},
		{"script fetches package.json then runs", npm(map[string]string{"install.sh": "curl -fsSL -o package.json https://example.com/p.json && npm run x\n"}), false, ""},

		// Controls.
		{"npm ci", npm(map[string]string{"install.sh": "npm ci --omit=dev\n"}), true, ""},
		{"Dockerfile COPY then npm run build", npm(map[string]string{"Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY package.json ./\nRUN npm run build\n"}), true, ""},
		{"npm run", npm(map[string]string{"install.sh": "npm run build\n"}), true, ""},
		{"npm run-script", npm(map[string]string{"Makefile": "build:\n\tnpm run-script build\n"}), true, ""},
		{"npm test, t, start", npm(map[string]string{"install.sh": "npm test\nnpm t\nnpm start\n"}), true, ""},
		{"yarn run, test, start", npm(map[string]string{"Procfile": "web: yarn start\nrelease: yarn run migrate\ncheck: yarn test\n"}), true, ""},
		{"scripts that run scripts", npm(map[string]string{"package.json": pkg(`"build":"tsc && npm run lint","lint":"eslint .","postinstall":"npm run build"`)}), true, ""},
		{"yarn --frozen-lockfile with yarn.lock", map[string]string{"package.json": yarnPkg, "yarn.lock": yarnLock, "install.sh": "yarn --frozen-lockfile\n"}, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveJS(t, filepath.Join(writeLockTree(t, tt.files), tt.root), "express")
			if !r.Found {
				t.Fatalf("express not found: %+v", r.All)
			}
			if r.Match.Resolved != tt.want {
				t.Fatalf("Resolved = %v, want %v (match %+v)", r.Match.Resolved, tt.want, r.Match)
			}
		})
	}
}
