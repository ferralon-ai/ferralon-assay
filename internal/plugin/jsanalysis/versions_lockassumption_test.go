package jsanalysis

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// A build command that installs with no package named, beside a lock that covers every
// package.json it installs for, keeps the pins under one stated assumption. A command that can
// move the installed tree off the lock, or one the lock does not cover, withholds; a command
// that installs nothing, or holds to the lock by its own flags, needs no assumption.
func TestResolveVersions_LockAssumption(t *testing.T) {
	const (
		lock = `{"name":"app","lockfileVersion":3,"packages":{` +
			`"":{"name":"app","version":"1.0.0","dependencies":{"express":"^4.19.0"}},` +
			`"node_modules/express":{"version":"4.19.2"}}}`
		yarnLock = "# yarn lockfile v1\n\n\nexpress@^4.19.0:\n  version \"4.19.2\"\n"
		pnpmLock = "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      express:\n        specifier: ^4.19.0\n        version: 4.19.2\n\npackages:\n  express@4.19.2:\n    resolution: {integrity: sha512-x}\n"
		whole    = "FROM node:20\nWORKDIR /app\nCOPY . /app\nRUN "
		copied   = "FROM node:20\nWORKDIR /app\nCOPY package.json package-lock.json ./\n"
		api      = `{"name":"api","version":"1.0.0","dependencies":{"express":"^4.19.0"}}`
	)
	pkg := func(extra string) string {
		return `{"name":"app","version":"1.0.0","dependencies":{"express":"^4.19.0"}` + extra + `}`
	}
	npm := func(extra map[string]string) map[string]string {
		files := map[string]string{"package.json": pkg(""), "package-lock.json": lock}
		for k, v := range extra {
			files[k] = v
		}
		return files
	}
	ci := func(run string) string {
		return "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: " + run + "\n"
	}
	type outcome int
	const (
		withheld outcome = iota
		assumed
		plain
	)
	tests := []struct {
		name  string
		files map[string]string
		want  outcome
	}{
		// Installs that rest on the lock.
		{"Dockerfile copies the tree, then npm install", npm(map[string]string{"Dockerfile": whole + "npm install\n"}), assumed},
		{"npm install with an override beside the lock", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "npm install\n"}), assumed},
		{"npm install --legacy-peer-deps", npm(map[string]string{"install.sh": "npm install --legacy-peer-deps\n"}), assumed},
		{"npm install under an .npmrc that sets legacy-peer-deps", npm(map[string]string{".npmrc": "legacy-peer-deps=true\n", "install.sh": "npm install\n"}), assumed},
		{"Dockerfile copies an .npmrc that names a registry", npm(map[string]string{"ci/npmrc": "registry=https://registry.example.test/\n", "Dockerfile": copied + "COPY ci/npmrc ./.npmrc\nRUN npm install\n"}), assumed},
		{"Dockerfile copies the yarn lock, then yarn install", map[string]string{"package.json": pkg(""), "yarn.lock": yarnLock, "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY package.json yarn.lock ./\nRUN yarn install\n"}, assumed},
		{"Dockerfile copies an .npmrc that names a registry, then pnpm install", map[string]string{"package.json": pkg(""), "pnpm-lock.yaml": pnpmLock, "ci/npmrc": "registry=https://registry.example.test/\n", "ci/ws.yaml": "packages:\n  - .\n", "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY package.json pnpm-lock.yaml ./\nCOPY ci/npmrc .npmrc\nCOPY ci/ws.yaml pnpm-workspace.yaml\nRUN pnpm install\n"}, assumed},
		{"Dockerfile copies an .npmrc that names a registry to the home directory", npm(map[string]string{"ci/npmrc": "registry=https://registry.example.test/\n", "Dockerfile": copied + "COPY ci/npmrc /root/.npmrc\nRUN npm install\n"}), assumed},
		{"Dockerfile runs another command before it copies the lock", npm(map[string]string{"Dockerfile": "FROM node:20\nRUN apt-get update\nWORKDIR /app\nCOPY package.json package-lock.json ./\nRUN npm install\n"}), assumed},
		{"Dockerfile copies an .npmrc that names a registry into the home directory", npm(map[string]string{"ci/.npmrc": "registry=https://registry.example.test/\n", "Dockerfile": copied + "COPY ci/.npmrc /root\nRUN npm install\n"}), assumed},
		{"npm install with an override that refers to the manifest's own range", npm(map[string]string{"package.json": pkg(`,"overrides":{"express":"$express"}`), "install.sh": "npm install\n"}), assumed},
		{"npm install with an override the lock holds to", npm(map[string]string{"package.json": pkg(`,"overrides":{"express":"4.19.2"}`), "install.sh": "npm install\n"}), assumed},
		{"yarn install", map[string]string{"package.json": pkg(""), "yarn.lock": yarnLock, ".github/workflows/ci.yml": ci("yarn install")}, assumed},
		{"yarn --frozen-lockfile", map[string]string{"package.json": pkg(""), "yarn.lock": yarnLock, ".github/workflows/ci.yml": ci("yarn --frozen-lockfile")}, assumed},
		{"pnpm install", map[string]string{"package.json": pkg(""), "pnpm-lock.yaml": pnpmLock, ".github/workflows/ci.yml": ci("pnpm install")}, assumed},

		// Commands that install nothing, or hold to the lock by their own flags.
		{"npm install the lock covers, placed", npm(map[string]string{"install.sh": "npm install\n"}), plain},
		{"Dockerfile copies the tree, then npm ci", npm(map[string]string{"Dockerfile": whole + "npm ci\n"}), plain},
		{"npm ci in a workflow", npm(map[string]string{".github/workflows/ci.yml": ci("npm ci")}), plain},
		{"Dockerfile copies the tree, then npm start", npm(map[string]string{"Dockerfile": whole + "npm start\n"}), plain},
		{"Dockerfile copies the tree, then npm run build", npm(map[string]string{"Dockerfile": whole + "npm run build\n"}), plain},
		{"npm run with arguments", npm(map[string]string{"package.json": pkg(`,"scripts":{"e2e":"mocha"}`), ".github/workflows/ci.yml": ci("npm run e2e -- --grep smoke")}), plain},
		{"wrapper then npm start", npm(map[string]string{"Dockerfile": whole + "/usr/local/wait-for-it.sh db:27017 -- npm start\n"}), plain},
		{"nx build", npm(map[string]string{"package.json": pkg(`,"scripts":{"build":"nx build"}`)}), plain},
		{"jq reads package.json", npm(map[string]string{".github/workflows/ci.yml": ci("npm ci\n      - run: jq -r .version package.json")}), plain},
		{"playwright browser install", npm(map[string]string{"package.json": `{"name":"app","version":"1.0.0","dependencies":{"express":"^4.19.0"},"devDependencies":{"@playwright/test":"^1.40.0"},"scripts":{"pretest":"npx playwright install chromium"}}`,
			"package-lock.json": `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"express":"^4.19.0"},"devDependencies":{"@playwright/test":"^1.40.0"}},"node_modules/express":{"version":"4.19.2"},"node_modules/@playwright/test":{"version":"1.40.0","dev":true}}}`}), plain},

		// Installs that can leave the lock.
		{"npm install names a package", npm(map[string]string{"Dockerfile": whole + "npm install left-pad\n"}), withheld},
		{"npm update", npm(map[string]string{"Dockerfile": whole + "npm update\n"}), withheld},
		{"npm install --no-package-lock", npm(map[string]string{"Dockerfile": whole + "npm install --no-package-lock\n"}), withheld},
		{"npm install with no lock", map[string]string{"package.json": pkg(""), "other/package.json": pkg(""), "other/package-lock.json": lock, "Dockerfile": whole + "npm install\n"}, withheld},
		{"npm install in a directory the lock above does not cover", npm(map[string]string{"api/package.json": api, "install.sh": "cd api && npm install\n"}), withheld},
		{"npm install beside a second package.json it does not install", npm(map[string]string{"api/package.json": api, "Dockerfile": whole + "npm install\n"}), assumed},
		{"npm install, the lock does not cover the manifest", npm(map[string]string{"package.json": `{"name":"app","version":"1.0.0","dependencies":{"express":"^4.19.0","left-pad":"^1.3.0"}}`, "Dockerfile": whole + "npm install\n"}), withheld},
		{"npm install under an .npmrc that turns the lock off", npm(map[string]string{".npmrc": "package-lock=false\n", "Dockerfile": whole + "npm install\n"}), withheld},
		{"npm install at a prefix that is not read", npm(map[string]string{"Dockerfile": whole + "npm --prefix api install\n"}), withheld},
		{"npm install beside a yarn lock too", npm(map[string]string{".npmrc": "legacy-peer-deps=true\n", "yarn.lock": yarnLock, "install.sh": "npm install\n"}), withheld},
		{"npm install at a prefix whose .npmrc turns the lock off", npm(map[string]string{"api/package.json": api, "api/package-lock.json": `{"name":"api","lockfileVersion":3,"packages":{"":{"name":"api","version":"1.0.0","dependencies":{"express":"^4.19.0"}},"node_modules/express":{"version":"4.19.2"}}}`, "api/.npmrc": "package-lock=false\n", "install.sh": "npm --prefix api install\n"}), withheld},
		{"npm install at a prefix under an .npmrc that sets legacy-peer-deps", npm(map[string]string{"api/package.json": api, "api/package-lock.json": `{"name":"api","lockfileVersion":3,"packages":{"":{"name":"api","version":"1.0.0","dependencies":{"express":"^4.19.0"}},"node_modules/express":{"version":"4.19.2"}}}`, "api/.npmrc": "legacy-peer-deps=true\n", "install.sh": "npm --prefix api install\n"}), assumed},
		{"npm install after a line is added to an .npmrc that sets legacy-peer-deps", npm(map[string]string{".npmrc": "legacy-peer-deps=true\n", ".github/workflows/ci.yml": ci("echo package-lock=false >> .npmrc && npm install")}), withheld},
		{"npm install at a prefix after a line is added to its .npmrc", npm(map[string]string{"api/package.json": api, "api/package-lock.json": `{"name":"api","lockfileVersion":3,"packages":{"":{"name":"api","version":"1.0.0","dependencies":{"express":"^4.19.0"}},"node_modules/express":{"version":"4.19.2"}}}`, "api/.npmrc": "legacy-peer-deps=true\n", ".github/workflows/ci.yml": ci("echo package-lock=false >> api/.npmrc && npm --prefix api install")}), withheld},
		{"Dockerfile copies a directory holding an .npmrc that turns the lock off into the home directory", npm(map[string]string{"ci/.npmrc": "package-lock=false\n", "Dockerfile": copied + "COPY ci/ /root/\nRUN npm install\n"}), withheld},
		{"npm install after the lock is removed", npm(map[string]string{"Dockerfile": whole + "rm package-lock.json && npm install\n"}), withheld},
		{"npm install after package.json is rewritten", npm(map[string]string{"Dockerfile": whole + "sed -i s/4.19/4.18/ package.json && npm install\n"}), withheld},
		{"yarn install beside an npm lock", npm(map[string]string{".github/workflows/ci.yml": ci("yarn install")}), withheld},
		{"yarn add", map[string]string{"package.json": pkg(""), "yarn.lock": yarnLock, ".github/workflows/ci.yml": ci("yarn add left-pad")}, withheld},
		{"pnpm install --no-lockfile", map[string]string{"package.json": pkg(""), "pnpm-lock.yaml": pnpmLock, ".github/workflows/ci.yml": ci("pnpm install --no-lockfile")}, withheld},
		{"Dockerfile copies only package.json, then npm install", npm(map[string]string{"Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY package.json ./\nRUN npm install\n"}), withheld},
		{"Dockerfile copies only package.json, then yarn install", map[string]string{"package.json": pkg(""), "yarn.lock": yarnLock, "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY package.json ./\nRUN yarn install\n"}, withheld},
		{"Dockerfile copies only package.json, then pnpm install", map[string]string{"package.json": pkg(""), "pnpm-lock.yaml": pnpmLock, "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY package.json ./\nRUN pnpm install\n"}, withheld},
		{"npm install in a directory the lock above only records", map[string]string{
			"package.json":      `{"name":"app","version":"1.0.0","dependencies":{"lib":"file:lib"}}`,
			"package-lock.json": `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"lib":"file:lib"}},"lib":{"name":"lib","version":"1.0.0","dependencies":{"express":"^4.19.0"}},"node_modules/lib":{"resolved":"lib","link":true},"node_modules/express":{"version":"4.19.2"}}}`,
			"lib/package.json":  `{"name":"lib","version":"1.0.0","dependencies":{"express":"^4.19.0"}}`,
			"install.sh":        "cd lib && npm install\n"}, withheld},
		{"pnpm install in a directory the lock above records, no workspace", map[string]string{"package.json": pkg(""),
			"pnpm-lock.yaml":   "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      express:\n        specifier: ^4.19.0\n        version: 4.19.2\n  api:\n    dependencies:\n      express:\n        specifier: ^4.19.0\n        version: 4.19.2\n\npackages:\n  express@4.19.2:\n    resolution: {integrity: sha512-x}\n",
			"api/package.json": api, "install.sh": "cd api && pnpm install\n"}, withheld},
		{"npm install, an override beside a lock that does not cover the manifest", npm(map[string]string{"package.json": `{"name":"app","version":"1.0.0","dependencies":{"express":"^5.0.0","left-pad":"^1.3.0"},"overrides":{"qs":"6.11.0"}}`, "install.sh": "npm install\n"}), withheld},
		{"pnpm install under an .npmrc that turns the lock off", map[string]string{"package.json": pkg(""), "pnpm-lock.yaml": pnpmLock, ".npmrc": "lockfile=false\n", ".github/workflows/ci.yml": ci("pnpm install")}, withheld},
		{"pnpm install under a pnpm-workspace.yaml that turns the lock off", map[string]string{"package.json": pkg(""), "pnpm-lock.yaml": pnpmLock, "pnpm-workspace.yaml": "lockfile: false\n", ".github/workflows/ci.yml": ci("pnpm install")}, withheld},
		{"yarn install under a .yarnrc", map[string]string{"package.json": pkg(""), "yarn.lock": yarnLock, ".yarnrc": "--install.no-lockfile true\n", ".github/workflows/ci.yml": ci("yarn install")}, withheld},
		{"yarn install under a .yarnrc.yml", map[string]string{"package.json": pkg(""), "yarn.lock": yarnLock, ".yarnrc.yml": "lockfileFilename: other.lock\n", ".github/workflows/ci.yml": ci("yarn install")}, withheld},
		{"npm install after a line is added to .npmrc", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), ".github/workflows/ci.yml": ci("echo package-lock=false >> .npmrc && npm install")}), withheld},
		{"npm install after a file is copied to the home .npmrc", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "ci/npmrc": "package-lock=false\n", ".github/workflows/ci.yml": ci("cp ci/npmrc ~/.npmrc && npm install")}), withheld},
		{"Dockerfile copies an .npmrc that turns the lock off", npm(map[string]string{"ci/npmrc": "package-lock=false\n", "Dockerfile": copied + "COPY ci/npmrc ./.npmrc\nRUN npm install\n"}), withheld},
		{"Dockerfile copies a directory holding an .npmrc that turns the lock off", npm(map[string]string{"ci/.npmrc": "package-lock=false\n", "Dockerfile": copied + "COPY ci/ ./\nRUN npm install\n"}), withheld},
		{"Dockerfile copies an .npmrc that turns the lock off to the home directory", npm(map[string]string{"ci/npmrc": "package-lock=false\n", "Dockerfile": copied + "COPY ci/npmrc /root/.npmrc\nRUN npm install\n"}), withheld},
		{"Dockerfile copies a .yarnrc.yml", map[string]string{"package.json": pkg(""), "yarn.lock": yarnLock, "ci/yarnrc.yml": "lockfileFilename: other.lock\n", "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY package.json yarn.lock ./\nCOPY ci/yarnrc.yml .yarnrc.yml\nRUN yarn install\n"}, withheld},
		{"Dockerfile copies a pnpm-workspace.yaml that turns the lock off", map[string]string{"package.json": pkg(""), "pnpm-lock.yaml": pnpmLock, "ci/ws.yaml": "lockfile: false\n", "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY package.json pnpm-lock.yaml ./\nCOPY ci/ws.yaml pnpm-workspace.yaml\nRUN pnpm install\n"}, withheld},
		{"Dockerfile copies an .npmrc that turns the pnpm lock off", map[string]string{"package.json": pkg(""), "pnpm-lock.yaml": pnpmLock, "ci/npmrc": "lockfile=false\n", "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY package.json pnpm-lock.yaml ./\nCOPY ci/npmrc .npmrc\nRUN pnpm install\n"}, withheld},
		{"pnpm install under an indented pnpm-workspace.yaml that turns the lock off", map[string]string{"package.json": pkg(""), "pnpm-lock.yaml": pnpmLock, "pnpm-workspace.yaml": "  lockfile: false\n", ".github/workflows/ci.yml": ci("pnpm install")}, withheld},
		{"Dockerfile adds an .npmrc to the home directory", npm(map[string]string{".npmrc": "registry=https://registry.example.test/\n", "Dockerfile": copied + "ADD .npmrc /root/.npmrc\nRUN npm install\n"}), withheld},
		{"Dockerfile copies an .npmrc that turns the lock off into the home directory", npm(map[string]string{"ci/.npmrc": "package-lock=false\n", "Dockerfile": copied + "COPY ci/.npmrc /root\nRUN npm install\n"}), withheld},
		{"pnpm install, an override keyed by a version selector", map[string]string{"package.json": pkg(`,"pnpm":{"overrides":{"express@<5":"4.19.2"}}`), "pnpm-lock.yaml": pnpmLock, ".github/workflows/ci.yml": ci("pnpm install")}, withheld},
		{"npm install, a nested override", npm(map[string]string{"package.json": pkg(`,"overrides":{"express":{"qs":"6.11.0"}}`), "install.sh": "npm install\n"}), withheld},
		{"npm install, an override pins a version the lock does not hold", npm(map[string]string{"package.json": pkg(`,"overrides":{"express":"4.19.0"}`), "install.sh": "npm install\n"}), withheld},
		{"yarn install, a resolution pins a version the lock does not hold", map[string]string{"package.json": pkg(`,"resolutions":{"express":"4.19.0"}`), "yarn.lock": yarnLock, ".github/workflows/ci.yml": ci("yarn install")}, withheld},
		{"pnpm install, an override pins a version the lock does not hold", map[string]string{"package.json": pkg(`,"pnpm":{"overrides":{"express":"4.17.0"}}`), "pnpm-lock.yaml": pnpmLock, ".github/workflows/ci.yml": ci("pnpm install")}, withheld},
		{"wrapper handed the lock, then npm start", npm(map[string]string{"Dockerfile": whole + "cp other.json package-lock.json -- npm start\n"}), withheld},
		{"wrapper then npm install of a package", npm(map[string]string{"Dockerfile": whole + "/usr/local/wait-for-it.sh db:27017 -- npm install left-pad\n"}), withheld},
		{"nx migrate", npm(map[string]string{"package.json": pkg(`,"scripts":{"up":"nx migrate latest"}`)}), withheld},
		{"read-only command with a command substitution", npm(map[string]string{".github/workflows/ci.yml": ci("npm ci\n      - run: cat $(npm install left-pad) package.json")}), withheld},
		{"read-only command redirected onto the lock", npm(map[string]string{".github/workflows/ci.yml": ci("npm ci\n      - run: echo '{}' > package-lock.json")}), withheld},
		{"playwright install of something else", npm(map[string]string{"package.json": pkg(`,"devDependencies":{"@playwright/test":"^1.40.0"},"scripts":{"pretest":"npx playwright install left-pad"}`)}), withheld},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := resolveJS(t, writeLockTree(t, tt.files), "express")
			if !r.Found {
				t.Fatalf("express not found: %+v", r.All)
			}
			if got := r.Match.Resolved; got != (tt.want != withheld) {
				t.Fatalf("Resolved = %v, want %v (partiality %+v)", got, tt.want != withheld, r.Partiality)
			}
			var notes []plugin.Annotation
			for _, a := range r.Annotations {
				if a.Reason == AnnotationInstallHonoursLock {
					notes = append(notes, a)
				}
			}
			switch {
			case tt.want != assumed && len(notes) > 0:
				t.Fatalf("annotations = %+v; want no lock assumption", notes)
			case tt.want == assumed && (len(notes) != 1 || notes[0].Detail != lockAssumption || notes[0].Path != ""):
				t.Fatalf("annotations = %+v; want one %s saying %q, with none of the tree's words", r.Annotations, AnnotationInstallHonoursLock, lockAssumption)
			}
		})
	}
}

// A package cleared as not loaded in a build whose install rests on the lock carries the
// assumption on its refutation.
func TestLoadClosure_LockAssumption(t *testing.T) {
	sink, pkg := "npm:idle@1.0.0#bad", "pkg:npm/idle@1.0.0"
	both := map[string]string{"used": "1.0.0", "idle": "1.0.0"}
	for _, tc := range []struct {
		name, run, src string
		deps           map[string]string
		want           []string
	}{
		{"npm ci from the copied lock", "COPY package.json package-lock.json ./\nRUN npm ci\n", "", both, nil},
		{"npm install over the whole tree", "COPY . /app\nRUN npm install\n", "", both, []string{lockAssumption}},
		// idle is no direct dependency here, so the computed load's bound leaves it out.
		{"npm install over a tree with a computed load", "COPY . /app\nRUN npm install\n", "module.exports = n => require(n);\n",
			map[string]string{"used": "1.0.0"}, []string{computedLoadAssumption([]string{"first-party code"}), lockAssumption}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDepFixture(t, map[string]string{"index.js": "const used = require('used');\nused.run();\n" + tc.src},
				closurePkg("used", nil),
				closurePkg("idle", map[string]string{"index.js": "exports.bad = function bad() {};\n"}),
			)
			// The fixture's lock records no root dependencies; an install is held to a lock only
			// when it covers what package.json declares.
			deps := tc.deps
			var lock map[string]any
			raw, err := os.ReadFile(filepath.Join(f.dir, "package-lock.json"))
			if err != nil || json.Unmarshal(raw, &lock) != nil {
				t.Fatalf("read the fixture lock: %v", err)
			}
			lock["packages"].(map[string]any)[""].(map[string]any)["dependencies"] = deps
			manifest, _ := json.Marshal(map[string]any{"name": "app", "version": "1.0.0", "dependencies": deps})
			raw, _ = json.Marshal(lock)
			for name, data := range map[string][]byte{"package-lock.json": raw, "package.json": manifest} {
				if err := os.WriteFile(filepath.Join(f.dir, name), data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(f.dir, "Dockerfile"), []byte("FROM node:20\nWORKDIR /app\n"+tc.run), 0o644); err != nil {
				t.Fatal(err)
			}
			res, err := Reachability(context.Background(), plugin.ReachabilityRequest{BuildDir: f.dir, Symbols: []string{sink}, Package: pkg, DependencyCache: f.diskCache(t)})
			if err != nil {
				t.Fatal(err)
			}
			if res.Refutation == nil || res.Refutation.Basis != plugin.RefutationPackageNotLoaded {
				t.Fatalf("want a package_not_loaded refutation; got %+v (partiality %+v)", res.Refutation, res.Partiality)
			}
			if got := res.Refutation.Assumptions; !slices.Equal(got, tc.want) {
				t.Fatalf("assumptions = %q, want %q", got, tc.want)
			}
		})
	}
}
