package jsanalysis

import (
	"os"
	"path/filepath"
	"strings"
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

		sampleInstall = "#!/bin/sh\nnpm install left-pad\n"
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
	// sample is a build holding an installing sample hook, with scripts and further files.
	sample := func(scripts string, more ...string) map[string]string {
		files := npm(map[string]string{".git/hooks/pre-commit.sample": sampleInstall, "package.json": pkg(scripts)})
		for i := 0; i+1 < len(more); i += 2 {
			files[more[i]] = more[i+1]
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
		{"bare npm install, lock covers it", npm(map[string]string{"install.sh": "npm install\n"}), true, ""},
		{"bare npm i, lock covers it", npm(map[string]string{"Makefile": "deps:\n\tnpm i\n"}), true, ""},
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
		{"alias: yarnpkg add", npm(map[string]string{"install.sh": "yarnpkg add express@4.18.2\n"}), false, ""},
		{"alias: cnpm install", npm(map[string]string{"install.sh": "cnpm install express@4.18.2\n"}), false, ""},
		{"wrapper: ni", npm(map[string]string{"install.sh": "ni express@4.18.2\n"}), false, ""},
		{"wrapper: nci", npm(map[string]string{"install.sh": "nci\n"}), false, ""},
		{"wrapper: nr runs a read script", npm(map[string]string{"install.sh": "nr build\n"}), true, ""},
		{"wrapper: nlx", npm(map[string]string{"install.sh": "nlx create-thing\n"}), false, ""},
		{"wrapper: nu", npm(map[string]string{"install.sh": "nu express\n"}), false, ""},
		{"wrapper: nun only uninstalls", npm(map[string]string{"install.sh": "nun express\n"}), true, ""},
		{"wrapper: na", npm(map[string]string{"install.sh": "na add express@4.18.2\n"}), false, ""},
		{"tool: volta install", npm(map[string]string{"install.sh": "volta install express\n"}), false, ""},
		{"monorepo: lerna bootstrap", npm(map[string]string{"install.sh": "lerna bootstrap\n"}), false, ""},
		{"monorepo: rush install", npm(map[string]string{"install.sh": "rush install\n"}), false, ""},
		{"monorepo: nx add", npm(map[string]string{"install.sh": "nx add @nx/react\n"}), false, ""},
		{"cli: ng add", npm(map[string]string{"install.sh": "ng add @angular/material\n"}), false, ""},
		{"cli: ncu upgrades and installs", npm(map[string]string{"install.sh": "ncu -u --install always\n"}), false, ""},
		{"unknown: vlt install", npm(map[string]string{"install.sh": "vlt install express@4.18.2\n"}), false, ""},

		{"action named for a manager", npm(map[string]string{".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: bahmutov/npm-install@v1\n        with:\n          useLockFile: false\n"}), false, ""},
		{"hyphenated runner: npm-run-all", npm(map[string]string{"install.sh": "npm-run-all build\n"}), false, ""},

		// package.json scripts, every value whatever its key.
		{"script body npm install, lock covers it", npm(map[string]string{"package.json": pkg(`"setup":"npm install"`)}), true, ""},
		{"prebuild hook runs yarn", npm(map[string]string{"package.json": pkg(`"prebuild":"yarn","build":"tsc"`)}), false, ""},
		{"nested a to b to npm i, lock covers it", npm(map[string]string{"package.json": pkg(`"a":"npm run b","b":"npm i"`)}), true, ""},
		{"npm test with an installing pretest", npm(map[string]string{"package.json": pkg(`"pretest":"npm install mocha","test":"mocha"`), "install.sh": "npm test\n"}), false, ""},
		{"postinstall", npm(map[string]string{"package.json": pkg(`"postinstall":"yarn add left-pad"`)}), false, ""},

		// Expansions and variables.
		{"npm_config_registry set by Dockerfile ENV", npm(map[string]string{"Dockerfile": "FROM node:20\nENV npm_config_registry=https://registry.example.com\nWORKDIR /app\nCOPY package.json package-lock.json ./\nRUN npm ci\n"}), false, ""},
		{"YARN_ variable in CI", npm(map[string]string{".github/workflows/ci.yml": "on: push\nenv:\n  YARN_REGISTRY: https://registry.example.com\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci\n"}), false, ""},
		{"NPM_FLAGS in netlify.toml", npm(map[string]string{"netlify.toml": "[build.environment]\n  NPM_FLAGS = \"--no-save express@4.18.2\"\n"}), false, ""},
		{"PNPM_FLAGS in netlify.toml", npm(map[string]string{"netlify.toml": "[build.environment]\n  PNPM_FLAGS = \"--no-frozen-lockfile\"\n"}), false, ""},
		{"BUN_FLAGS in a CI file", npm(map[string]string{".github/workflows/ci.yml": "on: push\nenv:\n  BUN_FLAGS: --no-save\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci\n"}), false, ""},
		{"NPM_CONFIG_REGISTRY set by Dockerfile ENV", npm(map[string]string{"Dockerfile": "FROM node:20\nENV NPM_CONFIG_REGISTRY=https://registry.example.com\nWORKDIR /app\nCOPY package.json package-lock.json ./\nRUN npm ci\n"}), false, ""},

		// npm configs that only choose which locked packages install keep the pin; every other
		// installer variable, alone or beside one of them, withholds.
		{"subset: NPM_CONFIG_PRODUCTION=false exported before npm ci", npm(map[string]string{"package.json": pkg(`"heroku-postbuild":"export NPM_CONFIG_PRODUCTION=false && npm ci"`)}), true, ""},
		{"subset: npm_config_production by Dockerfile ENV", npm(map[string]string{"Dockerfile": "FROM node:20\nENV npm_config_production=true\nWORKDIR /app\nCOPY package.json package-lock.json ./\nRUN npm ci\n"}), true, ""},
		{"subset: NPM_CONFIG_OMIT in CI", npm(map[string]string{".github/workflows/ci.yml": "on: push\nenv:\n  NPM_CONFIG_OMIT: dev\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci\n"}), true, ""},
		{"subset: npm_config_include in netlify.toml", npm(map[string]string{"netlify.toml": "[build.environment]\n  npm_config_include = \"dev\"\n"}), true, ""},
		{"subset: npm_config_production exported before npm ci", npm(map[string]string{"install.sh": "export npm_config_production=false && npm ci\n"}), true, ""},
		{"subset: NPM_CONFIG_INCLUDE in netlify.toml", npm(map[string]string{"netlify.toml": "[build.environment]\n  NPM_CONFIG_INCLUDE = \"dev\"\n"}), true, ""},
		{"subset: NPM_CONFIG_ONLY exported", npm(map[string]string{"install.sh": "export NPM_CONFIG_ONLY=prod\nnpm ci\n"}), true, ""},
		{"subset: NPM_CONFIG_PRODUCTION in a GitLab include", npm(map[string]string{".gitlab-ci.yml": "include: ci/vars.yml\nbuild:\n  script:\n    - npm ci\n", "ci/vars.yml": "variables:\n  NPM_CONFIG_PRODUCTION: \"false\"\n"}), true, ""},
		{"flag: npm ci --omit dev", npm(map[string]string{"package.json": pkg(`"b":"npm ci --omit dev"`)}), true, ""},
		{"flag: npm ci --omit=dev", npm(map[string]string{"package.json": pkg(`"b":"npm ci --omit=dev"`)}), true, ""},
		{"flag: npm ci --include=dev", npm(map[string]string{"package.json": pkg(`"b":"npm ci --include=dev"`)}), true, ""},
		{"flag: npm ci --omit=optional", npm(map[string]string{"package.json": pkg(`"b":"npm ci --omit=optional"`)}), true, ""},
		{"flag: npm ci --production", npm(map[string]string{"package.json": pkg(`"b":"npm ci --production"`)}), true, ""},
		{"flag: npm ci --only=prod", npm(map[string]string{"package.json": pkg(`"b":"npm ci --only=prod"`)}), true, ""},
		{"flag: npm ci --omit=dev beside NPM_CONFIG_OMIT=dev", npm(map[string]string{"package.json": pkg(`"b":"export NPM_CONFIG_OMIT=dev && npm ci --omit=dev"`)}), true, ""},
		{"flag: npm ci --omit with no value", npm(map[string]string{"package.json": pkg(`"b":"npm ci --omit"`)}), false, ""},
		{"flag: npm ci --omit=", npm(map[string]string{"package.json": pkg(`"b":"npm ci --omit="`)}), false, ""},
		{"flag: npm ci --omit=bogus", npm(map[string]string{"package.json": pkg(`"b":"npm ci --omit=bogus"`)}), false, ""},
		{"flag: npm ci --omit extra-pkg", npm(map[string]string{"package.json": pkg(`"b":"npm ci --omit extra-pkg"`)}), false, ""},
		{"flag: npm ci --omit dev extra-pkg", npm(map[string]string{"package.json": pkg(`"b":"npm ci --omit dev extra-pkg"`)}), false, ""},
		{"flag: npm ci --include=dev left-pad", npm(map[string]string{"package.json": pkg(`"b":"npm ci --include=dev left-pad"`)}), false, ""},
		{"flag: npm ci --production=true", npm(map[string]string{"package.json": pkg(`"b":"npm ci --production=true"`)}), false, ""},
		{"flag: yarn --frozen-lockfile --omit=dev", map[string]string{"package.json": yarnPkg, "yarn.lock": yarnLock, "install.sh": "yarn --frozen-lockfile --omit=dev\n"}, false, ""},
		{"kept: NPM_CONFIG_PACKAGE_LOCK=false", npm(map[string]string{"install.sh": "export NPM_CONFIG_PACKAGE_LOCK=false\nnpm ci\n"}), false, ""},
		{"kept: NPM_CONFIG_LEGACY_PEER_DEPS", npm(map[string]string{"install.sh": "export NPM_CONFIG_LEGACY_PEER_DEPS=true\nnpm ci\n"}), false, ""},
		{"kept: NPM_CONFIG_FORCE", npm(map[string]string{"install.sh": "export NPM_CONFIG_FORCE=true\nnpm ci\n"}), false, ""},
		{"kept: npm_config_registry by Dockerfile ENV beside a subset config", npm(map[string]string{"Dockerfile": "FROM node:20\nENV npm_config_omit=dev npm_config_registry=https://registry.example.com\nWORKDIR /app\nCOPY package.json package-lock.json ./\nRUN npm ci\n"}), false, ""},
		// pnpm 11 reads PNPM_CONFIG_* in either case, even under CI; none is a kept subset config.
		{"PNPM_CONFIG exported in install.sh", npm(map[string]string{"install.sh": "export PNPM_CONFIG_ENABLE_GLOBAL_VIRTUAL_STORE=true PNPM_CONFIG_STORE_DIR=../tools/.pnpm-store\nnpm ci\n"}), false, ""},
		{"pnpm_config lower-case exported", npm(map[string]string{"install.sh": "export pnpm_config_enable_global_virtual_store=true\nnpm ci\n"}), false, ""},
		{"PNPM_CONFIG in a workflow env", npm(map[string]string{".github/workflows/ci.yml": "on: push\nenv:\n  PNPM_CONFIG_ENABLE_GLOBAL_VIRTUAL_STORE: true\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci\n"}), false, ""},
		{"pnpm_config mixed case exported", npm(map[string]string{"install.sh": "export Pnpm_Config_Enable_Global_Virtual_Store=true\nnpm ci\n"}), false, ""},
		{"pnpm_config_omit is not a kept subset config", npm(map[string]string{"install.sh": "export pnpm_config_omit=dev\nnpm ci\n"}), false, ""},
		{"PNPM_CONFIG_PRODUCTION is not a kept subset config", npm(map[string]string{"install.sh": "export PNPM_CONFIG_PRODUCTION=false\nnpm ci\n"}), false, ""},
		{"kept: unknown NPM_CONFIG_ name", npm(map[string]string{"install.sh": "export NPM_CONFIG_SOMETHING_NEW=1\nnpm ci\n"}), false, ""},
		{"kept: a name that starts with a subset config", npm(map[string]string{"install.sh": "export NPM_CONFIG_OMIT_LOCKFILE_REGISTRY_RESOLVED=true\nnpm ci\n"}), false, ""},
		{"kept: YARN_PRODUCTION", npm(map[string]string{"install.sh": "export YARN_PRODUCTION=true\nnpm ci\n"}), false, ""},
		{"kept: NPM_FLAGS", npm(map[string]string{"netlify.toml": "[build.environment]\n  NPM_FLAGS = \"--production\"\n"}), false, ""},
		{"mixed: subset and registry on one line", npm(map[string]string{"install.sh": "export NPM_CONFIG_PRODUCTION=false NPM_CONFIG_REGISTRY=https://registry.example.com\nnpm ci\n"}), false, ""},
		{"mixed: subset in the file, registry later in it", npm(map[string]string{".github/workflows/ci.yml": "on: push\nenv:\n  NPM_CONFIG_OMIT: dev\njobs:\n  t:\n    runs-on: ubuntu-latest\n    env:\n      NPM_CONFIG_REGISTRY: https://registry.example.com\n    steps:\n      - run: npm ci\n"}), false, ""},
		{"mixed: subset in a GitLab include beside registry", npm(map[string]string{".gitlab-ci.yml": "include: ci/vars.yml\nbuild:\n  script:\n    - npm ci\n", "ci/vars.yml": "variables:\n  NPM_CONFIG_PRODUCTION: \"false\"\n  NPM_CONFIG_REGISTRY: https://registry.example.com\n"}), false, ""},
		{"proshop form: the install after the variable is not an allowed form", npm(map[string]string{"package.json": pkg(`"heroku-postbuild":"NPM_CONFIG_PRODUCTION=false npm install --prefix frontend"`)}), false, ""},

		{"folded run joins a pin to an allowed form", npm(map[string]string{".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: >\n          npm ci\n          express@4.18.2\n"}), false, ""},
		{"PowerShell pins express", npm(map[string]string{"deploy.ps1": "npm install express@4.18.2\n"}), false, ""},
		{"batch pins express", npm(map[string]string{"setup.bat": "call npm install express@4.18.2\r\n"}), false, ""},
		{"GitLab local include pins express", npm(map[string]string{".gitlab-ci.yml": "include:\n  - local: ci/build.yml\n", "ci/build.yml": "build:\n  script:\n    - npm ci && npm install express@4.18.2\n"}), false, ""},

		// yarn 1 --frozen-lockfile is not held to the lock: in a workspace, a member that adds a
		// dependency or moves a range, or a new member, installs versions yarn.lock does not
		// record, exits 0 and leaves the lock unchanged. Every yarn install withholds.
		{"yarn not lock-strict: yarn --frozen-lockfile with yarn.lock", map[string]string{"package.json": yarnPkg, "yarn.lock": yarnLock, "install.sh": "yarn --frozen-lockfile\n"}, false, ""},
		{"yarn not lock-strict: yarn install --frozen-lockfile with yarn.lock", map[string]string{"package.json": yarnPkg, "yarn.lock": yarnLock, "install.sh": "yarn install --frozen-lockfile\n"}, false, ""},
		{"yarn not lock-strict: yarn --frozen-lockfile --production", map[string]string{"package.json": yarnPkg, "yarn.lock": yarnLock, "install.sh": "yarn --frozen-lockfile --production\n"}, false, ""},
		{"yarn not lock-strict: workspace member adds a dependency missing from yarn.lock", map[string]string{
			"package.json":             `{"name":"root","private":true,"workspaces":["packages/*"],"dependencies":{"express":"^4.18.0"}}`,
			"packages/a/package.json":  `{"name":"a","version":"1.0.0","dependencies":{"express":"^4.18.0","absent-package":"^1.0.0"}}`,
			"yarn.lock":                yarnLock,
			".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: yarn --frozen-lockfile\n",
		}, false, ""},
		// yarn installs express 5 for the member; the 4.18.2 the lock records is a stale pin.
		{"yarn not lock-strict: workspace member moves express past the locked 4.18.2", map[string]string{
			"package.json":             `{"name":"root","private":true,"workspaces":["packages/*"],"dependencies":{"express":"^4.18.0"}}`,
			"packages/a/package.json":  `{"name":"a","version":"1.0.0","dependencies":{"express":"^5.0.0"}}`,
			"yarn.lock":                yarnLock,
			".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: yarn --frozen-lockfile\n",
		}, false, ""},
		{"control: pnpm install --frozen-lockfile keeps", map[string]string{"package.json": yarnPkg, "pnpm-lock.yaml": "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      express:\n        specifier: ^4.18.0\n        version: 4.18.2\n\npackages:\n  express@4.18.2:\n    resolution: {integrity: sha512-x}\n", "install.sh": "pnpm install --frozen-lockfile\n"}, true, ""},

		// What an allowed form reads.
		{"unreadable package.json", map[string]string{"package.json": "{not json", "package-lock.json": lock, "install.sh": "npm run build\n"}, false, ""},
		{"yarn --frozen-lockfile with no yarn.lock", npm(map[string]string{"install.sh": "yarn install --frozen-lockfile\n"}), false, ""},
		{"npm ci with no package-lock.json", map[string]string{"package.json": yarnPkg, "yarn.lock": yarnLock, "install.sh": "npm ci\n"}, false, ""},

		// Binding: the directory a command runs in and the file it reads there.
		{"npm pkg set then run", npm(map[string]string{"Dockerfile": docker + "npm pkg set scripts.x=\"npm i lodash\"\nRUN npm run x\n"}), false, ""},
		{"script fetches package.json then runs", npm(map[string]string{"install.sh": "curl -fsSL -o package.json https://example.com/p.json && npm run x\n"}), false, ""},

		{"sources a file beside nvm.sh", npm(map[string]string{"install.sh": ". ~/.nvm/other.sh && npm ci\n"}), false, ""},
		{"sources a file above NVM_DIR", npm(map[string]string{"install.sh": ". \"$NVM_DIR/../evil.sh\" && npm ci\n"}), false, ""},

		// Controls.
		{"npm ci", npm(map[string]string{"install.sh": "npm ci --omit=dev\n"}), true, ""},
		{"Dockerfile COPY then npm run build", npm(map[string]string{"Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY package.json ./\nRUN npm run build\n"}), true, ""},
		{"npm run", npm(map[string]string{"install.sh": "npm run build\n"}), true, ""},
		{"npm run-script", npm(map[string]string{"Makefile": "build:\n\tnpm run-script build\n"}), true, ""},
		{"npm test, t, start", npm(map[string]string{"install.sh": "npm test\nnpm t\nnpm start\n"}), true, ""},
		{"yarn run, test, start", npm(map[string]string{"Procfile": "web: yarn start\nrelease: yarn run migrate\ncheck: yarn test\n"}), true, ""},
		{"scripts that run scripts", npm(map[string]string{"package.json": pkg(`"build":"tsc && npm run lint","lint":"eslint .","postinstall":"npm run build"`)}), true, ""},
		{"nvm.sh, nvm use, npm ci", npm(map[string]string{"install.sh": ". \"$NVM_DIR/nvm.sh\" && nvm use && npm ci\n"}), true, ""},
		{"source ~/.nvm/nvm.sh in a CI run", npm(map[string]string{".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: source ~/.nvm/nvm.sh && npm ci\n"}), true, ""},
		{"cargo env then npm ci", npm(map[string]string{"install.sh": ". \"$HOME/.cargo/env\"\nnpm ci\n"}), true, ""},
		{"git sample hook sourcing git-sh-setup", npm(map[string]string{".git/hooks/pre-rebase.sample": "#!/bin/sh\n. git-sh-setup\n"}), true, ""},
		{"sample hook run in a group", npm(map[string]string{".git/hooks/pre-commit.sample": sampleInstall, "package.json": pkg(`"x":"{ ./.git/hooks/pre-commit.sample; }"`)}), false, ""},
		{"sample hook run in a command substitution", npm(map[string]string{".git/hooks/pre-commit.sample": sampleInstall, "package.json": pkg(`"x":"echo $(./.git/hooks/pre-commit.sample)"`)}), false, ""},
		{"sample hook run in backticks", npm(map[string]string{".git/hooks/pre-commit.sample": sampleInstall, "package.json": pkg(`"x":"echo ` + "`./.git/hooks/pre-commit.sample`" + `"`)}), false, ""},
		{"lock rewritten in a group", npm(map[string]string{"package.json": pkg(`"pre":"{ sed -i s/x/y/ package-lock.json; }","build":"npm ci"`)}), false, ""},
		{"sample hook run with a glued redirect", sample(`"x":"./.git/hooks/pre-commit.sample>out"`), false, ""},
		{"sample hook run in a glued group", sample(`"x":"{ ./.git/hooks/pre-commit.sample&&true; }"`), false, ""},
		{"sample hook run in a glued command substitution", sample(`"x":"echo $(./.git/hooks/pre-commit.sample)x"`), false, ""},
		{"sample hook run in sh -c", sample(`"x":"sh -c 'echo \"$(./.git/hooks/pre-commit.sample)\"'"`), false, ""},
		{"sample hooks run by a script's loop", sample(`"x":"sh scripts/hooks.sh"`, "scripts/hooks.sh", "for h in .git/hooks/*.sample; do sh \"$h\"; done\n"), false, ""},
		{"sample hooks run after command cd", sample(`"x":"command cd .git/hooks && sh ./*.sample"`), false, ""},
		{"sample hook run by a sourced script", sample(`"x":". ./go.sh"`, "go.sh", "cd .git/hooks && ./pre-commit.sample\n"), false, ""},
		{"sample hooks run through eval", sample(`"x":"eval 'cd .git/hooks && ./*.sample'"`), false, ""},
		{"sample hooks run through a dot-glob", sample(`"x":"cd .g*/h* && ./*"`), false, ""},
		{"sample hooks run from a variable directory", sample(`"x":"cd \"$GITDIR\" && ./*"`), false, ""},
		{"glob of every source file beside a sample hook", sample(`"format":"prettier --write \"src/**/*\""`), true, ""},
		{"glob of the build root beside a sample hook", sample(`"clean":"rm -rf *"`), true, ""},
		{"glob of another directory beside a sample hook", sample(`"zip":"cd dist && zip -r x.zip *"`, "dist/a.txt", "a\n"), true, ""},
		{"glob of every dotted name in the build root beside a sample hook", sample(`"copy":"cp *.* out/"`), true, ""},
		{"build beside a sample hook", sample(`"build":"tsc"`), true, ""},
		{"sample hook run by a node build script", sample(`"prepare":"node scripts/setup.js"`, "scripts/setup.js", "require('child_process').execSync('sh .git/hooks/pre-commit.sample')\n"), false, ""},
		{"sample hooks run by a node script's readdir loop", sample(`"prepare":"node scripts/prepare.js"`, "scripts/prepare.js", "const fs = require('fs'), cp = require('child_process')\nfor (const h of fs.readdirSync('.git/hooks')) cp.execSync('sh ' + h, {cwd: '.git/hooks'})\n"), false, ""},
		{"sample hook run by an ES module postinstall", sample(`"postinstall":"node tools/init.mjs"`, "tools/init.mjs", "import { execSync } from 'node:child_process'\nexecSync('sh .git/hooks/pre-commit.sample')\n"), false, ""},
		{"sample hook run by an extensionless node script", sample(`"prepare":"./bin/setup"`, "bin/setup", "#!/usr/bin/env node\nrequire('child_process').execSync('sh .git/hooks/pre-commit.sample')\n"), false, ""},
		{"node build script and React hooks beside a sample hook", sample(`"build":"node scripts/build.js"`, "scripts/build.js", "require('fs').copyFileSync('src/index.html', 'dist/index.html')\n", "src/hooks/useThing.ts", "export function useThing() { return 1 }\n", "src/index.ts", "import { useThing } from './hooks/useThing'\n"), true, ""},
		{"live git hook sourcing git-sh-setup", npm(map[string]string{".git/hooks/pre-rebase": "#!/bin/sh\n. git-sh-setup\n"}), false, ""},
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

// npm run, run-script and start bind to <dir>/package.json alone under --prefix <dir>, any npm
// form may follow assignments to subset-selection variables, and concurrently runs commands
// that pass the same gate. Every variant outside those withholds.
func TestResolveVersions_ScriptForms(t *testing.T) {
	const (
		lock = `{"name":"app","lockfileVersion":3,"packages":{` +
			`"":{"name":"app","version":"1.0.0","dependencies":{"express":"4.19.2"}},` +
			`"node_modules/express":{"version":"4.19.2"}}}`
		front = `{"name":"frontend","scripts":{"start":"react-scripts start","build":"react-scripts build"}}`
	)
	pkg := func(scripts string) string {
		return `{"name":"app","version":"1.0.0","dependencies":{"express":"4.19.2"},"scripts":{` + scripts + `}}`
	}
	tree := func(scripts string, extra map[string]string) map[string]string {
		files := map[string]string{"package.json": pkg(scripts), "package-lock.json": lock, "frontend/package.json": front}
		for k, v := range extra {
			files[k] = v
		}
		return files
	}
	tests := []struct {
		name  string
		files map[string]string
		links map[string]string // link → target, relative to the tree
		want  bool
	}{
		// (a) a leading assignment to a subset-selection variable.
		{"assignment: NPM_CONFIG_PRODUCTION=false npm ci", tree(`"heroku-postbuild":"NPM_CONFIG_PRODUCTION=false npm ci"`, nil), nil, true},
		{"assignment: two kept, lowercase, then npm ci", tree(`"build":"npm_config_omit=dev NPM_CONFIG_INCLUDE=optional npm ci"`, nil), nil, true},
		{"assignment: another variable", tree(`"build":"NODE_ENV=production npm ci"`, nil), nil, false},
		{"assignment: kept after another", tree(`"build":"NODE_ENV=production NPM_CONFIG_OMIT=dev npm ci"`, nil), nil, false},
		{"assignment: kept, then a named install", tree(`"build":"NPM_CONFIG_PRODUCTION=false npm install left-pad"`, nil), nil, false},
		{"assignment: kept, then a non-npm runner", tree(`"build":"NPM_CONFIG_PRODUCTION=false npx thing"`, nil), nil, false},

		// (b) --prefix <dir>.
		{"prefix: npm start --prefix frontend", tree(`"client":"npm start --prefix frontend"`, nil), nil, true},
		{"prefix: npm run build --prefix frontend", tree(`"build":"npm run build --prefix frontend"`, nil), nil, true},
		{"prefix: npm run-script --prefix=frontend build", tree(`"build":"npm run-script --prefix=frontend build"`, nil), nil, true},
		{"prefix: kept assignment then --prefix", tree(`"build":"NPM_CONFIG_PRODUCTION=false npm run build --prefix frontend"`, nil), nil, true},
		{"prefix: ../x", tree(`"client":"npm start --prefix ../x"`, map[string]string{"../x/package.json": front}), nil, false},
		{"prefix: .. inside the build", tree(`"client":"npm start --prefix frontend/../frontend"`, nil), nil, false},
		{"prefix: symlinked dir", tree(`"client":"npm start --prefix web"`, nil), map[string]string{"web": "frontend"}, false},
		{"prefix: symlinked package.json", tree(`"client":"npm start --prefix web"`, map[string]string{"web/x": ""}), map[string]string{"web/package.json": "../frontend/package.json"}, false},
		{"prefix: package.json not read", tree(`"client":"npm start --prefix frontend"`, map[string]string{"frontend/package.json": "{not json"}), nil, false},
		{"prefix: package.json in a directory the walk skips", tree(`"client":"npm start --prefix node_modules/web"`, map[string]string{"node_modules/web/package.json": front}), nil, false},
		{"prefix: no package.json there", tree(`"client":"npm start --prefix backend"`, map[string]string{"backend/server.js": ""}), nil, false},
		{"prefix: given twice", tree(`"client":"npm start --prefix frontend --prefix frontend"`, nil), nil, false},
		{"prefix: no dir", tree(`"client":"npm start --prefix"`, nil), nil, false},
		{"prefix: npm test is not a prefixed form", tree(`"t":"npm test --prefix frontend"`, nil), nil, false},
		{"prefix: npm start with another argument", tree(`"client":"npm start --prefix frontend extra"`, nil), nil, false},
		{"prefix: absolute dir", tree(`"build":"npm run build --prefix /frontend"`, nil), nil, false},
		{"prefix: after a cd to an expansion", tree(`"build":"cd $X && npm run build --prefix frontend"`, nil), nil, false},
		{"prefix: after a cd to no directory", tree(`"build":"cd nowhere && npm run build --prefix frontend"`, nil), nil, false},
		{"prefix: package.json rewritten first", tree(`"build":"sed -i s/x/y/ frontend/package.json; npm run build --prefix frontend"`, nil), nil, false},
		{"prefix: dir literally named with a glob character", tree(`"client":"npm start --prefix front*"`, map[string]string{"front*/package.json": front}), nil, false},
		{"prefix: dir literally named with a brace", tree(`"client":"npm start --prefix fr{o,}ntend"`, map[string]string{"fr{o,}ntend/package.json": front}), nil, false},

		// (d) concurrently.
		{"concurrently: two npm runs", tree(`"dev":"concurrently \"npm run server\" \"npm run client\"","server":"node server","client":"npm start --prefix frontend"`, nil), nil, true},
		{"concurrently: -k and a prefixed start", tree(`"dev":"concurrently -k \"npm run server\" \"npm start --prefix frontend\""`, nil), nil, true},
		{"concurrently: each command runs in a shell of its own", tree(`"dev":"concurrently \"cd nowhere\" \"npm ci\""`, nil), nil, true},
		{"concurrently: a cd in one command does not move the next", tree(`"dev":"concurrently \"cd frontend\" \"npm start --prefix frontend\""`, nil), nil, true},
		{"concurrently: a named install", tree(`"dev":"concurrently \"npm run server\" \"npm install left-pad\""`, nil), nil, false},
		{"concurrently: an unknown flag", tree(`"dev":"concurrently --passthrough-arguments \"npm run server\""`, nil), nil, false},
		{"concurrently: a valued flag", tree(`"dev":"concurrently -n api,web \"npm run server\" \"npm run client\""`, nil), nil, false},
		{"concurrently: an unterminated quote in a command", tree(`"dev":"concurrently \"npm run 'server\""`, nil), nil, false},
		{"concurrently: a subshell in a command", tree(`"dev":"concurrently \"(npm run server)\""`, nil), nil, false},
		{"concurrently: a command ending in &&", tree(`"dev":"concurrently \"npm run server &&\""`, nil), nil, false},
		{"concurrently: npm: shorthand", tree(`"dev":"concurrently \"npm:watch-*\""`, nil), nil, false},
		{"concurrently: a bare npm command", tree(`"dev":"concurrently -k npm"`, nil), nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeLockTree(t, tt.files)
			for link, target := range tt.links {
				p := filepath.Join(dir, link)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, p); err != nil {
					t.Fatal(err)
				}
			}
			r := resolveJS(t, dir, "express")
			if !r.Found {
				t.Fatalf("express not found: %+v", r.All)
			}
			if r.Match.Resolved != tt.want {
				t.Fatalf("Resolved = %v, want %v (match %+v)", r.Match.Resolved, tt.want, r.Match)
			}
		})
	}
}

// (c): a bare npm install keeps what its lock records exactly when that lock covers the
// package.json it installs (lockCovers), so it binds only to the package.json in its package
// root and the npm locks beside it.
func TestResolveVersions_BareInstall(t *testing.T) {
	const (
		lockV1 = `{"name":"app","lockfileVersion":1,"dependencies":{"express":{"version":"4.19.2"}}}`
		lockV3 = `{"name":"app","lockfileVersion":3,"packages":{` +
			`"":{"name":"app","dependencies":{"express":"^4.17.1"}},"node_modules/express":{"version":"4.19.2"}}}`
		front     = `{"name":"frontend","dependencies":{"react":"^16.13.1"}}`
		frontLock = `{"name":"frontend","lockfileVersion":1,"dependencies":{"react":{"version":"16.14.0"}}}`
	)
	pkg := func(extra string) string {
		return `{"name":"app","dependencies":{"express":"^4.17.1"},` + extra + `}`
	}
	scripts := func(s string) string { return pkg(`"scripts":{` + s + `}`) }
	tree := func(rootPkg, rootLock string, extra map[string]string) map[string]string {
		files := map[string]string{"package.json": rootPkg, "package-lock.json": rootLock, "frontend/package.json": front, "frontend/package-lock.json": frontLock}
		for k, v := range extra {
			files[k] = v
		}
		return files
	}
	tests := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"covered v1 lock", tree(scripts(`"build":"npm install"`), lockV1, nil), true},
		{"covered v3 lock", tree(scripts(`"build":"npm install"`), lockV3, nil), true},
		{"covered, npm i --omit=dev", tree(scripts(`"build":"npm i --omit=dev"`), lockV1, nil), true},
		{"covered, after cd", tree(scripts(`"build":"cd frontend && npm install"`), lockV1, nil), true},
		{"covered, kept assignment and --prefix", tree(scripts(`"heroku-postbuild":"NPM_CONFIG_PRODUCTION=false npm install --prefix frontend && npm run build --prefix frontend"`), lockV1,
			map[string]string{"frontend/package.json": `{"name":"frontend","dependencies":{"react":"^16.13.1"},"scripts":{"build":"react-scripts build"}}`}), true},
		{"uncovered v1 lock: version outside the range", tree(scripts(`"build":"npm install"`), strings.Replace(lockV1, "4.19.2", "5.0.0", 1), nil), false},
		{"uncovered v3 lock: spec drift", tree(pkg(`"scripts":{"build":"npm install"}`), strings.Replace(lockV3, `"^4.17.1"`, `"^4.16.0"`, 1), nil), false},
		{"uncovered, --prefix: frontend lock outside the range", tree(scripts(`"build":"npm install --prefix frontend"`), lockV1,
			map[string]string{"frontend/package-lock.json": strings.Replace(frontLock, "16.14.0", "17.0.2", 1)}), false},
		{"uncovered shrinkwrap beside a covering lock: same version, spec drift", tree(scripts(`"build":"npm install"`), lockV1,
			map[string]string{"npm-shrinkwrap.json": strings.Replace(lockV3, `"^4.17.1"`, `"^4.16.0"`, 1)}), false},
		{"uncovered v1 lock: root peer outside its range", tree(pkg(`"peerDependencies":{"react":"^18.0.0"},"scripts":{"build":"npm install"}`),
			`{"name":"app","lockfileVersion":1,"dependencies":{"express":{"version":"4.19.2"},"react":{"version":"17.0.2"}}}`, nil), false},
		{"uncovered v3 lock: root peer the lock keeps below its range (ferralon-ai/tracker#506)", tree(pkg(`"peerDependencies":{"ms":"^2.1.0"},"scripts":{"build":"npm install"}`),
			strings.Replace(lockV3, `"dependencies":{"express":"^4.17.1"}}`, `"dependencies":{"express":"^4.17.1"},"peerDependencies":{"ms":"^2.1.0"}},"node_modules/ms":{"version":"2.0.0"}`, 1), nil), false},
		{"covered v3 lock: root peer satisfied", tree(pkg(`"peerDependencies":{"ms":"^2.1.0"},"scripts":{"build":"npm install"}`),
			strings.Replace(lockV3, `"dependencies":{"express":"^4.17.1"}}`, `"dependencies":{"express":"^4.17.1"},"peerDependencies":{"ms":"^2.1.0"}},"node_modules/ms":{"version":"2.1.3"}`, 1), nil), true},
		{"lock replaced before the install", tree(scripts(`"build":"cp locks/other.json package-lock.json && npm install"`), lockV1,
			map[string]string{"locks/other.json": "{}\n"}), false},
		{".npmrc: package-lock=false", tree(scripts(`"build":"npm install"`), lockV1, map[string]string{".npmrc": "package-lock=false\n"}), false},
		{".npmrc: shrinkwrap=false", tree(scripts(`"build":"npm install"`), lockV1, map[string]string{".npmrc": "shrinkwrap=false\n"}), false},
		{".npmrc: the --prefix dir's own", tree(scripts(`"build":"npm install --prefix frontend"`), lockV1, map[string]string{"frontend/.npmrc": "package-lock=false\n"}), false},
		{".npmrc: above the package root", tree(scripts(`"build":"cd frontend && npm install"`), lockV1, map[string]string{".npmrc": "package-lock=false\n"}), false},
		{".npmrc: cannot be read", tree(scripts(`"build":"npm install"`), lockV1, map[string]string{".npmrc/x": "x\n"}), false},
		{".npmrc: registry, auth and output keys only", tree(scripts(`"build":"npm install"`), lockV1,
			map[string]string{".npmrc": "registry=https://registry.npmjs.org/\n@acme:registry=https://npm.acme.dev/\n//npm.acme.dev/:_authToken=${NPM_TOKEN}\nfund=false\nprogress=false\n"}), true},
		{"no lock beside the package.json", tree(scripts(`"build":"npm install --prefix frontend"`), lockV1,
			map[string]string{"frontend/package-lock.json": "", "frontend/yarn.lock": "# yarn lockfile v1\n\nreact@^16.13.1:\n  version \"16.14.0\"\n"}), false},
		{"covered, npm install --omit dev", tree(scripts(`"build":"npm install --omit dev"`), lockV1, nil), true},
		{"covered, npm install --include=dev", tree(scripts(`"build":"npm install --include=dev"`), lockV1, nil), true},
		{"covered, npm install --omit=optional", tree(scripts(`"build":"npm install --omit=optional"`), lockV1, nil), true},
		{"covered, npm install --production", tree(scripts(`"build":"npm install --production"`), lockV1, nil), true},
		{"covered, npm install --only=prod", tree(scripts(`"build":"npm install --only=prod"`), lockV1, nil), true},
		{"covered, --omit=dev beside NPM_CONFIG_OMIT=dev", tree(scripts(`"build":"NPM_CONFIG_OMIT=dev npm install --omit=dev"`), lockV1, nil), true},
		{"npm install --omit with no value", tree(scripts(`"build":"npm install --omit"`), lockV1, nil), false},
		{"npm install --omit=bogus", tree(scripts(`"build":"npm install --omit=bogus"`), lockV1, nil), false},
		{"npm install --omit dev extra-pkg", tree(scripts(`"build":"npm install --omit dev extra-pkg"`), lockV1, nil), false},
		{"npm install --include=dev left-pad", tree(scripts(`"build":"npm install --include=dev left-pad"`), lockV1, nil), false},
		{"named package", tree(scripts(`"build":"npm install left-pad"`), lockV1, nil), false},
		{"unknown flag", tree(scripts(`"build":"npm install --legacy-peer-deps"`), lockV1, nil), false},
		{"workspaces root", tree(pkg(`"workspaces":["frontend"],"scripts":{"build":"npm install"}`), lockV1, nil), false},
		{"workspace member under a workspaces root", tree(pkg(`"workspaces":["frontend"],"scripts":{"build":"npm install --prefix frontend"}`), lockV1, nil), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{}
			for k, v := range tt.files {
				if v != "" {
					files[k] = v
				}
			}
			r := resolveJS(t, writeLockTree(t, files), "express")
			if !r.Found {
				t.Fatalf("express not found: %+v", r.All)
			}
			if r.Match.Resolved != tt.want {
				t.Fatalf("Resolved = %v, want %v (match %+v)", r.Match.Resolved, tt.want, r.Match)
			}
		})
	}
}

// A symlink into .git lets a path naming neither reach a sample hook, so the hooks are surfaces.
func TestResolveVersions_SampleHookThroughSymlink(t *testing.T) {
	const lock = `{"name":"app","lockfileVersion":3,"packages":{` +
		`"":{"name":"app","version":"1.0.0","dependencies":{"express":"4.19.2"}},` +
		`"node_modules/express":{"version":"4.19.2"}}}`
	for _, tt := range []struct{ name, script string }{
		{"cp of sample hooks through the link", `cp s*/h/*.sample x/`},
		{"sample hook run through the link", `sh src/h/pre-commit.s*`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeLockTree(t, map[string]string{"package-lock.json": lock,
				".git/hooks/pre-commit.sample": "#!/bin/sh\nnpm install left-pad\n",
				"package.json":                 `{"name":"app","version":"1.0.0","dependencies":{"express":"4.19.2"},"scripts":{"x":"` + tt.script + `"}}`})
			if err := os.Symlink(filepath.Join("..", ".git", "hooks"), filepath.Join(dir, "src", "h")); err != nil {
				t.Fatal(err)
			}
			if r := resolveJS(t, dir, "express"); !r.Found || r.Match.Resolved {
				t.Fatalf("Found = %v, Resolved = %v, want found and withheld", r.Found, r.Match.Resolved)
			}
		})
	}
}
