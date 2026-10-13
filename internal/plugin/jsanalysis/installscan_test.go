package jsanalysis

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/buildtree"
)

// TestInstallScan covers the out-of-manifest install scanner: one row per install family,
// per veto form and per surface. Every tree carries an npm root (package.json +
// package-lock.json) unless the row replaces it.
func TestInstallScan(t *testing.T) {
	const byName = "by name, outside the lockfile"
	npmRoot := func(t *testing.T) map[string]string {
		return map[string]string{
			"package.json":      `{"name":"app"}`,
			"package-lock.json": npmLockJSON(t, map[string]lockPkg{}),
		}
	}
	eslintLock := func(dev bool) string {
		return npmLockJSON(t, map[string]lockPkg{"node_modules/eslint": {Version: "8.57.0", Dev: dev, Bin: map[string]string{"eslint": "bin/eslint.js"}}})
	}
	cases := []struct {
		name   string
		files  map[string]string
		noRoot bool
		setup  func(t *testing.T, dir string)
		all    string // substring of the veto; "" = no veto
	}{
		// --- families: a named install withholds every refutation ---
		{name: "npm install -g", files: map[string]string{"deploy.sh": "npm install -g pm2\n"}, all: byName},
		{name: "npm i --location=global", files: map[string]string{"deploy.sh": "npm i --location=global pm2\n"}, all: byName},
		{name: "npm add with version and alias", files: map[string]string{"deploy.sh": "npm add left-pad@1.3.0 alias@npm:real-pkg@2\n"}, all: byName},
		{name: "npx first positional", files: map[string]string{"deploy.sh": "npx --yes cowsay hello\n"}, all: byName},
		{name: "npx --package", files: map[string]string{"deploy.sh": "npx -p @scope/tool run-it\n"}, all: byName},
		{name: "npm exec after --", files: map[string]string{"deploy.sh": "npm exec -- tsx a.ts\n"}, all: byName},
		{name: "pnpx and bunx", files: map[string]string{"deploy.sh": "pnpx serve\nbunx vite\n"}, all: byName},
		{name: "bunx alone", files: map[string]string{"deploy.sh": "bunx vite\n"}, all: byName},
		{name: "yarn add", files: map[string]string{"deploy.sh": "yarn add sharp\n"}, all: byName},
		{name: "yarn global add", files: map[string]string{"deploy.sh": "yarn global add serve\n"}, all: byName},
		{name: "yarn dlx --package", files: map[string]string{"deploy.sh": "yarn dlx -p typescript tsc\n"}, all: byName},
		{name: "pnpm add -g", files: map[string]string{"deploy.sh": "pnpm add -g pm2\n"}, all: byName},
		{name: "pnpm dlx", files: map[string]string{"deploy.sh": "pnpm dlx create-vite\n"}, all: byName},
		{name: "bun add", files: map[string]string{"deploy.sh": "bun add hono\n"}, all: byName},
		{name: "npm init initializer", files: map[string]string{"deploy.sh": "npm init @scope/app\nyarn create next-app\n"}, all: byName},
		{name: "deno npm: specifier", files: map[string]string{"deploy.sh": "deno run npm:cowsay\n"}, all: byName},
		{name: "volta install", files: map[string]string{"deploy.sh": "volta install typescript\n"}, all: "volta installs tools by name"},
		{name: "command substitution body", files: map[string]string{"deploy.sh": "echo $(npm i -g leftpad)\n"}, all: byName},
		{name: "sh -c wrapper", files: map[string]string{"deploy.sh": "sudo -u node sh -c 'npm i -g pm2'\n"}, all: byName},

		// --- argless installs: the lane-read lockfile is required ---
		{name: "npm ci at the npm root", files: map[string]string{"deploy.sh": "npm ci\n"}},
		{name: "yarn install at an npm root", files: map[string]string{"deploy.sh": "yarn install --frozen-lockfile\n"}, all: "selected lockfile is npm"},
		{name: "npm ci in a directory without a lockfile", files: map[string]string{"deploy.sh": "cd web && npm ci\n", "web/package.json": "{}"}, all: "installs in web, which has no lockfile"},
		{name: "npm ci with --prefix to a lock root", files: map[string]string{"deploy.sh": "npm ci --prefix web\n", "web/package.json": "{}", "web/package-lock.json": `{"lockfileVersion":3,"packages":{}}`}},
		{name: "npm install at an ambiguous root", files: map[string]string{"deploy.sh": "npm install\n", "yarn.lock": "# yarn lockfile v1\n"}, all: "no lockfile the lane selected"},
		{name: "npm ci with no lockfile at all", noRoot: true, files: map[string]string{"package.json": `{"name":"app"}`, "deploy.sh": "npm ci\n"}, all: "no lockfile the lane selected"},
		{name: "cd to a variable before npm ci", files: map[string]string{"deploy.sh": "cd $APP && npm ci\n"}, all: "cannot determine"},
		{name: "bun install never matches a lane-read lockfile", files: map[string]string{"deploy.sh": "bun install\n"}, all: "selected lockfile is npm"},
		{name: "yarn workspaces foreach install", noRoot: true, files: map[string]string{"package.json": `{"name":"app"}`, "yarn.lock": "# yarn lockfile v1\n", "deploy.sh": "yarn workspaces foreach install\n"}, all: "cannot determine"},
		{name: "npm ci --prefix to a directory without a lockfile", files: map[string]string{"deploy.sh": "npm ci --prefix api\n"}, all: "installs in api"},
		{name: "pnpm -C to a directory without a lockfile", noRoot: true, files: map[string]string{"package.json": `{"name":"app"}`, "pnpm-lock.yaml": "lockfileVersion: '6.0'\n", "deploy.sh": "pnpm -C web install --frozen-lockfile\n", "web/package.json": "{}"}, all: "installs in web"},
		{name: "global argless install", files: map[string]string{"deploy.sh": "npm install -g\n"}, all: "global install with no package"},
		{name: "npm install --no-package-lock", files: map[string]string{"deploy.sh": "npm install --no-package-lock\n"}, all: "without the lockfile"},
		{name: "yarn --no-lockfile", files: map[string]string{"deploy.sh": "yarn --no-lockfile\n"}, all: "without the lockfile"},
		{name: "pnpm install --lockfile-dir", files: map[string]string{"deploy.sh": "pnpm install --lockfile-dir ..\n"}, all: "without the lockfile the lane read"},

		// --- veto forms ---
		{name: "variable argument", files: map[string]string{"deploy.sh": "npm install -g $TOOL\n"}, all: "not a registry package name"},
		{name: "substitution argument", files: map[string]string{"deploy.sh": "npm install $(cat tools.txt)\n"}, all: "not a registry package name"},
		{name: "path spec", files: map[string]string{"deploy.sh": "npm install ./vendor/pkg\n"}, all: "not a registry package name"},
		{name: "tarball spec", files: map[string]string{"deploy.sh": "npm install pkg-1.0.0.tgz\n"}, all: "not a registry package name"},
		{name: "URL spec", files: map[string]string{"deploy.sh": "npm install https://example.com/p.tgz\n"}, all: "not a registry package name"},
		{name: "git spec", files: map[string]string{"deploy.sh": "yarn add github:user/repo\n"}, all: "not a registry package name"},
		{name: "git range on a name", files: map[string]string{"deploy.sh": "npm i pkg@git+https://x/y.git\n"}, all: "not a registry package name"},
		{name: "dynamic command head", files: map[string]string{"deploy.sh": "$PM install\n"}, all: "a variable names the command"},
		{name: "xargs feeds an install", files: map[string]string{"deploy.sh": "cat list | xargs npm install -g\n"}, all: "xargs"},
		{name: "npm update with no packages", files: map[string]string{"deploy.sh": "npm update\n"}, all: "past the lockfile"},
		{name: "npm audit fix", files: map[string]string{"deploy.sh": "npm audit fix\n"}, all: "audit fix"},
		{name: "npm dedupe", files: map[string]string{"deploy.sh": "npm dedupe\n"}, all: "dedupe"},
		{name: "npx --package with no value", files: map[string]string{"deploy.sh": "npx -p\n"}, all: "a --package flag with no value"},
		{name: "variable initializer", files: map[string]string{"deploy.sh": "npm init $KIT\n"}, all: "a variable names the initializer"},
		{name: "npx --call", files: map[string]string{"deploy.sh": "npx -c 'eslint .'\n"}, all: "--call"},
		{name: "npm exec --call", files: map[string]string{"deploy.sh": "npm exec -c 'eslint .'\n"}, all: "--call"},
		{name: "yarn upgrade-interactive", files: map[string]string{"deploy.sh": "yarn upgrade-interactive\n"}, all: "upgrade-interactive"},
		{name: "yarn up with no packages", files: map[string]string{"deploy.sh": "yarn up\n"}, all: "past the lockfile"},
		{name: "pnpm dedupe", files: map[string]string{"deploy.sh": "pnpm dedupe\n"}, all: "pnpm dedupe"},
		{name: "pnpm dlx --shell-mode", files: map[string]string{"deploy.sh": "pnpm dlx -c 'echo hi'\n"}, all: "shell-mode"},
		{name: "deno install with no args", files: map[string]string{"deploy.sh": "deno install\n"}, all: "deno installs package.json"},
		{name: "ncu -u", files: map[string]string{"deploy.sh": "ncu -u\n"}, all: "npm-check-updates rewrites"},
		{name: "unparsed family: @antfu/ni", files: map[string]string{"deploy.sh": "ni\n"}, all: "ni install commands are not parsed"},
		{name: "unparsed family: lerna bootstrap", files: map[string]string{"deploy.sh": "lerna bootstrap\n"}, all: "lerna install commands are not parsed"},
		{name: "unparsed family: rush install", files: map[string]string{"deploy.sh": "rush install\n"}, all: "rush install commands are not parsed"},
		{name: "unparsed family: yalc add", files: map[string]string{"deploy.sh": "yalc add my-lib\n"}, all: "yalc install commands are not parsed"},
		{name: "unparsed family: cnpm", files: map[string]string{"deploy.sh": "cnpm i\n"}, all: "cnpm install commands are not parsed"},
		{name: "lerna run is not an install", files: map[string]string{"deploy.sh": "lerna run build\n"}},
		{name: "npm through node and npm-cli.js", files: map[string]string{"deploy.sh": "node /usr/lib/node_modules/npm/bin/npm-cli.js i -g pm2\n"}, all: byName},
		{name: "shell from standard input", files: map[string]string{"deploy.sh": "curl -fsSL https://example.com/setup.sh | bash\n"}, all: "standard input"},
		{name: "npm link", files: map[string]string{"deploy.sh": "npm link\n"}, all: "npm link installs a package from outside the lockfile"},
		{name: "npm workspace selector", files: map[string]string{"deploy.sh": "npm ci -w web\n"}, all: "workspace selector"},
		{name: "pnpm --filter", files: map[string]string{"deploy.sh": "pnpm --filter web install\n"}, all: "workspace selector"},
		{name: "yarn workspaces focus", files: map[string]string{"deploy.sh": "yarn workspaces focus --production\n"}, all: "yarn workspaces focus"},
		{name: "unmodelled npm flag", files: map[string]string{"deploy.sh": "npm ci --install-strategy=nested\n"}, all: "npm flag --install-strategy is not modelled"},
		{name: "unknown npm flag", files: map[string]string{"deploy.sh": "npm install --frobnicate\n"}, all: "npm flag --frobnicate is not modelled"},
		{name: "modelled npm flags pass", files: map[string]string{"deploy.sh": "npm ci --omit=dev --no-audit --ignore-scripts --loglevel warn\n"}},
		{name: ".npmrc omit=optional", files: map[string]string{".npmrc": "omit=optional\n"}, all: "npm config omit=optional is not modelled"},
		{name: ".npmrc global", files: map[string]string{".npmrc": "global\n"}, all: "npm config global changes what an install puts on disk"},
		{name: ".npmrc workspaces", files: map[string]string{".npmrc": "workspaces=true\n"}, all: "npm config workspaces changes"},
		{name: ".npmrc ini section", files: map[string]string{".npmrc": "[x]\nregistry=https://r\n"}, all: "an ini section"},
		{name: ".npmrc registry and auth pass", files: map[string]string{".npmrc": "registry=https://r.example\n//r.example/:_authToken=${T}\nlegacy-peer-deps=true\n"}},
		{name: "npm_config env in a script", files: map[string]string{"deploy.sh": "NPM_CONFIG_GLOBAL=true npm ci\n"}, all: "npm config global changes"},
		{name: "npm_config env in a workflow", files: map[string]string{".github/workflows/ci.yml": "on: push\nenv:\n  npm_config_install_strategy: nested\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: npm ci\n"}, all: "npm config install-strategy changes"},
		{name: "unreadable surface", files: map[string]string{"deploy.sh": "true\n"}, setup: func(t *testing.T, dir string) {
			if err := os.Chmod(filepath.Join(dir, "deploy.sh"), 0); err != nil {
				t.Fatal(err)
			}
		}, all: "deploy.sh: unreadable"},
		{name: "an in-root symlinked directory is read through its target", files: map[string]string{"real/x.txt": "x"}, setup: func(t *testing.T, dir string) {
			mustSymlink(t, "real", filepath.Join(dir, "linked"))
		}},
		{name: "an in-root symlinked directory's target is scanned at its real path", files: map[string]string{"real/deploy.sh": "npm i -g pm2\n"}, setup: func(t *testing.T, dir string) {
			mustSymlink(t, "real", filepath.Join(dir, "linked"))
		}, all: "real/deploy.sh: npm i -g pm2"},
		{name: "a symlinked directory into node_modules stays fail-closed", files: map[string]string{"node_modules/x/a.txt": "x"}, setup: func(t *testing.T, dir string) {
			mustSymlink(t, "node_modules/x", filepath.Join(dir, "vendor"))
		}, all: "vendor: symlinked directory the walk does not read"},
		{name: "a symlink cycle terminates fail-closed", setup: func(t *testing.T, dir string) {
			mustSymlink(t, "loop2", filepath.Join(dir, "loop1"))
			mustSymlink(t, "loop1", filepath.Join(dir, "loop2"))
		}, all: "loop1: symlink leaves the build dir"},
		{name: "unparseable package.json", files: map[string]string{"web/package.json": "{"}, all: "unparseable package.json"},
		{name: "unparseable workflow", files: map[string]string{".github/workflows/ci.yml": "jobs: [x\n"}, all: "unparseable workflow"},
		{name: "unparseable action", files: map[string]string{".github/actions/a/action.yml": "runs: [x\n"}, all: "unparseable action"},
		{name: "unparseable compose", files: map[string]string{"docker-compose.yml": "services: [x\n"}, all: "unparseable compose"},
		{name: "unparseable GitLab CI", files: map[string]string{".gitlab-ci.yml": "build: [x\n"}, all: "unparseable GitLab"},
		{name: "unparseable Cloud Build", files: map[string]string{"cloudbuild.yaml": "steps: {x\n"}, all: "unparseable Cloud Build"},
		{name: "unparseable keyed config", files: map[string]string{"fly.toml": "[deploy\n"}, all: "unparseable config"},
		{name: "unterminated Jenkinsfile string", files: map[string]string{"Jenkinsfile": "sh '''npm i -g x\n"}, all: "unterminated"},
		{name: "GitLab include is not followed", files: map[string]string{".gitlab-ci.yml": "include: other.yml\nbuild:\n  script: [echo]\n"}, all: "include: is not followed"},
		{name: "GitLab trigger include", files: map[string]string{".gitlab-ci.yml": "child:\n  trigger:\n    include: c.yml\n"}, all: "child pipeline"},
		{name: "GitLab unresolved !reference", files: map[string]string{".gitlab-ci.yml": "build:\n  script:\n    - !reference [.missing, script]\n"}, all: "unresolved !reference"},

		// --- surfaces ---
		{name: "Makefile recipe", files: map[string]string{"Makefile": "deploy:\n\t@npm install -g serve\n"}, all: byName},
		{name: "Makefile cd resets per line", files: map[string]string{"Makefile": "x:\n\tcd web\n\tnpm ci\n"}},
		{name: "Procfile", files: map[string]string{"Procfile": "release: npx prisma migrate deploy\n"}, all: byName},
		{name: "shebang script without extension", files: map[string]string{"bin/deploy": "#!/usr/bin/env bash\nnpm i -g pm2\n"}, all: byName},
		{name: "shell script in a test dir is scanned", files: map[string]string{"test/setup.sh": "npm i ./x\n"}, all: "not a registry package name"},
		{name: "Dockerfile in a dot directory", files: map[string]string{".devcontainer/Dockerfile": "FROM node:20\nRUN npm i -g pm2\n"}, all: byName},
		{name: "Dockerfile in a build directory", files: map[string]string{"build/Dockerfile": "FROM node:20\nRUN npm i -g pm2\n"}, all: byName},
		{name: "extensionless entrypoint without a shebang", files: map[string]string{"docker/entrypoint": "set -e\nnpm i -g pm2\n"}, all: "carries an install command the scanner does not parse"},
		{name: "Heroku bin/post_compile hook", files: map[string]string{"bin/post_compile": "npm i -g pm2\n"}, all: byName},
		{name: "Elastic Beanstalk platform hook", files: map[string]string{".platform/hooks/predeploy/01_tools": "npm i -g pm2\n"}, all: byName},
		{name: "Kubernetes manifest command", files: map[string]string{"k8s/job.yaml": "kind: Job\nspec:\n  template:\n    spec:\n      containers:\n        - name: m\n          command: [\"sh\", \"-c\", \"npx prisma migrate deploy\"]\n"}, all: byName},
		{name: "CodeBuild buildspec", files: map[string]string{"buildspec.yml": "version: 0.2\nphases:\n  install:\n    commands:\n      - npm i -g pm2\n"}, all: byName},
		{name: "JavaScript file with an install command", files: map[string]string{"scripts/setup.js": "require('child_process').execSync('npm install left-pad');\n"}, all: "carries an install command the scanner does not parse"},
		{name: "YAML install command outside a command key", files: map[string]string{"config/tools.yml": "setup: npm install -g pm2\n"}, all: "outside any key the scanner reads as a command"},
		{name: "documentation is not a candidate", files: map[string]string{"README.md": "Run `npm install -g pm2`.\n", "docs/setup.txt": "npx create-react-app x\n"}},
		{name: "git data is not a candidate", files: map[string]string{".git/logs/HEAD": "npm install -g pm2\n", ".git/hooks/pre-commit.sample": "npx lint-staged\n"}},
		{name: "git hook is a candidate", files: map[string]string{".git/hooks/post-checkout": "#!/bin/sh\nnpm i -g pm2\n"}, all: byName},
		{name: "symlink leaving the build dir", setup: func(t *testing.T, dir string) {
			if err := os.Symlink(t.TempDir(), filepath.Join(dir, "ext")); err != nil {
				t.Fatal(err)
			}
		}, all: "symlink leaves the build dir"},
		{name: "a committed node_modules is not walked", files: map[string]string{"node_modules/x/install.sh": "npm i -g pm2\n"}},
		{name: "Jenkinsfile sh step", files: map[string]string{"Jenkinsfile": "pipeline { stages { stage('d') { steps { sh 'npm i -g pm2' } } } }\n"}, all: byName},
		{name: "Jenkinsfile dir() makes the directory unknown", files: map[string]string{"Jenkinsfile": "dir('web') { sh 'npm ci' }\n"}, all: "cannot determine"},
		{name: "workflow run step", files: map[string]string{".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: npx playwright install\n"}, all: byName},
		{name: "workflow working-directory to a lock root", files: map[string]string{".github/workflows/ci.yml": "on: push\ndefaults:\n  run:\n    working-directory: web\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: npm ci\n", "web/package.json": "{}", "web/package-lock.json": `{"lockfileVersion":3,"packages":{}}`}},
		{name: "workflow defaults working-directory without a lockfile", files: map[string]string{".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: x\n    defaults:\n      run:\n        working-directory: api\n    steps:\n      - run: npm ci\n"}, all: "installs in api"},
		{name: "workflow step working-directory without a lockfile", files: map[string]string{".github/workflows/ci.yml": "on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: npm ci\n        working-directory: api\n"}, all: "installs in api"},
		{name: "local composite action", files: map[string]string{".github/actions/setup/action.yml": "runs:\n  using: composite\n  steps:\n    - run: npm i -g turbo\n      shell: bash\n"}, all: byName},
		{name: "compose command", files: map[string]string{"docker-compose.yml": "services:\n  web:\n    image: node\n    command: [\"npx\", \"nodemon\", \"app.js\"]\n"}, all: byName},
		{name: "compose command with a lockfile install", files: map[string]string{"compose.yaml": "services:\n  web:\n    image: node\n    command: sh -c \"npm ci && node app\"\n"}, all: "cannot determine"},
		{name: "GitLab job script", files: map[string]string{".gitlab-ci.yml": "deploy:\n  script:\n    - npm i -g firebase-tools\n"}, all: byName},
		{name: "GitLab default before_script", files: map[string]string{".gitlab-ci.yml": "default:\n  before_script:\n    - npm i -g pnpm\nbuild:\n  script: [echo]\n"}, all: byName},
		{name: "GitLab !reference resolves", files: map[string]string{".gitlab-ci.yml": ".tpl:\n  cmds:\n    - npx semantic-release\nrel:\n  script:\n    - !reference [.tpl, cmds]\n"}, all: byName},
		{name: "Cloud Build npm builder", files: map[string]string{"cloudbuild.yaml": "steps:\n  - name: gcr.io/cloud-builders/npm\n    args: [install, -g, firebase-tools]\n"}, all: byName},
		{name: "Cloud Build entrypoint", files: map[string]string{"cloudbuild.yaml": "steps:\n  - name: node:20\n    entrypoint: npx\n    args: [prisma, generate]\n"}, all: byName},
		{name: "Cloud Build script", files: map[string]string{"cloudbuild.yaml": "steps:\n  - name: node:20\n    script: |\n      npm i -g pm2\n"}, all: byName},
		{name: "render.yaml buildCommand", files: map[string]string{"render.yaml": "services:\n  - type: web\n    buildCommand: npm i -g typescript && tsc\n"}, all: byName},
		{name: "render.yaml rootDir without a lockfile", files: map[string]string{"render.yaml": "services:\n  - type: web\n    rootDir: api\n    buildCommand: npm ci\n"}, all: "installs in api"},
		{name: "fly.toml release_command", files: map[string]string{"fly.toml": "[deploy]\nrelease_command = \"npx prisma migrate deploy\"\n"}, all: byName},
		{name: "railway.json", files: map[string]string{"railway.json": `{"build":{"buildCommand":"npm i -g bun"}}`}, all: byName},
		{name: "netlify.toml", files: map[string]string{"netlify.toml": "[build]\ncommand = \"npx gatsby build\"\n"}, all: byName},
		{name: "vercel.json installCommand", files: map[string]string{"vercel.json": `{"installCommand":"npm install --no-package-lock"}`}, all: "without the lockfile"},
		{name: "app.json postdeploy", files: map[string]string{"app.json": `{"scripts":{"postdeploy":"npx knex migrate:latest"}}`}, all: byName},
		{name: "app.yaml entrypoint", files: map[string]string{"app.yaml": "runtime: nodejs20\nentrypoint: npx serve build\n"}, all: byName},
		{name: "CircleCI run", files: map[string]string{".circleci/config.yml": "jobs:\n  b:\n    steps:\n      - run: npm i -g codecov\n"}, all: byName},
		{name: "package.json script", files: map[string]string{"package.json": `{"name":"app","scripts":{"postinstall":"npx patch-package"}}`}, all: byName},

		// --- Dockerfiles: lockfile provenance in the image ---
		{name: "Dockerfile named install", files: map[string]string{"Dockerfile": "FROM node:20\nRUN npm i -g pm2\n"}, all: byName},
		{name: "Dockerfile CMD", files: map[string]string{"Dockerfile": "FROM node:20\nCMD [\"npx\", \"serve\", \"build\"]\n"}, all: byName},
		{name: "Dockerfile npm ci with the lockfile copied", files: map[string]string{"Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY package*.json ./\nRUN npm ci\n"}},
		{name: "Dockerfile npm ci with the context copied", files: map[string]string{"Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN cd /app && npm ci\n"}},
		{name: "Dockerfile npm ci with no lockfile in the image", files: map[string]string{"Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY package.json ./\nRUN npm install\n"}, all: "no npm lockfile at /app"},
		{name: "Dockerfile unknown WORKDIR", files: map[string]string{"Dockerfile": "FROM node:20\nCOPY . .\nRUN cd /app && npm ci\n"}, all: "may have been replaced"},
		{name: "Dockerfile variable WORKDIR", files: map[string]string{"Dockerfile": "FROM node:20\nWORKDIR $HOME/app\nRUN npm ci\n"}, all: "cannot determine"},
		{name: "Dockerfile .dockerignore excludes the lockfile", files: map[string]string{".dockerignore": "package-lock.json\n", "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci\n"}, all: "no npm lockfile"},
		{name: "Dockerfile bind-mounted lockfile", files: map[string]string{"Dockerfile": "FROM node:20\nWORKDIR /app\nRUN --mount=type=bind,source=package.json,target=package.json --mount=type=bind,source=package-lock.json,target=package-lock.json npm ci\n"}},
		{name: "Dockerfile cache mount over the workdir", files: map[string]string{"Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN --mount=type=cache,target=/app npm ci\n"}, all: "cannot see"},
		{name: "Dockerfile lockfile through a stage", files: map[string]string{"Dockerfile": "FROM node:20 AS deps\nWORKDIR /src\nCOPY package.json package-lock.json ./\nFROM node:20\nWORKDIR /app\nCOPY --from=deps /src/package-lock.json ./\nRUN npm ci\n"}},
		{name: "Dockerfile lockfile from an external image", files: map[string]string{"Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY --from=other/image:1 /x/ ./\nRUN npm ci\n"}, all: "cannot see"},
		{name: "Dockerfile COPY --from a stage with no workdir", files: map[string]string{"Dockerfile": "FROM node:20 AS b\nFROM node:20\nWORKDIR /app\nCOPY . .\nCOPY --from=b package-lock.json ./\nRUN npm ci\n"}, all: "comes from a source the scanner cannot see"},
		{name: "Dockerfile RUN cp of a lockfile", files: map[string]string{"Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN cp other/package-lock.json . && npm ci\n"}, all: "may have been replaced"},
		{name: "Dockerfile ADD of a URL over the workdir", files: map[string]string{"Dockerfile": "FROM node:20\nWORKDIR /app\nADD https://example.com/src.tgz /app/\nRUN npm ci\n"}, all: "cannot see"},
		{name: "Dockerfile COPY --from an image, no install", files: map[string]string{"Dockerfile": "FROM node:20\nCOPY --from=builder-image:1 /app/node_modules /app/node_modules\n"}, all: "copies from an image the scanner cannot see"},
		{name: "Dockerfile ADD of a URL, no install", files: map[string]string{"Dockerfile": "FROM node:20\nADD https://example.com/vendor.tgz /opt/\n"}, all: "adds a remote source the scanner cannot see"},
		{name: "Dockerfile ADD of an archive", files: map[string]string{"vendor.tar.gz": "x", "Dockerfile": "FROM node:20\nADD vendor.tar.gz /opt/\n"}, all: "extracts an archive"},
		{name: "Dockerfile script run by path", files: map[string]string{"boot.sh": "npm ci\n", "Dockerfile": "FROM node:20\nCOPY boot.sh /opt/boot.sh\nWORKDIR /srv\nRUN /opt/boot.sh\n"}, all: "no npm lockfile at /srv"},
		{name: "Dockerfile script it cannot trace", files: map[string]string{"Dockerfile": "FROM node:20\nWORKDIR /app\nRUN sh /opt/setup.sh\n"}, all: "cannot trace to the build context"},
		{name: "Dockerfile system script passes", files: map[string]string{"Dockerfile": "FROM node:20\nENTRYPOINT [\"/usr/local/bin/docker-entrypoint.sh\"]\n"}},
		{name: "Dockerfile heredoc RUN", files: map[string]string{"Dockerfile": "FROM node:20\nRUN <<EOF\nnpm i -g pm2\nEOF\n"}, all: byName},
		{name: "Dockerfile yarn install against an npm root", files: map[string]string{"Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN yarn install\n"}, all: "no yarn lockfile"},
		{name: "Dockerfile subdir context from compose", files: map[string]string{
			"web/package.json": "{}", "web/package-lock.json": `{"lockfileVersion":3,"packages":{}}`,
			"web/Dockerfile":     "FROM node:20\nWORKDIR /app\nCOPY package-lock.json package.json ./\nRUN npm ci\n",
			"docker-compose.yml": "services:\n  web:\n    build: ./web\n",
		}},
		{name: "compose build context is a variable", files: map[string]string{
			"Dockerfile":         "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci\n",
			"docker-compose.yml": "services:\n  web:\n    build: ${CTX}\n",
		}, all: "is not resolved"},
		{name: "Dockerfile context is a variable", files: map[string]string{
			"Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci\n",
			"build.sh":   "docker build -t x $CTX\n",
		}, all: "is not resolved"},
		{name: "container argv list", files: map[string]string{"k8s/job.yaml": "kind: Job\nspec:\n  containers:\n    - name: m\n      command: [\"sh\", \"-c\"]\n      args: [\"npm i -g pm2\"]\n"}, all: byName},
		{name: "list of command lines under cmd", files: map[string]string{"tool.yml": "cmd: [\"echo hi\", \"npm i -g pm2\"]\n"}, all: byName},
		{name: "container argv without an install", files: map[string]string{"k8s/dep.yaml": "kind: Deployment\nspec:\n  containers:\n    - name: m\n      command: [\"sh\", \"-c\", \"node server.js\"]\n"}},

		// --- runner exception: a bin the lockfile install put on disk ---
		{name: "npx of a production bin after npm ci", files: map[string]string{
			"package-lock.json": eslintLock(false), "deploy.sh": "npm ci && npx eslint .\n",
		}},
		{name: "Docker CMD npx of a production bin after RUN npm ci", files: map[string]string{
			"package-lock.json": eslintLock(false), "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci\nCMD [\"npx\", \"eslint\"]\n",
		}},
		{name: "npx of a bin with no install before it", files: map[string]string{
			"package-lock.json": eslintLock(false), "deploy.sh": "npx eslint .\n",
		}, all: byName},
		{name: "Docker CMD npx with no RUN npm ci", files: map[string]string{
			"package-lock.json": eslintLock(false), "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY . .\nCMD [\"npx\", \"eslint\"]\n",
		}, all: byName},
		{name: "pnpm dlx of a production bin", files: map[string]string{
			"package-lock.json": eslintLock(false), "deploy.sh": "npm ci && pnpm dlx eslint .\n",
		}, all: byName},
		{name: "npx of a dev-only bin", files: map[string]string{
			"package-lock.json": eslintLock(true), "deploy.sh": "npm ci && npx eslint .\n",
		}, all: byName},
		{name: "npx with a version is never the lockfile copy", files: map[string]string{
			"package-lock.json": eslintLock(false), "deploy.sh": "npm ci && npx eslint@8 .\n",
		}, all: byName},

		// --- install lifecycle of production packages ---
		{name: "postinstall that runs an installer", files: map[string]string{
			"package-lock.json":              npmLockJSON(t, map[string]lockPkg{"node_modules/evil": {Version: "1.0.0", Script: true}}),
			"node_modules/evil/package.json": `{"name":"evil","scripts":{"postinstall":"npm i x"}}`,
		}, all: "node_modules/evil/package.json scripts.postinstall"},
		{name: "postinstall script file that carries an install command", files: map[string]string{
			"package-lock.json":              npmLockJSON(t, map[string]lockPkg{"node_modules/evil": {Version: "1.0.0", Script: true}}),
			"node_modules/evil/package.json": `{"name":"evil","scripts":{"postinstall":"node install.js"}}`,
			"node_modules/evil/install.js":   "require('child_process').execSync('npm install left-pad');\n",
		}, all: "ships an install command"},
		{name: "a symlinked package directory is read through its target", files: map[string]string{
			"package-lock.json":                     npmLockJSON(t, map[string]lockPkg{"node_modules/evil": {Version: "1.0.0", Script: true}}),
			"node_modules/.store/evil/package.json": `{"name":"evil","scripts":{"postinstall":"node install.js"}}`,
			"node_modules/.store/evil/install.js":   "require('child_process').execSync('npm install left-pad');\n",
		}, setup: func(t *testing.T, dir string) {
			mustSymlink(t, ".store/evil", filepath.Join(dir, "node_modules", "evil"))
		}, all: "ships an install command"},
		{name: "an installed package's symlink out of the build dir", files: map[string]string{
			"package-lock.json":              npmLockJSON(t, map[string]lockPkg{"node_modules/evil": {Version: "1.0.0", Script: true}}),
			"node_modules/evil/package.json": `{"name":"evil","scripts":{"postinstall":"sh run.sh"}}`,
		}, setup: func(t *testing.T, dir string) {
			mustSymlink(t, t.TempDir(), filepath.Join(dir, "node_modules", "evil", "run.sh"))
		}, all: "node_modules/evil/run.sh: symlink leaves the build dir"},
		{name: "install script on a package not on disk", files: map[string]string{
			"package-lock.json": npmLockJSON(t, map[string]lockPkg{"node_modules/evil": {Version: "1.0.0", Script: true}}),
		}, all: "the package is not on disk"},
		{name: "dev-only package lifecycle is not production", files: map[string]string{
			"package-lock.json":              npmLockJSON(t, map[string]lockPkg{"node_modules/evil": {Version: "1.0.0", Dev: true, Script: true}}),
			"node_modules/evil/package.json": `{"name":"evil","scripts":{"postinstall":"npm i x"}}`,
		}},
		{name: "benign postinstall passes", files: map[string]string{
			"package-lock.json":                 npmLockJSON(t, map[string]lockPkg{"node_modules/esbuild": {Version: "0.20.0", Script: true}}),
			"node_modules/esbuild/package.json": `{"name":"esbuild","scripts":{"postinstall":"node install.js"}}`,
			"node_modules/esbuild/install.js":   "require('fs').chmodSync('bin/esbuild', 0o755);\n",
		}},
		{name: "Dockerfile ONBUILD RUN", files: map[string]string{"Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY . .\nONBUILD RUN npm ci\n"}, all: "may have been replaced"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string]string{}
			if !tc.noRoot {
				for k, v := range npmRoot(t) {
					files[k] = v
				}
			}
			for k, v := range tc.files {
				files[k] = v
			}
			dir := writeTree(t, files)
			if tc.setup != nil {
				tc.setup(t, dir)
			}
			ls := computeLoadSet(dir)
			sc := ls.scan
			if sc == nil {
				sc = scanBuild(ls.model.buildReal, ls.model, ls.installed)
			}
			if tc.all == "" && sc.all != "" {
				t.Fatalf("unexpected veto %q", sc.all)
			}
			if tc.all != "" && !strings.Contains(sc.all, tc.all) {
				t.Fatalf("veto = %q, want %q", sc.all, tc.all)
			}
		})
	}
}

// TestInstallScanNote: the refutation detail names the files the scan read.
func TestInstallScanNote(t *testing.T) {
	sc := &installScan{scanned: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}}
	got := sc.note()
	if !strings.Contains(got, "no out-of-manifest install in 10 scanned files: a, b, c, d, e, f, g, h, +2 more") {
		t.Fatalf("note = %q", got)
	}
}

// TestTreeWalkRule pins the walk to internal/plugin/buildtree as of commit bc0233d (buildtree.go
// blob 0219ca2d925dae344581fe87d7774381431c7e62): only a directory named node_modules or
// site-packages is skipped (.git and dot directories are entered); a symlink is never followed;
// a symlink to a file inside the root is read; one that leaves the root or does not resolve
// fails; and a symlinked directory is read through its target, once at the target's real path,
// only when the walk enters that target. A link into a skipped directory stays fail-closed, and
// a link cycle terminates as a failure. TestTreeWalkLinkToPipe pins the rest of bc0233d: a
// symlink to a pipe fails and is never opened.
func TestTreeWalkRule(t *testing.T) {
	for name, want := range map[string]bool{
		"node_modules": true, "site-packages": true, ".git": false, "vendor": false,
		"dist": false, "test": false, ".venv": false, "Node_Modules": false, "": false,
	} {
		if got := buildtree.Skipped(name); got != want {
			t.Errorf("buildtree.Skipped(%q) = %v, want %v", name, got, want)
		}
	}
	base := map[string]string{
		".git/hooks/post-checkout": "x", "a/node_modules/p/i.sh": "x", "b/site-packages/q.py": "x",
		"c/d.sh": "x", "test/e.sh": "x",
	}
	tests := []struct {
		name      string
		links     map[string]string // link → target relative to the link's directory; "OUTSIDE" is a dir outside root
		lock      string            // a directory made unlistable
		wantFiles []string
		wantFails []string
	}{
		{name: "skip rule", wantFiles: []string{".git/hooks/post-checkout", "c/d.sh", "test/e.sh"}},
		{name: "in-root symlinked dir is read through its target", links: map[string]string{"in": "c"},
			wantFiles: []string{".git/hooks/post-checkout", "c/d.sh", "test/e.sh"}},
		{name: "symlink to a file inside root is read", links: map[string]string{"f.sh": "c/d.sh"},
			wantFiles: []string{".git/hooks/post-checkout", "c/d.sh", "f.sh", "test/e.sh"}},
		{name: "link into node_modules stays fail-closed", links: map[string]string{"vendor": "a/node_modules/p"},
			wantFiles: []string{".git/hooks/post-checkout", "c/d.sh", "test/e.sh"},
			wantFails: []string{"vendor: symlinked directory the walk does not read"}},
		{name: "link to site-packages stays fail-closed", links: map[string]string{"pkgs": "b/site-packages"},
			wantFiles: []string{".git/hooks/post-checkout", "c/d.sh", "test/e.sh"},
			wantFails: []string{"pkgs: symlinked directory the walk does not read"}},
		{name: "cycle terminates", links: map[string]string{"loop1": "loop2", "loop2": "loop1"},
			wantFiles: []string{".git/hooks/post-checkout", "c/d.sh", "test/e.sh"},
			wantFails: []string{"loop1: symlink leaves the build dir", "loop2: symlink leaves the build dir"}},
		{name: "link out of root fails", links: map[string]string{"out": "OUTSIDE"},
			wantFiles: []string{".git/hooks/post-checkout", "c/d.sh", "test/e.sh"},
			wantFails: []string{"out: symlink leaves the build dir"}},
		{name: "link to an unreadable dir stays fail-closed", links: map[string]string{"via": "c"}, lock: "c",
			wantFiles: []string{".git/hooks/post-checkout", "test/e.sh"},
			wantFails: []string{"c: unreadable", "via: symlinked directory the walk does not read"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(writeTree(t, base))
			if err != nil {
				t.Fatal(err)
			}
			for link, target := range tt.links {
				if target == "OUTSIDE" {
					target = t.TempDir()
				}
				mustSymlink(t, target, filepath.Join(dir, link))
			}
			if tt.lock != "" {
				if os.Geteuid() == 0 {
					t.Skip("root reads every directory")
				}
				locked := filepath.Join(dir, tt.lock)
				if err := os.Chmod(locked, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
			}
			var files, fails []string
			walkTree(dir, func(_, rel string, _ fs.DirEntry) error {
				files = append(files, rel)
				return nil
			}, func(rel, why string) {
				fails = append(fails, rel+": "+why)
			})
			sort.Strings(files)
			sort.Strings(fails)
			if !reflect.DeepEqual(files, tt.wantFiles) {
				t.Errorf("files = %v, want %v", files, tt.wantFiles)
			}
			if !reflect.DeepEqual(fails, tt.wantFails) {
				t.Errorf("fails = %v, want %v", fails, tt.wantFails)
			}
		})
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}
