package jsanalysis

import (
	"strings"
	"testing"
)

func TestProdInstallKeepsDev(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string // substring of the evidence; "" = no deploy-path install keeps dev
	}{
		{"no ops files", map[string]string{"index.js": "require('a');"}, ""},
		{"Dockerfile npm ci keeps dev", map[string]string{"Dockerfile": "FROM node:20\nRUN npm ci\n"}, "Dockerfile: RUN npm ci"},
		{"Dockerfile omit dev", map[string]string{"Dockerfile": "FROM node:20\nRUN npm ci --omit=dev\n"}, ""},
		{"Dockerfile production flag after continuation", map[string]string{"Dockerfile": "FROM node:20\nRUN npm install \\\n  --production\n"}, ""},
		{"Dockerfile NODE_ENV=production before install", map[string]string{"Dockerfile": "FROM node:20\nENV NODE_ENV=production\nRUN npm ci\n"}, ""},
		{"Dockerfile NPM_CONFIG_PRODUCTION=false overrides", map[string]string{"Dockerfile": "FROM node:20\nENV NODE_ENV production\nRUN NPM_CONFIG_PRODUCTION=false npm install\n"}, "NPM_CONFIG_PRODUCTION=false"},
		{"Dockerfile production env with npm ci --include=dev", map[string]string{"Dockerfile": "FROM node:20\nENV NODE_ENV=production\nRUN npm ci --include=dev\n"}, "npm ci --include=dev"},
		{"Dockerfile production env with npm install --also=dev", map[string]string{"Dockerfile": "FROM node:20\nENV NODE_ENV=production\nRUN npm install --also=dev\n"}, "npm install --also=dev"},
		{"Dockerfile production env with split --include dev", map[string]string{"Dockerfile": "FROM node:20\nENV NODE_ENV=production\nRUN npm ci --include dev\n"}, "npm ci --include dev"},
		{"Dockerfile omit and include dev keeps dev", map[string]string{"Dockerfile": "FROM node:20\nRUN npm ci --omit=dev --include=dev\n"}, "npm ci --omit=dev --include=dev"},
		{"Dockerfile NPM_CONFIG_PRODUCTION=false on the NODE_ENV line", map[string]string{"Dockerfile": "FROM node:20\nENV NODE_ENV=production NPM_CONFIG_PRODUCTION=false\nRUN npm install\n"}, "RUN npm install"},
		{"Dockerfile NPM_CONFIG_INCLUDE=dev env", map[string]string{"Dockerfile": "FROM node:20\nENV NODE_ENV=production\nENV NPM_CONFIG_INCLUDE=dev\nRUN npm ci\n"}, "RUN npm ci"},
		{"Dockerfile keep-dev env resets at the next stage", map[string]string{"Dockerfile": "FROM node:20 AS build\nENV NPM_CONFIG_PRODUCTION=false\nRUN node --version\nFROM node:20-slim\nENV NODE_ENV=production\nRUN npm ci\n"}, ""},
		{"inline NPM_CONFIG_INCLUDE=dev overrides", map[string]string{"Dockerfile": "FROM node:20\nENV NODE_ENV=production\nRUN NPM_CONFIG_INCLUDE=dev npm ci\n"}, "NPM_CONFIG_INCLUDE=dev npm ci"},
		{"Dockerfile prune after full install", map[string]string{"Dockerfile": "FROM node:20\nRUN npm ci && npm run build && npm prune --omit=dev\n"}, ""},
		{"multi-stage builder keeps dev", map[string]string{"Dockerfile.prod": "FROM node:20 AS build\nRUN npm ci && npm run build\nFROM node:20-slim\nRUN npm ci --omit=dev\n"}, "Dockerfile.prod: RUN npm ci"},
		{"Containerfile yarn", map[string]string{"Containerfile": "FROM node:20\nRUN yarn --frozen-lockfile\n"}, "yarn --frozen-lockfile"},
		{"yarn production", map[string]string{"Dockerfile": "FROM node:20\nRUN yarn install --production\n"}, ""},
		{"pnpm -P", map[string]string{"Dockerfile": "FROM node:20\nRUN pnpm install -P\n"}, ""},
		{"global tool install", map[string]string{"Dockerfile": "FROM node:20\nRUN npm install -g pm2\n"}, ""},
		{"yarn build is not an install", map[string]string{"Makefile": "build:\n\tyarn build\n"}, ""},
		{"Makefile recipe", map[string]string{"Makefile": "deps:\n\t@npm install\n"}, "Makefile: @npm install"},
		{"Procfile release", map[string]string{"Procfile": "release: npm install\nweb: node index.js\n"}, "Procfile"},
		{"shell script", map[string]string{"scripts/deploy.sh": "#!/bin/sh\ncd app && npm i\n"}, "scripts/deploy.sh: npm i"},
		{"shell script in a test dir", map[string]string{"test/setup.sh": "npm install\n"}, ""},
		{"generic test workflow", map[string]string{".github/workflows/ci.yml": "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci\n"}, ""},
		{"deploy-named workflow file", map[string]string{".github/workflows/deploy.yml": "name: ship\non: push\njobs:\n  ship:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci\n"}, ".github/workflows/deploy.yml job ship: npm ci"},
		{"release-named workflow", map[string]string{".github/workflows/main.yml": "name: Release\non: push\njobs:\n  r:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          npm install\n          npm run build\n"}, "job r: npm install"},
		{"deploy job in a generic workflow: environment", map[string]string{".github/workflows/ci.yml": "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm ci --omit=dev\n  ship:\n    runs-on: ubuntu-latest\n    environment: production\n    steps:\n      - run: npm ci\n"}, "job ship: npm ci"},
		{"test environment is not a deploy job", map[string]string{".github/workflows/ci.yml": "name: CI\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    environment: Test\n    steps:\n      - run: npm ci\n"}, ""},
		{"development environment mapping is not a deploy job", map[string]string{".github/workflows/ci.yml": "name: CI\non: push\njobs:\n  t:\n    runs-on: ubuntu-latest\n    environment:\n      name: development\n    steps:\n      - run: npm ci\n"}, ""},
		{"staging environment mapping is a deploy job", map[string]string{".github/workflows/ci.yml": "name: CI\non: push\njobs:\n  s:\n    runs-on: ubuntu-latest\n    environment:\n      name: staging\n      url: https://x\n    steps:\n      - run: npm ci\n"}, "job s: npm ci"},
		{"expression environment is a deploy job", map[string]string{".github/workflows/ci.yml": "name: CI\non: push\njobs:\n  e:\n    runs-on: ubuntu-latest\n    environment: ${{ inputs.env }}\n    steps:\n      - run: npm ci\n"}, "job e: npm ci"},
		{"deploy job in a generic workflow: build-push-action", map[string]string{".github/workflows/ci.yml": "name: CI\non: push\njobs:\n  img:\n    runs-on: ubuntu-latest\n    steps:\n      - run: yarn\n      - uses: docker/build-push-action@v5\n"}, "job img: yarn"},
		{"deploy job in a generic workflow: deploy action", map[string]string{".github/workflows/ci.yml": "name: CI\non: push\njobs:\n  up:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pnpm install\n      - uses: peaceiris/actions-gh-pages-deploy@v3\n"}, "job up: pnpm install"},
		{"unparseable workflow fails closed", map[string]string{".github/workflows/ci.yml": "jobs: [unclosed\n"}, "unparseable workflow"},
		{"package.json scripts are out of scope", map[string]string{"package.json": `{"scripts":{"heroku-postbuild":"NPM_CONFIG_PRODUCTION=false npm install"}}`}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := prodInstallKeepsDev(writeTree(t, tc.files))
			if (got == "") != (tc.want == "") || !strings.Contains(got, tc.want) {
				t.Fatalf("prodInstallKeepsDev = %q, want %q", got, tc.want)
			}
		})
	}
}
