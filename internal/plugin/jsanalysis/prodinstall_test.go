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
		{"shell script in a test dir", map[string]string{"test/setup.sh": "npm install\n"}, "test/setup.sh: npm install"},
		{"job a deploy job needs", map[string]string{".github/workflows/ci.yml": "name: CI\non: push\njobs:\n  build:\n    runs-on: x\n    steps:\n      - run: npm ci\n  ship:\n    needs: build\n    runs-on: x\n    environment: production\n    steps:\n      - run: ./ship\n"}, "job build: npm ci"},
		{"job a deploy job needs transitively", map[string]string{".github/workflows/ci.yml": "name: CI\non: push\njobs:\n  deps:\n    runs-on: x\n    steps:\n      - run: npm ci\n  build:\n    needs: [deps]\n    runs-on: x\n    steps:\n      - run: ./b\n  ship:\n    needs: [build]\n    runs-on: x\n    environment: production\n    steps:\n      - run: ./ship\n"}, "job deps: npm ci"},
		{"reusable workflow judges every job", map[string]string{".github/workflows/build.yml": "name: Build\non: workflow_call\njobs:\n  b:\n    runs-on: x\n    steps:\n      - run: npm ci\n"}, "job b: npm ci"},
		{"workflow_run consumer judges every workflow", map[string]string{
			".github/workflows/ci.yml":    "name: CI\non: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: npm ci\n",
			".github/workflows/after.yml": "name: After\non:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: ./publish\n",
		}, "job t: npm ci"},
		{"omit optional keeps dev under NODE_ENV=production", map[string]string{"Dockerfile": "FROM node:20\nENV NODE_ENV=production\nRUN npm ci --omit=optional\n"}, "npm ci --omit=optional"},
		{"only dev keeps dev under NODE_ENV=production", map[string]string{"Dockerfile": "FROM node:20\nENV NODE_ENV=production\nRUN npm ci --only=dev\n"}, "npm ci --only=dev"},
		{"only prod omits dev", map[string]string{"Dockerfile": "FROM node:20\nRUN npm ci --only=production\n"}, ""},
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
		{"package.json script", map[string]string{"package.json": `{"scripts":{"heroku-postbuild":"NPM_CONFIG_PRODUCTION=false npm install"}}`}, "package.json scripts.heroku-postbuild"},
		{"RUN --mount before the install", map[string]string{"Dockerfile": "FROM node:20\nRUN --mount=type=cache,target=/root/.npm npm ci\n"}, "npm ci"},
		{"sh -c wrapper", map[string]string{"Makefile": "deps:\n\tsh -c \"npm ci\"\n"}, "npm ci"},
		{"sudo -u wrapper", map[string]string{"deploy.sh": "sudo -u node npm install\n"}, "npm install"},
		{"GitLab deploy job", map[string]string{".gitlab-ci.yml": "deploy:\n  script:\n    - npm ci\n"}, ".gitlab-ci.yml job deploy: npm ci"},
		{"GitLab deploy job through extends and default", map[string]string{".gitlab-ci.yml": "default:\n  before_script:\n    - npm install\n.base:\n  stage: release\nship:\n  extends: .base\n  script:\n    - ./ship\n"}, ".gitlab-ci.yml job ship: npm install"},
		{"GitLab test job", map[string]string{".gitlab-ci.yml": "test:\n  script:\n    - npm ci\n"}, ""},
		{"Cloud Build", map[string]string{"cloudbuild.yaml": "steps:\n  - name: node:20\n    entrypoint: npm\n    args: [ci]\n"}, "cloudbuild.yaml: npm ci"},
		{"Jenkinsfile", map[string]string{"Jenkinsfile": "node { sh 'npm install' }\n"}, "Jenkinsfile: npm install"},
		{"compose command", map[string]string{"docker-compose.yml": "services:\n  web:\n    image: node\n    command: sh -c \"npm install && node app\"\n"}, "service web"},
		{"CircleCI", map[string]string{".circleci/config.yml": "jobs:\n  b:\n    steps:\n      - run: npm ci\n"}, ".circleci/config.yml: npm ci"},
		{"render.yaml", map[string]string{"render.yaml": "services:\n  - type: web\n    buildCommand: npm install\n"}, "render.yaml: npm install"},
		{".npmrc production=false", map[string]string{".npmrc": "production=false\n"}, ".npmrc: production=false"},
		{"Dockerfile copies a lockfile root's node_modules", map[string]string{"package.json": `{"name":"app"}`, "package-lock.json": "{}", "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY . .\nCMD node index.js\n"}, "copies node_modules into the image"},
		{".dockerignore excludes node_modules", map[string]string{"package.json": `{"name":"app"}`, "package-lock.json": "{}", ".dockerignore": "node_modules\n", "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY . .\nCMD node index.js\n"}, ""},
		{"deploy job's local action", map[string]string{".github/workflows/deploy.yml": "on: push\njobs:\n  ship:\n    runs-on: x\n    steps:\n      - uses: ./.github/actions/setup\n", ".github/actions/setup/action.yml": "runs:\n  using: composite\n  steps:\n    - run: npm ci\n      shell: bash\n"}, ".github/workflows/deploy.yml job ship: npm ci"},
		{"deploy job's remote reusable workflow", map[string]string{".github/workflows/deploy.yml": "on: push\njobs:\n  ship:\n    uses: org/repo/.github/workflows/ship.yml@main\n"}, "remote reusable workflow"},
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
