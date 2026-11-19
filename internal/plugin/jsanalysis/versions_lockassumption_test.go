package jsanalysis

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	// gitLock is lock with qs installed from each of sources, the first at the root.
	const (
		commit   = "2a70b41d5a9eb377a5b730d3379d00f26368d1e4"
		other    = "6a15e5fcbc495fb3a9f107e356b683404c1130bb"
		fromGit  = "git+ssh://git@github.com/acme/qs.git#" + commit
		registry = "https://registry.npmjs.org/qs/-/qs-6.11.0.tgz"
	)
	gitLock := func(sources ...string) string {
		l := `{"name":"app","lockfileVersion":3,"packages":{` +
			`"":{"name":"app","version":"1.0.0","dependencies":{"express":"^4.19.0"}},` +
			`"node_modules/express":{"version":"4.19.2"}`
		at := "node_modules/qs"
		for _, src := range sources {
			l += `,"` + at + `":{"version":"6.11.0","resolved":"` + src + `"}`
			at = "node_modules/express/" + at
		}
		return l + `}}`
	}
	gitOverride := func(spec string, sources ...string) map[string]string {
		return map[string]string{"package.json": pkg(`,"overrides":{"qs":"` + spec + `"}`), "package-lock.json": gitLock(sources...), "install.sh": "npm install\n"}
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
	// out is a Dockerfile shaped like the one Nx generates for a Node app: it copies a build
	// output the tree does not hold to api, between commands that name api, then runs run.
	out := func(before, run string, extra map[string]string) map[string]string {
		files := npm(extra)
		files["Dockerfile"] = "FROM docker.io/node:lts-alpine\nENV HOST=0.0.0.0\nWORKDIR /app\n" +
			"RUN addgroup --system api && \\\n    adduser --system -G api api\n" +
			before + "COPY dist/api api\nRUN chown -R api:api .\nRUN " + run + "\n"
		return files
	}
	const prefixed = "npm --prefix api --omit=dev -f install"
	type outcome int
	const (
		withheld outcome = iota
		assumed
		plain
		built
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
		{"npm install, an override names the repository the lock installs from", gitOverride("github:acme/qs", fromGit), assumed},
		{"npm install, an override names that repository at the locked commit", gitOverride("github:acme/qs#"+commit, fromGit), assumed},
		{"npm install, an override names that repository by URL", gitOverride("git+https://github.com/acme/qs.git", fromGit, "git+https://github.com/acme/qs.git#"+commit), assumed},
		{"npm install, an override names that repository by shorthand ending in .git", gitOverride("github:acme/qs.git", fromGit), assumed},
		{"yarn install", map[string]string{"package.json": pkg(""), "yarn.lock": yarnLock, ".github/workflows/ci.yml": ci("yarn install")}, assumed},
		{"yarn --frozen-lockfile", map[string]string{"package.json": pkg(""), "yarn.lock": yarnLock, ".github/workflows/ci.yml": ci("yarn --frozen-lockfile")}, assumed},
		{"pnpm install", map[string]string{"package.json": pkg(""), "pnpm-lock.yaml": pnpmLock, ".github/workflows/ci.yml": ci("pnpm install")}, assumed},

		// Installs into a build output the tree does not hold.
		{"Dockerfile installs into a copied build output", out("", prefixed, nil), built},
		{"Dockerfile installs into a copied build output with --prefix=", out("", "npm install --prefix=api", nil), built},
		{"Dockerfile runs npm ci in a copied build output", out("", "npm ci --prefix api", nil), built},
		{"Dockerfile installs into a build output under an .npmrc that names a registry", out("COPY ci/npmrc .npmrc\n", prefixed, map[string]string{"ci/npmrc": "registry=https://registry.example.test/\n"}), built},
		{"Dockerfile installs into a build output below a copied directory that holds none of it", out("COPY ci/ ./\n", prefixed, map[string]string{"ci/notes.txt": "x\n"}), built},
		{"Dockerfile installs into a build output a mount does not reach", out("", "--mount=type=cache,target=/root/.npm "+prefixed, nil), built},
		{"Dockerfile installs into a build output, then runs it", out("", prefixed+"\nUSER api\nEXPOSE 3000\nCMD [ \"node\", \"api\" ]", nil), built},
		{"Dockerfile installs into a build output, then runs a command that names none of it", out("", prefixed+"\nRUN apk add --no-cache curl", nil), built},
		{"Dockerfile installs into a build output, then changes its owner", out("", prefixed+"\nRUN chown -R api:api api", nil), built},

		// Commands that install nothing, or hold to the lock by their own flags.
		{"npm install the lock covers, placed", npm(map[string]string{"install.sh": "npm install\n"}), plain},
		{"Dockerfile copies the tree, then npm ci", npm(map[string]string{"Dockerfile": whole + "npm ci\n"}), plain},
		{"npm ci in a workflow", npm(map[string]string{".github/workflows/ci.yml": ci("npm ci")}), plain},
		{"Dockerfile copies the tree, then npm start", npm(map[string]string{"Dockerfile": whole + "npm start\n"}), plain},
		{"Dockerfile copies the tree, then npm run build", npm(map[string]string{"Dockerfile": whole + "npm run build\n"}), plain},
		{"npm run with arguments", npm(map[string]string{"package.json": pkg(`,"scripts":{"e2e":"mocha"}`), ".github/workflows/ci.yml": ci("npm run e2e -- --grep smoke")}), plain},
		{"scripts that run scripts with arguments and a flag", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"npm run lint:js ","lint:eslint":"eslint --ignore-path .gitignore --ext .ts","lint:js":"npm run lint:eslint src/","lint:fix":"npm run lint:js -- --fix"}`)}), plain},
		{"npm test with arguments", npm(map[string]string{"package.json": pkg(`,"scripts":{"test":"jest"}`), ".github/workflows/ci.yml": ci("npm test -- --watch=false")}), plain},
		{"npm start with arguments and no start script", npm(map[string]string{".github/workflows/ci.yml": ci("npm start -- --port=3000")}), plain},
		{"npm run with an argument, at a prefix", npm(map[string]string{"api/package.json": `{"name":"api","version":"1.0.0","scripts":{"lint":"eslint"}}`, ".github/workflows/ci.yml": ci("npm --prefix api run lint src")}), plain},
		{"yarn script with arguments", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("yarn lint src/ --fix")}), plain},
		{"yarn run script with arguments", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("yarn run lint src/")}), plain},
		{"husky hook sources husky's helper", npm(map[string]string{".husky/pre-commit": "#!/usr/bin/env sh\n. \"$(dirname -- \"$0\")/_/husky.sh\"\n\nnpm test\n"}), plain},
		{"husky hook sources husky's helper with source", npm(map[string]string{".husky/pre-push": "#!/bin/sh\nsource \"$(dirname \"$0\")/_/husky.sh\"\nnpm test\n"}), plain},
		{"Dockerfile sources nvm from the image", npm(map[string]string{".gitpod.Dockerfile": "FROM gitpod/workspace-full:latest\nRUN bash -c \". .nvm/nvm.sh && nvm install 14.9.0 && nvm use 14.9.0\"\n"}), plain},
		{"script sources nvm where the build holds none", npm(map[string]string{"setup.sh": ". .nvm/nvm.sh\nnvm use\n"}), plain},
		{"wrapper then npm start", npm(map[string]string{"Dockerfile": whole + "/usr/local/wait-for-it.sh db:27017 -- npm start\n"}), plain},
		{"nx build", npm(map[string]string{"package.json": pkg(`,"scripts":{"build":"nx build"}`)}), plain},
		{"npm install after inline code that prints a field of package.json", npm(map[string]string{".github/workflows/ci.yml": ci("node -p \"require('./package.json').version\" && npm install")}), plain},
		{"npm install after a step that reads package.json in a command substitution", npm(map[string]string{".github/workflows/ci.yml": ci("echo \"version=$(jq -r '.version' package.json)\" >> $GITHUB_OUTPUT\n      - run: npm install")}), plain},
		{"grep for an interpreter's name in package.json", npm(map[string]string{".github/workflows/ci.yml": ci("npm ci\n      - run: grep node package.json")}), plain},
		{"npm install after a registry token is written to .npmrc", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "echo \"//registry.npmjs.org/:_authToken=${NPM_TOKEN}\" > .npmrc && npm install\n"}), assumed},
		{"npm install after a registry token is added to .npmrc in an earlier step", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), ".github/workflows/ci.yml": ci("echo \"//npm.pkg.github.com/:_authToken=${{ secrets.GITHUB_TOKEN }}\" >> .npmrc\n      - run: npm install")}), assumed},
		{"npm install after a scoped registry and its token are written to the home .npmrc", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "echo -e '@acme:registry=https://npm.pkg.github.com\\n//npm.pkg.github.com/:_authToken='\"$TOKEN\" > ~/.npmrc\nnpm install\n"}), assumed},
		{"npm install after printf writes a registry to .npmrc", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "printf 'registry=https://registry.example.test/\\nalways-auth=true\\n' >> .npmrc && npm install\n"}), assumed},
		{"npm install with an override after a registry token is written to .npmrc", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "echo '//registry.npmjs.org/:_authToken=${NPM_TOKEN}' > .npmrc && npm install\n"}), assumed},
		{"jq reads package.json", npm(map[string]string{".github/workflows/ci.yml": ci("npm ci\n      - run: jq -r .version package.json")}), plain},
		{"playwright browser install", npm(map[string]string{"package.json": `{"name":"app","version":"1.0.0","dependencies":{"express":"^4.19.0"},"devDependencies":{"@playwright/test":"^1.40.0"},"scripts":{"pretest":"npx playwright install chromium"}}`,
			"package-lock.json": `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"express":"^4.19.0"},"devDependencies":{"@playwright/test":"^1.40.0"}},"node_modules/express":{"version":"4.19.2"},"node_modules/@playwright/test":{"version":"1.40.0","dev":true}}}`}), plain},

		// Installs into a build output that may reach the scanned project, or leave the lock.
		{"build output install names a package", out("", "npm --prefix api install left-pad", nil), withheld},
		{"build output install --no-package-lock", out("", prefixed+" --no-package-lock", nil), withheld},
		{"build output install --package-lock=false", out("", prefixed+" --package-lock=false", nil), withheld},
		{"build output install --no-save", out("", prefixed+" --no-save", nil), withheld},
		{"build output install at a prefix that leaves the WORKDIR", map[string]string{"package.json": pkg(""), "package-lock.json": lock, "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY dist/api /api\nRUN npm --prefix ../api install\n"}, withheld},
		{"build output install at an absolute prefix", out("", "npm --prefix /app/api install", nil), withheld},
		{"build output install at a prefix in a variable", out("", "npm --prefix $API install", nil), withheld},
		{"build output install at a prefix a command prints", out("", "npm --prefix $(echo api) install", nil), withheld},
		{"build output install at a backquoted prefix", out("", "npm --prefix `echo api` install", nil), withheld},
		{"build output install at a brace-expanded prefix", map[string]string{"package.json": pkg(""), "package-lock.json": lock, "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY dist/api {api,web}\nRUN npm --prefix {api,web} install\n"}, withheld},
		{"build output install inside node_modules", map[string]string{"package.json": pkg(""), "package-lock.json": lock, "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY dist/api node_modules/api\nRUN npm --prefix node_modules/api install\n"}, withheld},
		{"build output install into a directory another stage fills", out("COPY --from=build /out api\n", prefixed, nil), withheld},
		{"build output install into a directory ADD fills", map[string]string{"package.json": pkg(""), "package-lock.json": lock, "Dockerfile": "FROM node:20\nWORKDIR /app\nADD dist/api api\nRUN npm --prefix api install\n"}, withheld},
		{"build output install below a directory another stage fills", out("COPY --from=build /out /app\n", prefixed, nil), withheld},
		{"build output install under an .npmrc that turns the lock off", out("COPY ci/npmrc .npmrc\n", prefixed, map[string]string{"ci/npmrc": "package-lock=false\n"}), withheld},
		{"build output install under a home directory another stage fills", out("COPY --from=build /root /root\n", prefixed, nil), withheld},
		{"build output install after a line is added to its .npmrc", out("", prefixed+" && echo x >> .npmrc", nil), withheld},
		{"build output install into a directory the tree's manifest and lock are copied to", map[string]string{"package.json": pkg(""), "package-lock.json": lock, "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY dist/api api\nCOPY package.json package-lock.json api/\nRUN npm --prefix api install\n"}, withheld},
		{"build output install above a directory the tree's project is copied to", map[string]string{"package.json": pkg(""), "package-lock.json": lock, "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY dist/api api\nCOPY . api/web/\nRUN npm --prefix api install\n"}, withheld},
		{"build output install below a copy of the tree that holds the directory", out("COPY . .\n", prefixed, map[string]string{"api/package.json": api}), withheld},
		{"build output install from a source the tree holds", out("", prefixed, map[string]string{"dist/api/package.json": api}), withheld},
		{"build output install beside a source the tree holds", map[string]string{"package.json": pkg(""), "package-lock.json": lock, "ci/notes.txt": "x\n", "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY dist/api ci/notes.txt api/\nRUN npm --prefix api install\n"}, withheld},
		{"build output install from a glob", map[string]string{"package.json": pkg(""), "package-lock.json": lock, "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY dist/ap* api\nRUN npm --prefix api install\n"}, withheld},
		{"build output install in an Earthfile", map[string]string{"package.json": pkg(""), "package-lock.json": lock, "Earthfile": "VERSION 0.8\nbuild:\n    FROM node:20\n    WORKDIR /app\n    COPY dist/api api\n    RUN npm --prefix api install\n"}, withheld},
		{"build output install under a mount of the output", out("", "--mount=type=cache,target=/app/api "+prefixed, nil), withheld},
		{"build output install under a mount inside the output", out("", "--mount=type=cache,target=/app/api/node_modules "+prefixed, nil), withheld},
		{"build output install under a mount above the output", out("", "--mount=type=bind,target=/app "+prefixed, nil), withheld},
		{"build output install under a mount between the WORKDIR and the output", map[string]string{"package.json": pkg(""), "package-lock.json": lock, "Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY dist/api x/api\nRUN --mount=type=cache,target=/app/x npm --prefix x/api install\n"}, withheld},
		{"build output install under a mount of the root", out("", "--mount=type=bind,target=/ "+prefixed, nil), withheld},
		{"build output install under a mount at a target in a variable", out("", "--mount=type=cache,target=$DIR "+prefixed, nil), withheld},
		{"build output install from a WORKDIR in a variable", map[string]string{"package.json": pkg(""), "package-lock.json": lock, "Dockerfile": "FROM node:20\nWORKDIR $APP\nCOPY dist/api api\nRUN npm --prefix api install\n"}, withheld},
		{"build output install after cd into it", out("", "cd api && npm --prefix . install", nil), withheld},
		{"build output install in a stage built on another", map[string]string{"package.json": pkg(""), "package-lock.json": lock, "Dockerfile": "FROM node:20 AS base\nRUN echo hi\nFROM base\nWORKDIR /app\nCOPY dist/api api\nRUN npm --prefix api install\n"}, withheld},
		{"build output install, then a command names package.json", out("", prefixed+"\nRUN sed -i s/4.19/4.18/ api/package.json", nil), withheld},
		{"build output install, then a command inside the output names the lock", out("", prefixed+"\nWORKDIR /app/api\nRUN rm -f package-lock.json", nil), withheld},
		{"build output install under a secret mounted as the home .npmrc", out("", "--mount=type=secret,id=npmrc,target=/root/.npmrc "+prefixed, nil), withheld},
		{"build output install, then a command names the lock", out("", prefixed+"\nRUN rm -f api/package-lock.json", nil), withheld},
		{"build output install beside an install of a package", out("", prefixed+"\nRUN npm install left-pad", nil), withheld},
		{"build output install into another directory than the output", out("", "npm --prefix web install", nil), withheld},
		{"build output install after a clone into the output", out("", "git clone https://example.test/x.git api\nRUN "+prefixed, nil), withheld},
		{"build output install after a copy into the output", out("", "cp -r x api\nRUN "+prefixed, nil), withheld},
		{"build output install, then another stage copies its node_modules", npm(map[string]string{"Dockerfile": "FROM docker.io/node:lts-alpine AS b\nWORKDIR /app\nCOPY dist/api api\nRUN " + prefixed + "\nFROM docker.io/node:lts-alpine\nWORKDIR /app\nCOPY . .\nCOPY --from=b /app/api/node_modules ./node_modules\n"}), withheld},
		{"build output install, then another stage copies a file from that stage", npm(map[string]string{"Dockerfile": "FROM docker.io/node:lts-alpine AS b\nWORKDIR /app\nCOPY dist/api api\nRUN " + prefixed + "\nFROM docker.io/node:lts-alpine\nWORKDIR /app\nCOPY . .\nCOPY --from=b /etc/passwd /etc/passwd\n"}), withheld},
		{"build output install, then another stage copies the directory above it", npm(map[string]string{"Dockerfile": "FROM docker.io/node:lts-alpine AS b\nWORKDIR /app\nCOPY dist/api api\nRUN " + prefixed + "\nFROM docker.io/node:lts-alpine\nWORKDIR /app\nCOPY . .\nCOPY --from=b /app ./\n"}), withheld},
		{"build output install, then a mount from another stage spelled with quotes", out("", prefixed+"\nRUN --mount=type=bind,\"from\"=b,target=/srv true", nil), withheld},
		{"build output install, then a mount from another stage spelled with a backslash", out("", prefixed+"\nRUN --mount=type=bind,fr\\om=b,target=/srv true", nil), withheld},
		{"build output install, then a mount from another stage that names no output", out("", prefixed+"\nRUN --mount=type=bind,from=b,target=/srv true", nil), withheld},
		{"build output install, then a mount at the same place from no other stage", out("", prefixed+"\nRUN --mount=type=bind,target=/srv true", nil), built},
		{"build output install, then another stage mounts its node_modules", npm(map[string]string{"Dockerfile": "FROM docker.io/node:lts-alpine AS b\nWORKDIR /app\nCOPY dist/api api\nRUN " + prefixed + "\nFROM docker.io/node:lts-alpine\nWORKDIR /app\nCOPY . .\nRUN --mount=type=bind,from=b,source=/app/api/node_modules,target=/app/node_modules node main.js\n"}), withheld},
		{"build output install, then its node_modules is moved", out("", prefixed+"\nRUN mv api/node_modules node_modules", nil), withheld},
		{"build output install, then its node_modules is copied", out("", prefixed+" && cp -r api/node_modules .", nil), withheld},
		{"build output install, then its node_modules is linked", out("", prefixed+" && ln -s api/node_modules node_modules", nil), withheld},
		{"build output install, then the output is copied", out("", prefixed+"\nRUN cp -a api/. .", nil), withheld},
		{"build output install, then a command copies from a variable", out("", prefixed+"\nRUN cp -r $SRC /srv", nil), withheld},
		{"build output install, then a command copies node_modules from inside it", out("", prefixed+"\nWORKDIR /app/api\nRUN cp -r node_modules /srv", nil), withheld},
		{"build output install, then the WORKDIR is copied", out("", prefixed+"\nRUN cp -r . /srv", nil), withheld},
		{"build output install, then the directory above it is copied", out("", prefixed+"\nRUN cp -r /app /srv", nil), withheld},
		{"build output install, then the root is archived", out("", prefixed+"\nRUN tar -cf /srv/image.tar /", nil), withheld},
		{"build output install, then a command names it in an option", out("", prefixed+"\nRUN tar --create --file=/srv/out.tar --directory=api lib", nil), withheld},
		{"build output install after a command that names it before the copy", out("RUN mkdir -p api/node_modules\n", prefixed, nil), withheld},
		{"build output install, then a command that does not tokenise", out("", prefixed+"\nRUN cp -r api/node_modules . \"x", nil), withheld},
		{"build output install, then a heredoc", out("", prefixed+"\nRUN <<EOF\ncp -r api/node_modules .\nEOF", nil), withheld},
		{"build output install, then the image copies from an expanded path when it starts", out("", prefixed+"\nCMD cp -r $SRC . && node main.js", nil), withheld},
		{"build output install, then the image moves its node_modules when it starts", out("", prefixed+"\nCMD mv api/node_modules . && node main.js", nil), withheld},
		{"build output install under an ENV NODE_PATH", out("ENV NODE_PATH=/app/api/node_modules\n", prefixed, nil), withheld},
		{"build output install under an ARG NODE_PATH", out("ARG NODE_PATH\n", prefixed, nil), withheld},
		{"build output install, then a command sets NODE_PATH", out("", prefixed+"\nRUN NODE_PATH=/app/api/node_modules node main.js", nil), withheld},
		{"build output install under an ENV that names node_modules", out("ENV PATH=/app/api/node_modules/.bin:$PATH\n", prefixed, nil), withheld},
		{"build output install with yarn", out("", "yarn --cwd api install", nil), withheld},
		{"build output install with pnpm", out("", "pnpm --dir api install", nil), withheld},

		// Installs that can leave the lock.
		{"npm install names a package", npm(map[string]string{"Dockerfile": whole + "npm install left-pad\n"}), withheld},
		{"npm update", npm(map[string]string{"Dockerfile": whole + "npm update\n"}), withheld},
		{"npm install --no-package-lock", npm(map[string]string{"Dockerfile": whole + "npm install --no-package-lock\n"}), withheld},
		{"npm install with no lock", map[string]string{"package.json": pkg(""), "other/package.json": pkg(""), "other/package-lock.json": lock, "Dockerfile": whole + "npm install\n"}, withheld},
		{"npm install in a directory the lock above does not cover", npm(map[string]string{"api/package.json": api, "install.sh": "cd api && npm install\n"}), withheld},
		{"npm install after inline code that names no build file", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "node -e \"require('fs').rmSync('tmp', { recursive: true, force: true });\" && npm install\n"}), assumed},
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
		{"npm install after a script's inline code removes the lock", npm(map[string]string{"package.json": pkg(`,"scripts":{"clean-install":"node -e \"const fs = require('fs'); fs.rmSync('node_modules', { recursive: true, force: true }); fs.rmSync('package-lock.json', { force: true });\" && npm install"}`)}), withheld},
		{"npm install after inline code rewrites the manifest", npm(map[string]string{".github/workflows/ci.yml": ci("node -e \"require('fs').writeFileSync('./package.json', '{}')\"\n      - run: npm install")}), withheld},
		{"npm install after inline code removes the lock named in a variable", npm(map[string]string{"install.sh": "node -e \"const f='package-lock.json'; const fs=require('fs'); fs.rmSync(f)\" && npm install\n"}), withheld},
		{"npm install after inline code removes the lock in an arrow function", npm(map[string]string{".github/workflows/ci.yml": ci("node -e \"['package-lock.json'].forEach(f => require('fs').rmSync(f))\" && npm install")}), withheld},
		{"npm install after inline code run through sudo removes the lock", npm(map[string]string{"install.sh": "sudo -E node -e \"require('fs').rmSync('package-lock.json')\" && npm install\n"}), withheld},
		{"npm install after inline code run through cross-env removes the lock", npm(map[string]string{"package.json": pkg(`,"scripts":{"fresh":"cross-env CI=1 node -e \"require('fs').rmSync('package-lock.json')\" && npm install"}`)}), withheld},
		{"npm install after inline code requires package.json and rewrites it", npm(map[string]string{"install.sh": "node -e \"const p=require('./package.json'); p.dependencies.express='5'; require('fs').writeFileSync('package.json', JSON.stringify(p))\" && npm install\n"}), withheld},
		{"npm install after a token and a lock setting are written to .npmrc", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "echo -e \"//registry.npmjs.org/:_authToken=${NPM_TOKEN}\\npackage-lock=false\" > .npmrc && npm install\n"}), withheld},
		{"npm install after a single-quoted token and lock setting are written to .npmrc", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "echo '//registry.npmjs.org/:_authToken=abc\\npackage-lock=false' > .npmrc && npm install\n"}), withheld},
		{"npm install after a key held in a variable is written to .npmrc", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "echo \"${KEY}=false\" >> .npmrc && npm install\n"}), withheld},
		{"npm install after a command's output is written to .npmrc", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "echo \"registry=$(cat ci/registry)\" >> .npmrc && npm install\n"}), withheld},
		{"npm install after printf fills a format onto .npmrc", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "printf '%s\\n' \"$NPMRC\" > .npmrc && npm install\n"}), withheld},
		{"npm install after printf is handed an argument for its format", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "printf 'registry=https://registry.example.test/\\n' 'always-auth=true' > .npmrc && npm install\n"}), withheld},
		{"npm install after a registry is written to package.json", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "echo registry=https://registry.example.test/ > package.json && npm install\n"}), withheld},
		{"npm install after a registry is written to the lock", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "echo registry=https://registry.example.test/ >> package-lock.json && npm install\n"}), withheld},
		{"npm install after a variable's text is written to .npmrc", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "echo \"$NPMRC\" > .npmrc && npm install\n"}), withheld},
		{"npm install after a registry token is written to .npmrc and a second file", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "echo \"//registry.npmjs.org/:_authToken=${NPM_TOKEN}\" > package-lock.json > .npmrc && npm install\n"}), withheld},
		{"npm install after a backquoted command's output is written to .npmrc", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "echo 'registry=https://registry.example.test/'`cat ci/suffix` > .npmrc && npm install\n"}), withheld},
		{"npm install after an escaped byte is written to .npmrc", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "echo -e 'registry=https://registry.example.test/\\x0apackage-lock=false' > .npmrc && npm install\n"}), withheld},
		{"npm install after a registry is written to an .npmrc under a computed directory", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "echo 'registry=https://registry.example.test/' > \"$(pwd)/.npmrc\" && npm install\n"}), withheld},
		{"npm install after legacy-peer-deps is written to .npmrc", npm(map[string]string{"package.json": pkg(`,"overrides":{"qs":"6.11.0"}`), "install.sh": "echo legacy-peer-deps=true >> .npmrc && npm install\n"}), withheld},
		{"npm install, an override names a repository for an alias the lock installs from the registry", map[string]string{
			"package.json":      `{"name":"app","version":"1.0.0","dependencies":{"express":"^4.19.0","qs":"npm:bar@1.0.0"},"overrides":{"qs":"github:acme/qs"}}`,
			"package-lock.json": `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0","dependencies":{"express":"^4.19.0","qs":"npm:bar@1.0.0"}},"node_modules/express":{"version":"4.19.2"},"node_modules/qs":{"name":"bar","version":"1.0.0","resolved":"https://registry.npmjs.org/bar/-/bar-1.0.0.tgz"}}}`,
			"install.sh":        "npm install\n"}, withheld},
		{"npm install, an override names a repository by a git+git URL", gitOverride("git+git://github.com/acme/qs", "git+git://github.com/acme/qs#"+commit), withheld},
		{"npm install, an override names another repository than the lock installs from", gitOverride("github:acme/qs-fork", fromGit), withheld},
		{"npm install, an override names another owner's repository", gitOverride("github:other/qs", fromGit), withheld},
		{"npm install, an override names a commit the lock does not hold", gitOverride("github:acme/qs#"+other, fromGit), withheld},
		{"npm install, an override names that repository in another case", gitOverride("github:Acme/qs", fromGit), withheld},
		{"npm install, an override names a repository and a dependent is locked to a ref of it", map[string]string{"package.json": pkg(`,"overrides":{"qs":"github:acme/qs"}`), "install.sh": "npm install\n",
			"package-lock.json": strings.Replace(gitLock(fromGit), `"node_modules/express":{`, `"node_modules/express":{"dependencies":{"qs":"github:acme/qs#main"},`, 1)}, withheld},
		{"npm install, an override names a branch", gitOverride("github:acme/qs#main", fromGit), withheld},
		{"npm install, an override names a branch and the lock holds no copy of it", gitOverride("github:acme/qs#main"), withheld},
		{"npm install, an override names a repository and the lock installs from the registry", gitOverride("github:acme/qs", registry), withheld},
		{"npm install, an override names a repository and one locked copy is from the registry", gitOverride("github:acme/qs", fromGit, registry), withheld},
		{"npm install, an override names a repository and the lock records no commit", gitOverride("github:acme/qs", "git+ssh://git@github.com/acme/qs.git"), withheld},
		{"npm install, an override names a repository and the lock records no source", gitOverride("github:acme/qs", ""), withheld},
		{"npm install, an override names a repository on another host", gitOverride("git+https://gitlab.com/acme/qs.git", "git+https://gitlab.com/acme/qs.git#"+commit), withheld},
		{"npm install, an override names a tarball", gitOverride("https://example.test/qs.tgz", fromGit), withheld},
		{"yarn install, a resolution names a repository", map[string]string{"package.json": pkg(`,"resolutions":{"express":"github:acme/express"}`), "yarn.lock": yarnLock, ".github/workflows/ci.yml": ci("yarn install")}, withheld},
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
		{"npm run hands an install script a flag that turns the lock off", npm(map[string]string{"package.json": pkg(`,"scripts":{"setup":"npm install"}`), ".github/workflows/ci.yml": ci("npm run setup -- --no-package-lock")}), withheld},
		{"npm run hands a script an expansion", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("npm run lint -- $FILES")}), withheld},
		{"npm run hands a script a command substitution", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("npm run lint -- $(cat files)")}), withheld},
		{"npm run with a redirect", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("npm run lint -- src > out.txt")}), withheld},
		{"npm run hands a script a command after ;", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("npm run lint -- \"src; npm install left-pad\"")}), withheld},
		{"npm run hands a script a command after &&", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("npm run lint -- 'src&&touch x'")}), withheld},
		{"npm run hands a script a pipe", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("npm run lint -- 'src|sh'")}), withheld},
		{"npm run hands a script the lock", npm(map[string]string{"package.json": pkg(`,"scripts":{"clean":"rm -f"}`), ".github/workflows/ci.yml": ci("npm run clean -- package-lock.json")}), withheld},
		{"npm run hands a script a token", npm(map[string]string{"package.json": pkg(`,"scripts":{"go":"exec"}`), ".github/workflows/ci.yml": ci("npm run go -- npm")}), withheld},
		{"script runs itself with arguments", npm(map[string]string{"package.json": pkg(`,"scripts":{"loop":"npm run loop x"}`)}), withheld},
		{"npm run with arguments of a missing script", npm(map[string]string{".github/workflows/ci.yml": ci("npm run nope -- src")}), withheld},
		{"npm run with a short flag", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("npm run lint -w api")}), withheld},
		{"npm run with an npm config flag", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("npm run lint --script-shell=./sh")}), withheld},
		{"npm run with an abbreviated npm config flag", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("npm run lint --ignore-scr")}), withheld},
		{"npm run with a word after a flag", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("npm run lint --fix src")}), withheld},
		{"npm run with a flag, of a script that runs npm", npm(map[string]string{"package.json": pkg(`,"scripts":{"fresh":"npm ci"}`), ".github/workflows/ci.yml": ci("npm run fresh --fix")}), withheld},
		{"npm run with arguments, of a script ending in a comment", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint . # all"}`), ".github/workflows/ci.yml": ci("npm run lint -- src")}), withheld},
		{"yarn script with a yarn option", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("yarn lint --cwd api")}), withheld},
		{"yarn script with arguments after --", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("yarn lint -- --fix")}), withheld},
		{"yarn script with arguments, of an install script", npm(map[string]string{"package.json": pkg(`,"scripts":{"setup":"npm install"}`), ".github/workflows/ci.yml": ci("yarn setup left-pad")}), withheld},
		{"husky hook beside a husky helper the repository holds", npm(map[string]string{".husky/pre-commit": "#!/bin/sh\n. \"$(dirname -- \"$0\")/_/husky.sh\"\nnpm test\n", ".husky/_/husky.sh": "#!/bin/sh\nnpm install left-pad\n"}), withheld},
		{"husky's helper line outside .husky", npm(map[string]string{"hooks/pre-commit": "#!/bin/sh\n. \"$(dirname -- \"$0\")/_/husky.sh\"\nnpm test\n"}), withheld},
		{"Dockerfile sources nvm after copying the tree", npm(map[string]string{"Dockerfile": whole + ". .nvm/nvm.sh && nvm use\n"}), withheld},
		{"Dockerfile sources nvm under a mount", npm(map[string]string{"Dockerfile": "FROM node:20\nRUN --mount=type=bind,target=/src . .nvm/nvm.sh\n"}), withheld},
		{"script sources an nvm.sh the build holds", npm(map[string]string{"setup.sh": ". .nvm/nvm.sh\n", ".nvm/nvm.sh": "npm install left-pad\n"}), withheld},
		{"--prefix after -- is the script's", npm(map[string]string{"package.json": pkg(`,"scripts":{"setup":"npm install"}`), "foo/package.json": `{"name":"foo","version":"1.0.0","scripts":{"setup":"echo hi"}}`, ".github/workflows/ci.yml": ci("npm run setup -- --prefix foo")}), withheld},
		{"--prefix= after -- is the script's", npm(map[string]string{"package.json": pkg(`,"scripts":{"setup":"npm install"}`), "foo/package.json": `{"name":"foo","version":"1.0.0","scripts":{"setup":"echo hi"}}`, ".github/workflows/ci.yml": ci("npm run setup -- --prefix=foo")}), withheld},
		{"npm test with --prefix after --", npm(map[string]string{"package.json": pkg(`,"scripts":{"test":"npm install"}`), "foo/package.json": `{"name":"foo","version":"1.0.0","scripts":{"test":"echo hi"}}`, ".github/workflows/ci.yml": ci("npm test -- --prefix foo")}), withheld},
		{"--prefix before -- is npm's", npm(map[string]string{"package.json": pkg(`,"scripts":{"setup":"echo root"}`), "foo/package.json": `{"name":"foo","version":"1.0.0","scripts":{"setup":"echo hi"}}`, ".github/workflows/ci.yml": ci("npm run setup --prefix foo -- x")}), plain},
		{"npm run with an underscored npm config", npm(map[string]string{"package.json": pkg(`,"scripts":{"setup":"sh scripts/ci.sh"}`), "scripts/ci.sh": "npm install\n", ".github/workflows/ci.yml": ci("npm run setup --package_lock=false")}), withheld},
		{"npm run with a negated negated npm config", npm(map[string]string{"package.json": pkg(`,"scripts":{"setup":"sh scripts/ci.sh"}`), "scripts/ci.sh": "npm install\n", ".github/workflows/ci.yml": ci("npm run setup --no-no-no-package-lock")}), withheld},
		{"npm run with an underscored script-shell", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("npm run lint --script_shell=./sh")}), withheld},
		{"npm run with a capitalised script-shell", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("npm run lint --Script-Shell=./sh")}), withheld},
		{"npm run with a negated npm config", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("npm run lint --no-color")}), withheld},
		{"npm run with arguments, of a script ending in fi", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"if true; then eslint; fi"}`), ".github/workflows/ci.yml": ci("npm run lint -- src")}), withheld},
		{"npm run with arguments, of a script ending in done", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"for d in a; do eslint; done"}`), ".github/workflows/ci.yml": ci("npm run lint -- src")}), withheld},
		{"npm run with arguments, of a script ending in &", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint . &"}`), ".github/workflows/ci.yml": ci("npm run lint -- src")}), withheld},
		{"npm run with arguments, of a script ending in a quote", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint \"src\""}`), ".github/workflows/ci.yml": ci("npm run lint -- lib")}), plain},
		{"yarn script with a short flag", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("yarn lint -f")}), withheld},
		{"yarn builtin shadowing a script", npm(map[string]string{"package.json": pkg(`,"scripts":{"add":"echo hi"}`), ".github/workflows/ci.yml": ci("yarn add left-pad")}), withheld},
		{"husky helper the build writes", npm(map[string]string{".husky/pre-commit": "#!/bin/sh\n. \"$(dirname -- \"$0\")/_/husky.sh\"\nnpm test\n", "tools/helper.txt": "npm install left-pad\n", ".github/workflows/ci.yml": ci("cp tools/helper.txt .husky/_/husky.sh")}), withheld},
		{"nvm.sh the build writes", npm(map[string]string{"tools/helper.txt": "npm install left-pad\n", ".github/workflows/ci.yml": ci("cp tools/helper.txt .nvm/nvm.sh && . .nvm/nvm.sh")}), withheld},
		{"husky helper the repository holds that only moves the hook", npm(map[string]string{".husky/pre-commit": "#!/bin/sh\n. \"$(dirname -- \"$0\")/_/husky.sh\"\nnpm install\n", ".husky/_/husky.sh": "cd sub\n", "sub/package.json": api}), withheld},
		{"husky hook beside husky install", npm(map[string]string{"package.json": pkg(`,"devDependencies":{"husky":"^8.0.0"},"scripts":{"prepare":"husky install"}`), ".husky/pre-commit": "#!/bin/sh\n. \"$(dirname -- \"$0\")/_/husky.sh\"\nnpm test\n"}), plain},
		{"husky helper directory the build extracts into", npm(map[string]string{".husky/pre-commit": "#!/bin/sh\n. \"$(dirname -- \"$0\")/_/husky.sh\"\nnpm test\n", "tools/hk.tar": "x", ".github/workflows/ci.yml": ci("tar -xf tools/hk.tar -C .husky")}), withheld},
		{"husky helper directory the build checks out", npm(map[string]string{".husky/pre-commit": "#!/bin/sh\n. \"$(dirname -- \"$0\")/_/husky.sh\"\nnpm test\n", ".github/workflows/ci.yml": ci("git checkout origin/tooling -- .husky")}), withheld},
		{"Dockerfile heredoc elsewhere, then nvm", npm(map[string]string{"Dockerfile": "FROM node:20\nCOPY <<EOF /x/a.txt\nhello\nEOF\nRUN . .nvm/nvm.sh\n"}), withheld},
		{"Dockerfile sources nvm where the image runs", npm(map[string]string{"Dockerfile": "FROM node:20\nCMD . .nvm/nvm.sh && npm start\n"}), withheld},
		{"npm run at a --prefix spelled as a flag", npm(map[string]string{"package.json": pkg(`,"scripts":{"setup":"npm install"}`), "-x/package.json": `{"name":"x","version":"1.0.0","scripts":{"setup":"echo hi"}}`, ".github/workflows/ci.yml": ci("npm run setup --prefix -x -- --no-package-lock")}), withheld},
		{"Dockerfile writes nvm.sh from a heredoc", npm(map[string]string{"Dockerfile": "FROM node:20\nCOPY <<EOF .nvm/nvm.sh\nexport npm_config_package_lock=false\nEOF\nRUN . .nvm/nvm.sh && npm install\n"}), withheld},
		{"npm run with an npm config spelled with a leading _", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("npm run lint --_auth=x")}), withheld},
		{"npm run hands a script a command after && before --", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("npm run lint 'src&&touch x'")}), withheld},
		{"npm run with a lone short flag", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("npm run lint -ws")}), withheld},
		{"npm run with a flag where the script name goes", npm(map[string]string{"package.json": pkg(`,"scripts":{"-s":"echo hi","setup":"npm install"}`), ".github/workflows/ci.yml": ci("npm run -s setup")}), withheld},
		{"yarn script handed a command after &&", npm(map[string]string{"package.json": pkg(`,"scripts":{"lint":"eslint"}`), ".github/workflows/ci.yml": ci("yarn lint 'src&&touch x'")}), withheld},
		{"Earthfile sources nvm on a stage built from the repository's Dockerfile", npm(map[string]string{"Dockerfile": "FROM node:20\nCOPY . .\n", "Earthfile": "VERSION 0.8\nbuild:\n    FROM DOCKERFILE .\n    RUN . .nvm/nvm.sh\n"}), withheld},
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
			for _, want := range []struct {
				o              outcome
				reason, detail string
			}{{assumed, AnnotationInstallHonoursLock, lockAssumption}, {built, AnnotationBuildOutputInstall, buildOutputAssumption}} {
				var notes []plugin.Annotation
				for _, a := range r.Annotations {
					if a.Reason == want.reason {
						notes = append(notes, a)
					}
				}
				switch {
				case tt.want != want.o && len(notes) > 0:
					t.Fatalf("annotations = %+v; want no %s", notes, want.reason)
				case tt.want == want.o && (len(notes) != 1 || notes[0].Detail != want.detail || notes[0].Path != ""):
					t.Fatalf("annotations = %+v; want one %s saying %q, with none of the tree's words", r.Annotations, want.reason, want.detail)
				}
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
		{"npm install into a build output", "COPY dist/api api\nRUN npm --prefix api install\n", "", both, []string{buildOutputAssumption}},
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
