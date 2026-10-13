package jsanalysis

import (
	"strings"
	"testing"
)

// launchTree is devBinTree with tool declared and a serve script that runs it, so a launch
// command reaching `npm run serve` (or tool itself) loads tool. Nothing else names tool.
func launchTree(t *testing.T, extra map[string]string) map[string]string {
	files := devBinTree(t, map[string]string{
		"package.json":  `{"name":"app","scripts":{"serve":"tool index.js"},"devDependencies":{"tool":"*"}}`,
		".gitignore":    "node_modules\n",
		".dockerignore": "node_modules\n",
	})
	for k, v := range extra {
		files[k] = v
	}
	return files
}

const nodeDockerfile = "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci --omit=dev\n"

const (
	loads    = "loads"    // complete, tool loaded
	refutes  = "refutes"  // complete, tool refuted
	withhold = "withhold" // incomplete, with a gap naming the reason
)

func TestLaunchReader(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string
		gap   string // substring of a gap, for withhold
	}{
		// Launch commands a production image or platform runs.
		{
			name: "L1 the node image's docker-entrypoint.sh runs CMD npm run serve",
			files: map[string]string{
				"Dockerfile": nodeDockerfile + "ENTRYPOINT [\"docker-entrypoint.sh\"]\nCMD [\"npm\",\"run\",\"serve\"]\n",
			},
			want: loads,
		},
		{
			name: "L2 an entrypoint COPY'd onto PATH is read",
			files: map[string]string{
				"entrypoint.sh": "#!/bin/sh\nexec tool serve\n",
				"Dockerfile":    nodeDockerfile + "COPY entrypoint.sh /usr/local/bin/\nENTRYPOINT [\"entrypoint.sh\"]\n",
			},
			want: loads,
		},
		{
			name: "L3 a script COPY'd under /usr/local/bin is read, not taken for a system tool",
			files: map[string]string{
				"start.sh":   "#!/bin/sh\nexec tool serve\n",
				"Dockerfile": nodeDockerfile + "COPY start.sh /usr/local/bin/start.sh\nENTRYPOINT [\"/usr/local/bin/start.sh\"]\n",
			},
			want: loads,
		},
		{
			name:  "L16 forever withholds",
			files: map[string]string{"Procfile": "web: forever start node_modules/tool/cli.js\n"},
			want:  withhold,
			gap:   "runs forever",
		},
		{
			name:  "corepack pnpm run serve runs the script",
			files: map[string]string{"Procfile": "web: corepack pnpm run serve\n"},
			want:  loads,
		},
		{
			name:  "corepack yarn serve runs the script",
			files: map[string]string{"Procfile": "web: corepack yarn serve\n"},
			want:  loads,
		},
		{
			name: "L11g a compose list command naming its program by variable withholds",
			files: map[string]string{
				"Dockerfile":         nodeDockerfile + "CMD [\"node\",\"index.js\"]\n",
				"docker-compose.yml": "services:\n  web:\n    build: .\n    command: [\"${RUNNER}\", \"serve\"]\n",
			},
			want: withhold,
			gap:  "a variable names the launch command",
		},
		{
			name: "L11i a compose list command naming its script by variable withholds",
			files: map[string]string{
				".env":               "SCRIPT=serve\n",
				"Dockerfile":         nodeDockerfile + "CMD [\"node\",\"index.js\"]\n",
				"docker-compose.yml": "services:\n  web:\n    build: .\n    command: [\"npm\", \"run\", \"${SCRIPT}\"]\n",
			},
			want: withhold,
			gap:  "a variable names the script",
		},
		{
			name: "L11j a compose list entrypoint naming a bin by variable withholds",
			files: map[string]string{
				"Dockerfile":         nodeDockerfile + "CMD [\"node\",\"index.js\"]\n",
				"docker-compose.yml": "services:\n  web:\n    build: .\n    entrypoint: [\"node_modules/.bin/${BIN}\"]\n",
			},
			want: withhold,
			gap:  "a variable names a path into node_modules",
		},
		{
			name: "L8 a Kubernetes container command running a dev bin loads it",
			files: map[string]string{
				"k8s/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n          image: myorg/app:1\n          command: [\"tool\", \"serve\"]\n",
			},
			want: loads,
		},
		{
			name:  "L9b a systemd ExecStart running a dev bin by path loads it",
			files: map[string]string{"deploy/app.service": "[Service]\nExecStart=/srv/app/node_modules/.bin/tool serve\n"},
			want:  loads,
		},
		{
			name: "L10 a pm2 ecosystem file withholds",
			files: map[string]string{
				"ecosystem.config.js": "module.exports = { apps: [{ script: './node_modules/.bin/tool' }] };\n",
				"Dockerfile":          nodeDockerfile + "CMD [\"pm2-runtime\",\"ecosystem.config.js\"]\n",
			},
			want: withhold,
			gap:  "pm2 process file",
		},
		{
			name: "a pm2 process file withholds even when no launch command names pm2",
			files: map[string]string{
				"pm2.config.js": "module.exports = { apps: [{ script: 'node_modules/tool/bin/tool.js' }] };\n",
				"Dockerfile":    nodeDockerfile + "CMD [\"node\",\"index.js\"]\n",
			},
			want: withhold,
			gap:  "pm2 process file",
		},
		{
			name:  "N-r3a a Procfile.* is a launch surface",
			files: map[string]string{"Procfile.dev": "web: tool serve\n"},
			want:  loads,
		},

		// One row per class the reader decides.
		{
			name:  "an unknown launch command withholds",
			files: map[string]string{"Procfile": "web: mystery-server index.js\n"},
			want:  withhold,
			gap:   "runs mystery-server, which the reader does not follow",
		},
		{
			name: "an in-tree script is read and refutes when it runs no dev bin",
			files: map[string]string{
				"Procfile":     "web: ./bin/start.sh\n",
				"bin/start.sh": "#!/bin/sh\nset -e\nexec node index.js\n",
			},
			want: refutes,
		},
		{
			name: "an in-tree script's positional arguments are followed",
			files: map[string]string{
				"Procfile":       "web: sh scripts/run.sh serve\n",
				"scripts/run.sh": "#!/bin/sh\nexec npm run \"$1\"\n",
			},
			want: loads,
		},
		{
			name: "set -- and exec \"$@\" are followed",
			files: map[string]string{
				"entrypoint.sh": "#!/bin/sh\nset -- npm run serve\nexec \"$@\"\n",
				"Dockerfile":    nodeDockerfile + "ENTRYPOINT [\"./entrypoint.sh\"]\n",
			},
			want: loads,
		},
		{
			name:  "a script that is not in the build dir withholds",
			files: map[string]string{"Procfile": "web: ./missing.sh\n"},
			want:  withhold,
			gap:   "missing.sh",
		},
		{
			name:  "a script outside the build dir withholds",
			files: map[string]string{"Procfile": "web: ../outside.sh\n"},
			want:  withhold,
			gap:   "outside the build dir",
		},
		{
			name:  "a script the image supplies withholds",
			files: map[string]string{"Dockerfile": nodeDockerfile + "CMD [\"/usr/local/bin/custom-start\"]\n"},
			want:  withhold,
			gap:   "which the image supplies",
		},
		{
			name: "a script a RUN rewrites withholds",
			files: map[string]string{
				"start.sh":   "#!/bin/sh\nexec node index.js\n",
				"Dockerfile": nodeDockerfile + "RUN sed -i 's/node/tool/' /app/start.sh\nCMD [\"/app/start.sh\"]\n",
			},
			want: withhold,
			gap:  "comes from a source the reader cannot see",
		},
		{
			name:  "a non-node base image's entrypoint around CMD withholds",
			files: map[string]string{"Dockerfile": "FROM python:3.12\nWORKDIR /app\nCOPY . .\nCMD [\"node\",\"index.js\"]\n"},
			want:  withhold,
			gap:   "the base image python:3.12 supplies the launch command",
		},
		{
			name:  "a base image's own launch command withholds when the Dockerfile sets none",
			files: map[string]string{"Dockerfile": "FROM myorg/base\nCOPY . .\n"},
			want:  withhold,
			gap:   "the base image myorg/base supplies the launch command",
		},
		{
			name:  "the node image with no command refutes",
			files: map[string]string{"Dockerfile": nodeDockerfile},
			want:  refutes,
		},
		{
			name:  "a distribution image runs CMD as it is",
			files: map[string]string{"Dockerfile": "FROM alpine:3.20\nWORKDIR /app\nCOPY . .\nCMD [\"node_modules/.bin/tool\", \"serve\"]\n"},
			want:  loads,
		},
		{
			name:  "a variable naming the launch command withholds",
			files: map[string]string{"Procfile": "web: $RUNNER index.js\n"},
			want:  withhold,
			gap:   "a variable names the launch command",
		},
		{
			name:  "a process wrapper withholds",
			files: map[string]string{"Procfile": "web: nodemon index.js\n"},
			want:  withhold,
			gap:   "runs nodemon",
		},
		{
			name:  "corepack running something other than a package manager withholds",
			files: map[string]string{"Procfile": "web: corepack bogus serve\n"},
			want:  withhold,
			gap:   "corepack runs bogus",
		},
		{
			name:  "a node_modules/.bin path no package provides withholds",
			files: map[string]string{"Procfile": "web: node_modules/.bin/nothere serve\n"},
			want:  withhold,
			gap:   "which no installed package provides",
		},
		{
			name:  "a HEALTHCHECK running a dev bin loads it",
			files: map[string]string{"Dockerfile": nodeDockerfile + "HEALTHCHECK CMD tool ping\nCMD [\"node\",\"index.js\"]\n"},
			want:  loads,
		},
		{
			name: "a Kubernetes args list on the node image runs through its entrypoint",
			files: map[string]string{
				"deploy.yaml": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  containers:\n    - name: web\n      image: node:20\n      args: [\"npm\", \"run\", \"serve\"]\n",
			},
			want: loads,
		},
		{
			name: "a Kubernetes args list under another image's entrypoint withholds",
			files: map[string]string{
				"deploy.yaml": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  containers:\n    - name: web\n      image: myorg/app:1\n      args: [\"serve\"]\n",
			},
			want: withhold,
			gap:  "the image myorg/app:1 supplies the command",
		},
		{
			name: "a Kubernetes container on an official image with a volume is read",
			files: map[string]string{
				"k8s.yaml": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  containers:\n    - name: web\n      image: alpine:3.20\n      args: [\"tool\", \"serve\"]\n      volumeMounts:\n        - name: app\n          mountPath: /app\n",
			},
			want: loads,
		},
		{
			name: "a manifest template that does not parse withholds",
			files: map[string]string{
				"chart/templates/deploy.yaml": "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - image: {{ .Values.image }}\n          command: {{ .Values.cmd | toJson }}\n          {{- if .Values.x }}\n  bad: [\n",
			},
			want: withhold,
			gap:  "manifest not parsed",
		},
		{
			name:  "a systemd unit running a script outside the build dir withholds",
			files: map[string]string{"app.service": "[Service]\nExecStart=/srv/app/start.sh\n"},
			want:  withhold,
			gap:   "which is not in the build dir",
		},
		{
			name:  "a render.yaml start command is a launch command",
			files: map[string]string{"render.yaml": "services:\n  - type: web\n    name: web\n    startCommand: npm run serve\n"},
			want:  loads,
		},
		{
			name: "a fly.toml process runs in its Dockerfile's image",
			files: map[string]string{
				"Dockerfile": nodeDockerfile + "CMD [\"node\",\"index.js\"]\n",
				"fly.toml":   "app = \"x\"\n[processes]\nweb = \"npm run serve\"\n",
			},
			want: loads,
		},
		{
			name: "a build context only the build scan names withholds a container script",
			files: map[string]string{
				"start.sh":     "#!/bin/sh\nexec node index.js\n",
				"app/start.sh": "#!/bin/sh\nexec node index.js\n",
				"other/x":      "",
				"build.sh":     "docker build -f Dockerfile other\n",
				"Dockerfile":   "FROM node:20\nWORKDIR /app\nCOPY . .\nCMD [\"./start.sh\"]\n",
			},
			want: withhold,
			gap:  "a docker build context (other) the launch reader did not simulate",
		},

		// Launch surfaces the reader does not model withhold on presence.
		{
			name:  "a supervisord config withholds",
			files: map[string]string{"deploy/supervisord.conf": "[program:web]\ncommand=node_modules/.bin/tool serve\n"},
			want:  withhold,
			gap:   "a supervisord config",
		},
		{
			name:  "an ECS task definition withholds",
			files: map[string]string{"taskdef.json": `{"containerDefinitions":[{"name":"web","image":"x","command":["tool","serve"]}]}`},
			want:  withhold,
			gap:   "an ECS task definition",
		},
		{
			name:  "a Terraform ECS task definition withholds",
			files: map[string]string{"infra/main.tf": "resource \"aws_ecs_task_definition\" \"web\" {\n  container_definitions = file(\"defs.json\")\n}\n"},
			want:  withhold,
			gap:   "an ECS task definition",
		},
		{
			name:  "a Nomad job withholds",
			files: map[string]string{"deploy/web.nomad.hcl": "job \"web\" {}\n"},
			want:  withhold,
			gap:   "a Nomad job",
		},
		{
			name:  "a crontab withholds",
			files: map[string]string{"cron.d/app": "* * * * * root /srv/app/node_modules/.bin/tool sweep\n"},
			want:  withhold,
			gap:   "a crontab",
		},
		{
			name:  "an s6 service script withholds",
			files: map[string]string{"rootfs/etc/services.d/web/run": "#!/bin/sh\nexec tool serve\n"},
			want:  withhold,
			gap:   "an s6 or runit service script",
		},
		{
			name:  "a script starting a container with its own command line withholds",
			files: map[string]string{"deploy.sh": "#!/bin/sh\ndocker run -d myorg/app tool serve\n"},
			want:  withhold,
			gap:   "starts a container with a command line",
		},

		// Controls: a clean parse still refutes.
		{
			name:  "control: CMD node index.js refutes",
			files: map[string]string{"Dockerfile": nodeDockerfile + "CMD [\"node\",\"index.js\"]\n"},
			want:  refutes,
		},
		{
			name:  "control: a shell-form CMD with a variable argument refutes",
			files: map[string]string{"Dockerfile": nodeDockerfile + "CMD node index.js --port $PORT\n"},
			want:  refutes,
		},
		{
			name:  "control: an exec-form sh -c with a variable argument refutes",
			files: map[string]string{"Dockerfile": nodeDockerfile + "CMD [\"sh\",\"-c\",\"exec node index.js --port $PORT\"]\n"},
			want:  refutes,
		},
		{
			name: "shell control flow in an entrypoint withholds",
			files: map[string]string{
				"docker/entrypoint.sh": "#!/bin/sh\nset -e\nif [ -n \"$X\" ]; then :; fi\nexec node index.js\n",
				"Dockerfile":           nodeDockerfile + "COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh\nENTRYPOINT [\"entrypoint.sh\"]\n",
			},
			want: withhold,
			gap:  "shell control flow",
		},
		{
			name: "control: a COPY'd entrypoint running node refutes",
			files: map[string]string{
				"docker/entrypoint.sh": "#!/bin/sh\nset -e\nexport NODE_ENV=production\nexec node index.js \"$@\"\n",
				"Dockerfile":           nodeDockerfile + "COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh\nENTRYPOINT [\"entrypoint.sh\"]\nCMD [\"--port\", \"8080\"]\n",
			},
			want: refutes,
		},
		{
			name: "control: compose services on other official images refute",
			files: map[string]string{
				"Dockerfile":         nodeDockerfile + "CMD [\"node\",\"index.js\"]\n",
				"docker-compose.yml": "services:\n  web:\n    build: .\n  db:\n    image: postgres:16\n    command: postgres -c log_statement=all\n",
			},
			want: refutes,
		},
		{
			name: "control: a Kubernetes container on another official image refutes",
			files: map[string]string{
				"k8s.yaml": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: cache\nspec:\n  containers:\n    - name: redis\n      image: redis:7\n      command: [\"redis-server\", \"--save\", \"\"]\n",
			},
			want: refutes,
		},
		{
			name:  "control: a systemd unit running node refutes",
			files: map[string]string{"app.service": "[Service]\nExecStartPre=-/bin/mkdir -p /run/app\nExecStart=/usr/bin/node /srv/app/index.js\n"},
			want:  refutes,
		},
		{
			name:  "control: a Procfile running npm start refutes",
			files: map[string]string{"Procfile": "web: npm start\n", "package.json": `{"name":"app","scripts":{"start":"node index.js","serve":"tool index.js"},"devDependencies":{"tool":"*"}}`},
			want:  refutes,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ls := computeLoadSet(writeTree(t, launchTree(t, tc.files)))
			ref := ls.refute("tool", "2.0.0")
			switch tc.want {
			case loads:
				if !ls.complete || !ls.loaded["node_modules/tool"] {
					t.Fatalf("complete=%v loaded=%v, want tool loaded (gaps %q)", ls.complete, ls.loaded, ls.gaps)
				}
			case refutes:
				if !ls.complete || ref == nil {
					t.Fatalf("complete=%v refute=%+v, want tool refuted (gaps %q, withheld %q)", ls.complete, ref, ls.gaps, ls.noDevOnly)
				}
			case withhold:
				if ls.complete || ref != nil {
					t.Fatalf("complete=%v refute=%+v, want withheld", ls.complete, ref)
				}
				found := false
				for _, g := range ls.gaps {
					found = found || strings.Contains(g, tc.gap)
				}
				if !found {
					t.Fatalf("gaps %q lack %q", ls.gaps, tc.gap)
				}
			}
		})
	}
}
