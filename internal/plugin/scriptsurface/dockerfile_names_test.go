package scriptsurface

import (
	"strings"
	"testing"
)

// Dockerfile or Containerfile with anything joined by ".", "-" or "_" on either side is
// read as a Dockerfile, so an install in Dockerfile-prod withholds as one in Dockerfile.prod does.
func TestVeto_DockerfileNames(t *testing.T) {
	const install = "FROM base\nWORKDIR /app\nCOPY inst.toml inst.lock reqs.txt ./\nRUN tool rewrite\nRUN inst sync\n"
	tests := []struct {
		name string
		want bool
	}{
		{"Dockerfile", true},
		{"Containerfile", true},
		{"Dockerfile.prod", true},
		{"Dockerfile-prod", true},
		{"Dockerfile_api", true},
		{"dockerfile-dev", true},
		{"Containerfile-dev", true},
		{"Containerfile_api", true},
		{"api.Dockerfile", true},
		{"api-Dockerfile", true},
		{"api_Dockerfile", true},
		{"api-Containerfile", true},
		{"docker/Dockerfile-prod", true},

		// Guards: the name is what makes it one.
		{"notes.txt", false},
		{"Dockerfiles", false},
		{"myDockerfile", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n", "reqs.txt": "x==1\n", tt.name: install})
			if got := withheld(dir, testSpec); got != tt.want {
				t.Fatalf("withheld = %v, want %v", got, tt.want)
			}
		})
	}
}

// A file whose extension or path names another kind is read as that kind, not as a
// Dockerfile, so an install on a line of its own still withholds.
func TestVeto_DockerfileNamedOtherKinds(t *testing.T) {
	tests := []struct{ name, body string }{
		{"dockerfile-build", "#!/bin/sh\ninst add evil\n"},
		{"dockerfile-build.sh", "inst add evil\n"},
		{"Dockerfile_lint.sh", "inst add evil\n"},
		{"Dockerfile.sh", "inst add evil\n"},
		{"dockerfile_tasks.mk", "all:\n\tinst add evil\n"},
		{"dockerfile-build.ps1", "inst add evil\n"},
		{".github/workflows/dockerfile-lint.yml", "jobs:\n  b:\n    steps:\n      - run: |\n          inst add evil\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n", tt.name: tt.body})
			if !withheld(dir, testSpec) {
				t.Fatal("withheld = false, want true")
			}
		})
	}
}

// A file read as a Dockerfile may be a script another one sources; an install on a line
// of its own still withholds.
func TestVeto_DockerfileNamedSourced(t *testing.T) {
	for _, src := range []string{". ./dockerfile_env", "source ./dockerfile-common"} {
		t.Run(src, func(t *testing.T) {
			name := strings.Fields(src)[1][2:]
			dir := writeTree(t, map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n",
				"build.sh": "#!/bin/sh\n" + src + "\n", name: "inst add evil\n"})
			if !withheld(dir, testSpec) {
				t.Fatal("withheld = false, want true")
			}
		})
	}
}

func TestSurfaceOf_DockerfileNamedOtherKinds(t *testing.T) {
	tests := []struct {
		path, head string
		want       string
	}{
		{"Dockerfile-prod", "FROM base\n", kindDockerfile},
		{"dockerfile-build", "#!/bin/sh\n", kindShell},
		{"dockerfile-build.sh", "", kindShell},
		{"dockerfile_tasks.mk", "", kindMakefile},
		{"dockerfile-build.ps1", "", kindOpaque},
		{"Procfile.dockerfile", "", kindData},
		{"docker-compose.dockerfile.yml", "", kindData},
		{".github/workflows/dockerfile-lint.yml", "", kindData},
		{"Jenkinsfile.dockerfile", "", kindData},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, ok := surfaceOf(tt.path, []byte(tt.head))
			if !ok || got.kind != tt.want {
				t.Fatalf("surfaceOf = %v, %v; want kind %v", got, ok, tt.want)
			}
		})
	}
}
