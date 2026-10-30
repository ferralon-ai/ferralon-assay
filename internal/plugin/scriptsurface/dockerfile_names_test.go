package scriptsurface

import "testing"

// A Dockerfile is read as one whatever word it is joined to, by ".", "-" or "_", on either
// side, so an install in Dockerfile-prod withholds as one in Dockerfile.prod does.
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
		{"dockerfile-build.sh", "#!/bin/sh\ninst add evil\n"},
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
