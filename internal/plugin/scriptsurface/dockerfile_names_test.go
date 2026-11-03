package scriptsurface

import "testing"

// Dockerfile or Containerfile with anything joined by ".", "-" or "_" on either side is
// read as a Dockerfile, unless surfaceOf reads it as another kind, so an install in
// Dockerfile-prod withholds as one in Dockerfile.prod does.
func TestVeto_DockerfileNames(t *testing.T) {
	const install = "FROM base\nWORKDIR /app\nCOPY inst.toml inst.lock reqs.txt ./\nRUN tool rewrite\nRUN inst sync\n"
	tests := []struct {
		name     string
		want     bool
		backstop bool // withheld by the backstop, which names the line, not by a surface rule
	}{
		{"Dockerfile", true, false},
		{"Containerfile", true, false},
		{"Dockerfile.prod", true, false},
		{"Dockerfile-prod", true, false},
		{"Dockerfile_api", true, false},
		{"dockerfile-dev", true, false},
		{"Containerfile-dev", true, false},
		{"Containerfile_api", true, false},
		{"api.Dockerfile", true, false},
		{"api-Dockerfile", true, false},
		{"api_Dockerfile", true, false},
		{"api-Containerfile", true, false},
		{"docker/Dockerfile-prod", true, false},

		// Guards: the name is what makes it one. Dockerfiles and myDockerfile are no surface,
		// but their content is Dockerfile-like, so the backstop withholds on them and names
		// the line; a surface withholds by its own rule and the backstop names nothing.
		{"notes.txt", false, false},
		{"Dockerfiles", true, true},
		{"myDockerfile", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n", "reqs.txt": "x==1\n", tt.name: install})
			got, at := backstopped(dir)
			if got != tt.want {
				t.Fatalf("withheld = %v, want %v", got, tt.want)
			}
			if tt.backstop != (at != "") {
				t.Fatalf("Unrecognised() = %q, want a backstop line %v", at, tt.backstop)
			}
		})
	}
}

// A file whose extension, shebang or path names another kind is read as that kind, not as a
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

// A file read as a Dockerfile by name may be a script, such as one another sources; an
// install on a line of its own still withholds.
func TestVeto_DockerfileNamedScript(t *testing.T) {
	for _, name := range []string{"dockerfile_env", "dockerfile-common"} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"inst.toml": "[deps]\n", "inst.lock": "lock\n", name: "inst add evil\n"})
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
