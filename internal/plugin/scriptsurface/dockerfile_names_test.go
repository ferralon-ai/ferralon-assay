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
