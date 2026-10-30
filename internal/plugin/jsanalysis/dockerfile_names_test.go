package jsanalysis

import "testing"

// An install in a Dockerfile under a dashed or underscored name may put a package no lock
// read here names into the build, as one in Dockerfile.prod does, so it withholds Exhaustive.
func TestResolveVersions_DockerfileNames(t *testing.T) {
	const run = "FROM node:20\nWORKDIR /app\nCOPY package.json package-lock.json ./\nRUN npm ci && npm install absent-package\n"
	for _, name := range []string{"Dockerfile.prod", "Dockerfile-prod", "Dockerfile_api", "Containerfile-dev", "api-Dockerfile", "docker/Dockerfile_api"} {
		t.Run(name, func(t *testing.T) {
			r := resolveJS(t, writeLockTree(t, map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, name: run}), "absent-package")
			if r.Found || r.Exhaustive {
				t.Fatalf("absent-package = found %v exhaustive %v, want absent and not exhaustive", r.Found, r.Exhaustive)
			}
		})
	}
	// Control: the same install under a name that is not a Dockerfile's is not read as one.
	r := resolveJS(t, writeLockTree(t, map[string]string{"package.json": exPkgJSON, "package-lock.json": exLockV3, "notes.txt": run}), "absent-package")
	if r.Found || !r.Exhaustive {
		t.Fatalf("absent-package = found %v exhaustive %v, want absent and exhaustive", r.Found, r.Exhaustive)
	}
}
