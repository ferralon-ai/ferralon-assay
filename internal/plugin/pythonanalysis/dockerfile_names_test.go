package pythonanalysis

import "testing"

// An install in a Dockerfile under a dashed or underscored name may put a package no lock
// read here names into the build, as one in Dockerfile.prod does, so it withholds Exhaustive
// and every pin.
func TestResolveVersions_DockerfileNames(t *testing.T) {
	const run = "FROM python:3.12\nRUN pip install PyJWT==2.8.0\n"
	for _, name := range []string{"Dockerfile.prod", "Dockerfile-prod", "Dockerfile_api", "Containerfile-dev", "api-Dockerfile", "docker/Dockerfile_api"} {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"pyproject.toml": exPyproject, "uv.lock": exUVLock, name: run})
			if r := resolveVersion(t, dir, "PyJWT"); r.Found || r.Exhaustive {
				t.Fatalf("PyJWT = found %v exhaustive %v, want absent and not exhaustive", r.Found, r.Exhaustive)
			}
			dir = writeTree(t, map[string]string{"requirements.txt": "jinja2==3.1.4\n", name: run})
			if r := resolveVersion(t, dir, "jinja2"); !r.Found || r.Match.Resolved {
				t.Fatalf("jinja2 = %+v, want found and unresolved", r.Match)
			}
		})
	}
	// Control: the same install under a name that is not a Dockerfile's is not read as one.
	dir := writeTree(t, map[string]string{"pyproject.toml": exPyproject, "uv.lock": exUVLock, "notes.txt": run})
	if r := resolveVersion(t, dir, "PyJWT"); r.Found || !r.Exhaustive {
		t.Fatalf("PyJWT = found %v exhaustive %v, want absent and exhaustive", r.Found, r.Exhaustive)
	}
}
