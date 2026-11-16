package buildgraph

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWrapperGradleVersion(t *testing.T) {
	tests := []struct {
		name, props          string
		wantMajor, wantMinor int
		wantOK               bool
	}{
		{"bin patch", `distributionUrl=https\://services.gradle.org/distributions/gradle-7.3.1-bin.zip`, 7, 3, true},
		{"all minor", "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.5-all.zip\n", 8, 5, true},
		{"milestone", `distributionUrl=https\://services.gradle.org/distributions/gradle-9.1.0-rc-1-bin.zip`, 9, 1, true},
		{"spaced key", "distributionBase=GRADLE_USER_HOME\n distributionUrl = https\\://x/gradle-7.6.4-bin.zip", 7, 6, true},
		{"mirror without version", `distributionUrl=https\://mirror.example/gradle-dist.zip`, 0, 0, false},
		{"no url", "distributionBase=GRADLE_USER_HOME", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, filepath.Join(dir, "gradle", "wrapper", "gradle-wrapper.properties"), tt.props)
			major, minor, ok := wrapperGradleVersion(dir)
			if major != tt.wantMajor || minor != tt.wantMinor || ok != tt.wantOK {
				t.Fatalf("got %d.%d ok=%v, want %d.%d ok=%v", major, minor, ok, tt.wantMajor, tt.wantMinor, tt.wantOK)
			}
		})
	}
	if _, _, ok := wrapperGradleVersion(t.TempDir()); ok {
		t.Fatal("a checkout without wrapper properties read a version")
	}
}

func TestMaxGradleJDK(t *testing.T) {
	tests := []struct{ major, minor, want int }{
		{6, 9, 0}, {7, 2, 0}, {7, 3, 17}, {7, 4, 17}, {7, 5, 18}, {7, 6, 19}, {8, 2, 19}, {8, 3, 20},
		{8, 5, 21}, {8, 7, 21}, {8, 8, 22}, {8, 10, 23}, {8, 14, 24}, {9, 0, 24}, {9, 1, 0}, {10, 0, 0},
	}
	for _, tt := range tests {
		if got := maxGradleJDK(tt.major, tt.minor); got != tt.want {
			t.Errorf("maxGradleJDK(%d.%d) = %d, want %d", tt.major, tt.minor, got, tt.want)
		}
	}
}

func TestGradleJDK(t *testing.T) {
	root := t.TempDir()
	gradle := func(version string) string {
		dir := t.TempDir()
		writeTestFile(t, filepath.Join(dir, "gradle", "wrapper", "gradle-wrapper.properties"),
			`distributionUrl=https\://services.gradle.org/distributions/gradle-`+version+`-bin.zip`)
		return dir
	}
	jdk := func(name, version string) string {
		home := filepath.Join(root, name)
		writeTestFile(t, filepath.Join(home, "release"), "IMPLEMENTOR=\"Eclipse Adoptium\"\nJAVA_VERSION=\""+version+"\"\n")
		writeTestFile(t, filepath.Join(home, "bin", "java"), "")
		return home
	}
	j26, j25, j21, j17, j11, j8 := jdk("26", "26.0.1"), jdk("25", "25.0.1"), jdk("21", "21.0.12"), jdk("17", "17.0.20.1"), jdk("11", "11.0.25"), jdk("8", "1.8.0_432")
	liar := jdk("liar", "21.0.12") // a JAVA_HOME_17_X64 that holds a JDK 21
	j17arm := jdk("17arm", "17.0.20.1")
	noLauncher := filepath.Join(root, "nolauncher")
	writeTestFile(t, filepath.Join(noLauncher, "release"), `JAVA_VERSION="17.0.20.1"`)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relJ17, err := filepath.Rel(wd, j17) // names the JDK 17 from the producer's directory only
	if err != nil {
		t.Fatal(err)
	}
	pinned := gradle("7.3.1")
	writeTestFile(t, filepath.Join(pinned, "gradle.properties"), "org.gradle.java.home="+j21+"\n")

	runner := []string{"JAVA_HOME=" + j21, "PATH=/usr/bin", "JAVA_HOME_8_X64=" + j8, "JAVA_HOME_11_X64=" + j11, "JAVA_HOME_17_X64=" + j17, "JAVA_HOME_21_X64=" + j21}

	tests := []struct {
		name         string
		dir          string
		env          []string
		c            Conditions
		wantHome     string // "" means env unchanged
		wantProvided string
	}{
		{name: "gradle 7.3 on 21 runs on the newest provided JDK in range", dir: gradle("7.3.1"), env: runner, wantHome: j17, wantProvided: "JAVA_HOME_17_X64"},
		{name: "gradle 7.0 predates the matrix", dir: gradle("7.0.2"), env: runner},
		{name: "gradle 8.5 runs on 21", dir: gradle("8.5"), env: runner},
		{name: "a stated JDK is never replaced", dir: gradle("7.3.1"), env: runner, c: Conditions{JDK: "21.0.12"}},
		{name: "a stated JAVA_HOME is never replaced", dir: gradle("7.3.1"), env: runner, c: Conditions{Env: map[string]string{"JAVA_HOME": j21}}},
		{name: "no provided JDK in range", dir: gradle("7.3.1"), env: []string{"JAVA_HOME=" + j21, "PATH=/usr/bin", "JAVA_HOME_21_X64=" + j21}},
		{name: "a provided variable naming another JDK is skipped", dir: gradle("7.3.1"), env: []string{"JAVA_HOME=" + j21, "PATH=/usr/bin", "JAVA_HOME_17_X64=" + liar, "JAVA_HOME_11_X64=" + j11}, wantHome: j11, wantProvided: "JAVA_HOME_11_X64"},
		{name: "unreadable job JDK", dir: gradle("7.3.1"), env: []string{"JAVA_HOME=" + filepath.Join(root, "missing"), "PATH=/usr/bin", "JAVA_HOME_17_X64=" + j17}},
		{name: "no wrapper properties", dir: t.TempDir(), env: runner},
		{name: "a stated empty JAVA_HOME is never replaced", dir: gradle("7.3.1"), env: runner, c: Conditions{Env: map[string]string{"JAVA_HOME": ""}}},
		{name: "a stated PATH is never replaced", dir: gradle("7.3.1"), env: runner, c: Conditions{Env: map[string]string{"PATH": "/usr/bin"}}},
		{name: "the build names its Gradle JVM in gradle.properties", dir: pinned, env: runner},
		{name: "the job names its Gradle JVM in GRADLE_OPTS", dir: gradle("7.3.1"), env: append([]string{"GRADLE_OPTS=-Dorg.gradle.java.home=" + j21}, runner...)},
		{name: "gradle 9.1 on a newer JDK than the matrix lists", dir: gradle("9.1.0"), env: []string{"JAVA_HOME=" + j26, "PATH=/usr/bin", "JAVA_HOME_25_X64=" + j25}},
		{name: "gradle 9.0 never runs on a JDK below 17", dir: gradle("9.0.0"), env: []string{"JAVA_HOME=" + j25, "PATH=/usr/bin", "JAVA_HOME_11_X64=" + j11}},
		{name: "a relative provided JDK is skipped", dir: gradle("7.3.1"), env: []string{"JAVA_HOME=" + j21, "PATH=/usr/bin", "JAVA_HOME_17_X64=" + relJ17}},
		{name: "a provided JDK without a launcher is skipped", dir: gradle("7.3.1"), env: []string{"JAVA_HOME=" + j21, "PATH=/usr/bin", "JAVA_HOME_17_X64=" + noLauncher, "JAVA_HOME_11_X64=" + j11}, wantHome: j11, wantProvided: "JAVA_HOME_11_X64"},
		{name: "equal features tie by variable name", dir: gradle("7.3.1"), env: []string{"JAVA_HOME=" + j21, "PATH=/usr/bin", "JAVA_HOME_17_X64=" + j17, "JAVA_HOME_17_ARM64=" + j17arm}, wantHome: j17arm, wantProvided: "JAVA_HOME_17_ARM64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, provided := gradleJDK(tt.dir, tt.env, tt.c)
			if provided != tt.wantProvided {
				t.Fatalf("provided = %q, want %q", provided, tt.wantProvided)
			}
			if tt.wantHome == "" {
				if strings.Join(got, "\n") != strings.Join(tt.env, "\n") {
					t.Fatalf("env changed:\n%v", got)
				}
				return
			}
			if h := envValue(got, "JAVA_HOME"); h != tt.wantHome {
				t.Fatalf("JAVA_HOME = %q, want %q", h, tt.wantHome)
			}
			if p := envValue(got, "PATH"); !strings.HasPrefix(p, filepath.Join(tt.wantHome, "bin")+string(os.PathListSeparator)) {
				t.Fatalf("PATH = %q, want the selected JDK's bin first", p)
			}
		})
	}
}

func TestGradleJDKFromJavaOnPath(t *testing.T) {
	root := t.TempDir()
	j21 := filepath.Join(root, "21")
	writeTestFile(t, filepath.Join(j21, "release"), `JAVA_VERSION="21.0.12"`)
	java := filepath.Join(j21, "bin", "java")
	writeTestFile(t, java, "#!/bin/sh\n")
	if err := os.Chmod(java, 0o755); err != nil {
		t.Fatal(err)
	}
	j17 := filepath.Join(root, "17")
	writeTestFile(t, filepath.Join(j17, "release"), `JAVA_VERSION="17.0.20"`)
	writeTestFile(t, filepath.Join(j17, "bin", "java"), "")
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "gradle", "wrapper", "gradle-wrapper.properties"), `distributionUrl=https\://x/gradle-7.3.1-bin.zip`)

	got, provided := gradleJDK(dir, []string{"PATH=" + filepath.Join(j21, "bin"), "JAVA_HOME_17_AARCH64=" + j17}, Conditions{})
	if provided != "JAVA_HOME_17_AARCH64" || envValue(got, "JAVA_HOME") != j17 {
		t.Fatalf("provided %q, JAVA_HOME %q; want the JDK 17 for a job whose java on PATH is 21", provided, envValue(got, "JAVA_HOME"))
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestResolveRunsOldWrapperOnProvidedJDK: Resolve runs a wrapper whose Gradle predates the job's
// JDK on the provided JDK, records it in the graph, and leaves a Gradle on PATH alone.
func TestResolveRunsOldWrapperOnProvidedJDK(t *testing.T) {
	root := t.TempDir()
	jdk := func(name, version string) string {
		home := filepath.Join(root, name)
		writeTestFile(t, filepath.Join(home, "release"), `JAVA_VERSION="`+version+`"`)
		writeTestFile(t, filepath.Join(home, "bin", "java"), "")
		return home
	}
	j21, j17 := jdk("21", "21.0.12"), jdk("17", "17.0.20.1")
	const seen = "java_home.seen"

	tests := []struct {
		name         string
		onPath       bool
		wantHome     string
		wantProvided string
	}{
		{name: "wrapper", wantHome: j17, wantProvided: "JAVA_HOME_17_X64"},
		{name: "gradle on PATH", onPath: true, wantHome: j21},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newFakeGradle(t, "", nil)
			record := strings.Replace(fakeGradle, "#!/bin/sh\n", "#!/bin/sh\necho \"$JAVA_HOME\" > \"$FAKE_DIR/"+seen+"\"\n", 1)
			writeFiles(t, r.dir, map[string]string{
				"gradle/wrapper/gradle-wrapper.properties": `distributionUrl=https\://services.gradle.org/distributions/gradle-7.3.1-bin.zip`,
				"gradlew": record,
			})
			r.env = append(r.env, "JAVA_HOME="+j21, "JAVA_HOME_17_X64="+j17)
			if tt.onPath {
				if err := os.Remove(filepath.Join(r.dir, "gradlew")); err != nil {
					t.Fatal(err)
				}
				bin := filepath.Join(root, tt.name, "bin")
				writeTestFile(t, filepath.Join(bin, "gradle"), record)
				if err := os.Chmod(filepath.Join(bin, "gradle"), 0o755); err != nil {
					t.Fatal(err)
				}
				r.env = append(r.env, "PATH="+bin+string(os.PathListSeparator)+"/usr/bin:/bin")
			}
			g, err := r.resolve(t, ToolGradle, Conditions{})
			if err != nil {
				t.Fatalf("resolve: %v", cause(err))
			}
			b, err := os.ReadFile(filepath.Join(r.fake, seen))
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.TrimSpace(string(b)); got != tt.wantHome {
				t.Errorf("Gradle ran with JAVA_HOME %q, want %q", got, tt.wantHome)
			}
			if g.JVM.Provided != tt.wantProvided {
				t.Errorf("jvm.provided %q, want %q", g.JVM.Provided, tt.wantProvided)
			}
			file := filepath.Join(t.TempDir(), "graph.json")
			data, err := json.Marshal(g)
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, file, string(data))
			back, err := Decode(file)
			if err != nil {
				t.Fatal(err)
			}
			if back.JVM.Provided != tt.wantProvided {
				t.Errorf("decoded jvm.provided %q, want %q", back.JVM.Provided, tt.wantProvided)
			}
		})
	}
}
