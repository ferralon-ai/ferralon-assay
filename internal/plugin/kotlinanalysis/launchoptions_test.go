package kotlinanalysis

import (
	"archive/zip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis"
)

// TestReachability_LaunchOptions: a JVM launch option the lane does not model can run code no
// call graph shows before main (a system class loader, a security manager, a logging config
// class, an agent), so any such option on any launch surface the checkout carries withholds
// Searched, as does a surface whose options cannot be read. Allowlisted options leave the
// sink Searched. Every row's main is empty and never calls the sink.
func TestReachability_LaunchOptions(t *testing.T) {
	agent, option := javaanalysis.PartialReasonLaunchAgent, javaanalysis.PartialReasonLaunchOption
	inventory := func(files map[string]string) func(t *testing.T) string {
		return func(t *testing.T) string {
			dir := gradleJacksonBuild(t, "")
			writeMain(t, dir, func(b *kclassBuilder) []byte { return nil })
			for rel, content := range files {
				p := filepath.Join(dir, filepath.FromSlash(rel))
				writeFileAt(t, filepath.Dir(p), filepath.Base(p), content)
			}
			return dir
		}
	}
	appendBuild := func(extra string) func(t *testing.T) string {
		return func(t *testing.T) string {
			dir := inventory(nil)(t)
			p := filepath.Join(dir, "build.gradle.kts")
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, append(data, []byte(extra)...), 0o644); err != nil {
				t.Fatal(err)
			}
			return dir
		}
	}
	tests := []struct {
		name   string
		setup  func(t *testing.T) string
		reason string // "" when the row stays Searched
	}{
		{"start script: -Djava.system.class.loader", func(t *testing.T) string {
			return jvmOptsBuild(t, `'"-Djava.system.class.loader=org.d.D"'`)
		}, option},
		{"start script: -Djava.security.manager", func(t *testing.T) string {
			return jvmOptsBuild(t, `'"-Djava.security.manager=org.d.D"'`)
		}, option},
		{"start script: -Djava.util.logging.config.class", func(t *testing.T) string {
			return jvmOptsBuild(t, `'"-Djava.util.logging.config.class=org.d.D"'`)
		}, option},
		{"start script: allowlisted -Dfile.encoding stays searched", func(t *testing.T) string {
			return jvmOptsBuild(t, `'"-Dfile.encoding=UTF-8"'`)
		}, ""},
		{"start script: -Dfile.encoding with a provider charset", func(t *testing.T) string {
			return jvmOptsBuild(t, `'"-Dfile.encoding=x-custom"'`)
		}, option},
		{".bat start script", func(t *testing.T) string {
			dir := jvmOptsBuild(t, `''`)
			writeFileAt(t, filepath.Join(dir, "build", "scripts"), "app.bat", "@rem\r\nset DEFAULT_JVM_OPTS=\"-Djava.system.class.loader=org.d.D\"\r\n")
			return dir
		}, option},
		{"applicationDefaultJvmArgs", appendBuild("\napplication {\n    applicationDefaultJvmArgs = listOf(\"-Xmx64m\", \"-Djava.security.manager=org.d.D\")\n}\n"), option},
		{"applicationDefaultJvmArgs, allowlisted: searched", appendBuild("\napplication {\n    applicationDefaultJvmArgs = listOf(\"-Xmx64m\", \"-Dfile.encoding=UTF-8\")\n}\n"), ""},
		{"applicationDefaultJvmArgs unparseable", appendBuild("\napplication {\n    applicationDefaultJvmArgs = jvmArgsFrom(project)\n}\n"), option},
		{"Dockerfile ENV JAVA_TOOL_OPTIONS", inventory(map[string]string{
			"Dockerfile": "FROM eclipse-temurin:21\nENV JAVA_TOOL_OPTIONS=\"-Djava.util.logging.config.class=org.d.D\"\nENTRYPOINT [\"/app/bin/app\"]\n",
		}), option},
		{"Dockerfile ENV allowlisted, entrypoint expands it: searched", inventory(map[string]string{
			"Dockerfile": "FROM eclipse-temurin:21\nENV JAVA_OPTS=\"-XX:MaxRAMPercentage=75 -Dfile.encoding=UTF-8\"\nENTRYPOINT exec java $JAVA_OPTS -jar /app.jar\n",
		}), ""},
		{"Dockerfile ENTRYPOINT java option", inventory(map[string]string{
			"docker/Dockerfile": "FROM eclipse-temurin:21\nENTRYPOINT [\"java\", \"-Djava.system.class.loader=org.d.D\", \"-jar\", \"/app.jar\"]\n",
		}), option},
		{"Dockerfile ENTRYPOINT @argfile", inventory(map[string]string{
			"Dockerfile": "FROM eclipse-temurin:21\nENTRYPOINT [\"java\", \"@/app/jvm.args\", \"-jar\", \"/app.jar\"]\n",
		}), option},
		{"Dockerfile ENTRYPOINT javaagent", inventory(map[string]string{
			"Dockerfile": "FROM eclipse-temurin:21\nENTRYPOINT [\"java\", \"-javaagent:/otel.jar\", \"-jar\", \"/app.jar\"]\n",
		}), agent},
		{"Procfile", inventory(map[string]string{
			"Procfile": "web: java -Djava.security.manager=org.d.D -jar build/libs/app.jar\n",
		}), option},
		{"deploy manifest env", inventory(map[string]string{
			"k8s/deployment.yaml": "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n        - name: app\n          env:\n            - name: JDK_JAVA_OPTIONS\n              value: \"-Djava.system.class.loader=org.d.D\"\n",
		}), option},
		{"deploy manifest env from a secret: unparseable", inventory(map[string]string{
			"k8s/deployment.yaml": "spec:\n  containers:\n    - name: app\n      env:\n        - name: JAVA_OPTS\n          valueFrom:\n            secretKeyRef: {name: s, key: k}\n",
		}), option},
		{"deploy manifest env allowlisted: searched", inventory(map[string]string{
			"manifest.yml": "applications:\n  - name: app\n    env:\n      JAVA_OPTS: \"-Xmx512m -Djava.awt.headless=true\"\n",
		}), ""},
		{"MANIFEST Launcher-Agent-Class", func(t *testing.T) string {
			dir := inventory(nil)(t)
			p := filepath.Join(dir, "build", "libs", "app.jar")
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			f, err := os.Create(p)
			if err != nil {
				t.Fatal(err)
			}
			zw := zip.NewWriter(f)
			w, err := zw.Create("META-INF/MANIFEST.MF")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write([]byte("Manifest-Version: 1.0\r\nLauncher-Agent-Class: org.d.Agent\r\n")); err != nil {
				t.Fatal(err)
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			return dir
		}, agent},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.setup(t)
			res := reach(t, dir, readValueSink)
			if tt.reason == "" {
				if !reflect.DeepEqual(res.Searched, []string{readValueSink}) {
					t.Fatalf("Searched = %v, want the sink searched (%+v)", res.Searched, res.Partiality)
				}
				return
			}
			if len(res.Searched) > 0 {
				t.Errorf("Searched = %v under an unmodeled launch option", res.Searched)
			}
			if !hasReason(res.Partiality, tt.reason) {
				t.Errorf("reasons %v must carry %q", res.Partiality.Reasons, tt.reason)
			}
		})
	}
}
