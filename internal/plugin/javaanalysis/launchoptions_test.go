package javaanalysis

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestClassifyLaunchOption(t *testing.T) {
	tests := []struct {
		opt  string
		want optionClass
	}{
		{"-Xmx512m", optionInert},
		{"-XX:+UseG1GC", optionInert},
		{"-XX:MaxRAMPercentage=75.0", optionInert},
		{"-XX:OnOutOfMemoryError=kill -9 %p", optionUnmodeled},
		{"-XX:+UnlockDiagnosticVMOptions", optionUnmodeled},
		{"-Duser.timezone=UTC", optionInert},
		{"-Duser.=x", optionUnmodeled},
		{"-Djava.security.egd=file:/dev/./urandom", optionInert},
		{"-Dfile.encoding=utf-8", optionInert},
		{"-Dfile.encoding=Cp1252", optionUnmodeled},
		{"-Dspring.profiles.active=prod", optionUnmodeled},
		{"-Djava.system.class.loader=org.d.D", optionUnmodeled},
		{"-javaagent:/otel.jar", optionAgent},
		{"-agentlib:jdwp=transport=dt_socket", optionAgent},
		{"-Xbootclasspath/a:/boot.jar", optionAgent},
		{"--module-path", optionUnmodeled},
		{"--patch-module", optionUnmodeled},
		{"-cp", optionTakesValue},
		{"--add-opens", optionTakesValue},
		{"--add-opens=java.base/java.lang=ALL-UNNAMED", optionInert},
		{"-ea", optionInert},
		{"-showversion", optionUnmodeled},
	}
	for _, tt := range tests {
		if got := classifyLaunchOption(tt.opt); got != tt.want {
			t.Errorf("classifyLaunchOption(%q) = %v, want %v", tt.opt, got, tt.want)
		}
	}
}

func TestLaunchOptionReasons(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"no surfaces", nil, []string{}},
		{"gradle default start script", map[string]string{"build/scripts/app": "DEFAULT_JVM_OPTS=''\n"}, []string{}},
		{"start script option with a variable value", map[string]string{"build/install/app/bin/app": `DEFAULT_JVM_OPTS='"-Dapp.home=$APP_HOME"'` + "\n"}, []string{PartialReasonLaunchOption}},
		{"start script variable option", map[string]string{"build/scripts/app": `DEFAULT_JVM_OPTS='"$EXTRA"'` + "\n"}, []string{PartialReasonLaunchOption}},
		{"start script agent with a variable path", map[string]string{"build/scripts/app": `DEFAULT_JVM_OPTS='"-javaagent:$APP_HOME/lib/otel.jar"'` + "\n"}, []string{PartialReasonLaunchAgent}},
		{"applicationDefaultJvmArgs from a variable", map[string]string{"build.gradle.kts": "application {\n    applicationDefaultJvmArgs = listOf(jvmFlag)\n}\n"}, []string{PartialReasonLaunchOption}},
		{"procfile java command", map[string]string{"Procfile": "web: java -Djava.system.class.loader=org.d.D -jar build/libs/app.jar\n"}, []string{PartialReasonLaunchOption}},
		{"groovy applicationDefaultJvmArgs", map[string]string{"build.gradle": "applicationDefaultJvmArgs = ['-Xmx1g', '-Djava.awt.headless=true']\n"}, []string{}},
		{"applicationDefaultJvmArgs mutated", map[string]string{"build.gradle.kts": "application { applicationDefaultJvmArgs.add(\"-Xmx1g\") }\n"}, []string{PartialReasonLaunchOption}},
		{"dockerfile legacy ENV form", map[string]string{"Dockerfile": "ENV JAVA_OPTS -Xmx1g -Dlogback.configurationFile=/x.xml\n"}, []string{PartialReasonLaunchOption}},
		{"dockerfile ARG expanded by the entrypoint", map[string]string{"Dockerfile": "ARG EXTRA=-Djava.security.manager=org.d.D\nENTRYPOINT java $EXTRA -jar /app.jar\n"}, []string{PartialReasonLaunchOption}},
		{"dockerfile unset variable is deploy-time residue", map[string]string{"Dockerfile": "ENTRYPOINT java ${JAVA_OPTS} -jar /app.jar\n"}, []string{}},
		{"dockerfile sh -c form", map[string]string{"Containerfile": `CMD ["sh", "-c", "java -Djava.system.class.loader=org.d.D -jar /app.jar"]` + "\n"}, []string{PartialReasonLaunchOption}},
		{"dockerfile program arguments after the jar are not options", map[string]string{"Dockerfile": `ENTRYPOINT ["java", "-jar", "/app.jar", "--spring.profiles.active=prod"]` + "\n"}, []string{}},
		{"dockerfile build-tool options are not the program's", map[string]string{"Dockerfile": "ENV GRADLE_OPTS=-Dorg.gradle.daemon=false\n"}, []string{}},
		{"compose environment list", map[string]string{"docker-compose.yml": "services:\n  app:\n    environment:\n      - JAVA_TOOL_OPTIONS=-javaagent:/otel.jar\n"}, []string{PartialReasonLaunchAgent}},
		{"yaml java command list", map[string]string{"deploy/app.yaml": "spec:\n  command: [\"java\", \"-Djava.system.class.loader=org.d.D\", \"-jar\", \"/app.jar\"]\n"}, []string{PartialReasonLaunchOption}},
		{"yaml block it cannot attach", map[string]string{"deploy/app.yaml": "notes: |\n  set JAVA_OPTS before launch\n"}, []string{PartialReasonLaunchOption}},
		{"CI workflows are skipped", map[string]string{".github/workflows/ci.yml": "env:\n  JAVA_TOOL_OPTIONS: -Djava.security.manager=allow\n"}, []string{}},
		{"module access option takes a value", map[string]string{"Dockerfile": `ENV JAVA_OPTS="--add-opens java.base/java.lang=ALL-UNNAMED -Xss1m"` + "\n"}, []string{}},
		{"dockerfile main class ends the options", map[string]string{"Dockerfile": `ENTRYPOINT ["java", "-cp", "/app/lib/*", "com.example.MainKt", "--spring.profiles.active=prod"]` + "\n"}, []string{}},
		{"dockerfile value option skips its value", map[string]string{"Dockerfile": `ENTRYPOINT ["java", "--add-opens", "java.base/java.lang=ALL-UNNAMED", "-Dlogback.configurationFile=/x.xml", "-jar", "/app.jar"]` + "\n"}, []string{PartialReasonLaunchOption}},
		{"kubernetes env allowlisted", map[string]string{"k8s/deploy.yaml": "spec:\n  containers:\n    - name: app\n      env:\n        - name: JAVA_TOOL_OPTIONS\n          value: \"-XX:MaxRAMPercentage=75\"\n"}, []string{}},
		{"unreadable project jar", map[string]string{"build/libs/app.jar": "not a zip"}, []string{PartialReasonLaunchOption}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, content := range tt.files {
				p := filepath.Join(dir, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := LaunchOptionReasons(dir); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LaunchOptionReasons = %v, want %v", got, tt.want)
			}
		})
	}
}
