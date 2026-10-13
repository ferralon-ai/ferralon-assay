package javaanalysis

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
		{"-cp", optionUnmodeled},
		{"-jar", optionUnmodeled},
		{"--class-path", optionUnmodeled},
		{"-Duser.dir=/srv", optionUnmodeled},
		{"-Duser.home=/srv", optionUnmodeled},
		{"-Duser.language=en", optionInert},
		{"-Duser.name=app", optionInert},
		{"-Djava.io.tmpdir=/tmp", optionUnmodeled},
		{"-Djava.library.path=/lib", optionUnmodeled},
		{"-Djava.class.path=/a.jar", optionUnmodeled},
		{"-Xrunjdwp:transport=dt_socket", optionAgent},
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

var (
	agentOnly      = []string{PartialReasonLaunchAgent}
	optionOnly     = []string{PartialReasonLaunchOption}
	agentAndOption = []string{PartialReasonLaunchAgent, PartialReasonLaunchOption}
)

// gradlewExcerpt and gradlewBatExcerpt are the option lines of Gradle 8's wrapper templates.
const gradlewExcerpt = `#   * -classpath
#   * -D...appname settings
#   * --module-path (only if needed)
#   * DEFAULT_JVM_OPTS, JAVA_OPTS, and GRADLE_OPTS environment variables.
DEFAULT_JVM_OPTS='"-Xmx64m" "-Xms64m"'
CLASSPATH=$APP_HOME/gradle/wrapper/gradle-wrapper.jar
set -- \
        "-Dorg.gradle.appname=$APP_BASE_NAME" \
        -classpath "$CLASSPATH" \
        org.gradle.wrapper.GradleWrapperMain \
        "$@"
exec "$JAVACMD" "$@" -jar "$APP_HOME/gradle/wrapper/gradle-wrapper.jar"
`

const gradlewBatExcerpt = "set DEFAULT_JVM_OPTS=\"-Xmx64m\" \"-Xms64m\"\r\n" +
	"\"%JAVA_EXE%\" %DEFAULT_JVM_OPTS% %JAVA_OPTS% %GRADLE_OPTS% \"-Dorg.gradle.appname=%APP_BASE_NAME%\" -classpath \"%CLASSPATH%\" org.gradle.wrapper.GradleWrapperMain %*\r\n"

func manifestJar(manifest string) string {
	return zipOf(map[string]string{"META-INF/MANIFEST.MF": manifest})
}

func zipOf(entries map[string]string) string {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			panic(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.String()
}

func tarOf(entries map[string]string) string {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			panic(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			panic(err)
		}
	}
	if err := tw.Close(); err != nil {
		panic(err)
	}
	return buf.String()
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
		{"dockerfile unset variable is deploy-time residue", map[string]string{"Dockerfile": "ENTRYPOINT java ${JAVA_OPTS} com.example.Main\n"}, []string{}},
		{"dockerfile sh -c form", map[string]string{"Containerfile": `CMD ["sh", "-c", "java -Djava.system.class.loader=org.d.D -jar /app.jar"]` + "\n"}, []string{PartialReasonLaunchOption}},
		{"dockerfile program arguments are not options", map[string]string{"Dockerfile": `ENTRYPOINT ["java", "com.example.Main", "--spring.profiles.active=prod"]` + "\n"}, []string{}},
		{"dockerfile build-tool options are not the program's", map[string]string{"Dockerfile": "ENV GRADLE_OPTS=-Dorg.gradle.daemon=false\n"}, []string{}},
		{"compose environment list", map[string]string{"docker-compose.yml": "services:\n  app:\n    environment:\n      - JAVA_TOOL_OPTIONS=-javaagent:/otel.jar\n"}, []string{PartialReasonLaunchAgent}},
		{"yaml java command list", map[string]string{"deploy/app.yaml": "spec:\n  command: [\"java\", \"-Djava.system.class.loader=org.d.D\", \"-jar\", \"/app.jar\"]\n"}, []string{PartialReasonLaunchOption}},
		{"yaml block it cannot attach", map[string]string{"deploy/app.yaml": "notes: |\n  set JAVA_OPTS before launch\n"}, []string{PartialReasonLaunchOption}},
		{"CI workflows are scanned", map[string]string{".github/workflows/ci.yml": "env:\n  JAVA_TOOL_OPTIONS: -Djava.security.manager=allow\n"}, []string{PartialReasonLaunchOption}},
		{"module access option takes a value", map[string]string{"Dockerfile": `ENV JAVA_OPTS="--add-opens java.base/java.lang=ALL-UNNAMED -Xss1m"` + "\n"}, []string{}},
		{"dockerfile main class ends the options", map[string]string{"Dockerfile": `ENTRYPOINT ["java", "-Xss1m", "com.example.MainKt", "--spring.profiles.active=prod"]` + "\n"}, []string{}},
		{"dockerfile value option skips its value", map[string]string{"Dockerfile": `ENTRYPOINT ["java", "--add-opens", "java.base/java.lang=ALL-UNNAMED", "-Dlogback.configurationFile=/x.xml", "-jar", "/app.jar"]` + "\n"}, []string{PartialReasonLaunchOption}},
		{"kubernetes env allowlisted", map[string]string{"k8s/deploy.yaml": "spec:\n  containers:\n    - name: app\n      env:\n        - name: JAVA_TOOL_OPTIONS\n          value: \"-XX:MaxRAMPercentage=75\"\n"}, []string{}},
		{"unreadable project jar", map[string]string{"build/libs/app.jar": "not a zip"}, []string{PartialReasonLaunchOption}},

		// Every file is scanned; a reader only accounts for an occurrence it can read whole.
		{"entrypoint script", map[string]string{"entrypoint.sh": "#!/bin/sh\nexec java -javaagent:/otel.jar -jar /app.jar\n"}, agentAndOption},
		{"workflow env agent", map[string]string{".github/workflows/deploy.yml": "jobs:\n  deploy:\n    env:\n      JAVA_TOOL_OPTIONS: -javaagent:/otel.jar\n"}, agentOnly},
		{".env file", map[string]string{".env": "JAVA_TOOL_OPTIONS=-javaagent:/otel.jar\n"}, agentOnly},
		{"script export", map[string]string{"scripts/run.sh": "#!/bin/sh\nexport JAVA_TOOL_OPTIONS=\"-javaagent:/otel.jar\"\nexec ./bin/app\n"}, agentOnly},
		{"fly.toml env", map[string]string{"fly.toml": "[env]\n  JAVA_TOOL_OPTIONS = \"-javaagent:/otel.jar\"\n"}, agentOnly},
		{"ECS task definition", map[string]string{"ecs/taskdef.json": `{"containerDefinitions": [{"environment": [{"name": "JAVA_TOOL_OPTIONS", "value": "-javaagent:/otel.jar"}]}]}` + "\n"}, agentOnly},
		{"ECS task definition allowlisted", map[string]string{"ecs/taskdef.json": "{\"containerDefinitions\": [{\"environment\": [\n  {\"name\": \"JAVA_TOOL_OPTIONS\",\n   \"value\": \"-XX:MaxRAMPercentage=75\"}]}]}\n"}, []string{}},
		{"Makefile java line", map[string]string{"Makefile": "run:\n\tjava -javaagent:/otel.jar com.example.Main\n"}, agentOnly},
		{"dockerfile shell-form sh -c", map[string]string{"Dockerfile": `CMD sh -c "java -javaagent:/otel.jar com.example.Main"` + "\n"}, agentOnly},
		{"dockerfile tini sh -c", map[string]string{"Dockerfile": `ENTRYPOINT ["tini", "--", "sh", "-c", "java -javaagent:/otel.jar com.example.Main"]` + "\n"}, agentOnly},
		{"dockerfile bash -lc", map[string]string{"Dockerfile": `ENTRYPOINT ["bash", "-lc", "java -javaagent:/otel.jar com.example.Main"]` + "\n"}, agentOnly},
		{"dockerfile /bin/sh -ec", map[string]string{"Dockerfile": `ENTRYPOINT ["/bin/sh", "-ec", "java -javaagent:/otel.jar com.example.Main"]` + "\n"}, agentOnly},
		{"procfile sh -c", map[string]string{"Procfile": `web: sh -c "java -javaagent:/otel.jar com.example.Main"` + "\n"}, agentOnly},
		{"dockerfile ENV of another variable expanded by the entrypoint", map[string]string{"Dockerfile": "ENV JVM_ARGS=-javaagent:/a.jar\nENTRYPOINT java ${JVM_ARGS:-} com.example.Main\n"}, agentOnly},
		{"k8s command and args", map[string]string{"k8s/deploy.yaml": "spec:\n  containers:\n    - command: [\"java\"]\n      args: [\"-javaagent:/otel.jar\", \"com.example.Main\"]\n"}, agentOnly},
		{"k8s args only", map[string]string{"k8s/deploy.yaml": "spec:\n  containers:\n    - args: [\"-javaagent:/otel.jar\"]\n"}, agentOnly},
		{"helm template it cannot parse", map[string]string{"chart/templates/deployment.yaml": "env:\n{{- if .Values.tuned }}\n  - name: JAVA_TOOL_OPTIONS\n    value: \"-XX:MaxRAMPercentage=75\"\n{{- end }}\n"}, optionOnly},
		{"compose command scalar", map[string]string{"compose.yaml": "services:\n  app:\n    command: /opt/java/openjdk/bin/java -javaagent:/otel.jar com.example.Main\n"}, agentOnly},
		{"jib jvmFlags in Kotlin DSL", map[string]string{"build.gradle.kts": "jib {\n    container {\n        jvmFlags = listOf(\"-javaagent:/otel.jar\")\n    }\n}\n"}, agentOnly},
		{"jib jvmFlags allowlisted", map[string]string{"build.gradle.kts": "jib {\n    container {\n        jvmFlags = listOf(\"-Xms512m\", \"-Duser.timezone=UTC\")\n    }\n}\n"}, []string{}},
		{"jib jvmFlags from a variable", map[string]string{"build.gradle.kts": "jib {\n    container {\n        jvmFlags = flags\n    }\n}\n"}, optionOnly},
		{"jib jvmFlags in a pom", map[string]string{"pom.xml": "<container>\n  <jvmFlags>\n    <jvmFlag>-javaagent:/otel.jar</jvmFlag>\n  </jvmFlags>\n</container>\n"}, agentOnly},
		{"jib jvmFlags in a pom, allowlisted", map[string]string{"pom.xml": "<container>\n  <jvmFlags>\n    <jvmFlag>-Xms512m</jvmFlag>\n  </jvmFlags>\n</container>\n"}, []string{}},
		{"pom jvmFlags from a property", map[string]string{"pom.xml": "<container>\n  <jvmFlags>\n    <jvmFlag>${jvm.flag}</jvmFlag>\n  </jvmFlags>\n</container>\n"}, optionOnly},
		{"spring-boot-maven jvmArguments", map[string]string{"pom.xml": "<configuration>\n  <jvmArguments>-javaagent:/otel.jar</jvmArguments>\n</configuration>\n"}, agentOnly},
		{"bootBuildImage BPE_APPEND_JAVA_TOOL_OPTIONS", map[string]string{"build.gradle.kts": "tasks.bootBuildImage {\n    environment.set(mapOf(\"BPE_APPEND_JAVA_TOOL_OPTIONS\" to \"-javaagent:/otel.jar\"))\n}\n"}, agentOnly},
		{"bootBuildImage environment from a variable", map[string]string{"build.gradle.kts": "tasks.bootBuildImage {\n    environment.set(mapOf(\"BPE_APPEND_JAVA_TOOL_OPTIONS\" to opts))\n}\n"}, optionOnly},
		{"startScripts defaultJvmOpts", map[string]string{"build.gradle.kts": "tasks.startScripts {\n    defaultJvmOpts = listOf(\"-javaagent:/otel.jar\")\n}\n"}, agentOnly},
		{"bootRun jvmArgs configure a dev JVM", map[string]string{"build.gradle.kts": "tasks.bootRun {\n    jvmArgs = listOf(\"-javaagent:/otel.jar\", \"-Dspring.profiles.active=dev\",\n        \"-Dx=$y\")\n}\n"}, []string{}},
		{"surefire argLine configures a test JVM", map[string]string{"pom.xml": "<configuration>\n  <argLine>-javaagent:${jacoco.agent} -Dx=${y}</argLine>\n</configuration>\n"}, []string{}},

		// Sound probes.
		{"P1 dockerfile shell form, quoted -D", map[string]string{"Dockerfile": `ENTRYPOINT java "-Djava.security.manager=allow" com.example.Main` + "\n"}, optionOnly},
		{"P2 expansion before -D", map[string]string{"Dockerfile": "ENTRYPOINT java ${JAVA_OPTS:-} -Djava.security.manager=allow com.example.Main\n"}, optionOnly},
		{"P2 option in an expansion default", map[string]string{"Dockerfile": "ENTRYPOINT java ${JAVA_OPTS:--Djava.system.class.loader=org.d.D} com.example.Main\n"}, optionOnly},
		{"P3 quoted procfile", map[string]string{"Procfile": `web: sh -c 'java "-Djava.system.class.loader=org.d.D" com.example.Main'` + "\n"}, optionOnly},
		{"P4 k8s command/args split", map[string]string{"k8s/deploy.yaml": "spec:\n  containers:\n    - command: [\"java\"]\n      args: [\"-Djava.system.class.loader=org.d.D\", \"com.example.Main\"]\n"}, optionOnly},
		{"P4 k8s module path split from java", map[string]string{"k8s/deploy.yaml": "spec:\n  containers:\n    - command: [\"java\"]\n      args: [\"-p\", \"/mods\", \"-m\", \"app/com.example.Main\"]\n"}, optionOnly},
		{"P5 applicationDefaultJvmArgs concatenation", map[string]string{"build.gradle.kts": "application {\n    applicationDefaultJvmArgs = listOf(\"-Xmx1g\") + listOf(\"-D\" + \"java.system.class.loader=org.d.D\")\n}\n"}, optionOnly},
		{"P5 literal list concatenation", map[string]string{"build.gradle.kts": "application {\n    applicationDefaultJvmArgs = listOf(\"-Xmx1g\") + listOf(\"-Duser.timezone=UTC\")\n}\n"}, []string{}},
		{"P13 quoted compose entrypoint scalar", map[string]string{"compose.yaml": "services:\n  app:\n    entrypoint: \"java -Djava.security.manager=allow com.example.Main\"\n"}, optionOnly},

		// Classpath, JAR and module-path options name the launch's code: unclassifiable.
		{"java -cp", map[string]string{"Dockerfile": `ENTRYPOINT ["java", "-cp", "/app/lib/*", "com.example.Main"]` + "\n"}, optionOnly},
		{"java -jar", map[string]string{"Procfile": "web: java -jar build/libs/app.jar\n"}, optionOnly},
		{"java --module-path", map[string]string{"Dockerfile": "ENTRYPOINT java --module-path=/mods -m app/com.example.Main\n"}, optionOnly},
		{"java -p", map[string]string{"run.sh": "java -p /mods -m app/com.example.Main\n"}, optionOnly},
		{"java @argfile", map[string]string{"run.sh": "exec java @/app/jvm.args com.example.Main\n"}, optionOnly},
		{"-p of another command", map[string]string{"run.sh": "mkdir -p /app && exec java com.example.Main\n"}, []string{}},
		{"start script template classpath", map[string]string{"build/scripts/app": "DEFAULT_JVM_OPTS=''\nCLASSPATH=$APP_HOME/lib/app.jar\nset -- \\\n        -classpath \"$CLASSPATH\" \\\n        com.example.MainKt \\\n        \"$@\"\n", "build/scripts/app.bat": "set DEFAULT_JVM_OPTS=\r\n\"%JAVA_EXE%\" %DEFAULT_JVM_OPTS% %JAVA_OPTS% %APP_OPTS% -classpath \"%CLASSPATH%\" com.example.MainKt %*\r\n"}, []string{}},
		{"start script classpath of another variable", map[string]string{"build/scripts/app": "set -- -classpath \"$EXTRA\" com.example.MainKt\n"}, optionOnly},
		{"template classpath outside a start script", map[string]string{"run.sh": "exec java -classpath \"$CLASSPATH\" com.example.Main\n"}, optionOnly},
		{"gradle wrapper template", map[string]string{"gradlew": gradlewExcerpt, "gradlew.bat": gradlewBatExcerpt}, []string{}},
		{"gradle wrapper agent", map[string]string{"gradlew": "DEFAULT_JVM_OPTS='\"-javaagent:/a.jar\"'\n"}, agentOnly},
		{"MANIFEST Class-Path", map[string]string{"build/libs/app.jar": manifestJar("Manifest-Version: 1.0\r\nClass-Path: lib/a.jar\r\n")}, optionOnly},
		{"MANIFEST Launcher-Agent-Class, folded", map[string]string{"app.war": manifestJar("Manifest-Version: 1.0\r\nlauncher-agent-class: org.d.\r\n Agent\r\n")}, agentOnly},
		{"MANIFEST plain", map[string]string{"build/libs/app.jar": manifestJar("Manifest-Version: 1.0\r\nMain-Class: com.example.Main\r\n")}, []string{}},

		// Distribution archives, build tools, binaries and large files.
		{"distZip lib JAR Class-Path", map[string]string{"build/distributions/app.zip": zipOf(map[string]string{"app/lib/app.jar": manifestJar("Class-Path: x.jar\r\n")})}, optionOnly},
		{"distTar start script agent", map[string]string{"build/distributions/app.tar": tarOf(map[string]string{"app/bin/app": "DEFAULT_JVM_OPTS='\"-javaagent:$APP_HOME/lib/a.jar\"'\n"})}, agentOnly},
		{"distTar start script template", map[string]string{"build/distributions/app.tar": tarOf(map[string]string{"app/bin/app": "set -- -classpath \"$CLASSPATH\" com.example.MainKt\n"})}, []string{}},
		{"unreadable distribution", map[string]string{"build/distributions/app.tgz": "not gzip"}, optionOnly},
		{"build tool's own options", map[string]string{".mvn/jvm.config": "-Xmx2g -Dmaven.repo.local=/r\n", "gradle.properties": "org.gradle.jvmargs=-Xmx2g -Dfile.encoding=x-custom\n", "ci.sh": "./gradlew build -Dorg.gradle.caching=true && cmake -DFOO=1 .\n"}, []string{}},
		{"build tool command then another command", map[string]string{"ci.sh": "mvn package && ./bin/app -Dapp.mode=x\n"}, optionOnly},
		{"applicationDefaultJvmArgs with a non-literal item", map[string]string{"build.gradle.kts": "applicationDefaultJvmArgs = listOf(\"-Xmx1g\", heap)\n"}, optionOnly},
		{"applicationDefaultJvmArgs with a trailing call", map[string]string{"build.gradle.kts": "applicationDefaultJvmArgs = listOf(\"-Xmx1g\").plus(extra)\n"}, optionOnly},
		{"quoted encoding value", map[string]string{"Dockerfile": "ENTRYPOINT java -Dfile.encoding=\"UTF-8\" com.example.Main\n"}, []string{}},
		{"large file option cut by a window edge", map[string]string{"big.txt": strings.Repeat("x", launchWindow+launchOverlap-12) + " -Duser.timezone=UTC " + strings.Repeat("y", launchTextLimit)}, []string{}},
		{"build tool command then java", map[string]string{"ci.sh": "mvn package; java -Dapp.mode=x com.example.Main\n"}, optionOnly},
		{"jib property is a launch option", map[string]string{"ci.sh": "./gradlew jib -Djib.container.jvmFlags=-javaagent:/a.jar\n"}, optionOnly},
		{"jib property in a build command blocks", map[string]string{"ci.sh": "./gradlew jib -Djib.container.mainClass=com.acme.Main\n"}, optionOnly},
		{"spring-boot property in a build command blocks", map[string]string{"ci.sh": "./mvnw package -Dspring-boot.build-image.imageName=app\n"}, optionOnly},
		{"name in a binary serialization", map[string]string{".gradle/8.4/executionHistory/executionHistory.bin": "\x00\x8fdefaultJvmOpts\x0c\x01APP_OPTS\x92"}, []string{}},
		{"name in prose", map[string]string{"README.md": "Set JAVA_OPTS to tune the heap.\n"}, optionOnly},
		{"name in a comment", map[string]string{"run.sh": "# JAVA_OPTS is read by the start script\nexec ./bin/app\n"}, []string{}},
		{"large file name", map[string]string{"big.txt": strings.Repeat("x", launchTextLimit) + "\nJAVA_OPTS=-Xmx1g\n"}, optionOnly},
		{"large file allowlisted option", map[string]string{"big.txt": strings.Repeat("x", launchTextLimit) + "\n-Duser.timezone=UTC\n"}, []string{}},
		{"large file agent across a window edge", map[string]string{"big.txt": strings.Repeat("x", launchWindow+launchOverlap-5) + " -javaagent:/a.jar " + strings.Repeat("y", launchTextLimit)}, agentOnly},
		{"node_modules skipped", map[string]string{"node_modules/x/run.sh": "java -javaagent:/a.jar\n"}, []string{}},
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

// TestLaunchOptionReasons_Walk: symlinks are followed only inside the checkout, the walk
// terminates on cycles, and anything it cannot read withholds Searched.
func TestLaunchOptionReasons_Walk(t *testing.T) {
	write := func(t *testing.T, p, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(t *testing.T, target, p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	const agentFile = "ENV JAVA_TOOL_OPTIONS=-javaagent:/a.jar\n"
	const inertFile = "ENV JAVA_TOOL_OPTIONS=-Xmx1g\n"
	tests := []struct {
		name  string
		setup func(t *testing.T, base string) string // returns the build dir
		want  []string
	}{
		{"symlinked build root is walked at its real path", func(t *testing.T, base string) string {
			write(t, filepath.Join(base, "real", "Dockerfile"), agentFile)
			link(t, filepath.Join(base, "real"), filepath.Join(base, "root"))
			return filepath.Join(base, "root")
		}, agentOnly},
		{"in-root directory link is read", func(t *testing.T, base string) string {
			write(t, filepath.Join(base, "root", "conf", "Dockerfile"), inertFile)
			link(t, "conf", filepath.Join(base, "root", "deploy"))
			return filepath.Join(base, "root")
		}, []string{}},
		{"in-root file link is read", func(t *testing.T, base string) string {
			write(t, filepath.Join(base, "root", "conf", "env"), agentFile)
			link(t, "conf/env", filepath.Join(base, "root", ".env"))
			return filepath.Join(base, "root")
		}, agentOnly},
		{"escaping link", func(t *testing.T, base string) string {
			write(t, filepath.Join(base, "outside", "Dockerfile"), inertFile)
			write(t, filepath.Join(base, "root", "README"), "")
			link(t, filepath.Join(base, "outside"), filepath.Join(base, "root", "ext"))
			return filepath.Join(base, "root")
		}, optionOnly},
		{"dangling link", func(t *testing.T, base string) string {
			link(t, "missing", filepath.Join(base, "root", "Dockerfile"))
			return filepath.Join(base, "root")
		}, optionOnly},
		{"link into node_modules", func(t *testing.T, base string) string {
			write(t, filepath.Join(base, "root", "node_modules", "x", "run.sh"), "")
			link(t, "node_modules/x", filepath.Join(base, "root", "tools"))
			return filepath.Join(base, "root")
		}, optionOnly},
		{"cycle terminates", func(t *testing.T, base string) string {
			write(t, filepath.Join(base, "root", "a", "Dockerfile"), inertFile)
			link(t, "..", filepath.Join(base, "root", "a", "up"))
			link(t, ".", filepath.Join(base, "root", "self"))
			return filepath.Join(base, "root")
		}, []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.setup(t, t.TempDir())
			if got := LaunchOptionReasons(dir); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LaunchOptionReasons = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestLaunchOptionReasons_Unreadable: a file or directory the scan cannot open withholds
// Searched rather than being skipped (P6).
func TestLaunchOptionReasons_Unreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads mode-000 files")
	}
	for _, tt := range []struct {
		name string
		rel  string
	}{
		{"mode-000 Dockerfile", "Dockerfile"},
		{"mode-000 directory", "deploy"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, tt.rel)
			if tt.rel == "deploy" {
				if err := os.MkdirAll(filepath.Join(p, "k8s"), 0o755); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(p, []byte("ENV JAVA_TOOL_OPTIONS=-javaagent:/otel.jar\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(p, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(p, 0o755) })
			if got := LaunchOptionReasons(dir); !reflect.DeepEqual(got, optionOnly) {
				t.Errorf("LaunchOptionReasons = %v, want %v", got, optionOnly)
			}
		})
	}
}
