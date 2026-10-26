package javaanalysis

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/depreach"
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
		{"dockerfile SBT_OPTS are not the program's", map[string]string{"Dockerfile": "ENV SBT_OPTS=-Dsbt.server.forcestart=true\n"}, []string{}},
		{"dockerfile GRADLE_OPTS classify like JAVA_TOOL_OPTIONS", map[string]string{"Dockerfile": "ENV GRADLE_OPTS=-Dorg.gradle.daemon=false\n"}, optionOnly},
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
		{"surefire argLine configures a test JVM", map[string]string{"pom.xml": "<plugin>\n  <groupId>org.apache.maven.plugins</groupId>\n  <artifactId>maven-surefire-plugin</artifactId>\n  <configuration>\n    <argLine>-javaagent:${jacoco.agent} -Dx=${y}</argLine>\n  </configuration>\n</plugin>\n"}, []string{}},

		// jvmArgs and argLine are exempt only in a recognised test-task block; any other JVM the
		// build starts may run the program (./gradlew run, bootRun, mvn exec:java at deploy).
		{"R4-B1 gradlew run with run-task jvmArgs", map[string]string{"Dockerfile": "CMD [\"./gradlew\",\"run\"]\n", "build.gradle.kts": "tasks.named<JavaExec>(\"run\") { jvmArgs(\"-javaagent:/otel.jar\") }\n"}, agentOnly},
		{"R4-B1 bootRun with bootRun jvmArgs", map[string]string{"Procfile": "web: ./gradlew bootRun\n", "build.gradle": "bootRun { jvmArgs = ['-javaagent:/otel.jar'] }\n"}, agentOnly},
		{"R4-B1 mvn exec:java with MAVEN_OPTS", map[string]string{"Procfile": "web: mvn exec:java\n", ".env": "MAVEN_OPTS=-Dlogback.configurationFile=/x.xml\n"}, optionOnly},
		{"bootRun jvmArgs, multi-line", map[string]string{"build.gradle.kts": "tasks.bootRun {\n    jvmArgs = listOf(\"-javaagent:/otel.jar\", \"-Dspring.profiles.active=dev\",\n        \"-Dx=$y\")\n}\n"}, agentAndOption},
		{"registered JavaExec jvmArgs", map[string]string{"build.gradle.kts": "tasks.register<JavaExec>(\"serve\") {\n    jvmArgs(\"-Djava.security.manager=allow\")\n}\n"}, optionOnly},
		{"run-task jvmArgs mutation, like any DSL mutation", map[string]string{"build.gradle.kts": "tasks.named<JavaExec>(\"run\") {\n    jvmArgs.add(\"-Duser.timezone=UTC\")\n}\n"}, optionOnly},
		{"run-task jvmArgs of an inert literal", map[string]string{"build.gradle.kts": "tasks.named<JavaExec>(\"run\") {\n    jvmArgs(\"-Duser.timezone=UTC\")\n}\n"}, []string{}},
		{"unattributable jvmArgs", map[string]string{"build.gradle.kts": "jvmArgs(extraJvmArgs)\n"}, optionOnly},
		{"unattributable jvmArgumentProviders", map[string]string{"build.gradle.kts": "tasks.named<JavaExec>(\"run\") {\n    jvmArgumentProviders.add(OtelAgent())\n}\n"}, optionOnly},
		{"MAVEN_OPTS on a build command", map[string]string{"ci.sh": "MAVEN_OPTS=-Dlogback.configurationFile=/x.xml mvn exec:java\n"}, optionOnly},
		{"GRADLE_OPTS in .env", map[string]string{".env": "GRADLE_OPTS=\"-Dlogback.configurationFile=/x.xml\"\n"}, optionOnly},
		{"MAVEN_OPTS expanded", map[string]string{"ci.sh": "exec mvn $MAVEN_OPTS exec:java\n"}, []string{}},
		{".mvn/jvm.config classifies like MAVEN_OPTS", map[string]string{".mvn/jvm.config": "-Xmx2g -Dmaven.repo.local=/r\n"}, optionOnly},
		{"argLine outside a test plugin", map[string]string{"pom.xml": "<properties>\n  <argLine>-javaagent:/otel.jar</argLine>\n</properties>\n"}, agentOnly},
		{"argLine in another plugin", map[string]string{"pom.xml": "<plugin>\n  <artifactId>exec-maven-plugin</artifactId>\n  <configuration>\n    <argLine>-javaagent:/otel.jar</argLine>\n  </configuration>\n</plugin>\n"}, agentOnly},
		{"argLine in a plugin depending on surefire", map[string]string{"pom.xml": "<plugin>\n  <dependencies><dependency><artifactId>maven-surefire-plugin</artifactId></dependency></dependencies>\n  <artifactId>exec-maven-plugin</artifactId>\n  <configuration><argLine>-javaagent:/otel.jar</argLine></configuration>\n</plugin>\n"}, agentOnly},
		{"argLine in an unclosed surefire plugin", map[string]string{"pom.xml": "<plugin>\n  <artifactId>maven-surefire-plugin</artifactId>\n  <configuration><argLine>-javaagent:/otel.jar</argLine></configuration>\n"}, agentOnly},
		{"argLine as a property reference", map[string]string{"pom.xml": "<plugin>\n  <artifactId>jacoco-maven-plugin</artifactId>\n  <configuration><propertyName>argLine</propertyName></configuration>\n</plugin>\n"}, []string{}},
		{"failsafe argLine", map[string]string{"pom.xml": "<plugin>\n  <artifactId>maven-failsafe-plugin</artifactId>\n  <executions><execution><goals><goal>integration-test</goal></goals></execution></executions>\n  <configuration><argLine>@{argLine} -javaagent:/a.jar</argLine></configuration>\n</plugin>\n"}, []string{}},
		{"groovy test block jvmArgs", map[string]string{"build.gradle": "test {\n    useJUnitPlatform()\n    jvmArgs '-javaagent:/a.jar', '-Dx=1'\n}\n"}, []string{}},
		{"test block jvmArgs, multi-line", map[string]string{"build.gradle.kts": "tasks.test {\n    jvmArgs = listOf(\"-javaagent:/a.jar\",\n        \"-Dx=$y\")\n}\n"}, []string{}},
		{"surefire argLine, multi-line", map[string]string{"pom.xml": "<plugin>\n  <artifactId>maven-surefire-plugin</artifactId>\n  <configuration>\n    <argLine>\n      -javaagent:/a.jar\n      -Dx=${y}\n    </argLine>\n  </configuration>\n</plugin>\n"}, []string{}},
		{"tasks.test jvmArgs", map[string]string{"build.gradle.kts": "tasks.test {\n    jvmArgs(\"-javaagent:/a.jar\")\n}\n"}, []string{}},
		{"tasks.test.configure jvmArgs", map[string]string{"build.gradle.kts": "tasks.test.configure {\n    jvmArgs(\"-javaagent:/a.jar\")\n}\n"}, []string{}},
		{"tasks.named test jvmArgs", map[string]string{"build.gradle.kts": "tasks.named(\"test\") {\n    jvmArgs(\"-javaagent:/a.jar\")\n}\n"}, []string{}},
		{"tasks.named<Test> test jvmArgs", map[string]string{"build.gradle.kts": "tasks.named<Test>(\"test\").configure {\n    jvmArgs(\"-javaagent:/a.jar\")\n}\n"}, []string{}},
		{"groovy tasks.named test, Test jvmArgs", map[string]string{"build.gradle": "tasks.named('test', Test) {\n    jvmArgs '-javaagent:/a.jar'\n}\n"}, []string{}},
		{"withType<Test> jvmArgs", map[string]string{"build.gradle.kts": "tasks.withType<Test> {\n    jvmArgs(\"-javaagent:/a.jar\")\n}\n"}, []string{}},
		{"withType<Test>().configureEach jvmArgs", map[string]string{"build.gradle.kts": "tasks.withType<Test>().configureEach {\n    jvmArgs(\"-javaagent:/a.jar\")\n}\n"}, []string{}},
		{"groovy withType(Test) jvmArgs", map[string]string{"build.gradle": "tasks.withType(Test) {\n    jvmArgs '-javaagent:/a.jar'\n}\n"}, []string{}},
		{"withType(Test::class.java) jvmArgs", map[string]string{"build.gradle.kts": "tasks.withType(Test::class.java).configureEach {\n    jvmArgs(\"-javaagent:/a.jar\")\n}\n"}, []string{}},
		{"test block jvmArgumentProviders", map[string]string{"build.gradle.kts": "tasks.test {\n    jvmArgumentProviders.add(JacocoAgent())\n}\n"}, []string{}},
		{"test block with nested braces, a brace string and a brace comment", map[string]string{"build.gradle.kts": "tasks.test {\n    doFirst { println(\"}\") } // }\n    jvmArgs(\"-javaagent:/a.jar\")\n}\n"}, []string{}},
		{"jvmArgs after a test block closes", map[string]string{"build.gradle.kts": "tasks.test {\n    useJUnitPlatform()\n}\ntasks.named<JavaExec>(\"run\") { jvmArgs(\"-javaagent:/a.jar\") }\n"}, agentOnly},
		{"unclosed test block", map[string]string{"build.gradle.kts": "tasks.test {\n    jvmArgs(\"-javaagent:/a.jar\")\n"}, agentOnly},
		{"unrecognised test-like task", map[string]string{"build.gradle.kts": "integrationTest {\n    jvmArgs(\"-javaagent:/a.jar\")\n}\n"}, agentOnly},
		// The innermost block holding a jvmArgs decides: a run block inside a test block is run.
		{"run block nested in a test block", map[string]string{"build.gradle.kts": "tasks.test {\n    useJUnitPlatform()\n    tasks.named<JavaExec>(\"run\") { jvmArgs(\"-javaagent:/otel.jar\") }\n}\n"}, agentOnly},
		{"groovy run block nested in a test block", map[string]string{"build.gradle": "test {\n    tasks.named('run') {\n        jvmArgs '-javaagent:/otel.jar'\n    }\n}\n"}, agentOnly},
		{"bootRun block nested in a withType<Test> block", map[string]string{"build.gradle.kts": "tasks.withType<Test>().configureEach {\n    tasks.named<BootRun>(\"bootRun\") { jvmArgs(\"-javaagent:/otel.jar\") }\n}\n"}, agentOnly},
		{"jvmArgumentProviders in a run block nested in a test block", map[string]string{"build.gradle.kts": "tasks.test {\n    tasks.named<JavaExec>(\"run\") { jvmArgumentProviders.add(OtelAgent()) }\n}\n"}, optionOnly},
		{"test block jvmArgs after a nested block", map[string]string{"build.gradle.kts": "tasks.test {\n    tasks.named<JavaExec>(\"run\") { mainClass.set(\"a.Main\") }\n    jvmArgs(\"-javaagent:/a.jar\")\n}\n"}, []string{}},
		{"run task's jvmArgs set from a test block", map[string]string{"build.gradle.kts": "tasks.test {\n    useJUnitPlatform()\n    tasks.run.get().jvmArgs(\"-javaagent:/otel.jar\")\n}\n"}, agentOnly},
		{"named run block in a test block", map[string]string{"build.gradle.kts": "tasks.test {\n    useJUnitPlatform()\n    tasks.named(\"run\") { jvmArgs(\"-javaagent:/otel.jar\") }\n}\n"}, agentOnly},
		{"groovy getByName run jvmArgs from a test block", map[string]string{"build.gradle": "test {\n    useJUnitPlatform()\n    tasks.getByName('run').jvmArgs '-javaagent:/otel.jar'\n}\n"}, agentOnly},
		{"groovy run.jvmArgs from a test block", map[string]string{"build.gradle": "test {\n    useJUnitPlatform()\n    run.jvmArgs '-javaagent:/otel.jar'\n}\n"}, agentOnly},
		{"findByName bootRun jvmArgs from a test block", map[string]string{"build.gradle.kts": "tasks.test {\n    useJUnitPlatform()\n    (project.tasks.findByName(\"bootRun\") as JavaExec).jvmArgs(\"-javaagent:/otel.jar\")\n}\n"}, agentOnly},
		{"groovy findByName bootRun jvmArgs from a test block", map[string]string{"build.gradle": "test {\n    useJUnitPlatform()\n    project.tasks.findByName('bootRun').jvmArgs '-javaagent:/otel.jar'\n}\n"}, agentOnly},
		{"arbitrary receiver's jvmArgs in a test block", map[string]string{"build.gradle.kts": "tasks.test {\n    useJUnitPlatform()\n    foo.jvmArgs(\"-javaagent:/otel.jar\")\n}\n"}, agentOnly},
		{"review repro: Groovy run.jvmArgs assigned in a test block", map[string]string{"build.gradle": "test {\n useJUnitPlatform()\n run.jvmArgs = ['-javaagent:/otel.jar']\n}\n"}, agentOnly},
		{"review repro: Groovy tasks.run.jvmArgs command call in a test block", map[string]string{"build.gradle": "test {\n tasks.run.jvmArgs '-javaagent:/otel.jar'\n}\n"}, agentOnly},
		{"review repro: Groovy bootRun.jvmArgs in a test block", map[string]string{"build.gradle": "test {\n bootRun.jvmArgs('-javaagent:/otel.jar')\n}\n"}, agentOnly},
		{"review repro: Kotlin tasks.named<JavaExec>(\"run\").get().jvmArgs in a test block", map[string]string{"build.gradle.kts": "tasks.test {\n tasks.named<JavaExec>(\"run\").get().jvmArgs(\"-javaagent:/otel.jar\")\n}\n"}, agentOnly},
		{"review repro: Kotlin (tasks.getByName(\"run\") as JavaExec).jvmArgs assigned in a test block", map[string]string{"build.gradle.kts": "tasks.test {\n (tasks.getByName(\"run\") as JavaExec).jvmArgs = listOf(\"-javaagent:/otel.jar\")\n}\n"}, agentOnly},
		{"receiver on the previous line", map[string]string{"build.gradle.kts": "tasks.test {\n    useJUnitPlatform()\n    tasks.run.get()\n        .jvmArgs(\"-javaagent:/otel.jar\")\n}\n"}, agentOnly},
		{"dot ending the previous line", map[string]string{"build.gradle": "test {\n    useJUnitPlatform()\n    tasks.run.\n        jvmArgs '-javaagent:/otel.jar'\n}\n"}, agentOnly},
		{"safe-call receiver", map[string]string{"build.gradle.kts": "tasks.test {\n    useJUnitPlatform()\n    tasks.findByName(\"run\")?.let { it as JavaExec }?.jvmArgs(\"-javaagent:/otel.jar\")\n}\n"}, agentOnly},
		{"receiver whose name ends in it", map[string]string{"build.gradle.kts": "tasks.test {\n    useJUnitPlatform()\n    submit.jvmArgs(\"-javaagent:/otel.jar\")\n}\n"}, agentOnly},
		{"receiver whose name ends in this", map[string]string{"build.gradle.kts": "tasks.test {\n    useJUnitPlatform()\n    notthis.jvmArgs(\"-javaagent:/otel.jar\")\n}\n"}, agentOnly},
		{"argument continuing the previous line", map[string]string{"build.gradle.kts": "tasks.test {\n    useJUnitPlatform()\n    foo(1,\n        jvmArgs(\"-javaagent:/otel.jar\"))\n}\n"}, agentOnly},
		{"run task's jvmArgumentProviders from a test block", map[string]string{"build.gradle.kts": "tasks.test {\n    useJUnitPlatform()\n    tasks.run.get().jvmArgumentProviders.add(OtelAgent())\n}\n"}, optionOnly},
		{"control: bare jvmArgs in a test block", map[string]string{"build.gradle.kts": "tasks.test {\n    useJUnitPlatform()\n    jvmArgs(\"-javaagent:/otel.jar\")\n}\n"}, []string{}},
		{"control: this.jvmArgs in a test block", map[string]string{"build.gradle.kts": "tasks.test {\n    useJUnitPlatform()\n    this.jvmArgs(\"-javaagent:/otel.jar\")\n}\n"}, []string{}},
		{"control: groovy it.jvmArgs in a test block", map[string]string{"build.gradle": "test {\n    useJUnitPlatform()\n    it.jvmArgs '-javaagent:/otel.jar'\n}\n"}, []string{}},
		{"control: groovy it. ending the previous line", map[string]string{"build.gradle": "test {\n    useJUnitPlatform()\n    it.\n        jvmArgs '-javaagent:/otel.jar'\n}\n"}, []string{}},
		{"control: bare jvmArgumentProviders in a test block", map[string]string{"build.gradle.kts": "tasks.test {\n    useJUnitPlatform()\n    jvmArgumentProviders.add(OtelAgent())\n}\n"}, []string{}},
		{"control: jvmArgs after a statement ending in a string", map[string]string{"build.gradle.kts": "tasks.test {\n    useJUnitPlatform()\n    val n = \"x\"\n    jvmArgs(\"-javaagent:/otel.jar\")\n}\n"}, []string{}},
		// An unbracketed jvmArgs value is exempt only up to a positive end: string literals and
		// commas, then a ';', a line end or the block's '}'. Anything else, and it is not exempt.
		{"review repro: Groovy jvmArgs; run.jvmArgs on one line", map[string]string{"build.gradle": "test {\n    jvmArgs '-Xmx1g'; run.jvmArgs '-javaagent:/otel.jar'\n}\n"}, agentOnly},
		{"review repro: Groovy jvmArgs; tasks.run.jvmArgs on one line", map[string]string{"build.gradle": "test {\n    jvmArgs '-Xmx1g'; tasks.run.jvmArgs '-javaagent:/otel.jar'\n}\n"}, agentOnly},
		{"review repro: Groovy jvmArgs; bootRun.jvmArgs() on one line", map[string]string{"build.gradle": "test {\n    jvmArgs '-Xmx1g'; bootRun.jvmArgs('-javaagent:/otel.jar')\n}\n"}, agentOnly},
		{"review repro: Groovy jvmArgs; applicationDefaultJvmArgs on one line", map[string]string{"build.gradle": "test {\n    jvmArgs '-Xmx1g'; project.applicationDefaultJvmArgs = ['-javaagent:/otel.jar']\n}\n"}, agentOnly},
		{"review repro: Groovy jvmArgs with a run.jvmArgs() argument", map[string]string{"build.gradle": "test {\n    jvmArgs '-Xmx1g', run.jvmArgs('-javaagent:/otel.jar')\n}\n"}, agentAndOption},
		{"one-line test block: jvmArgs; run.jvmArgs", map[string]string{"build.gradle": "test { jvmArgs '-Xmx1g'; run.jvmArgs '-javaagent:/otel.jar' }\n"}, agentOnly},
		{"Kotlin jvmArgs assignment; another task's arguments on one line", map[string]string{"build.gradle.kts": "tasks.test {\n    jvmArgs = testArgs; tasks.run.get().allJvmArgs = listOf(\"-javaagent:/otel.jar\")\n}\n"}, agentAndOption},
		{"Groovy closure chained after an unbracketed jvmArgs", map[string]string{"build.gradle": "test {\n    jvmArgs '-Xmx1g' doFirst { run.jvmArgs '-javaagent:/otel.jar' }\n}\n"}, agentAndOption},
		{"Groovy jvmArgs value continued by an operator", map[string]string{"build.gradle": "test {\n    jvmArgs '-javaagent:/a.jar' + suffix\n}\n"}, agentAndOption},
		{"Groovy jvmArgs value with an unterminated string", map[string]string{"build.gradle": "test {\n    jvmArgs '-javaagent:/a.jar\n}\n"}, agentAndOption},
		{"Groovy run.jvmArgs on the line after an unbracketed jvmArgs", map[string]string{"build.gradle": "test {\n    jvmArgs '-Xmx1g'\n    run.jvmArgs '-javaagent:/otel.jar'\n}\n"}, agentOnly},
		{"Groovy closure on the line after an exempt jvmArgs", map[string]string{"build.gradle": "test {\n    jvmArgs '-javaagent:/test.jar'\n    doFirst { run.jvmArgs '-javaagent:/otel.jar' }\n}\n"}, agentOnly},
		{"control: one-line Groovy test block jvmArgs", map[string]string{"build.gradle": "test { jvmArgs '-Xmx1g' }\n"}, []string{}},
		{"control: one-line Groovy test block jvmArgs ends at the brace", map[string]string{"build.gradle": "test { jvmArgs '-javaagent:/test.jar' }\n"}, []string{}},
		{"control: Groovy jvmArgs ends at a semicolon", map[string]string{"build.gradle": "test {\n    jvmArgs '-javaagent:/test.jar'; useJUnitPlatform()\n}\n"}, []string{}},
		{"control: Groovy jvmArgs ends at the line end", map[string]string{"build.gradle": "test {\n    jvmArgs '-javaagent:/test.jar'\n    useJUnitPlatform()\n}\n"}, []string{}},
		{"control: Groovy jvmArgs ends at a CRLF", map[string]string{"build.gradle": "test {\r\n    jvmArgs '-javaagent:/test.jar'\r\n    useJUnitPlatform()\r\n}\r\n"}, []string{}},
		{"control: Groovy jvmArgs string holding a semicolon", map[string]string{"build.gradle": "test {\n    jvmArgs '-Dx=a;b'\n}\n"}, []string{}},
		{"control: Groovy jvmArgs string holding a brace", map[string]string{"build.gradle": "test {\n    jvmArgs '-Dx=}'\n}\n"}, []string{}},
		{"control: Groovy jvmArgs template holding a semicolon", map[string]string{"build.gradle": "test {\n    jvmArgs \"-Dx=${a; b}\"\n}\n"}, []string{}},
		{"control: Groovy jvmArgs continued after a comma", map[string]string{"build.gradle": "test {\n    jvmArgs '-Dx=1',\n        '-javaagent:/test.jar'\n    useJUnitPlatform()\n}\n"}, []string{}},
		{"control: Groovy jvmArgs list then a line end", map[string]string{"build.gradle": "test {\n    jvmArgs '-javaagent:/test.jar', '-Dx=1'\n    useJUnitPlatform()\n}\n"}, []string{}},
		{"control: Groovy jvmArgs with a trailing line comment", map[string]string{"build.gradle": "test {\n    jvmArgs '-javaagent:/test.jar' // test agent\n}\n"}, []string{}},
		{"control: Groovy jvmArgs with a trailing block comment", map[string]string{"build.gradle": "test {\n    jvmArgs '-javaagent:/test.jar' /* test agent */\n}\n"}, []string{}},
		{"control: Groovy jvmArgs += literal", map[string]string{"build.gradle": "test {\n    jvmArgs += '-javaagent:/test.jar'\n}\n"}, []string{}},
		// A brace the reader cannot classify leaves the test block unclosed; it never stretches
		// the block over a later run block's jvmArgs.
		{"block comment brace in a test block", map[string]string{"build.gradle.kts": "tasks.named<JavaExec>(\"run\") {\n    tasks.test { /* { */ }\n    jvmArgs(\"-javaagent:/otel.jar\")\n}\n"}, agentOnly},
		{"groovy block comment brace in a test block", map[string]string{"build.gradle": "tasks.named('run') {\n    test { /* { */ }\n    jvmArgs '-javaagent:/otel.jar'\n}\n"}, agentOnly},
		{"slashy string brace in a test block", map[string]string{"build.gradle": "tasks.named('run') {\n    test { def re = /{/ }\n    jvmArgs '-javaagent:/otel.jar'\n}\n"}, agentOnly},
		{"dollar-slashy string brace in a test block", map[string]string{"build.gradle": "tasks.named('run') {\n    test { def re = $/{/$ }\n    jvmArgs '-javaagent:/otel.jar'\n}\n"}, agentOnly},
		{"template brace in a test block", map[string]string{"build.gradle.kts": "tasks.named<JavaExec>(\"run\") {\n    tasks.test { val s = \"${if (true) \"{\" else \"\"}\" }\n    jvmArgs(\"-javaagent:/otel.jar\")\n}\n"}, agentOnly},
		{"raw string brace in a test block", map[string]string{"build.gradle.kts": "tasks.named<JavaExec>(\"run\") {\n    tasks.test { val s = \"\"\"a\"{\"b\"\"\" }\n    jvmArgs(\"-javaagent:/otel.jar\")\n}\n"}, agentOnly},
		{"groovy triple-quoted brace in a test block", map[string]string{"build.gradle": "tasks.named('run') {\n    test { def s = '''a'{'b''' }\n    jvmArgs '-javaagent:/otel.jar'\n}\n"}, agentOnly},
		{"a stray closing brace stops the reader", map[string]string{"build.gradle.kts": "}\ntasks.test {\n    jvmArgs(\"-javaagent:/a.jar\")\n}\n"}, agentOnly},
		{"nested block comment closes once in Kotlin", map[string]string{"build.gradle.kts": "tasks.named<JavaExec>(\"run\") {\n    tasks.test { /* /* */ { */ }\n    jvmArgs(\"-javaagent:/otel.jar\")\n}\n"}, agentOnly},
		{"test block opener in a comment", map[string]string{"build.gradle.kts": "tasks.named<JavaExec>(\"run\") { /* tasks.test { */\n    jvmArgs(\"-javaagent:/otel.jar\")\n}\n"}, agentOnly},
		{"test block opener in a line comment", map[string]string{"build.gradle": "tasks.named('run') { // tasks.test {\n    jvmArgs '-javaagent:/otel.jar'\n}\n"}, agentOnly},
		{"test block with comments, templates and strings", map[string]string{"build.gradle.kts": "tasks.test {\n    /* note { /* nested } */ */\n    val n = \"${project.name}-${listOf(1).map { it }}-${\"}\"}-${'}'}\" + '}' + \"\"\"}\"\"\" + \"\"\"C:\\\"\"\" + `a}`\n    jvmArgs(\"-javaagent:/a.jar\", \"-Dout=\" + 4 / 2)\n}\n"}, []string{}},
		{"groovy test block with comments and strings", map[string]string{"build.gradle": "test {\n    /* { /* */\n    def s = \"${project.name}\" + '}' + '''}'''\n    jvmArgs '-javaagent:/a.jar'\n}\n"}, []string{}},

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
		{"build tool's own options", map[string]string{".mvn/maven.config": "-B -Dmaven.repo.local=/r\n", "gradle.properties": "org.gradle.jvmargs=-Xmx2g -Dfile.encoding=x-custom\n", "ci.sh": "./gradlew build -Dorg.gradle.caching=true && cmake -DFOO=1 .\n"}, []string{}},
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
		// sound r4 R4-B1: the exemption holds in Gradle build scripts and pom.xml only, and ends at the value.
		{"J4 test jvmArgs then application agent on one line", map[string]string{"build.gradle.kts": `tasks.test { jvmArgs("-ea") }; application { applicationDefaultJvmArgs = listOf("-javaagent:/opt/a.jar") }` + "\n"}, agentOnly},
		{"J5 helm values jvmArgs passed to java", map[string]string{
			"charts/app/values.yaml":               "jvmArgs: \"-javaagent:/opt/agent.jar\"\n",
			"charts/app/templates/deployment.yaml": "command: [\"sh\", \"-c\", \"exec java {{ .Values.jvmArgs }} com.example.Main\"]\n",
		}, agentAndOption},
		{"test block outside a Gradle build script", map[string]string{"docs/build.md": "test { jvmArgs(\"-javaagent:/a.jar\") }\n"}, agentOnly},
		{"surefire argLine outside pom.xml", map[string]string{"repo/app-1.0.pom": "<plugin><artifactId>maven-surefire-plugin</artifactId><configuration><argLine>-javaagent:/a.jar</argLine></configuration></plugin>\n"}, agentOnly},
		{"surefire argLine with no closing tag", map[string]string{"pom.xml": "<plugin><artifactId>maven-surefire-plugin</artifactId><configuration><argLine>-javaagent:/a.jar</configuration></plugin>\n"}, agentAndOption},
		{"nested test blocks end the value at the inner block", map[string]string{"build.gradle": "tasks.withType(Test) {\n    tasks.test { jvmArgs '-ea' }; println '-javaagent:/a.jar'\n}\n"}, agentOnly},
		{"test jvmArgs with a module path", map[string]string{"build.gradle.kts": `tasks.test { jvmArgs("-Dtool=/usr/bin/java", "-p", "build/mods") }` + "\n"}, []string{}},
		{"test jvmArgs value ends at its bracket", map[string]string{"build.gradle": "test { jvmArgs('-ea'); systemProperty 'k', 'v' }\ntest { jvmArgs '-ea' }; tasks.run { jvmArgs '-javaagent:/a.jar' }\n"}, agentOnly},
		// sound r4 R4-B2: CLASSPATH names the launch's code.
		{"J3 dockerfile CLASSPATH with exec-form java", map[string]string{"Dockerfile": "ENV CLASSPATH=/opt/plugins/*:/app/lib/*\nENTRYPOINT [\"java\", \"com.example.Main\"]\n"}, optionOnly},
		{"CLASSPATH in a kubernetes env", map[string]string{"k8s/deploy.yaml": "env:\n  - name: CLASSPATH\n    value: /opt/plugins/*\n"}, optionOnly},
		{"CLASSPATH unset", map[string]string{"run.sh": "unset CLASSPATH\nexec ./bin/app\n"}, []string{}},
		{"gradle wrapper CLASSPATH", map[string]string{"gradlew": gradlewExcerpt}, []string{}},
		// sound r4 R4-B3: quoted and continued property names are unquoted and joined first.
		{"J1 quoted system class loader property", map[string]string{"Dockerfile": "ENTRYPOINT java -D\"java.system.class.loader=org.d.D\" com.example.Main\n"}, optionOnly},
		{"single-quoted property", map[string]string{"run.sh": "exec java -D'java.system.class.loader=org.d.D' com.example.Main\n"}, optionOnly},
		{"quote inside a property name", map[string]string{"run.sh": "exec java -Djava.system.\"class.loader=org.d.D\" com.example.Main\n"}, optionOnly},
		{"quoted inert property", map[string]string{"run.sh": "exec java -D'user.timezone=UTC' com.example.Main\n"}, []string{}},
		{"empty quoted property name", map[string]string{"run.sh": "exec java -D\"\" com.example.Main\n"}, optionOnly},
		{"unclosed quoted property", map[string]string{"run.sh": "exec java -D\"java.system.class.loader=org.d.D com.example.Main\n"}, optionOnly},
		{"quoted property run into a word", map[string]string{"run.sh": "exec java -D\"user.timezone\"x=UTC com.example.Main\n"}, optionOnly},
		{"empty property name", map[string]string{"run.sh": "exec java -D=x com.example.Main\n"}, optionOnly},
		{"J2 property name after a continuation", map[string]string{"run.sh": "exec java -D\\\njava.system.class.loader=org.d.D com.example.Main\n"}, optionOnly},
		{"property split mid-name by a continuation", map[string]string{"run.sh": "exec java -Djava.system.\\\nclass.loader=org.d.D com.example.Main\n"}, optionOnly},
		{"inert property split by a CRLF continuation", map[string]string{"run.sh": "exec java -Duser.time\\\r\nzone=UTC com.example.Main\r\n"}, []string{}},
		{"inert property split by a continuation", map[string]string{"run.sh": "exec java -Duser.time\\\nzone=UTC com.example.Main\n"}, []string{}},
		{"continuation after a property", map[string]string{"run.sh": "exec java -Duser.timezone=UTC \\\n  com.example.Main\n"}, []string{}},
		// sound r4 non-blockers.
		{"J8 long token across a window edge", map[string]string{"big.txt": strings.Repeat("x", launchWindow-100) + " -Duser.timezone=" + strings.Repeat("v", 734) + " " + strings.Repeat("y", launchTextLimit)}, optionOnly},
		{"J9 kotlin -J agent", map[string]string{"Procfile": "web: kotlin -J-javaagent:/a.jar MainKt\n"}, agentOnly},
		{"J10 gradlew outside the root", map[string]string{"deploy/gradlew": "exec java -Djava.system.class.loader=org.d.D com.example.Main\n"}, optionOnly},
		{"wrapper template outside the root", map[string]string{"deploy/gradlew": gradlewExcerpt + "exec java -Djava.system.class.loader=org.d.D com.example.Main\n"}, optionOnly},
		{"root gradlew that is not the wrapper", map[string]string{"gradlew": "exec java -Djava.system.class.loader=org.d.D com.example.Main\n"}, optionOnly},
		{"gradle wrapper batch file", map[string]string{"gradlew.bat": gradlewBatExcerpt}, []string{}},
		{"J6 UTF-16LE script", map[string]string{"start.ps1": utf16Text("$env:JAVA_TOOL_OPTIONS = \"-javaagent:C:\\otel.jar\"\r\n", false)}, agentAndOption},
		{"UTF-16BE script", map[string]string{"start.ps1": utf16Text("$env:JAVA_TOOL_OPTIONS = \"-javaagent:C:\\otel.jar\"\r\n", true)}, agentAndOption},
		{"names in a binary file are not read", map[string]string{"bin/tool": "ELF\x01JAVA_OPTS\x02\x00\x00"}, []string{}},
		{"text lines before a binary's first NUL are not read", map[string]string{"bin/tool": "\x7fELF\x02\nJAVA_OPTS=$FLAGS\n\x00\x00"}, []string{}},
		{"J7 script with a binary payload", map[string]string{"bin/run": "#!/bin/sh\nexport JAVA_TOOL_OPTIONS=\"$AGENT_FLAGS\"\nexec \"$JAVA_HOME/bin/java\" Main \"$0\"\n\x00\x01payload"}, optionOnly},
		{"bzip2 distTar start script agent", map[string]string{"build/distributions/app.tbz2": distTarBz2}, agentOnly},
		{"bzip2 distTar, .tar.bz2", map[string]string{"build/distributions/app.tar.bz2": distTarBz2}, agentOnly},
		{"corrupt bzip2 distTar", map[string]string{"build/distributions/app.tbz2": "BZh9 not bzip2"}, optionOnly},
		{"xz distTar is not read", map[string]string{"build/distributions/app.tar.xz": "\xfd7zXZ\x00"}, optionOnly},
		// sound r4 surviving mutants.
		{"tar that cannot be read", map[string]string{"build/distributions/app.tar": "not a tar"}, optionOnly},
		{".git is scanned", map[string]string{".git/hooks/post-checkout": "ENV JAVA_TOOL_OPTIONS=-javaagent:/a.jar\n"}, agentOnly},
		{"startScripts defaultJvmOpts from a variable", map[string]string{"build.gradle.kts": "tasks.startScripts { defaultJvmOpts = listOf(otelFlag) }\n"}, optionOnly},
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
			if got := LaunchOptionReasons(dir, nil); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LaunchOptionReasons = %v, want %v", got, tt.want)
			}
		})
	}
}

// distTarBz2 is a bzip2 tar of a start script, app/bin/app, whose DEFAULT_JVM_OPTS set an agent.
const distTarBz2 = "\x42\x5a\x68\x39\x31\x41\x59\x26\x53\x59\x7b\xf1\xcb\xf7\x00\x00\x7f\xdf\x81\xca\x90\x54\x83\xef\x92\x27\x56\xcf\x00\xf2\xb5\x5f\x00\x00\x02\x08\x08\x20\x00\x74\x1a\x45\x3f\x49\x0c\x83\x41\xa0\x69\xa0\x0d\xa4\x7e\xa4\x1e\x49\xfa\xa0\xd2\x44\xcd\x00\x4c\x26\x98\x01\x34\x60\x13\x00\xcd\x9e\x8c\x60\x08\x03\xf8\x04\x01\x0f\x3a\x3c\xa0\x79\x75\x4e\x40\x10\x30\x0d\xa0\x74\x20\x6f\xd9\xae\xbf\x47\x26\x7d\x80\x58\x98\x08\x3d\xa0\x6e\xbc\xd6\x15\x3a\x37\xec\x74\x1f\x4f\x35\xaf\xac\xe8\x27\xb1\x1e\x6f\x3f\x28\xc4\xcc\xe4\x37\x63\x72\x7e\xe2\xd5\xd5\x11\x13\x8c\x97\x76\x84\x24\xbf\x75\x63\x00\x0b\x62\xa9\xe7\x22\x20\x3f\x8b\xb9\x22\x9c\x28\x48\x3d\xf8\xe5\xfb\x80"

// utf16Text encodes s as UTF-16 with a byte-order mark.
func utf16Text(s string, bigEndian bool) string {
	out := []byte{0xff, 0xfe}
	if bigEndian {
		out = []byte{0xfe, 0xff}
	}
	for _, u := range utf16.Encode([]rune(s)) {
		if bigEndian {
			out = append(out, byte(u>>8), byte(u))
		} else {
			out = append(out, byte(u), byte(u>>8))
		}
	}
	return string(out)
}

// errReader returns data, then a read error.
type errReader struct{ data []byte }

func (r *errReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, errors.New("read error")
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

// TestLaunchContent_ReadError: a read that fails, whole or mid-window, withholds Searched.
func TestLaunchContent_ReadError(t *testing.T) {
	for _, tt := range []struct {
		name string
		size int64
		data []byte
	}{
		{"whole read", 10, nil},
		{"window read", launchTextLimit + 1, bytes.Repeat([]byte("x"), launchWindow+launchOverlap)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := &launchScan{reasons: map[string]bool{}}
			s.content("x", false, &errReader{data: tt.data}, tt.size)
			if !s.reasons[PartialReasonLaunchOption] {
				t.Errorf("reasons = %v, want %s", s.reasons, PartialReasonLaunchOption)
			}
		})
	}
}

// TestLaunchOptionReasons_MissingRoot: a build root that cannot be resolved withholds Searched.
func TestLaunchOptionReasons_MissingRoot(t *testing.T) {
	if got := LaunchOptionReasons(filepath.Join(t.TempDir(), "missing"), nil); !reflect.DeepEqual(got, optionOnly) {
		t.Errorf("LaunchOptionReasons = %v, want %v", got, optionOnly)
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
			if got := LaunchOptionReasons(dir, nil); !reflect.DeepEqual(got, tt.want) {
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
			if got := LaunchOptionReasons(dir, nil); !reflect.DeepEqual(got, optionOnly) {
				t.Errorf("LaunchOptionReasons = %v, want %v", got, optionOnly)
			}
		})
	}
}

// TestLaunchOptionReasons_LocalRepository: the artifact files of the local repository a Maven
// graph's dependency files lie in are not read as launch configuration when that repository is
// inside the checkout. Only that repository is left out, and only its artifact-named files:
// anything else under it, a directory merely named like one, and every file when the repository
// cannot be identified are scanned as before.
func TestLaunchOptionReasons_LocalRepository(t *testing.T) {
	const (
		repo = ".m2/repository"
		// A cached plugin POM: argLine outside the project's pom.xml is not exempt.
		pluginPOM = "<plugin><artifactId>maven-surefire-plugin</artifactId><configuration><argLine>-javaagent:/a.jar</argLine></configuration></plugin>\n"
		dataJar   = "com/fasterxml/jackson/core/jackson-databind/2.17.2/jackson-databind-2.17.2.jar"
		agentFile = "ENV JAVA_TOOL_OPTIONS=-javaagent:/a.jar\n"
	)
	agentJar := manifestJar("Manifest-Version: 1.0\r\nLauncher-Agent-Class: net.bytebuddy.agent.Installer\r\n")
	// cached is what a resolved build leaves in its local repository: a dependency JAR the graph
	// lists, a plugin POM and an agent JAR it does not.
	cached := func(root string) map[string]string {
		return map[string]string{
			root + "/" + dataJar: zipOf(map[string]string{"x.txt": ""}),
			root + "/org/apache/maven/surefire/surefire/3.2.5/surefire-3.2.5.pom":                                    pluginPOM,
			root + "/net/bytebuddy/byte-buddy-agent/1.14.19/byte-buddy-agent-1.14.19.jar":                            agentJar,
			root + "/org/apache/commons/commons-parent/69/commons-parent-69.pom.lastUpdated":                         pluginPOM,
			root + "/com/acme/lib/1.0-SNAPSHOT/lib-1.0-20240101.120000-1.pom":                                        pluginPOM,
			root + "/org/apache/maven/surefire/surefire/3.2.5/surefire-3.2.5-tests.jar":                              agentJar,
			root + "/org/apache/maven/surefire/surefire/3.2.5/_remote.repositories":                                  "surefire-3.2.5.pom>central=\n",
			root + "/org/apache/maven/surefire/surefire/maven-metadata-central.xml":                                  "<metadata/>\n",
			root + "/org/springframework/boot/spring-boot-starter-parent/3.3.5/spring-boot-starter-parent-3.3.5.pom": pluginPOM,
		}
	}
	with := func(base map[string]string, extra map[string]string) map[string]string {
		out := map[string]string{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	// dep is the graph node for dataJar under root (a path from the build dir, or absolute).
	dep := graphDep{group: "com.fasterxml.jackson.core", artifact: "jackson-databind", version: "2.17.2"}
	tests := []struct {
		name  string
		files map[string]string // build-dir-relative; "@out/" lies beside the checkout, "@up/" in its parent
		links map[string]string // build-dir-relative link -> target
		tool  string            // "" for no graph
		root  string            // where the graph's dependency file lies
		rel   bool              // the graph names that file by a relative path
		want  []string
	}{
		{"resolved in-checkout repository is left out", cached(repo), nil, "maven", repo, false, []string{}},
		{"no graph: repository unidentified, withheld", cached(repo), nil, "", repo, false, agentOnly},
		{"graph lists no file: repository unidentified, withheld", cached(repo), nil, "maven", "", false, agentOnly},
		{"gradle graph: no Maven repository identified, withheld", cached(repo), nil, "gradle", repo, false, agentOnly},
		{"a .m2/repository that is not the resolved one is scanned", with(cached("cache/m2"), map[string]string{
			repo + "/org/apache/maven/surefire/surefire/3.2.5/surefire-3.2.5.pom": pluginPOM,
		}), nil, "maven", "cache/m2", false, agentOnly},
		{"launch file at the repository root is scanned", with(cached(repo), map[string]string{repo + "/Dockerfile": agentFile}), nil, "maven", repo, false, agentOnly},
		{"launch file in a group directory is scanned", with(cached(repo), map[string]string{repo + "/com/acme/run.sh": agentFile}), nil, "maven", repo, false, agentOnly},
		{"non-artifact name in a version directory is scanned", with(cached(repo), map[string]string{repo + "/com/acme/app/1.0/start.sh": agentFile}), nil, "maven", repo, false, agentOnly},
		{"artifact-name prefix without a separator is scanned", with(cached(repo), map[string]string{repo + "/com/acme/app/1.0/app-1.0evil.sh": agentFile}), nil, "maven", repo, false, agentOnly},
		{"snapshot prefix without a timestamp is scanned", with(cached(repo), map[string]string{repo + "/com/acme/app/1.0-SNAPSHOT/app-1.0-local.sh": agentFile}), nil, "maven", repo, false, agentOnly},
		{"artifact-named file under the resolved repository is left out", with(cached(repo), map[string]string{repo + "/com/acme/app/1.0/app-1.0.sh": agentFile}), nil, "maven", repo, false, []string{}},
		{"project launch file outside the repository is scanned", with(cached(repo), map[string]string{"Dockerfile": agentFile}), nil, "maven", repo, false, agentOnly},
		{"repository at the checkout root is not left out", cached("."), nil, "maven", ".", false, agentOnly},
		{"repository in the checkout's parent is not left out", with(cached("@up"), map[string]string{"com/acme/app/1.0/app-1.0.sh": agentFile}), nil, "maven", "@up", false, agentOnly},
		{"graph naming its file by a relative path identifies no repository", cached(repo), nil, "maven", repo, true, agentOnly},
		{"artifact-shaped project file outside the repository is scanned", with(cached(repo), map[string]string{"com/acme/app/1.0/app-1.0.sh": agentFile}), nil, "maven", repo, false, agentOnly},
		{"artifact path with no group directory is scanned", with(cached(repo), map[string]string{repo + "/app/1.0/app-1.0.sh": agentFile}), nil, "maven", repo, false, agentOnly},
		{"linked artifact in the repository is left out", with(cached(repo), map[string]string{repo + "/com/acme/app/1.0/app-1.0-cached.pom": pluginPOM}),
			map[string]string{repo + "/com/acme/app/1.0/app-1.0.pom": "app-1.0-cached.pom"}, "maven", repo, false, []string{}},
		{"repository outside the checkout: clean checkout unchanged", with(cached("@out/m2"), map[string]string{"Dockerfile": "ENV JAVA_TOOL_OPTIONS=-Xmx1g\n"}), nil, "maven", "@out/m2", false, []string{}},
		{"repository outside the checkout: in-checkout cache still scanned", with(cached("@out/m2"), map[string]string{
			repo + "/org/apache/maven/surefire/surefire/3.2.5/surefire-3.2.5.pom": pluginPOM,
		}), nil, "maven", "@out/m2", false, agentOnly},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "checkout")
			at := func(rel string) string {
				if out, ok := strings.CutPrefix(rel, "@out/"); ok {
					return filepath.Join(base, "outside", filepath.FromSlash(out))
				}
				if up, ok := strings.CutPrefix(rel, "@up"); ok {
					return filepath.Join(base, filepath.FromSlash(up))
				}
				return filepath.Join(dir, filepath.FromSlash(rel))
			}
			for rel, content := range tt.files {
				writeFile(t, at(rel), content)
			}
			for rel, target := range tt.links {
				if err := os.Symlink(target, at(rel)); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			var g *buildgraph.Graph
			if tt.tool != "" {
				var deps []graphDep
				if tt.root != "" {
					d := dep
					d.jar = at(tt.root + "/" + dataJar)
					if tt.rel {
						t.Chdir(base)
						d.jar, _ = filepath.Rel(base, d.jar)
					}
					deps = append(deps, d)
				}
				g = &buildgraph.Graph{Tool: buildgraph.Tool{Name: tt.tool}, Modules: []buildgraph.Module{testModule(t, ".", "app", deps...)}}
			}
			got := LaunchOptionReasons(dir, g)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LaunchOptionReasons = %v, want %v", got, tt.want)
			}
			if strings.HasPrefix(tt.root, "@out/") {
				if unchanged := LaunchOptionReasons(dir, nil); !reflect.DeepEqual(got, unchanged) {
					t.Errorf("LaunchOptionReasons = %v, without the graph %v", got, unchanged)
				}
			}
		})
	}
}

func TestRepoArtifactName(t *testing.T) {
	for _, tt := range []struct {
		name, artifact, version string
		want                    bool
	}{
		{"a-1.0.pom", "a", "1.0", true},
		{"a-1.0.jar.sha1", "a", "1.0", true},
		{"a-1.0-tests.jar", "a", "1.0", true},
		{"a-1.0-SNAPSHOT.pom", "a", "1.0-SNAPSHOT", true},
		{"a-1.0-20240101.120000-1.jar", "a", "1.0-SNAPSHOT", true},
		{"a-1.0", "a", "1.0", false},
		{"a-1.0x.pom", "a", "1.0", false},
		{"b-1.0.pom", "a", "1.0", false},
		{"a-1.0-x.sh", "a", "1.0-SNAPSHOT", false},
		{"a--1.jar", "a", "-SNAPSHOT", false},
		{"pom.xml", "a", "1.0", false},
	} {
		if got := repoArtifactName(tt.name, tt.artifact, tt.version); got != tt.want {
			t.Errorf("repoArtifactName(%q, %q, %q) = %v, want %v", tt.name, tt.artifact, tt.version, got, tt.want)
		}
	}
}

// TestReachClosure_LocalRepositoryLaunchReasons: the Java closure hands the launch scan its
// graph, so a cached POM in the resolved in-checkout repository does not withhold Searched, and
// one in a directory merely named like it still does.
func TestReachClosure_LocalRepositoryLaunchReasons(t *testing.T) {
	const pluginPOM = "<plugin><artifactId>maven-surefire-plugin</artifactId><configuration><argLine>-javaagent:/a.jar</argLine></configuration></plugin>\n"
	for _, tt := range []struct {
		name, root string
		want       bool
	}{
		{"resolved repository", ".m2/repository", false},
		{"repository resolved elsewhere in the checkout", "cache/m2", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			jar := filepath.Join(dir, filepath.FromSlash(tt.root), "com/acme/lib/1.0/lib-1.0.jar")
			writeFile(t, jar, zipOf(map[string]string{"x.txt": ""}))
			writeFile(t, filepath.Join(dir, ".m2/repository/org/apache/maven/surefire/surefire/3.2.5/surefire-3.2.5.pom"), pluginPOM)
			opt := graphOption(t, "maven", testModule(t, ".", "app", graphDep{group: "com.acme", artifact: "lib", version: "1.0", jar: jar}))
			rc, err := loadReachClosure(dir, nil, depreach.Classpath{}, opt)
			if err != nil {
				t.Fatal(err)
			}
			if got := hasStr(rc.Reasons, PartialReasonLaunchAgent); got != tt.want {
				t.Errorf("Reasons = %v; %s present %v, want %v", rc.Reasons, PartialReasonLaunchAgent, got, tt.want)
			}
		})
	}
}
