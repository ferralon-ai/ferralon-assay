package javaanalysis

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/buildgraph"
)

// This round trip runs a real Maven, so it needs the network and a JDK and runs only when
// ASSAY_BUILDGRAPH_MAVEN_BIN names Maven's bin directory, as buildgraph's real-tool tests do.

const springBootStarterPOM = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>3.3.5</version>
		<relativePath/>
	</parent>
	<groupId>com.example</groupId>
	<artifactId>demo</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<properties>
		<java.version>17</java.version>
	</properties>
	<dependencies>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-web</artifactId>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
	</dependencies>
	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
			</plugin>
		</plugins>
	</build>
</project>
`

const springBootMain = `package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DemoApplication {
	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}
}
`

// TestLaunchOptionReasons_MavenLocalRepositoryRoundTrip: a stock spring-boot-starter-parent
// 3.3.5 app, built with its local repository at .m2/repository in the checkout as a CI cache
// lays it out, then resolved by the producer against that repository. Its cached POMs and JARs
// withhold Searched when the scan has no graph; with the graph they are left out, and nothing
// else in the checkout withholds.
func TestLaunchOptionReasons_MavenLocalRepositoryRoundTrip(t *testing.T) {
	bin := os.Getenv("ASSAY_BUILDGRAPH_MAVEN_BIN")
	if bin == "" {
		t.Skip("ASSAY_BUILDGRAPH_MAVEN_BIN unset")
	}
	path := bin + string(os.PathListSeparator) + os.Getenv("PATH")
	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		path = filepath.Join(jh, "bin") + string(os.PathListSeparator) + path
	}
	env := append(os.Environ(), "PATH="+path)

	dir := filepath.Join(t.TempDir(), "demo")
	writeFile(t, filepath.Join(dir, "pom.xml"), springBootStarterPOM)
	writeFile(t, filepath.Join(dir, "src/main/java/com/example/demo/DemoApplication.java"), springBootMain)
	repo := filepath.Join(dir, ".m2", "repository")

	build := exec.Command(filepath.Join(bin, "mvn"), "-B", "-q", "-Dmaven.repo.local="+repo, "package")
	build.Dir, build.Env = dir, env
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("mvn package: %v\n%s", err, out)
	}
	g, err := buildgraph.Resolve(context.Background(), buildgraph.Request{
		Dir: dir, Tool: buildgraph.ToolMaven, WorkDir: filepath.Join(t.TempDir(), "w"), Env: env,
		Conditions: buildgraph.Conditions{Properties: map[string]string{"maven.repo.local": repo}},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	realRepo, err := filepath.EvalSymlinks(repo)
	if err != nil {
		t.Fatal(err)
	}
	var resolved []string
	for _, r := range buildgraph.LocalRepositories(g) {
		if real, err := filepath.EvalSymlinks(r); err == nil {
			resolved = append(resolved, real)
		}
	}
	if !reflect.DeepEqual(resolved, []string{realRepo}) {
		t.Fatalf("LocalRepositories = %v, want [%s]", resolved, realRepo)
	}

	// The files that withhold on their own, as the issue counted them.
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	var inRepo, outside []string
	_ = filepath.WalkDir(realDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		s := &launchScan{reasons: map[string]bool{}}
		rel, _ := filepath.Rel(realDir, p)
		s.file(p, filepath.ToSlash(rel))
		if len(s.reasons) == 0 {
			return nil
		}
		if strings.HasPrefix(p, realRepo+string(filepath.Separator)) {
			inRepo = append(inRepo, filepath.ToSlash(rel))
		} else {
			outside = append(outside, filepath.ToSlash(rel))
		}
		return nil
	})
	t.Logf("maven %s: %d local-repository files withhold on their own: %v", g.Tool.Version, len(inRepo), inRepo)
	if len(inRepo) == 0 {
		t.Fatal("no cached file withholds on its own; the round trip no longer reproduces the scan's input")
	}
	if len(outside) != 0 {
		t.Errorf("files outside the local repository withhold: %v", outside)
	}

	if got := LaunchOptionReasons(dir, nil); len(got) == 0 {
		t.Errorf("LaunchOptionReasons without the graph = %v, want withheld", got)
	}
	if got := LaunchOptionReasons(dir, g); !reflect.DeepEqual(got, []string{}) {
		t.Errorf("LaunchOptionReasons with the graph = %v, want none", got)
	}
}
