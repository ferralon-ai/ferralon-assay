package javaanalysis

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// withinDeadline runs fn and fails the test if it has not returned in time. A build file that is
// a FIFO blocks a plain open until something writes to it, so a reader that does not refuse it
// hangs instead of failing.
func withinDeadline(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("did not return within %v: a FIFO was opened for reading", d)
	}
}

func mustFIFO(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Fatal(err)
	}
}

// Every build file the Java lane reads is refused when it is not a regular file: the read fails,
// the reader takes its fail-closed branch, and nothing waits on a writer.
func TestBuildFileReads_RefuseAFIFO(t *testing.T) {
	const deadline = 5 * time.Second
	const enforced = "dependencyLocking {\n    lockAllConfigurations()\n}\n"
	const lock = "com.evil:netkit:1.0.0=compileClasspath,runtimeClasspath\n"
	const declares = enforced + "dependencies {\n    implementation 'com.evil:netkit:1.0.0'\n}\n"
	netkit := mavenPURL("com.evil", "netkit", "1.0.0")
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
		check func(t *testing.T, dir string)
	}{
		{"settings.gradle, project count", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "build.gradle"), "")
			writeFile(t, filepath.Join(dir, "src", "main", "java", "A.java"), "")
			mustFIFO(t, filepath.Join(dir, "settings.gradle"))
		}, func(t *testing.T, dir string) {
			if multi, why := multipleProjects(dir); !multi {
				t.Errorf("multipleProjects = false (%s), want true", why)
			}
		}},
		{"settings.gradle, lock confirmation", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "build.gradle"), declares)
			writeFile(t, filepath.Join(dir, "gradle.lockfile"), lock)
			mustFIFO(t, filepath.Join(dir, "settings.gradle"))
		}, func(t *testing.T, dir string) {
			if findNode(t, toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir()))), netkit) != nil {
				t.Error("netkit bound at its locked version with an unreadable settings script")
			}
		}},
		{"settings.gradle, project name", func(t *testing.T, dir string) {
			mustFIFO(t, filepath.Join(dir, "settings.gradle"))
		}, func(t *testing.T, dir string) {
			if got := gradleProjectRoot(dir); got != filepath.Base(dir) {
				t.Errorf("gradleProjectRoot = %q, want the directory name %q", got, filepath.Base(dir))
			}
		}},
		{"a subproject's build.gradle", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "settings.gradle"), "include 'a'\n")
			writeFile(t, filepath.Join(dir, "build.gradle"), "")
			writeFile(t, filepath.Join(dir, "a", "gradle.lockfile"), lock)
			mustFIFO(t, filepath.Join(dir, "a", "build.gradle"))
		}, func(t *testing.T, dir string) {
			if findNode(t, toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir()))), netkit) != nil {
				t.Error("netkit bound at its locked version with an unreadable build script")
			}
		}},
		{"build.gradle, lock confirmation", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "gradle.lockfile"), lock)
			mustFIFO(t, filepath.Join(dir, "build.gradle"))
		}, func(t *testing.T, dir string) {
			if findNode(t, toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir()))), netkit) != nil {
				t.Error("netkit bound at its locked version with an unreadable root build script")
			}
		}},
		{"build.gradle, JVM target", func(t *testing.T, dir string) {
			mustFIFO(t, filepath.Join(dir, "build.gradle"))
		}, func(t *testing.T, dir string) {
			if got := parseGradleManifest(filepath.Join(dir, "build.gradle")); got != "" {
				t.Errorf("parseGradleManifest = %q, want empty", got)
			}
		}},
		{"build.gradle, declared versions", func(t *testing.T, dir string) {
			mustFIFO(t, filepath.Join(dir, "build.gradle"))
		}, func(t *testing.T, dir string) {
			if _, ok := parseGradle(filepath.Join(dir, "build.gradle")); ok {
				t.Error("parseGradle read a FIFO")
			}
		}},
		{"gradle.lockfile", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "build.gradle"), declares)
			mustFIFO(t, filepath.Join(dir, "gradle.lockfile"))
		}, func(t *testing.T, dir string) {
			inv := toJSON(t, resolveGradle(dir, newGradleCache(t.TempDir())))
			if !hasStr(inv.Partiality.Reasons, reasonGradleLockUnparsed) {
				t.Errorf("want %s; partiality %+v", reasonGradleLockUnparsed, inv.Partiality)
			}
		}},
		{"version catalog", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "build.gradle"), "dependencies {\n    implementation libs.netkit\n}\n")
			mustFIFO(t, filepath.Join(dir, "gradle", "libs.versions.toml"))
		}, func(t *testing.T, dir string) {
			resolveGradle(dir, newGradleCache(t.TempDir()))
		}},
		{"root pom.xml, project count", func(t *testing.T, dir string) {
			mustFIFO(t, filepath.Join(dir, "pom.xml"))
		}, func(t *testing.T, dir string) {
			if multi, why := multipleProjects(dir); !multi {
				t.Errorf("multipleProjects = false (%s), want true", why)
			}
		}},
		{"nested pom.xml, project walk", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "pom.xml"), "<project><artifactId>a</artifactId></project>")
			mustFIFO(t, filepath.Join(dir, "sub", "pom.xml"))
		}, func(t *testing.T, dir string) {
			if multi, why := multipleProjects(dir); !multi {
				t.Errorf("multipleProjects = false (%s), want true", why)
			}
		}},
		{"nested pom.xml linking to a FIFO, project walk", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "pom.xml"), "<project><artifactId>a</artifactId></project>")
			mustFIFO(t, filepath.Join(dir, "f"))
			mustSymlink(t, filepath.Join("..", "f"), filepath.Join(dir, "sub", "pom.xml"))
		}, func(t *testing.T, dir string) {
			if multi, why := multipleProjects(dir); !multi {
				t.Errorf("multipleProjects = false (%s), want true", why)
			}
		}},
		{"pom.xml, module listing", func(t *testing.T, dir string) {
			mustFIFO(t, filepath.Join(dir, "pom.xml"))
		}, func(t *testing.T, dir string) {
			if !pomListsModules(filepath.Join(dir, "pom.xml")) {
				t.Error("pomListsModules = false for a POM it cannot read")
			}
		}},
		{"a FIFO under another name, project walk", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "pom.xml"), "<project><artifactId>a</artifactId></project>")
			mustFIFO(t, filepath.Join(dir, "notes"))
		}, func(t *testing.T, dir string) {
			if multi, why := multipleProjects(dir); !multi {
				t.Errorf("multipleProjects = false (%s), want true", why)
			}
		}},
		{"a link under another name to a FIFO the walk skips, project walk", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, "pom.xml"), "<project><artifactId>a</artifactId></project>")
			mustFIFO(t, filepath.Join(dir, ".git", "f"))
			mustSymlink(t, filepath.Join(".git", "f"), filepath.Join(dir, "notes"))
		}, func(t *testing.T, dir string) {
			if multi, why := multipleProjects(dir); !multi {
				t.Errorf("multipleProjects = false (%s), want true", why)
			}
		}},
		{"pom.xml, inventory", func(t *testing.T, dir string) {
			mustFIFO(t, filepath.Join(dir, "pom.xml"))
		}, func(t *testing.T, dir string) {
			if _, ok := parseMavenPOM(filepath.Join(dir, "pom.xml")); ok {
				t.Error("parseMavenPOM read a FIFO")
			}
			if inv := toJSON(t, resolveInventory(dir, newMavenCacheAt(t.TempDir()), newGradleCache(t.TempDir()), nil)); inv.Partiality.Complete {
				t.Error("inventory over an unreadable pom.xml is Complete")
			}
		}},
		{"pom.xml, manifest", func(t *testing.T, dir string) {
			mustFIFO(t, filepath.Join(dir, "pom.xml"))
		}, func(t *testing.T, dir string) {
			if _, ok := parsePOMProject(filepath.Join(dir, "pom.xml")); ok {
				t.Error("parsePOMProject read a FIFO")
			}
		}},
		{"pom.xml, declared versions", func(t *testing.T, dir string) {
			mustFIFO(t, filepath.Join(dir, "pom.xml"))
		}, func(t *testing.T, dir string) {
			if _, ok := parsePOM(filepath.Join(dir, "pom.xml")); ok {
				t.Error("parsePOM read a FIFO")
			}
		}},
		{".tool-versions and .sdkmanrc", func(t *testing.T, dir string) {
			mustFIFO(t, filepath.Join(dir, ".tool-versions"))
			mustFIFO(t, filepath.Join(dir, ".sdkmanrc"))
		}, func(t *testing.T, dir string) {
			if got := toolchainPin(dir); got != "" {
				t.Errorf("toolchainPin = %q, want empty", got)
			}
		}},
		{".sdkmanrc after a pinless .tool-versions", func(t *testing.T, dir string) {
			writeFile(t, filepath.Join(dir, ".tool-versions"), "nodejs 20.1.0\n")
			mustFIFO(t, filepath.Join(dir, ".sdkmanrc"))
		}, func(t *testing.T, dir string) {
			if got := toolchainPin(dir); got != "" {
				t.Errorf("toolchainPin = %q, want empty", got)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			withinDeadline(t, deadline, func() { tc.check(t, dir) })
		})
	}
}
