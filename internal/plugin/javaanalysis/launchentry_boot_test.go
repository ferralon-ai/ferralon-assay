package javaanalysis

import (
	"path/filepath"
	"slices"
	"testing"
)

// With no main named in the build, the main spring-boot-maven-plugin finds itself is the launch
// entry: the one public static main(String[]), preferring a class annotated
// @SpringBootApplication. Several candidates fail the Boot build and anything in the build that
// can hand the plugin a main bootMain does not see keeps launch_entry_unnamed.
func TestBytecodeReach_BootMainDetection(t *testing.T) {
	boot := []string{springBootApplication}
	main := mainCalling(justReturn)
	noProfiles := map[string]string{"maven.profiles": ","}
	tests := []struct {
		name   string
		setup  func(a *appFixture)
		env    map[string]string
		reason string // "" for a row that stays Searched
	}{
		{name: "annotated main: searched", setup: func(a *appFixture) {
			a.bootApp(boot)
		}},
		{name: "one unannotated main: searched", setup: func(a *appFixture) {
			a.bootApp(nil)
		}},
		{name: "annotated main preferred over another main: searched", setup: func(a *appFixture) {
			a.bootApp(boot)
			a.class("target/classes", "com/acme/Tool", main)
		}},
		{name: "two unannotated mains: launch_entry_unnamed", setup: func(a *appFixture) {
			a.bootApp(nil)
			a.class("target/classes", "com/acme/Tool", main)
		}, reason: reasonLaunchEntryUnnamed},
		{name: "two annotated mains: launch_entry_unnamed", setup: func(a *appFixture) {
			a.bootApp(boot)
			a.classA("target/classes", "com/acme/Tool", "java/lang/Object", nil, 0x0021, boot, main)
		}, reason: reasonLaunchEntryUnnamed},
		{name: "annotated main is not static: launch_entry_unnamed", setup: func(a *appFixture) {
			a.bootPOM()
			a.classA("target/classes", "com/acme/App", "java/lang/Object", nil, 0x0021, boot, func(b *cpb) []xmethod {
				return []xmethod{{"main", mainDescriptor, accPublic, ret}}
			})
		}, reason: reasonLaunchEntryUnnamed},
		{name: "annotated main is not public: launch_entry_unnamed", setup: func(a *appFixture) {
			a.bootPOM()
			a.classA("target/classes", "com/acme/App", "java/lang/Object", nil, 0x0021, boot, func(b *cpb) []xmethod {
				return []xmethod{{"main", mainDescriptor, 0x0008, ret}}
			})
		}, reason: reasonLaunchEntryUnnamed},
		// The plugin's pick (Tool: the only public static main) and the broader pick (App: the
		// only annotated main) differ, so neither is trusted.
		{name: "annotated instance main beside a static main: launch_entry_unnamed", setup: func(a *appFixture) {
			a.bootPOM()
			a.classA("target/classes", "com/acme/App", "java/lang/Object", nil, 0x0021, boot, func(b *cpb) []xmethod {
				return []xmethod{{"main", mainDescriptor, accPublic, ret}}
			})
			a.class("target/classes", "com/acme/Tool", main)
		}, reason: reasonLaunchEntryUnnamed},
		{name: "a second, non-public main: launch_entry_unnamed", setup: func(a *appFixture) {
			a.bootApp(nil)
			a.class("target/classes", "com/acme/Tool", func(b *cpb) []xmethod {
				return []xmethod{{"main", mainDescriptor, 0x0008, ret}}
			})
		}, reason: reasonLaunchEntryUnnamed},
		{name: "no Boot plugin: launch_entry_unnamed", setup: func(a *appFixture) {
			a.editPOM(pomMainClass, "")
			a.classA("target/classes", "com/acme/App", "java/lang/Object", nil, 0x0021, boot, main)
		}, reason: reasonLaunchEntryUnnamed},
		{name: "Boot plugin artifactId without its groupId: launch_entry_unnamed", setup: func(a *appFixture) {
			a.bootApp(boot)
			a.editPOM(`<groupId>org.springframework.boot</groupId>`, "")
		}, reason: reasonLaunchEntryUnnamed},
		{name: "starter-parent ${start-class} wiring: searched", setup: func(a *appFixture) {
			a.bootApp(boot)
			a.cachedParent(starterParentWiring(""))
		}},
		{name: "parent sets start-class: launch_entry_unnamed", setup: func(a *appFixture) {
			a.bootApp(boot)
			a.cachedParent(starterParentWiring(`<start-class>com.acme.Tool</start-class>`))
		}, reason: reasonLaunchEntryUnnamed},
		{name: "parent configures a literal mainClass: launch_entry_unnamed", setup: func(a *appFixture) {
			a.bootApp(boot)
			a.cachedParent(`<build><pluginManagement><plugins><plugin><artifactId>maven-jar-plugin</artifactId>` +
				`<configuration><archive><manifest><mainClass>com.acme.Tool</mainClass></manifest></archive></configuration>` +
				`</plugin></plugins></pluginManagement></build>`)
		}, reason: reasonLaunchEntryUnnamed},
		{name: "jar plugin manifestFile: launch_entry_unnamed", setup: func(a *appFixture) {
			a.bootApp(boot)
			a.editPOM(`</plugins>`, `<plugin><artifactId>maven-jar-plugin</artifactId><configuration><archive>`+
				`<manifestFile>src/main/manifest/MANIFEST.MF</manifestFile></archive></configuration></plugin></plugins>`)
		}, reason: reasonLaunchEntryUnnamed},
		{name: "unread parent: launch_entry_unnamed", setup: func(a *appFixture) {
			a.bootApp(boot)
			a.editPOM(`<modelVersion>4.0.0</modelVersion>`, `<modelVersion>4.0.0</modelVersion>`+
				`<parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0.0</version></parent>`)
		}, reason: reasonLaunchEntryUnnamed},
		{name: "spring-boot.run.main-class set: launch_entry_unnamed", setup: func(a *appFixture) {
			a.bootApp(boot)
			a.editPOM(`<dependencies>`, `<properties><spring-boot.run.main-class>com.acme.Tool</spring-boot.run.main-class></properties><dependencies>`)
		}, reason: reasonLaunchEntryUnnamed},
		// Profile properties count whether or not the profile is active: a profile the run
		// does not select still blocks, so selection never decides the Boot main.
		{name: "profile with another property, none selected: searched", setup: func(a *appFixture) {
			a.bootApp(boot)
			a.editPOM(`</project>`, `<profiles><profile><id>x</id><properties><deploy.env>prod</deploy.env></properties></profile></profiles></project>`)
		}, env: noProfiles},
		{name: "profile sets spring-boot.run.main-class, none selected: launch_entry_unnamed", setup: func(a *appFixture) {
			a.bootApp(boot)
			a.editPOM(`</project>`, `<profiles><profile><id>x</id><properties><spring-boot.run.main-class>com.acme.Tool</spring-boot.run.main-class></properties></profile></profiles></project>`)
		}, env: noProfiles, reason: reasonLaunchEntryUnnamed},
		{name: "CI workflow -Dstart-class: launch_entry_cli_property", setup: func(a *appFixture) {
			a.bootApp(boot)
			writeFileT(t, filepath.Join(a.build, ".github", "workflows", "ci.yml"), ciMaven("-Dstart-class=com.acme.Tool"))
		}, reason: reasonLaunchEntryCLIProperty},
		{name: "CI workflow -Dspring-boot.run.main-class: launch_entry_cli_property", setup: func(a *appFixture) {
			a.bootApp(boot)
			writeFileT(t, filepath.Join(a.build, ".github", "workflows", "ci.yml"), ciMaven("-Dspring-boot.run.main-class=com.acme.Tool"))
		}, reason: reasonLaunchEntryCLIProperty},
		{name: "mains in two class output directories: launch_entry_unnamed", setup: func(a *appFixture) {
			a.bootApp(boot)
			a.class("build/classes/java/main", "com/acme/Tool", main)
		}, reason: reasonLaunchEntryUnnamed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := newApp(t, "", false)
			a.source("src/main/java/com/acme/App.java", appSource)
			tt.setup(a)
			res := a.reachUnder(tt.env, netkitSinkID)
			if tt.reason == "" {
				if !slices.Equal(res.Searched, []string{netkitSinkID}) {
					t.Fatalf("Searched = %v, partiality %+v", res.Searched, res.Partiality)
				}
				return
			}
			if len(res.Searched) != 0 {
				t.Fatalf("Searched despite %s: %v", tt.reason, res.Searched)
			}
			if !hasReason(res.Partiality, tt.reason) {
				t.Errorf("missing run-wide %s: %+v", tt.reason, res.Partiality)
			}
		})
	}
}

// bootPOM swaps the fixture's jar-plugin mainClass for spring-boot-maven-plugin with no main
// configured.
func (a *appFixture) bootPOM() {
	a.t.Helper()
	a.editPOM(pomMainClass, "")
	a.editPOM(`<artifactId>maven-jar-plugin</artifactId>`, `<groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId>`)
}

// bootApp is bootPOM with com.acme.App compiled as a public static main carrying annos.
func (a *appFixture) bootApp(annos []string) {
	a.t.Helper()
	a.bootPOM()
	a.classA("target/classes", "com/acme/App", "java/lang/Object", nil, 0x0021, annos, mainCalling(justReturn))
}

// starterParentWiring is the launch wiring spring-boot-starter-parent 3.3.5 carries in its
// pluginManagement, plus extra properties.
func starterParentWiring(props string) string {
	return `<properties>` + props + `<spring-boot.run.main-class>${start-class}</spring-boot.run.main-class></properties>
  <build><pluginManagement><plugins>
    <plugin><artifactId>maven-jar-plugin</artifactId><configuration><archive><manifest><mainClass>${start-class}</mainClass></manifest></archive></configuration></plugin>
    <plugin><groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId>
      <executions><execution><id>repackage</id><goals><goal>repackage</goal></goals></execution></executions>
      <configuration><mainClass>${spring-boot.run.main-class}</mainClass></configuration></plugin>
  </plugins></pluginManagement></build>`
}
