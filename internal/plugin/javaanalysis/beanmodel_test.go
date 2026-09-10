package javaanalysis

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/beangraph"
)

// scanSrc is a per-file convenience: clean + raw runes from one source string.
func scanSrc(pkg, src string) []sourceClass {
	return scanSourceClasses([]rune(stripJava(src)), []rune(src), pkg)
}

func TestScanSourceClasses_ServiceWithFieldInjection(t *testing.T) {
	src := `
package com.ex;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserRepo repo;
    private int count;
    public String fetch(String id) { return repo.byId(id); }
}
`
	classes := scanSrc("com.ex", src)
	if len(classes) != 1 {
		t.Fatalf("want 1 class, got %d", len(classes))
	}
	sc := classes[0]
	if !sc.isStereotype {
		t.Error("UserServiceImpl not recognized as a stereotype bean")
	}
	if len(sc.supers) != 1 || sc.supers[0] != "UserService" {
		t.Errorf("supers = %v, want [UserService]", sc.supers)
	}
	if len(sc.injections) != 1 || sc.injections[0].DeclaredType != "UserRepo" {
		t.Errorf("field injections = %+v, want one UserRepo", sc.injections)
	}

	data := buildSourceBeanData(classes)
	r := beangraph.NewRegistry(data.beans)
	got := r.Resolve(beangraph.InjectionPoint{DeclaredType: "UserService"})
	if !got.Found || got.Impl != "UserServiceImpl" {
		t.Errorf("Resolve(UserService) = %+v, want UserServiceImpl", got)
	}
	// The impl is a first-party class the resolver can mint an SCIP for.
	if _, ok := data.classLocs["UserServiceImpl"]; !ok {
		t.Error("classLocs missing UserServiceImpl")
	}
}

func TestScanSourceClasses_ConstructorInjectionWithQualifier(t *testing.T) {
	src := `
package com.ex;
@Service
public class Notifier {
    private final Mailer mailer;
    public Notifier(@Qualifier("ses") Mailer mailer, int retries) {
        this.mailer = mailer;
    }
}
`
	data := buildSourceBeanData(scanSrc("com.ex", src))
	key := ownerKey("com.ex", []string{"Notifier"})
	ips := data.injByOwner[key]
	if len(ips) != 1 {
		t.Fatalf("want 1 ctor injection (primitive dropped), got %+v", ips)
	}
	if ips[0].Site != "ctorParam" || ips[0].DeclaredType != "Mailer" || ips[0].Qualifier != "ses" {
		t.Errorf("ctor injection = %+v", ips[0])
	}
}

func TestScanSourceClasses_ConfigurationBeanMethodPrimary(t *testing.T) {
	src := `
package com.ex;
@Configuration
public class AppConfig {
    @Bean
    @Primary
    public Mailer smtpMailer() { return new SmtpMailer(); }

    @Bean
    public Mailer sesMailer() { return new SesMailer(); }
}
`
	classes := scanSrc("com.ex", src)
	sc := classes[0]
	if len(sc.beanMethods) != 2 {
		t.Fatalf("want 2 @Bean methods, got %d: %+v", len(sc.beanMethods), sc.beanMethods)
	}

	data := buildSourceBeanData(classes)
	r := beangraph.NewRegistry(data.beans)
	// Both @Bean methods return Mailer; @Primary smtpMailer wins.
	got := r.Resolve(beangraph.InjectionPoint{DeclaredType: "Mailer"})
	if !got.Found || got.Impl != "Mailer" {
		t.Errorf("Resolve(Mailer) = %+v", got)
	}
	// A @Qualifier by bean-method name selects a specific one.
	q := r.Resolve(beangraph.InjectionPoint{DeclaredType: "Mailer", Qualifier: "sesMailer"})
	if !q.Found {
		t.Errorf("Resolve(Mailer, @Qualifier sesMailer) = %+v, want found", q)
	}
}

func TestScanSourceClasses_TransitiveSupertypeAcrossFiles(t *testing.T) {
	a := scanSrc("com.ex", `package com.ex; @Service class Impl extends AbstractSvc {}`)
	b := scanSrc("com.ex", `package com.ex; abstract class AbstractSvc implements BaseSvc {}`)
	data := buildSourceBeanData(append(a, b...))
	r := beangraph.NewRegistry(data.beans)
	got := r.Resolve(beangraph.InjectionPoint{DeclaredType: "BaseSvc"})
	if !got.Found || got.Impl != "Impl" {
		t.Errorf("Resolve(BaseSvc) = %+v, want Impl via transitive closure", got)
	}
}

// TestScanSourceClasses_NoBeansIsInert proves a plain class produces no bean data — the
// H2 no-op precondition (behavior byte-identical to pre-bean-model when no beans exist).
func TestScanSourceClasses_NoBeansIsInert(t *testing.T) {
	data := buildSourceBeanData(scanSrc("com.ex", `package com.ex; public class Plain { void f(){} }`))
	if len(data.beans) != 0 {
		t.Errorf("plain class produced beans: %+v", data.beans)
	}
	if len(data.injByOwner) != 0 {
		t.Errorf("plain class produced injections: %+v", data.injByOwner)
	}
}

func TestSourceRepositoryTypes(t *testing.T) {
	a := scanSrc("com.ex", `package com.ex; interface UserRepo extends JpaRepository<User,Long> { User findByName(String n); }`)
	b := scanSrc("com.ex", `package com.ex; interface CustomBase extends CrudRepository<Object,Long> {}`)
	c := scanSrc("com.ex", `package com.ex; interface OrderRepo extends CustomBase {}`)
	d := scanSrc("com.ex", `package com.ex; interface UserService { String greet(); }`)
	repos := sourceRepositoryTypes(append(append(append(a, b...), c...), d...))
	for _, want := range []string{"UserRepo", "CustomBase", "OrderRepo"} {
		if !repos[want] {
			t.Errorf("%s not classified as a repository; got %v", want, repos)
		}
	}
	if repos["UserService"] {
		t.Errorf("UserService wrongly classified as a repository")
	}
}
