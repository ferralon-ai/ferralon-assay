package javaanalysis

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

func TestParseSpringXMLBeans(t *testing.T) {
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans">
  <bean id="mailer" class="com.ex.SmtpMailer" primary="true"/>
  <bean class="com.ex.PlainBean"/>
  <bean id="noclass"/>
</beans>`
	got := parseSpringXMLBeans([]byte(xml))
	if len(got) != 2 {
		t.Fatalf("want 2 beans (class-less skipped), got %d: %+v", len(got), got)
	}
	if got[0].class != "com.ex.SmtpMailer" || got[0].id != "mailer" || !got[0].primary {
		t.Errorf("first bean = %+v", got[0])
	}
}

// TestParseSpringXMLBeans_NonSpringXMLIgnored: a non-<beans> document yields nothing.
func TestParseSpringXMLBeans_NonSpringXMLIgnored(t *testing.T) {
	if got := parseSpringXMLBeans([]byte(`<project><bean class="x.Y"/></project>`)); len(got) != 0 {
		t.Errorf("non-Spring XML produced beans: %+v", got)
	}
}

// TestXMLBean_ResolvesInjection: an interface impl declared ONLY in XML (no stereotype
// annotation) still resolves an @Autowired interface injection — end to end.
func TestXMLBean_ResolvesInjection(t *testing.T) {
	t.Setenv(scipAnalyzerImageEnv, "")
	dir := writeModule(t, map[string]string{
		"Mailer.java":     `package com.ex; interface Mailer { void send(); }`,
		"SmtpMailer.java": `package com.ex; class SmtpMailer implements Mailer { public void send(){} }`,
		"Notifier.java":   `package com.ex; @Service class Notifier { @Autowired Mailer mailer; void go(){ mailer.send(); } }`,
		"context.xml": `<beans xmlns="http://www.springframework.org/schema/beans">
  <bean id="mailer" class="com.ex.SmtpMailer"/>
</beans>`,
	})

	cg, err := CallGraph(t.Context(), plugin.CallGraphRequest{BuildDir: dir})
	if err != nil {
		t.Fatalf("CallGraph: %v", err)
	}
	if !hasEdgeContaining(cg.Edges, "Notifier#go", "SmtpMailer#send") {
		t.Errorf("XML-declared bean did not resolve the interface injection; edges=%+v", cg.Edges)
	}
}
