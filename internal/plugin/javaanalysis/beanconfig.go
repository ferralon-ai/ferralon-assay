package javaanalysis

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/beangraph"
)

// beanconfig.go reads legacy Spring XML application-context bean definitions — the
// pre-annotation wiring still common in older Spring apps — into the same bean model
// (#6, spring-surface.md §2). It is an on-disk read of .xml files under the build tree
// (zero-egress, §3.3); no context is instantiated. An XML bean is an ADDITIVE bean
// source: it only widens the candidate set (inv.5), never narrows or misdirects.

// xmlBean is one <bean> element's wiring-relevant attributes.
type xmlBean struct {
	class   string // fully-qualified implementation class
	id      string // bean id/name (a qualifier)
	primary bool
}

// xmlBeansFromDir scans buildDir recursively for Spring XML bean definitions and returns
// them as bean definitions in the Java lane's SIMPLE-name space. supers is the
// first-party direct-supertype map (from the source scan) so an XML bean's class can be
// indexed under the interfaces it implements; a class absent from that map contributes
// only its own simple type (its supertypes are unknown from XML alone — a bounded,
// sound under-approximation). Files that are not bean XML, or cannot be parsed, are
// skipped, never fatal.
func xmlBeansFromDir(buildDir string, supers map[string][]string) []beangraph.BeanDef {
	var beans []beangraph.BeanDef
	_ = filepath.WalkDir(buildDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".xml") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		for _, xb := range parseSpringXMLBeans(data) {
			// XML class attributes are dot-separated FQNs (com.ex.Foo); reduce to the
			// simple leaf the Java lexical lane keys on.
			simple := xb.class
			if k := strings.LastIndexAny(simple, "./$"); k >= 0 {
				simple = simple[k+1:]
			}
			if simple == "" {
				continue
			}
			quals := []string{decapitalize(simple)}
			if xb.id != "" {
				quals = append(quals, xb.id)
			}
			beans = append(beans, beangraph.BeanDef{
				Impl:       simple,
				Origin:     beangraph.OriginStereotype,
				Satisfies:  supertypeClosureNames(simple, supers),
				Qualifiers: dedupe(quals),
				Primary:    xb.primary,
			})
		}
		return nil
	})
	sort.Slice(beans, func(i, j int) bool { return beans[i].Impl < beans[j].Impl })
	return beans
}

// parseSpringXMLBeans extracts <bean class= id= primary=> elements from a Spring XML
// context body. It only recognizes a document whose root is a Spring <beans> element
// (namespace-agnostic on the local name) so an unrelated XML file yields nothing. A
// <bean> without a class attribute (a parent/factory-bean form) is irreducible — the
// impl is computed elsewhere — and is skipped rather than guessed.
func parseSpringXMLBeans(data []byte) []xmlBean {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	sawBeansRoot := false
	var out []xmlBean
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "beans":
			sawBeansRoot = true
		case "bean":
			if !sawBeansRoot {
				continue
			}
			var xb xmlBean
			for _, a := range se.Attr {
				switch a.Name.Local {
				case "class":
					xb.class = a.Value
				case "id", "name":
					if xb.id == "" {
						xb.id = a.Value
					}
				case "primary":
					xb.primary = a.Value == "true"
				}
			}
			if xb.class != "" {
				out = append(out, xb)
			}
		}
	}
	return out
}
