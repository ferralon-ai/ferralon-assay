package classfile

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// release.go — folding a multi-release JAR's version entries into one body per class.
//
// A JDK at release N or later loads META-INF/versions/N/<name>.class in place of the base
// entry, so either body may be the one that runs. A call graph keeps one class per binary
// name, so each override is merged into its base: the merged class declares every method
// either body declares, and a method both declare carries the union of both bodies' calls.
// A search over the merged class then covers what any release runs.
//
// The union is only sound while it leaves resolution unchanged. A member one body declares
// and the other does not would, in the merged class, hide an ancestor's member of the same
// name on the release that lacks it, so the ancestor's body would never be a target. Such a
// one-sided member is admitted only when no ancestor can declare it: every ancestor is
// loaded and none declares it, or the ancestor is java/lang/Object and the member is not one
// of Object's, or the ancestor is an unread java/ class and the member is a field or its
// descriptor names a type no JDK release defines (ReleaseMerge.JDKType). Only the boot and
// platform loaders define a java/ class, so it is JDK code, and JDK code is compiled against
// the JDK alone: everything above it is JDK code too, and none of it names a type outside the
// JDK. So no such ancestor declares the accessor javac emits for an instance member, which
// takes the class it serves. A field matters
// only for the class a getstatic or putstatic initializes, and a JDK class's initializer is
// JDK code, so a field the merged class hides from a java/ ancestor loses no application
// target. Private methods, constructors and static initializers are never resolved through
// an ancestor, so they are always admitted. A class whose two bodies disagree on the
// super class, the interfaces, or a shared method's flags cannot be merged at all. Two bodies
// whose @kotlin.Metadata differ leave the merged class with metadata that answers nothing,
// since either body's inline set may be the one that runs.

// ReleaseMerge accumulates the override bodies of one class set.
type ReleaseMerge struct {
	classes map[string]*Class
	// oneSided records, per class, the members only one body declares, for Check.
	oneSided map[string][]member
	// origin names the version entry each override came from, for conflict messages.
	origin map[string]string
	// JDKType reports whether some JDK release may define the named class. When nil, every
	// unread ancestor may declare any member.
	JDKType func(name string) bool
}

type member struct {
	field      bool
	name, desc string
}

// NewReleaseMerge starts a merge over classes, which it modifies in place: pass a slice the
// caller owns and indexes by name for the merge's lifetime.
func NewReleaseMerge(classes []Class) *ReleaseMerge {
	m := &ReleaseMerge{classes: make(map[string]*Class, len(classes)), oneSided: map[string][]member{}, origin: map[string]string{}}
	for i := range classes {
		m.classes[classes[i].Name] = &classes[i]
	}
	return m
}

// Lookup returns the class the merge holds under name.
func (m *ReleaseMerge) Lookup(name string) (*Class, bool) {
	c, ok := m.classes[name]
	return c, ok
}

// Add registers a class no base entry defines, so later overrides merge into it.
func (m *ReleaseMerge) Add(c *Class) { m.classes[c.Name] = c }

// Merge folds the override v into the class of the same name. It returns an error, and
// leaves the base unchanged, when the two bodies cannot be merged.
func (m *ReleaseMerge) Merge(v VersionedClass) error {
	base, ok := m.classes[v.Class.Name]
	if !ok {
		return fmt.Errorf("%s: no base class", v.Entry)
	}
	o := v.Class
	if base.Super != o.Super || !sameSet(base.Interfaces, o.Interfaces) {
		return fmt.Errorf("%s: super class or interfaces differ from the base entry", v.Entry)
	}
	byKey := make(map[string]int, len(base.Methods))
	for i, bm := range base.Methods {
		byKey[bm.Ref.Name+bm.Ref.Descriptor] = i
	}
	var added []Method
	var sided []member
	inOverride := map[string]bool{}
	for _, om := range o.Methods {
		key := om.Ref.Name + om.Ref.Descriptor
		inOverride[key] = true
		i, shared := byKey[key]
		if !shared {
			om.Ref.Owner = base.Name
			added = append(added, om)
			if resolvedByName(om) {
				sided = append(sided, member{name: om.Ref.Name, desc: om.Ref.Descriptor})
			}
			continue
		}
		bm := base.Methods[i]
		if bm.Static != om.Static || bm.Private != om.Private || bm.Abstract != om.Abstract || bm.Native != om.Native {
			return fmt.Errorf("%s: %s flags differ from the base entry", v.Entry, key)
		}
	}
	for _, bm := range base.Methods {
		if !inOverride[bm.Ref.Name+bm.Ref.Descriptor] && resolvedByName(bm) {
			sided = append(sided, member{name: bm.Ref.Name, desc: bm.Ref.Descriptor})
		}
	}
	baseFields := map[string]bool{}
	for _, f := range base.Fields {
		baseFields[f.Name+" "+f.Descriptor] = true
	}
	overFields := map[string]bool{}
	var addedFields []Field
	for _, f := range o.Fields {
		overFields[f.Name+" "+f.Descriptor] = true
		if !baseFields[f.Name+" "+f.Descriptor] {
			addedFields = append(addedFields, f)
			sided = append(sided, member{field: true, name: f.Name, desc: f.Descriptor})
		}
	}
	for _, f := range base.Fields {
		if !overFields[f.Name+" "+f.Descriptor] {
			sided = append(sided, member{field: true, name: f.Name, desc: f.Descriptor})
		}
	}

	for _, om := range o.Methods {
		i, shared := byKey[om.Ref.Name+om.Ref.Descriptor]
		if !shared {
			continue
		}
		bm := &base.Methods[i]
		bm.Edges = unionEdges(bm.Edges, om.Edges)
		bm.InitTriggers = unionStrings(bm.InitTriggers, om.InitTriggers)
		bm.StaticFieldRefs = unionFieldRefs(bm.StaticFieldRefs, om.StaticFieldRefs)
		bm.Public = bm.Public || om.Public
	}
	base.Methods = append(base.Methods, added...)
	base.Fields = append(base.Fields, addedFields...)
	base.KotlinMetadata = mergeKotlinMetadata(base.KotlinMetadata, o.KotlinMetadata)
	base.Abstract = base.Abstract && o.Abstract
	base.Public = base.Public || o.Public
	m.oneSided[base.Name] = append(m.oneSided[base.Name], sided...)
	m.origin[base.Name] = v.Entry
	return nil
}

// ReleaseConflict is a merged class whose union may hide an ancestor's member.
type ReleaseConflict struct {
	Class, Detail string
}

// Check reports, sorted by class, every merged class with a one-sided member an ancestor
// could also declare. Call it after every override is merged, so ancestors are seen merged
// too.
func (m *ReleaseMerge) Check() []ReleaseConflict {
	var out []ReleaseConflict
	for name, sided := range m.oneSided {
		for _, s := range sided {
			if why, bad := m.ancestorMayDeclare(name, s); bad {
				out = append(out, ReleaseConflict{Class: name, Detail: fmt.Sprintf("%s: one-sided %s%s %s", m.origin[name], s.name, s.desc, why)})
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Class < out[j].Class })
	return out
}

// objectMethods are java/lang/Object's declared methods, name plus descriptor.
var objectMethods = map[string]bool{
	"<init>()V": true, "getClass()Ljava/lang/Class;": true, "hashCode()I": true,
	"equals(Ljava/lang/Object;)Z": true, "clone()Ljava/lang/Object;": true,
	"toString()Ljava/lang/String;": true, "notify()V": true, "notifyAll()V": true,
	"wait()V": true, "wait(J)V": true, "wait(JI)V": true, "finalize()V": true,
}

func (m *ReleaseMerge) ancestorMayDeclare(name string, s member) (string, bool) {
	c := m.classes[name]
	seen := map[string]bool{}
	stack := append([]string{c.Super}, c.Interfaces...)
	for len(stack) > 0 {
		a := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		if a == "java/lang/Object" {
			if !s.field && objectMethods[s.name+s.desc] {
				return "hides a java/lang/Object method", true
			}
			continue
		}
		ac, ok := m.classes[a]
		if !ok {
			if strings.HasPrefix(a, "java/") && (s.field || m.namesNonJDKType(s.desc)) {
				continue
			}
			return "under ancestor " + a + ", whose members are unread", true
		}
		if s.field {
			for _, f := range ac.Fields {
				if f.Name == s.name && f.Descriptor == s.desc {
					return "hides a field of " + a, true
				}
			}
		} else {
			for _, am := range ac.Methods {
				if am.Ref.Name == s.name && am.Ref.Descriptor == s.desc {
					return "hides a method of " + a, true
				}
			}
		}
		stack = append(stack, ac.Super)
		stack = append(stack, ac.Interfaces...)
	}
	return "", false
}

// namesNonJDKType reports whether descriptor desc names a class no JDK release defines.
func (m *ReleaseMerge) namesNonJDKType(desc string) bool {
	if m.JDKType == nil {
		return false
	}
	for {
		i := strings.IndexByte(desc, 'L')
		if i < 0 {
			return false
		}
		j := strings.IndexByte(desc[i:], ';')
		if j < 0 {
			return false
		}
		if !m.JDKType(desc[i+1 : i+j]) {
			return true
		}
		desc = desc[i+j+1:]
	}
}

// resolvedByName reports whether a method can be selected through an ancestor's member of
// the same name: anything but a private method, a constructor or a static initializer.
func resolvedByName(m Method) bool {
	return !m.Private && m.Ref.Name != "<init>" && m.Ref.Name != "<clinit>"
}

func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	slices.Sort(x)
	slices.Sort(y)
	return slices.Equal(x, y)
}

func unionEdges(a, b []Edge) []Edge {
	out := slices.Clone(a)
	for _, e := range b {
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	return out
}

func unionStrings(a, b []string) []string {
	out := slices.Clone(a)
	for _, s := range b {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func unionFieldRefs(a, b []FieldRef) []FieldRef {
	out := slices.Clone(a)
	for _, f := range b {
		if !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}
