package depreach

import (
	"testing"

	"github.com/ferralon-ai/ferralon-assay/internal/plugin/javaanalysis/classfile"
)

// TestEngine_Links: a named class links unless a supertype is neither loaded nor the JDK's,
// and so does each lambda site it holds unless the site's interface or a marker interface is
// neither loaded nor the JDK's. Only the named classes are checked.
func TestEngine_Links(t *testing.T) {
	const (
		app    = "com/acme/App"
		absent = "org/opt/Plugin"
		loaded = "com/acme/Handler"
	)
	lambda := func(produced string, markers ...string) classfile.Class {
		args := []classfile.BootstrapArg{{MethodType: "()V"}, handleArg(classfile.RefInvokeStatic, app, "lambda$0", "()V"), {MethodType: "()V"}}
		bsm, desc := "metafactory", lmfDesc
		if len(markers) > 0 {
			bsm, desc = "altMetafactory", lmfAltDesc
			args = append(args, classfile.BootstrapArg{})
			for _, m := range markers {
				args = append(args, classfile.BootstrapArg{Class: m})
			}
		}
		return class(app, objectClass, nil, meth(app, "make", "()L"+produced+";",
			indy("run", "()L"+produced+";", bootstrap(classfile.RefInvokeStatic, lmfOwner, bsm, desc, args...))))
	}
	tests := []struct {
		name    string
		classes []classfile.Class
		names   []string
		want    bool
	}{
		{"a class below loaded and JDK types", []classfile.Class{class(app, objectClass, []string{"java/lang/Runnable"})}, []string{app}, true},
		{"a class below an absent type", []classfile.Class{class(app, objectClass, []string{absent})}, []string{app}, false},
		{"a class below one below an absent type", []classfile.Class{class(app, loaded, nil), class(loaded, objectClass, []string{absent})}, []string{app}, false},
		{"an unlinkable class not named", []classfile.Class{class(app, objectClass, nil), class(loaded, objectClass, []string{absent})}, []string{app}, true},
		{"a name not loaded", nil, []string{app}, true},
		{"a lambda of a JDK interface", []classfile.Class{lambda("java/lang/Runnable")}, []string{app}, true},
		{"a lambda of a loaded interface", []classfile.Class{lambda(loaded), iface(loaded)}, []string{app}, true},
		{"a lambda of an absent interface", []classfile.Class{lambda(absent)}, []string{app}, false},
		{"a lambda with an absent marker interface", []classfile.Class{lambda("java/lang/Runnable", absent)}, []string{app}, false},
		{"a lambda with a JDK marker interface", []classfile.Class{lambda("java/lang/Runnable", "java/io/Serializable")}, []string{app}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewEngine(tt.classes).Links(tt.names); got != tt.want {
				t.Errorf("Links = %v, want %v", got, tt.want)
			}
		})
	}
}
