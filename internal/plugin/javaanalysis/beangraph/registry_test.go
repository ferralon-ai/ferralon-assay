package beangraph

import "testing"

// bean is a terse BeanDef constructor for tests; satisfies always includes impl.
func bean(impl string, satisfies ...string) BeanDef {
	return BeanDef{Impl: impl, Satisfies: append([]string{impl}, satisfies...)}
}

func (b BeanDef) primary() BeanDef { b.Primary = true; return b }
func (b BeanDef) quals(q ...string) BeanDef {
	b.Qualifiers = append(b.Qualifiers, q...)
	return b
}

func TestResolve(t *testing.T) {
	tests := []struct {
		name  string
		beans []BeanDef
		ip    InjectionPoint
		want  Resolution
	}{
		{
			name:  "unique satisfying impl resolves",
			beans: []BeanDef{bean("UserServiceImpl", "UserService")},
			ip:    InjectionPoint{DeclaredType: "UserService"},
			want:  Resolution{Impl: "UserServiceImpl", Found: true},
		},
		{
			name:  "no satisfying bean is unknown, not ambiguous",
			beans: []BeanDef{bean("UserServiceImpl", "UserService")},
			ip:    InjectionPoint{DeclaredType: "PaymentService"},
			want:  Resolution{},
		},
		{
			name: "two impls, no primary/qualifier is ambiguous",
			beans: []BeanDef{
				bean("SmtpMailer", "Mailer"),
				bean("SesMailer", "Mailer"),
			},
			ip:   InjectionPoint{DeclaredType: "Mailer"},
			want: Resolution{Ambiguous: true},
		},
		{
			name: "primary breaks the tie",
			beans: []BeanDef{
				bean("SmtpMailer", "Mailer"),
				bean("SesMailer", "Mailer").primary(),
			},
			ip:   InjectionPoint{DeclaredType: "Mailer"},
			want: Resolution{Impl: "SesMailer", Found: true},
		},
		{
			name: "two primaries is still ambiguous",
			beans: []BeanDef{
				bean("SmtpMailer", "Mailer").primary(),
				bean("SesMailer", "Mailer").primary(),
			},
			ip:   InjectionPoint{DeclaredType: "Mailer"},
			want: Resolution{Ambiguous: true},
		},
		{
			name: "qualifier selects the matching bean",
			beans: []BeanDef{
				bean("SmtpMailer", "Mailer").quals("smtp"),
				bean("SesMailer", "Mailer").quals("ses"),
			},
			ip:   InjectionPoint{DeclaredType: "Mailer", Qualifier: "ses"},
			want: Resolution{Impl: "SesMailer", Found: true},
		},
		{
			name: "qualifier matching two impls is ambiguous",
			beans: []BeanDef{
				bean("SmtpMailer", "Mailer").quals("fast"),
				bean("SesMailer", "Mailer").quals("fast"),
			},
			ip:   InjectionPoint{DeclaredType: "Mailer", Qualifier: "fast"},
			want: Resolution{Ambiguous: true},
		},
		{
			name: "qualifier matching nothing is unknown",
			beans: []BeanDef{
				bean("SmtpMailer", "Mailer").quals("smtp"),
			},
			ip:   InjectionPoint{DeclaredType: "Mailer", Qualifier: "carrier-pigeon"},
			want: Resolution{},
		},
		{
			name: "same impl indexed twice under a type is not ambiguous",
			beans: []BeanDef{
				bean("UserServiceImpl", "UserService", "UserService"),
			},
			ip:   InjectionPoint{DeclaredType: "UserService"},
			want: Resolution{Impl: "UserServiceImpl", Found: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRegistry(tt.beans)
			got := r.Resolve(tt.ip)
			if got != tt.want {
				t.Errorf("Resolve(%+v) = %+v, want %+v", tt.ip, got, tt.want)
			}
		})
	}
}

// TestResolveOrderIndependent proves resolution does not depend on bean input order —
// the winner rules are set-based (a determinism guard for the emitted edge set).
func TestResolveOrderIndependent(t *testing.T) {
	a := []BeanDef{
		bean("SmtpMailer", "Mailer"),
		bean("SesMailer", "Mailer").primary(),
	}
	b := []BeanDef{
		bean("SesMailer", "Mailer").primary(),
		bean("SmtpMailer", "Mailer"),
	}
	ip := InjectionPoint{DeclaredType: "Mailer"}
	if NewRegistry(a).Resolve(ip) != NewRegistry(b).Resolve(ip) {
		t.Error("resolution depends on input order")
	}
}
