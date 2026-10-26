package pythonanalysis

import "testing"

// A requirements file's backslash continuations join the way pip joins them: the backslash and
// line break vanish with nothing in their place, a comment line never continues, and a line
// continued after an inline comment stays inside that comment.
func TestResolveVersions_RequirementsContinuation(t *testing.T) {
	tests := []struct {
		name string
		req  string
		want map[string]string // coordinate → pinned version; "" means not found
	}{
		{"control: no continuation", "flask==3.0.0\njinja2==3.1.4\n", map[string]string{"flask": "3.0.0", "jinja2": "3.1.4"}},
		{"split name", "fla\\\nsk==3.0.0\n", map[string]string{"flask": "3.0.0"}},
		{"split specifier", "flask==3.\\\n0.0\n", map[string]string{"flask": "3.0.0"}},
		{"comment line ending in a backslash does not continue", "# pinned below \\\nflask==3.0.0\n", map[string]string{"flask": "3.0.0"}},
		{"line continued after an inline comment stays in it", "jinja2==3.1.4 # pinned \\\nflask==3.0.0\n", map[string]string{"jinja2": "3.1.4", "flask": ""}},
		{"line continued into a comment line", "flask==3.0.0 \\\n# hashes follow\njinja2==3.1.4\n", map[string]string{"flask": "3.0.0", "jinja2": "3.1.4"}},
		{"hashed pin over continued lines", "flask==3.0.0 \\\n    --hash=sha256:aaa \\\n    --hash=sha256:bbb\njinja2==3.1.4\n", map[string]string{"flask": "3.0.0", "jinja2": "3.1.4"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"requirements.txt": tt.req})
			for coord, version := range tt.want {
				r := resolveVersion(t, dir, coord)
				if version == "" {
					if r.Found {
						t.Errorf("%s found (%+v), want not found", coord, r.Match)
					}
					continue
				}
				if !r.Found || !r.Match.Resolved || r.Match.Version != version {
					t.Errorf("%s: got found=%v %+v, want %s", coord, r.Found, r.Match, version)
				}
			}
		})
	}
}

// A marker split over a continuation is evaluated whole.
func TestResolveRequirements_ContinuedMarker(t *testing.T) {
	reqs := resolveRequirements([]byte("flask==3.0.0 ; python_ver\\\nsion >= \"3.8\"\n"), map[string]string{"python_version": "3.12"}, nil)
	if len(reqs) != 1 {
		t.Fatalf("got %d requirements, want 1: %+v", len(reqs), reqs)
	}
	r := reqs[0]
	if r.Name != "flask" || r.Marker != `python_version >= "3.8"` || !r.Selected || r.Unresolved {
		t.Fatalf("got %+v, want flask selected under python_version >= \"3.8\"", r)
	}
}

// A -r or -c include split over a continuation names the joined file, which the resolver reads.
func TestResolveVersions_ExhaustiveContinuedInclude(t *testing.T) {
	for _, flag := range []string{"-r", "-c"} {
		t.Run(flag, func(t *testing.T) {
			r := resolveVersion(t, writeTree(t, map[string]string{
				"uv.lock":              exUVLock,
				"pyproject.toml":       exPyproject,
				"requirements.txt":     flag + " requirements-\\\ndev.txt\nflask==3.0.0 --hash=sha256:aaa\n",
				"requirements-dev.txt": "jinja2==3.1.4 --hash=sha256:aaa\n",
			}), "PyJWT")
			if r.Found || !r.Exhaustive {
				t.Fatalf("Found=%v Exhaustive=%v, want absent and exhaustive (partiality %+v)", r.Found, r.Exhaustive, r.Partiality)
			}
		})
	}
}

// pip splits a requirements file wherever Python's str.splitlines does, not only at "\n". Each
// boundary below ends the flask line, so jinja2 is a requirement of its own; read as one line,
// jinja2 would be trailing text of the flask pin and go missing.
func TestResolveVersions_RequirementsLineBoundaries(t *testing.T) {
	boundaries := []struct{ name, sep string }{
		{"CR", "\r"},
		{"VT", "\v"},
		{"FF", "\f"},
		{"FS", "\x1c"},
		{"GS", "\x1d"},
		{"RS", "\x1e"},
		{"NEL", "\u0085"},
		{"LINE SEPARATOR", " "},
		{"PARAGRAPH SEPARATOR", " "},
	}
	for _, b := range boundaries {
		t.Run(b.name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{"requirements.txt": "flask==3.0.0" + b.sep + "jinja2==3.1.4\n"})
			for coord, version := range map[string]string{"flask": "3.0.0", "jinja2": "3.1.4"} {
				r := resolveVersion(t, dir, coord)
				if !r.Found || !r.Match.Resolved || r.Match.Version != version {
					t.Errorf("%s: got found=%v %+v, want %s", coord, r.Found, r.Match, version)
				}
			}
		})
	}
	t.Run("CR continuation", func(t *testing.T) {
		r := resolveVersion(t, writeTree(t, map[string]string{"requirements.txt": "flask==3.\\\r0.0\r"}), "flask")
		if !r.Found || !r.Match.Resolved || r.Match.Version != "3.0.0" {
			t.Errorf("flask: got found=%v %+v, want 3.0.0", r.Found, r.Match)
		}
	})
}
