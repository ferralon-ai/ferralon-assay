package pythonanalysis

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/ferralon-ai/ferralon-assay/plugin"
)

// A package a build script's pip install names joins the inventory, scoped to the script or to
// the -r file it names, and a withheld script surface leaves the inventory partial.
func TestInventory_ScriptInstalls(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string // beside requirements.txt flask==3.0.0
		want    []string          // script node ID PURL pairs, sorted
		partial bool
	}{
		{"a bare pip install", map[string]string{"install.sh": "pip install pyjwt==1.5.0\n"},
			[]string{"install.sh#pyjwt pkg:pypi/pyjwt@1.5.0"}, true},
		{"a range stays unversioned", map[string]string{"install.sh": "pip install pyjwt\n"},
			[]string{"install.sh#pyjwt pkg:pypi/pyjwt"}, true},
		{"a -r file no manifest reads", map[string]string{"install.sh": "pip install -r deps/extra.in\n", "deps/extra.in": "pyjwt==1.5.0\n"},
			[]string{"deps/extra.in#pyjwt pkg:pypi/pyjwt@1.5.0"}, true},
		{"--requirement= beside the script", map[string]string{"ci/install.sh": "pip install --requirement=extra.in\n", "ci/extra.in": "pyjwt==1.5.0\n"},
			[]string{"ci/extra.in#pyjwt pkg:pypi/pyjwt@1.5.0"}, true},
		{"a -r file outside the tree", map[string]string{"Dockerfile": "FROM python:3.12\nRUN pip install -r /app/extra.in\n"}, nil, true},
		{"a Dockerfile RUN", map[string]string{"Dockerfile": "FROM python:3.12\nRUN pip install pyjwt==1.5.0\n"},
			[]string{"Dockerfile#pyjwt pkg:pypi/pyjwt@1.5.0"}, true},
		{"python -m pip and uv pip", map[string]string{"ci.sh": "uv pip install pyjwt\npython3 -m pip install 'requests[socks]==2.0'\n"},
			[]string{"ci.sh#pyjwt pkg:pypi/pyjwt", "ci.sh#requests pkg:pypi/requests@2.0"}, true},
		{"every install in a surface, one name twice", map[string]string{"install.sh": "pip install a==1\npip install a==2\n"},
			[]string{"install.sh#a pkg:pypi/a@1", "install.sh#a#2 pkg:pypi/a@2"}, true},
		{"options and their values are not requirements", map[string]string{"install.sh": "pip install -i https://x/simple --no-deps -c c.txt pyjwt==1.5.0\n"},
			[]string{"install.sh#pyjwt pkg:pypi/pyjwt@1.5.0"}, true},
		{"an expansion names nothing", map[string]string{"install.sh": "pip install $PKG\n"}, nil, true},
		{"a sample hook git never runs", map[string]string{".git/hooks/pre-commit.sample": "#!/bin/sh\npip install evil==1\n"}, nil, false},
		{"a pip self-upgrade", map[string]string{"install.sh": "pip install -U pip==24.0\n"},
			[]string{"install.sh#pip pkg:pypi/pip@24.0"}, false},
		{"an allowed -r of a read manifest adds nothing", map[string]string{"install.sh": "pip install -r requirements.txt\n"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"requirements.txt": "flask==3.0.0\n"}
			for k, v := range tt.files {
				files[k] = v
			}
			dir := writeTree(t, files)
			inv, err := ResolveInventory(context.Background(), plugin.ResolveInventoryRequest{BuildDir: dir})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, n := range inv.Nodes {
				if !strings.HasPrefix(n.ID, "requirements.txt#") {
					got = append(got, n.ID+" "+n.PURL)
				}
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("script nodes = %q, want %q", got, tt.want)
			}
			if _, ok := nodeByPURL(inv, "pkg:pypi/flask@3.0.0"); !ok {
				t.Error("the requirements.txt node is missing")
			}
			partial := slices.Contains(inv.Partiality.Reasons, plugin.PartialReasonToolFailure)
			if partial != tt.partial || inv.Partiality.Complete == tt.partial {
				t.Errorf("partiality = %+v, want tool_failure %v", inv.Partiality, tt.partial)
			}
		})
	}
}
