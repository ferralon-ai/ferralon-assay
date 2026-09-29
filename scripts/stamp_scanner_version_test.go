// Self-test for stamp-scanner-version.sh, the release workflow's leaf stamp. It runs the script
// against copies of the real action.yml, so a reshaped input block fails here rather than at a cut.
package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const stampActionYML = "../action.yml"

func stampScript(t *testing.T) string {
	t.Helper()
	s, err := filepath.Abs("stamp-scanner-version.sh")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func runStamp(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command("bash", append([]string{stampScript(t)}, args...)...).CombinedOutput()
	return string(out), err
}

// actionCopy writes the real action.yml, with optional edits applied, into a temp file.
func actionCopy(t *testing.T, edit func(string) string) string {
	t.Helper()
	data, err := os.ReadFile(stampActionYML)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	if edit != nil {
		s = edit(s)
	}
	p := filepath.Join(t.TempDir(), "action.yml")
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// scannerDefault returns the `default:` line of the scanner-version input.
func scannerDefault(t *testing.T, s string) string {
	t.Helper()
	_, rest, ok := strings.Cut(s, "\n  scanner-version:\n")
	if !ok {
		t.Fatal("no scanner-version input")
	}
	for _, line := range strings.Split(rest, "\n") {
		if strings.HasPrefix(line, "    default:") {
			return line
		}
	}
	t.Fatal("scanner-version input has no default")
	return ""
}

// The committed action.yml is what every branch carries, and every cut starts from: a vX.Y alias.
func TestCommittedActionCarriesMinorAlias(t *testing.T) {
	if out, err := runStamp(t, "check", stampActionYML); err != nil {
		t.Fatalf("check on the committed action.yml: %v\n%s", err, out)
	}
}

func TestStampScannerVersion(t *testing.T) {
	t.Run("stamps exactly the default line", func(t *testing.T) {
		p := actionCopy(t, nil)
		before, _ := os.ReadFile(p)
		if out, err := runStamp(t, "stamp", "v9.8.7", p); err != nil {
			t.Fatalf("stamp: %v\n%s", err, out)
		}
		after, _ := os.ReadFile(p)
		b, a := strings.Split(string(before), "\n"), strings.Split(string(after), "\n")
		if len(b) != len(a) {
			t.Fatalf("stamp changed the line count: %d -> %d", len(b), len(a))
		}
		var diffs []int
		for i := range b {
			if b[i] != a[i] {
				diffs = append(diffs, i)
			}
		}
		if len(diffs) != 1 {
			t.Fatalf("stamp changed %d lines, want 1", len(diffs))
		}
		if got := scannerDefault(t, string(after)); got != `    default: "v9.8.7"` {
			t.Fatalf("stamped default line = %q", got)
		}
	})

	t.Run("the alias need not match the release minor", func(t *testing.T) {
		p := actionCopy(t, nil)
		if out, err := runStamp(t, "stamp", "v1.0.0", p); err != nil {
			t.Fatalf("stamp: %v\n%s", err, out)
		}
	})

	t.Run("a stamped file is refused by check and by a second stamp", func(t *testing.T) {
		p := actionCopy(t, nil)
		if out, err := runStamp(t, "stamp", "v9.8.7", p); err != nil {
			t.Fatalf("stamp: %v\n%s", err, out)
		}
		stamped, _ := os.ReadFile(p)
		for _, args := range [][]string{{"check", p}, {"stamp", "v9.8.8", p}} {
			out, err := runStamp(t, args...)
			if err == nil || !strings.Contains(out, "expected a minor alias") {
				t.Fatalf("%v: err=%v, want refusal naming the alias\n%s", args[0], err, out)
			}
		}
		if now, _ := os.ReadFile(p); string(now) != string(stamped) {
			t.Fatal("a refused stamp modified the file")
		}
	})

	refusals := []struct {
		name    string
		version string
		edit    func(string) string
		wantErr string
	}{
		{name: "release version without a patch", version: "v9.8", wantErr: "is not a vX.Y.Z release version"},
		{name: "release version with junk", version: "v9.8.7;rm", wantErr: "is not a vX.Y.Z release version"},
		{name: "branch carries an exact version", version: "v9.8.7",
			edit: func(s string) string {
				return strings.Replace(s, scannerDefault(t, s), `    default: "v0.3.1"`, 1)
			},
			wantErr: "expected a minor alias"},
		{name: "input block has no default", version: "v9.8.7",
			edit: func(s string) string {
				return strings.Replace(s, scannerDefault(t, s)+"\n", "", 1)
			},
			wantErr: "found 0"},
		{name: "input block has two defaults", version: "v9.8.7",
			edit: func(s string) string {
				d := scannerDefault(t, s)
				return strings.Replace(s, d, d+"\n"+d, 1)
			},
			wantErr: "found 2"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			p := actionCopy(t, tc.edit)
			before, _ := os.ReadFile(p)
			out, err := runStamp(t, "stamp", tc.version, p)
			if err == nil || !strings.Contains(out, tc.wantErr) {
				t.Fatalf("err=%v, want failure containing %q\n%s", err, tc.wantErr, out)
			}
			if after, _ := os.ReadFile(p); string(after) != string(before) {
				t.Fatal("a refused stamp modified the file")
			}
		})
	}
}
