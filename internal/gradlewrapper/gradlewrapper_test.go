package gradlewrapper

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// StockGradleWrapper reads the properties only from a regular file it opened without blocking:
// missing properties are no wrapper, and anything else it can't read that way is not stock.
func TestStockGradleWrapper_ReadsOnlyARegularFile(t *testing.T) {
	const stock = "distributionUrl=https\\://services.gradle.org/distributions/gradle-8.5-bin.zip\n"
	write := func(t *testing.T, path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, props string)
		want  bool
	}{
		{"no properties", func(t *testing.T, props string) {}, true},
		{"stock properties", func(t *testing.T, props string) { write(t, props, stock) }, true},
		{"custom distribution", func(t *testing.T, props string) {
			write(t, props, "distributionUrl=https\\://repo.example.com/gradle-8.5-custom.zip\n")
		}, false},
		{"a FIFO", func(t *testing.T, props string) {
			if err := syscall.Mkfifo(props, 0o644); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"a symlink to stock properties", func(t *testing.T, props string) {
			target := filepath.Join(filepath.Dir(props), "real.properties")
			write(t, target, stock)
			if err := os.Symlink(target, props); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"a directory", func(t *testing.T, props string) {
			if err := os.Mkdir(props, 0o755); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"stock properties that can't be opened", func(t *testing.T, props string) {
			if os.Geteuid() == 0 {
				t.Skip("root ignores file permissions")
			}
			write(t, props, stock)
			if err := os.Chmod(props, 0); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"a wrapper directory that can't be searched", func(t *testing.T, props string) {
			if os.Geteuid() == 0 {
				t.Skip("root ignores directory permissions")
			}
			write(t, props, stock)
			dir := filepath.Dir(props)
			if err := os.Chmod(dir, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := t.TempDir()
			wrapper := filepath.Join(build, "gradle", "wrapper")
			if err := os.MkdirAll(wrapper, 0o755); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, filepath.Join(wrapper, "gradle-wrapper.properties"))
			done := make(chan bool, 1)
			go func() { done <- StockGradleWrapper(build) }()
			select {
			case got := <-done:
				if got != tc.want {
					t.Errorf("StockGradleWrapper = %v, want %v", got, tc.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("StockGradleWrapper did not return: the properties were opened blocking")
			}
		})
	}
}
