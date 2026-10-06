package gittest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScrubDropsLocatingVarsAndKeepsTheRest(t *testing.T) {
	in := []string{
		"PATH=/usr/bin",
		"GIT_DIR=/repo/.git",
		"GIT_WORK_TREE=/repo",
		"GIT_INDEX_FILE=/repo/.git/index.lock",
		"GIT_CONFIG_KEY_0=core.bare",
		"GIT_CONFIG_VALUE_0=true",
		"GIT_AUTHOR_NAME=someone",
		"GIT_TERMINAL_PROMPT=0",
	}
	got := strings.Join(Scrub(in), " ")
	for _, gone := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_AUTHOR_NAME"} {
		if strings.Contains(got, gone) {
			t.Errorf("Scrub kept %s: %s", gone, got)
		}
	}
	for _, kept := range []string{"PATH=/usr/bin", "GIT_TERMINAL_PROMPT=0"} {
		if !strings.Contains(got, kept) {
			t.Errorf("Scrub dropped %s: %s", kept, got)
		}
	}
}

func TestCommandIgnoresInheritedRepository(t *testing.T) {
	enclosing := t.TempDir()
	t.Setenv("GIT_DIR", enclosing)
	t.Setenv("GIT_WORK_TREE", enclosing)

	fixture := t.TempDir()
	cmd := Command("init", "-q")
	cmd.Dir = fixture
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(fixture, ".git")); err != nil {
		t.Fatalf("fixture was not initialised: %v", err)
	}
	if entries, _ := os.ReadDir(enclosing); len(entries) != 0 {
		t.Fatalf("git wrote into the inherited GIT_DIR: %v", entries)
	}
}
