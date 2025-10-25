package marketplace

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSafeJoinWithinBase(t *testing.T) {
	base := t.TempDir()

	target, err := safeJoin(base, filepath.Join("nested", "file.txt"))
	if err != nil {
		t.Fatalf("safeJoin returned error: %v", err)
	}
	expectedPrefix := base + string(filepath.Separator)
	if !strings.HasPrefix(target, expectedPrefix) {
		t.Fatalf("target %q should be within base %q", target, base)
	}
	if filepath.Base(target) != "file.txt" {
		t.Fatalf("unexpected target path: %q", target)
	}
}

func TestSafeJoinRejectsTraversal(t *testing.T) {
	base := t.TempDir()

	tests := []string{
		"../escape",
		filepath.Join("..", "escape"),
		filepath.Join("nested", "..", "..", "escape"),
	}
	for _, rel := range tests {
		rel := rel
		t.Run(rel, func(t *testing.T) {
			t.Parallel()
			if runtime.GOOS == "windows" {
				rel = strings.ReplaceAll(rel, "/", "\\")
			}
			if _, err := safeJoin(base, rel); err == nil {
				t.Fatalf("expected error for path %q", rel)
			}
		})
	}
}

func TestSafeJoinRejectsAbsolute(t *testing.T) {
	base := t.TempDir()

	abs := filepath.Join(base, "..", "outside")
	if !filepath.IsAbs(abs) {
		abs, _ = filepath.Abs(abs)
	}
	if _, err := safeJoin(base, abs); err == nil {
		t.Fatalf("expected error for absolute path %q", abs)
	}
}
