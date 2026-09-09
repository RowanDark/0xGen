package launcher

import (
	"debug/elf"
	"path/filepath"
	"runtime"
	"testing"
)

// TestBuildGoBinaryStaticallyLinksExampleHello is a regression test for the
// sandbox ENOENT failure caused by cgo-enabled builds: Run stages only the
// plugin and sandbox binaries into the chroot, with no dynamic loader or
// libc, so a dynamically linked plugin binary fails execve with an opaque
// "no such file or directory" rather than a clear build error. It builds
// plugins/example-hello through the same buildGoBinary path Run uses and
// asserts the resulting artifact has no PT_INTERP segment.
func TestBuildGoBinaryStaticallyLinksExampleHello(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("static-link assertion only applies on linux, where the sandbox chroots")
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("determine test file path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", ".."))
	pluginDir := filepath.Join(repoRoot, "plugins", "example-hello")

	outPath := filepath.Join(t.TempDir(), "example-hello")
	if err := buildGoBinary(pluginDir, ".", outPath, nil, nil); err != nil {
		t.Fatalf("buildGoBinary: %v", err)
	}

	f, err := elf.Open(outPath)
	if err != nil {
		t.Fatalf("open built binary: %v", err)
	}
	defer f.Close()

	for _, prog := range f.Progs {
		if prog.Type == elf.PT_INTERP {
			t.Fatalf("built plugin binary %q is dynamically linked (found PT_INTERP segment); expected a static, CGO_ENABLED=0 build", outPath)
		}
	}
}
