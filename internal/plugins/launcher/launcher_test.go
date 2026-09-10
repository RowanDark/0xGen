package launcher

import (
	"debug/elf"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

// TestRestrictedBuildEnvScrubsSecretsAndPath is a regression test for the
// plugin build-time trust boundary: buildGoBinary compiles verified-but-
// untrusted plugin source before any sandbox exists to contain it, so the
// build subprocess must not inherit the daemon's full environment (which
// may hold auth tokens or other secrets) or an attacker-influenceable PATH.
func TestRestrictedBuildEnvScrubsSecretsAndPath(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}

	env := restrictedBuildEnv(goBin)

	want := map[string]string{
		"CGO_ENABLED": "0",
		"GOFLAGS":     "-mod=readonly",
		"GOTOOLCHAIN": "local",
	}
	got := map[string]string{}
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			t.Fatalf("malformed env entry %q", kv)
		}
		if _, dup := got[k]; dup {
			t.Fatalf("duplicate env key %q in restricted build env", k)
		}
		got[k] = v
	}

	for key, wantVal := range want {
		if gotVal, ok := got[key]; !ok || gotVal != wantVal {
			t.Errorf("env[%q] = %q, want %q", key, gotVal, wantVal)
		}
	}

	path, ok := got["PATH"]
	if !ok {
		t.Fatal("restricted build env has no PATH")
	}
	if !strings.Contains(path, filepath.Dir(goBin)) {
		t.Errorf("PATH %q does not contain resolved go toolchain dir %q", path, filepath.Dir(goBin))
	}

	// Anything not on the explicit allowlist below must not be forwarded,
	// since a leaked env var here is a leaked daemon secret at build time.
	allowed := map[string]bool{
		"PATH": true, "CGO_ENABLED": true, "GOFLAGS": true, "GOTOOLCHAIN": true,
		"HOME": true, "USERPROFILE": true, "GOPATH": true, "GOCACHE": true,
		"GOMODCACHE": true, "GOROOT": true, "TMPDIR": true, "TEMP": true,
		"TMP": true, "SystemRoot": true,
	}
	for key := range got {
		if !allowed[key] {
			t.Errorf("restricted build env forwards unexpected variable %q", key)
		}
	}
}
