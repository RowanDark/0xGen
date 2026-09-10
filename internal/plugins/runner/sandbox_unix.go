//go:build !windows

package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/RowanDark/0xgen/internal/plugins/runner/sandboxenv"
)

const (
	sandboxUserID  = 65534
	sandboxGroupID = 65534
)

// caBundlePaths lists the well-known locations Go's pure-Go x509 verifier
// checks for a system CA bundle (see crypto/x509/root_linux.go). Plugin and
// sandbox binaries are built with CGO disabled (see launcher.buildGoBinary),
// so they always use that verifier; copying whichever of these paths exist
// on the host to the same path inside the chroot lets a plugin validate TLS
// certificates without any libc or NSS support staged into the sandbox.
var caBundlePaths = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/pki/tls/cacert.pem",
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

func createSandboxCommand(ctx context.Context, cfg Config) (*exec.Cmd, sandboxEnv, func(), error) {
	if strings.TrimSpace(cfg.SandboxBinary) == "" {
		return nil, sandboxEnv{}, nil, errors.New("sandbox binary is required")
	}

	// chroot(2) and the setresuid/setresgid drop to the sandbox uid below
	// both require CAP_SYS_CHROOT / root. Failing fast here with a clear
	// message beats letting cmd.Start() surface a raw "operation not
	// permitted" from deep inside the exec path.
	if os.Geteuid() != 0 {
		return nil, sandboxEnv{}, nil, fmt.Errorf("plugin sandbox requires the 0xgen daemon to run as root (uid 0): chroot and dropping privileges to the sandbox user both require root, but the daemon is running as uid %d", os.Geteuid())
	}

	root, err := os.MkdirTemp("", "0xgen-sandbox-")
	if err != nil {
		return nil, sandboxEnv{}, nil, fmt.Errorf("create sandbox root: %w", err)
	}
	cleanup := func() {
		_ = os.RemoveAll(root)
	}

	if err := os.Chmod(root, 0o755); err != nil {
		cleanup()
		return nil, sandboxEnv{}, nil, fmt.Errorf("configure sandbox root permissions: %w", err)
	}

	binDir := filepath.Join(root, "bin")
	homeDir := filepath.Join(root, "home", "plugin")
	workDir := filepath.Join(root, "workspace")
	tmpDir := filepath.Join(root, "tmp")
	devDir := filepath.Join(root, "dev")
	etcDir := filepath.Join(root, "etc")
	for _, dir := range []struct {
		path  string
		perm  os.FileMode
		chown bool
	}{
		{binDir, 0o755, false},
		{homeDir, 0o755, true},
		{workDir, 0o755, true},
		{devDir, 0o755, false},
		{etcDir, 0o755, false},
	} {
		if err := os.MkdirAll(dir.path, dir.perm); err != nil {
			cleanup()
			return nil, sandboxEnv{}, nil, fmt.Errorf("create sandbox dir %q: %w", dir.path, err)
		}
		if dir.chown {
			if err := os.Chown(dir.path, sandboxUserID, sandboxGroupID); err != nil {
				cleanup()
				return nil, sandboxEnv{}, nil, fmt.Errorf("set sandbox dir ownership %q: %w", dir.path, err)
			}
		}
	}
	// tmpDir is owned by the sandbox user and closed to everyone else. It
	// used to be created world-writable (0o777), which let any other
	// process running as the shared sandbox uid — including a concurrently
	// sandboxed plugin — read or tamper with another plugin's temp files.
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		cleanup()
		return nil, sandboxEnv{}, nil, fmt.Errorf("create sandbox tmp dir: %w", err)
	}
	if err := os.Chown(tmpDir, sandboxUserID, sandboxGroupID); err != nil {
		cleanup()
		return nil, sandboxEnv{}, nil, fmt.Errorf("set sandbox tmp dir ownership: %w", err)
	}

	if err := stageDeviceNodes(devDir); err != nil {
		cleanup()
		return nil, sandboxEnv{}, nil, fmt.Errorf("stage sandbox device nodes: %w", err)
	}
	// Best-effort: a host missing /etc/resolv.conf or a CA bundle just means
	// DNS/TLS aren't available inside the sandbox either, matching the host.
	stageNetworkFiles(etcDir)

	pluginDst := filepath.Join(binDir, "plugin")
	if err := copyExecutable(cfg.Binary, pluginDst, 0o755); err != nil {
		cleanup()
		return nil, sandboxEnv{}, nil, fmt.Errorf("stage plugin binary: %w", err)
	}
	sandboxDst := filepath.Join(binDir, "sandbox")
	if err := copyExecutable(cfg.SandboxBinary, sandboxDst, 0o755); err != nil {
		cleanup()
		return nil, sandboxEnv{}, nil, fmt.Errorf("stage sandbox binary: %w", err)
	}

	args := append([]string{"/bin/plugin"}, cfg.Args...)
	cmd := exec.CommandContext(ctx, "/bin/sandbox", args...)
	cmd.Dir = "/workspace"
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Chroot:  root,
		Setpgid: true,
	}

	extra := make(map[string]string, 2)
	if cfg.Limits.CPUSeconds > 0 {
		extra[sandboxenv.CPUSecondsEnv] = strconv.FormatUint(cfg.Limits.CPUSeconds, 10)
	}
	if cfg.Limits.MemoryBytes > 0 {
		extra[sandboxenv.MemoryBytesEnv] = strconv.FormatUint(cfg.Limits.MemoryBytes, 10)
	}

	env := sandboxEnv{
		Path:  "/bin",
		Home:  "/home/plugin",
		Tmp:   "/tmp",
		Extra: extra,
	}

	return cmd, env, cleanup, nil
}

// stageDeviceNodes creates /dev/null and /dev/urandom inside the chroot.
// Without them, any plugin code that reads randomness (crypto/rand, and by
// extension most TLS and signing paths) or writes to /dev/null fails with
// ENOENT instead of exercising the error handling it's actually built for.
func stageDeviceNodes(devDir string) error {
	nodes := []struct {
		name  string
		major uint32
		minor uint32
	}{
		{"null", 1, 3},
		{"urandom", 1, 9},
	}
	for _, n := range nodes {
		path := filepath.Join(devDir, n.name)
		dev := int(unix.Mkdev(n.major, n.minor))
		if err := unix.Mknod(path, unix.S_IFCHR|0o666, dev); err != nil {
			return fmt.Errorf("create /dev/%s: %w", n.name, err)
		}
	}
	return nil
}

// stageNetworkFiles copies /etc/resolv.conf and whichever system CA bundle
// exists on the host into the chroot's /etc, so a plugin that reaches the
// network (directly, or once CAP_NETWORK-style egress is enforced) can
// still resolve names and validate TLS certificates. Every step here is
// best-effort: a missing source file is not staged and not an error.
func stageNetworkFiles(etcDir string) {
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		_ = os.WriteFile(filepath.Join(etcDir, "resolv.conf"), data, 0o644)
	}
	for _, src := range caBundlePaths {
		data, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		rel := strings.TrimPrefix(src, "/etc/")
		dst := filepath.Join(etcDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			continue
		}
		_ = os.WriteFile(dst, data, 0o644)
	}
}
