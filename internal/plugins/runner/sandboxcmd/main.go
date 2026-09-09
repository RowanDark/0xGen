package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/RowanDark/0xgen/internal/plugins/runner/sandboxenv"
)

const (
	sandboxUserID  = 65534
	sandboxGroupID = 65534
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sandbox <binary> [args...]")
		os.Exit(2)
	}

	if err := dropPrivileges(); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: drop privileges: %v\n", err)
		os.Exit(1)
	}

	// Resource limits are applied here, to this process, rather than by the
	// 0xgen daemon on itself. This process is single-use, unprivileged
	// (post dropPrivileges), and about to exec the plugin binary, so it is
	// safe to cap its hard limits (Max) as well as the soft ones (Cur):
	// the plugin must never be able to raise its own ceiling back up, and
	// this process holds no other state that a permanently-lowered Max
	// could later harm.
	if err := applyResourceLimits(); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: apply resource limits: %v\n", err)
		os.Exit(1)
	}

	if err := applyPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: configure seccomp: %v\n", err)
		os.Exit(1)
	}

	target := os.Args[1]
	args := os.Args[1:]
	env := stripEnv(os.Environ(), sandboxenv.CPUSecondsEnv, sandboxenv.MemoryBytesEnv)
	if err := syscall.Exec(target, args, env); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: exec %s: %v\n", target, err)
		os.Exit(1)
	}
}

// applyResourceLimits sets RLIMIT_CPU and RLIMIT_AS on the current process
// (this sandbox helper, not the 0xgen daemon) from the limits the daemon
// passed in via the environment. It sets Max equal to Cur: see the comment
// in main for why capping the hard limit here is intentional.
func applyResourceLimits() error {
	if v := os.Getenv(sandboxenv.CPUSecondsEnv); v != "" {
		cpuSeconds, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return fmt.Errorf("parse %s: %w", sandboxenv.CPUSecondsEnv, err)
		}
		limit := syscall.Rlimit{Cur: cpuSeconds, Max: cpuSeconds}
		if err := syscall.Setrlimit(syscall.RLIMIT_CPU, &limit); err != nil {
			return fmt.Errorf("set cpu limit: %w", err)
		}
	}

	if v := os.Getenv(sandboxenv.MemoryBytesEnv); v != "" {
		memoryBytes, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return fmt.Errorf("parse %s: %w", sandboxenv.MemoryBytesEnv, err)
		}
		limit := syscall.Rlimit{Cur: memoryBytes, Max: memoryBytes}
		if err := syscall.Setrlimit(syscall.RLIMIT_AS, &limit); err != nil {
			return fmt.Errorf("set memory limit: %w", err)
		}
	}

	return nil
}

// stripEnv returns env with any entries for the given keys removed, so
// sandbox-internal signaling variables never reach the plugin process.
func stripEnv(env []string, keys ...string) []string {
	out := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, found := strings.Cut(entry, "=")
		if found && contains(keys, name) {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func contains(keys []string, name string) bool {
	for _, k := range keys {
		if k == name {
			return true
		}
	}
	return false
}

func applyPolicy() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}

	disallowed := []uint32{
		uint32(unix.SYS_PTRACE),
		uint32(unix.SYS_KEXEC_LOAD),
		uint32(unix.SYS_OPEN_BY_HANDLE_AT),
		uint32(unix.SYS_MOUNT),
		uint32(unix.SYS_UMOUNT2),
		uint32(unix.SYS_PIVOT_ROOT),
		uint32(unix.SYS_SWAPON),
		uint32(unix.SYS_SWAPOFF),
		uint32(unix.SYS_REBOOT),
		uint32(unix.SYS_SETNS),
		uint32(unix.SYS_UNSHARE),
		uint32(unix.SYS_CHROOT),
		uint32(unix.SYS_BPF),
		uint32(unix.SYS_PERF_EVENT_OPEN),
	}
	appendIfDefined := func(sysno int) {
		if sysno != 0 {
			disallowed = append(disallowed, uint32(sysno))
		}
	}
	appendIfDefined(int(unix.SYS_KEXEC_FILE_LOAD))

	filters := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
	}
	for _, sc := range disallowed {
		filters = append(filters,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: sc, Jt: 0, Jf: 1},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		)
	}
	filters = append(filters, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})

	prog := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0); err != nil {
		return fmt.Errorf("set seccomp filter: %w", err)
	}
	return nil
}

func dropPrivileges() error {
	if err := unix.Setgroups([]int{sandboxGroupID}); err != nil {
		return err
	}
	if err := unix.Setresgid(sandboxGroupID, sandboxGroupID, sandboxGroupID); err != nil {
		return err
	}
	if err := unix.Setresuid(sandboxUserID, sandboxUserID, sandboxUserID); err != nil {
		return err
	}
	return nil
}
