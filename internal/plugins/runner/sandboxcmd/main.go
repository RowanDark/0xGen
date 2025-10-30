package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
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

	if err := applyPolicy(); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: configure seccomp: %v\n", err)
		os.Exit(1)
	}

	target := os.Args[1]
	args := os.Args[1:]
	if err := syscall.Exec(target, args, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "sandbox: exec %s: %v\n", target, err)
		os.Exit(1)
	}
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
