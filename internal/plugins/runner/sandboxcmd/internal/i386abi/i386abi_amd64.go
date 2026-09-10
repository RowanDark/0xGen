// Package i386abi issues a syscall through the i386 (32-bit) ABI entry
// point (INT 0x80) on amd64. It exists solely so sandboxcmd's tests can
// prove the seccomp filter's architecture check rejects that entry point;
// it is never imported by the sandbox binary itself (main.go does not
// import it), so it never ships in the built sandbox helper.
package i386abi

// Getpid issues the i386 getpid syscall (number 20 in the i386 syscall
// table) via INT 0x80 and returns the raw value the kernel wrote back to
// AX. getpid is never seccomp-denylisted by sandboxcmd, so a call that
// returns normally demonstrates the syscall reached the kernel: it proves
// the process was not killed by the denylist, only (if at all) by the
// arch check.
func Getpid() int32
